# Metodologija eksternog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje imovine

Za kategorizovan spisak dodatnih OSINT projekata i projekata za otkrivanje veb-sadržaja pogledajte [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint).

> Rečeno vam je da je sve što pripada nekoj kompaniji u opsegu i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađemo sve **kompanije u vlasništvu glavne kompanije**, a zatim i svu **imovinu** tih kompanija. Da bismo to uradili, potrebno je da:<sup>[[1]](#references)</sup>

1. Pronađemo akvizicije glavne kompanije; tako ćemo saznati koje su kompanije u opsegu.
2. Pronađemo ASN svake kompanije (ako ga ima); tako ćemo saznati koje IP opsege svaka kompanija poseduje.
3. Koristimo reverse whois pretrage da bismo pronašli druge zapise (nazive organizacija, domene...) povezane s prvim zapisom (ovo se može raditi rekurzivno).
4. Koristimo druge tehnike, kao što su Shodan filteri `org` i `ssl`, da bismo pronašli drugu imovinu (trik sa `ssl` može se primenjivati rekurzivno).

Za postepenu predaju od razrešenih poddomena ka HTTP crawlu i otkrivanju portova pogledajte [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Akvizicije**

Pre svega, treba da saznamo **koje su druge kompanije u vlasništvu glavne kompanije**.\
Jedna od mogućnosti je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **potražite** **glavnu kompaniju** i **kliknete** na „**acquisitions**“. Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga mogućnost je da posetite stranicu glavne kompanije na **Wikipediji** i potražite **acquisitions**.\
Za javna preduzeća proverite dokumentaciju **SEC/EDGAR**, stranice za **investitore** ili lokalne registre privrednih subjekata (npr. **Companies House** u UK).\
Za globalne korporativne strukture i podružnice pogledajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku trebalo bi da znate sve kompanije koje su u opsegu. Hajde da vidimo kako da pronađemo njihovu imovinu.

### **ASN-ovi**

Broj autonomnog sistema (**ASN**) je **jedinstveni broj** koji **Internet Assigned Numbers Authority (IANA)** dodeljuje **autonomnom sistemu** (AS).\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa spoljnim mrežama. Njima upravlja jedna organizacija, ali mogu obuhvatati više operatera.

Važno je utvrditi da li je **kompaniji dodeljen neki ASN**, kako bismo pronašli njene **IP opsege**. Bilo bi korisno izvršiti **test ranjivosti** nad svim **hostovima** u **opsegu** i **potražiti domene** na tim IP adresama.\
Možete **pretraživati** po nazivu kompanije, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kom se kompanija nalazi, ove veze mogu biti korisne za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). Ipak, verovatno su sve** korisne informacije **(IP opsezi i Whois)** već prikazane na prvoj vezi.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Takođe, enumeracija pomoću [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatski agregira i sumira ASN-ove na kraju skeniranja.

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

Takođe možete pronaći IP opsege organizacije pomoću [ASNLookup](https://asnlookup.com/), koji ima ograničeni besplatni API paket.

### **Traženje ranjivosti**

U ovom trenutku znamo **sva sredstva u opsegu**, pa ako vam je to dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti usluge kao što su** Shodan, Censys ili ZoomEye **da biste pronašli** otvorene portove **i, u zavisnosti od toga šta pronađete, pogledati u ovoj knjizi kako da pentestujete razne servise koji možda rade.**\
**Vredi pomenuti i da možete pripremiti liste** podrazumevanih korisničkih imena **i** lozinki **i pokušati da izvršite** bruteforce napade na servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije u opsegu i njihova sredstva; vreme je da pronađemo domene u opsegu.

_Imajte na umu da pomoću tehnika navedenih u nastavku možete pronaći i poddomene i da te informacije ne treba potcenjivati._

Pre svega, trebalo bi da potražite **glavni domen** svake kompanije. Na primer, za _Tesla Inc._ to je _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse DNS pretrage** tih **IP adresa kako biste pronašli još domena u opsegu**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i [SecurityTrails](https://securitytrails.com/), mada su za pristup istorijskim DNS podacima potrebni plaćeni planovi.\
Za velike opsege korisni su alati poput [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), koji automatizuju obrnute pretrage i dopunu podataka.

### **Reverse Whois (loop)**

U **whois** zapisu možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **adrese e-pošte**, telefonski brojevi... Još je zanimljivije to što možete pronaći **dodatne resurse povezane sa kompanijom** ako izvršite **reverse whois pretrage na osnovu bilo kog od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista adresa e-pošte).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatan** web interfejs; API se plaća.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Plaća se
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Ograničen besplatan API pristup za aktuelne DNS zapise/poddomene; za istorijske i obrnute pretrage potreban je plaćeni plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 besplatnih API kredita nakon registracije; nakon toga se plaća.

Ovaj zadatak možete automatizovati pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink)(potreban je whoxy API ključ).\
Možete obaviti i automatsko otkrivanje putem reverse whois-a pomoću alata [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovom tehnikom možete otkriti dodatna imena domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako pronađete **isti ID istog trackera** na 2 različite stranice, možete pretpostaviti da **obema stranicama** **upravlja isti tim**.\
Na primer, ako na nekoliko stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji omogućavaju pretragu po ovim i drugim trackerima:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Plaćena** web i API usluga ([cene](https://www.stackscan.com/pricing)); trenutno se ne nudi besplatan plan. Pretražujte prema bilo kom resursu koji se isporučuje, a ne samo prema ID-ovima trackera: putanji skripte, nazivu samostalno hostovanog paketa ili hostu sa kog se učitava resurs; rezultat prikazuje sve sajtove koji ga koriste.

API vraća tehnološki skup za jedan domen, što je korisno za potvrdu da kandidat-resurs pripada istoj infrastrukturi:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Vraća svaku detektovanu tehnologiju zajedno s njenom kategorijom. Pivotiranje preko asseta trenutno je dostupno samo za web, dok API omogućava pretragu po domenu.

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene naše mete tako što ćemo potražiti isti hash favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti hash favicon ikone kao naša meta.

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati hash favicon ikone kao pivot u Shodan-u ili FOFA-i da biste pronašli druge javno izložene instance iste tehnologije.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ovako možete da izračunate favicon hash veb-sajta (MMH3 nad bajtovima favicon-a kodiranim u base64):

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

Takođe možete prikupljati favicon hash vrednosti u velikom obimu pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim pivotovati u Shodan/Censys.

Favicon otiske tretirajte kao tragove i potvrdite ih pomoću pratećih signala.<sup>[[3]](#references)[[4]](#references)</sup>

- **Tretirajte hash kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su sudari, ponovo korišćene ikone i namerno lažiranje.
- **Proverite više od** `/favicon.ico`: pregledajte putanje framework-a/build-a, datoteke manifesta, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL-ove i HTML oznake `<link rel="icon">`.
- **Statički resursi mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno zatražite ikonu i pregledajte `ETag`, `Last-Modified`, preusmeravanja i zaglavlja keša.
- **Potvrdite podudaranja pomoću pratećih signala**: uporedite naslov, hash HTML-a/tela, zaglavlja, subjekte/SAN-ove TLS sertifikata, komponente proizvoda i izložene portove.
- **Grupišite prema hash-u HTML-a/tela**: dosledan šablon jača otisak; različiti šabloni ukazuju na generičku ili zajedničku ikonu.
- **Hash koji se pojavljuje u nepovezanim potpisima, portovima i proizvodima tretirajte kao mogući honeypot ili rezervnu ikonu.**
- **Kod dvosmislenih ciljeva uporedite stvarnu stranicu sa nepostojećom putanjom**, kao što je `/_favicon_probe_<8-hex>`; podudarni odgovori hostinga ili stranice za parkiranje domena mogu objasniti zajedničku ikonu.
- **Pokrenite trijažu pomoću Nuclei pravila za detekciju ili javnih skupova podataka** koji povezuju hash vrednosti favicon-a sa proizvodima i CPE-ovima.
- **Imajte u vidu ograničenja pokrivenosti zasnovane na IP adresama**: površine iza CDN-a, usmeravane preko SNI-ja, anycast i površine dostupne samo preko domena možda nedostaju u skupovima podataka sličnim Shodan-u.

### **Copyright / jedinstveni string**

Pretražite web stranice i pronađite **stringove koji bi mogli biti zajednički različitim sajtovima iste organizacije**. Dobar primer je **string autorskih prava**. Zatim pretražite taj string u **Google-u**, drugim **pregledačima** ili čak u **Shodan-u**: `shodan search http.html:"Copyright string"`

### **Vreme CRT-a**

Često postoji cron posao kao što je

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

kako bi se istovremeno obnovili svi sertifikati na serveru. Povezivanje vremenskih oznaka sertifikata ili pozicija u logovima transparentnosti sertifikata može otkriti povezane domene.<sup>[[6]](#references)</sup>

Koristite i direktno logove **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o Mail DMARC-u

Možete koristiti veb-sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da biste pronašli **domene i poddomene koji dele iste DMARC informacije**.\
Još jedna korisna usluga je [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Napušteni A zapis može postati dostupan kada cloud provajder ponovo dodeli IP adresu. Opisano istraživanje prikazuje oportunistički postupak koji kreira instancu i povezuje njenu adresu sa podacima pasivnog DNS-a; scenarije preuzimanja testirajte samo u okviru odobrenog opsega.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće korake otkrivanja svaki put kada pronađete novi domen: svaki rezultat može otkriti dodatna imena sertifikata, veze kroz pasivni DNS, podudaranja favikona i identifikatore organizacije koji nisu bili vidljivi na osnovu početnog domena.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Pošto već znate naziv organizacije koja poseduje IP prostor, te podatke možete pretražiti na Shodanu koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove da biste u TLS sertifikatu otkrili nove, neočekivane domene.

Možete da pristupite **TLS sertifikatu** glavne veb-stranice, pribavite **naziv organizacije**, a zatim potražite taj naziv u **TLS sertifikatima** svih veb-stranica poznatih servisu **Shodan**, koristeći filter: `ssl:"Tesla Motors"` ili alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomeje**; zaista je odličan.

**Pasivni DNS / Istorijski DNS**

Podaci pasivnog DNS-a su sjajan način za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili mogu biti preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom različitom** od onih koje ste već otkrili tokom otkrivanja imovine, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove kako da ih „napadnete“**.\
_Imajte na umu da se domen ponekad nalazi na IP adresi koju klijent ne kontroliše, pa nije u opsegu; budite pažljivi._

## Poddomeni

> Znamo sve kompanije obuhvaćene opsegom, svu imovinu svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i u pronalaženju poddomena

### **DNS**

Pokušajmo da pronađemo **poddomenе** u **DNS** zapisima. Trebalo bi da pokušamo i sa **Zone Transfer**-om (ako je ranjiv, prijavite to).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Za API-je i platforme koje obuhvataju infrastrukturu, reputaciju, evidenciju o kompromitovanim podacima i obogaćivanje podataka izvan otkrivanja poddomena, pogledajte [katalog API-ja za izviđanje i obaveštajne podatke o pretnjama](reconnaissance-and-threat-intelligence-apis.md).

Najbrži način da pronađete mnogo poddomena jeste pretraživanje eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate podesite API ključeve):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

Postoje **i drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za pronalaženje poddomena, kao što su:

- [**IP.THC.ORG**](https://ip.thc.org) besplatan API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB free API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove iz AlienVault-ovog Open Threat Exchange-a, Wayback Machine-a i Common Crawl-a za bilo koji domen.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Pretražuju web u potrazi za JS datotekama i iz njih izdvajaju poddomene.

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

- [**Censys alat za pronalaženje poddomena**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) nudi ograničen besplatan API pristup aktuelnim DNS podacima i podacima o poddomenima; za istorijske DNS/IP podatke potreban je plaćeni plan.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ovaj projekat besplatno nudi **sve poddomene povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/Moaaz-0x/chaospy), ili čak pristupiti opsegu koji koristi ovaj projekat: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Poređenje** mnogih ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomene** tako što ćemo brute-force metodom proveravati DNS servere koristeći moguće nazive poddomena.

Za ovu radnju biće vam potrebne neke **uobičajene wordliste poddomena, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrebne su vam i IP adrese kvalitetnih DNS resolvera. Da biste napravili listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i pomoću alata [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) filtrirati listu. Možete koristiti i: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno obavljao DNS brute-force. Veoma je brz, ali je sklon davanju lažno pozitivnih rezultata.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper za `massdns`, napisan u Go jeziku, koji omogućava enumeraciju važećih poddomena pomoću aktivnog bruteforce-a, kao i razrešavanje poddomena uz rukovanje wildcard-om i jednostavnu podršku za ulazne i izlazne podatke.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhrono brute-force isprobavanje naziva domena.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Drugi DNS brute-force krug

Nakon što pronađete poddomene koristeći otvorene izvore i brute-forcing, možete generisati izmene pronađenih poddomena kako biste pokušali da pronađete još njih. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
  - goaltdns permutations **wordlist** možete preuzeti [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka sa permutacijama, gotator će koristiti sopstvenu.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Pored generisanja permutacija poddomena, može pokušati i da ih razreši (ali je bolje koristiti prethodno pomenute alate).
  - **wordlist** za altdns permutacije možete pronaći [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će izvršiti brute force rezultata (ne podržava DNS wildcard).
  - dmut wordlist sa permutacijama možete preuzeti [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše potencijalne nazive novih poddomena** prema navedenim obrascima, kako bi pokušao da otkrije još poddomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči obrasce nalik regex-u iz otkrivenih poddomena i generiše kandidate za razrešavanje.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force poddomena povezan sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dati skup ulaznih podataka, kao što su prilagođena wordlist-a ili istorijski DNS/TLS zapisi, da precizno generiše više odgovarajućih naziva domena i dodatno ih proširuje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.

```
echo www | subzuf facebook.com
```

### **Tok rada za otkrivanje poddomena**

Primeri tokova rada Trickest kombinuju OSINT, DNS brute force i faze permutacija za ponovljivo enumerisanje poddomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više veb-stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa veb-stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** potražiti domene na određenoj IP adresi ili tako što ćete **brute force metodom isprobavati nazive VHost domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da neki poddomen može biti skriven na veb-serveru, možete pokušati da ga pronađete brute force metodom:

Kod vhostova zasnovanih na imenima, fuzz-ujte zaglavlje `Host` i koristite ffuf-ovu automatsku kalibraciju da biste filtrirali podrazumevani odgovor.<sup>[[2]](#references)</sup>

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
> Ovom tehnikom možda ćete moći da pristupite i internim/skrivenim endpoint-ima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je u zaglavlju _**Origin**_ navedena važeća domena/poddomena. U takvim slučajevima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **poddomene**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Dok tražite **subdomains**, obratite pažnju na to da li neki **pokazuje** na neku vrstu **bucket-a** i, u tom slučaju, [**proverite dozvole**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar scope-a, pokušajte da [**brute force-ujete moguće nazive bucket-a i proverite dozvole**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Praćenje**

Možete **pratiti** da li se kreiraju **novi subdomains** nekog domena tako što ćete pratiti **Certificate Transparency** logove, što radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite moguće [**preuzimanje subdomain-a**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomain** pokazuje na neki **S3 bucket**, [**proverite dozvole**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Ako pronađete neki **subdomain sa IP adresom koja se razlikuje** od onih koje ste već otkrili tokom otkrivanja asset-a, trebalo bi da obavite **osnovno skeniranje ranjivosti** (koristeći Nessus ili OpenVAS) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad”**.\
_Napomena: ponekad je subdomain hostovan na IP adresi koju klijent ne kontroliše, pa nije u scope-u. Budite oprezni._

## IPs

Tokom početnih koraka možda ste **pronašli neke opsege IP adresa, domene i subdomains**.\
Sada je vreme da **prikupite sve IP adrese iz tih opsega**, kao i one za **domene/subdomains (DNS upiti).**

Koristeći servise kao što su sledeći, možete pronaći i **prethodne IP adrese koje su koristili domeni i subdomains**. Klijent je možda i dalje vlasnik tih IP adresa (što vam može pomoći da pronađete [**CloudFlare bypass-e**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (za istorijske DNS/IP podatke potreban je plaćeni plan)

Možete i da potražite domene koji pokazuju na određenu IP adresu pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host) ili online servisa za obrnuto IP pretraživanje, kao što je [**NetAPI**](https://netapi.com/lookup-ip/)

### **Traženje ranjivosti**

**Skenirajte portove na svim IP adresama koje ne pripadaju CDN-ovima** (jer tamo verovatno nećete pronaći ništa zanimljivo). Na otkrivenim servisima koji rade možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**uputstvo**](../pentesting-network/index.html) **o tome kako da skenirate hostove.**

## Potraga za web serverima

> Pronašli smo sve kompanije i njihovu infrastrukturu i poznajemo opsege IP adresa, domene i subdomains unutar scope-a. Vreme je da potražimo web servere.

Tokom prethodnih koraka verovatno ste već obavili **recon nad otkrivenim IP adresama i domenima**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo pogledati neke **brze trikove za pronalaženje web servera** unutar scope-a.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da obavite i **skeniranje ranjivosti** i **skeniranje portova** (**ako je dozvoljeno** scope-om).

**Brz način** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću [**masscan-a možete pronaći ovde**](../pentesting-network/index.html#http-port-discovery).\
Još neki alati za pronalaženje web servera su [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Prosledite im listu domena, pa će pokušati da se povežu na port 80 (http) i 443 (https). Možete i da navedete druge portove koje želite da provere:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Snimci ekrana**

Sada kada ste otkrili **sve web servere** u opsegu (među **IP adresama** kompanije i svim **domenima** i **poddomenima),** verovatno **ne znate odakle da počnete**. Zato, pojednostavimo i počnimo tako što ćemo napraviti snimke ekrana svih njih. Samo **pogledom** na **glavnu stranicu** možete pronaći **neobične** endpoint-e koji su **podložniji** tome da budu **ranjivi**.

Da biste sproveli ovu ideju, možete koristiti [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete pokrenuti [**eyeballer**](https://github.com/BishopFox/eyeballer) nad svim **snimcima ekrana** da biste saznali **šta verovatno sadrži ranjivosti**, a šta ne.

## Javni cloud resursi

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, trebalo bi **da počnete od liste ključnih reči koje je identifikuju**. Na primer, za kripto kompaniju mogli biste da koristite reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i liste reči sa **čestim nazivima koji se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, koristeći te reči, napravite **permutacije** (više informacija potražite u odeljku [**Drugi krug DNS brute-force-a**](#second-dns-bruteforce-round)).

Sa dobijenim listama reči možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da pri traženju cloud resursa treba da **tražite i više od samih bucket-a u AWS-u**.

### **Traženje ranjivosti**

Ako pronađete stvari kao što su **otvoreni bucket-i ili izložene cloud funkcije**, trebalo bi da im **pristupite** i proverite šta vam nude i da li možete da ih zloupotrebite.

## Email adrese

Uz **domene** i **podd domene** u opsegu, praktično imate sve što vam je **potrebno za početak traženja email adresa**. Ovo su **API-ji** i **alati** koji su mi se najbolje pokazali u pronalaženju email adresa neke kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - uz API-je
- API za [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API za [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API za [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

Email adrese će vam kasnije dobro doći za **brute-force prijava na web i auth servise** (kao što je SSH). Potrebne su i za **phishing**. Pored toga, ovi API-ji će vam dati još **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Curenje kredencijala

Uz **domene,** **podd domene** i **email adrese** možete početi da tražite kredencijale koji su ranije procureli i pripadaju tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** kredencijale, to je veoma laka pobeda.

## Curenje tajni

Curenje kredencijala povezano je sa hakovima kompanija pri kojima su **osetljive informacije procurele i bile prodate**. Međutim, kompanije mogu biti pogođene i **drugim curenjima** čiji podaci nisu u tim bazama:

### Curenja sa GitHub-a

Kredencijali i API-ji mogu procureti u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu kompaniju na GitHub-u.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** neke **organizacije** i njenih **programera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/gitleaks/gitleaks) nad njima.

**Leakos** se može koristiti i za pokretanje **gitleaks** nad svim **tekstualnim** URL-ovima koje mu prosledite, jer ponekad i **web stranice sadrže tajne**.

#### GitHub dorks

Pogledajte stranicu [GitHub dorks and leaks](github-leaked-secrets.md) za potencijalne **GitHub dorks** koje možete pretražiti u organizaciji.

### Curenja sa paste sajtova

Ponekad napadači ili zaposleni **objave sadržaj kompanije na paste sajtu**. Taj sadržaj može, ali ne mora, da sadrži **osetljive informacije**, ali svakako vredi pretražiti ga.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) za istovremenu pretragu na više od 80 paste sajtova.

### Google dorks

Stari, ali dobri Google dorks uvek su korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu tamo**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno da pokrenete. Zato možete izabrati svojih omiljenih 10 ili upotrebiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da biste ih sve pokrenuli**.

_Napomena: alati koji pokušavaju da pretraže celu bazu koristeći uobičajeni Google pregledač nikada neće završiti, jer će vas Google vrlo brzo blokirati._

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** kredencijale ili API tokene, to je veoma laka pobeda.

## Ranjivosti u javnom kodu

Ako ste otkrili da kompanija ima **open-source kod**, možete da ga **analizirate** i potražite **ranjivosti**.

**U zavisnosti od jezika**, možete koristiti različite **alate**; pogledajte listu [alata za pregled izvornog koda](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji omogućavaju **skeniranje javnih repozitorijuma**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologija pentestiranja web aplikacija**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje pronađu lovci na bagove nalazi se u **web aplikacijama**, zato bih u ovom trenutku želeo da predstavim **metodologiju testiranja web aplikacija**; [**te informacije možete pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Želim posebno da pomenem odeljak [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako od njih ne treba očekivati da pronađu veoma ozbiljne ranjivosti, korisni su za uključivanje u **workflow-e radi prikupljanja početnih informacija o webu**.

## Rekapitulacija

> Čestitamo! Do ovog trenutka ste već obavili **svo osnovno izviđanje**. Da, osnovno je zato što se može obaviti još mnogo izviđanja (kasnije ćemo videti još trikova).

Dakle, već ste:

1. Pronašli sve **kompanije** u opsegu
2. Pronašli sve **resurse** koji pripadaju kompanijama (i obavili skeniranje ranjivosti ako je to u opsegu)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **podd domene** tih domena (da li je moguće preuzimanje poddomena?)
5. Pronašli sve **IP adrese** (sa **CDN-ova** i van njih) u opsegu.
6. Pronašli sve **web servere** i napravili njihove **snimke ekrana** (ima li nečeg neobičnog što vredi detaljnije proveriti?)
7. Pronašli sve **potencijalne javne cloud resurse** koji pripadaju kompaniji.
8. Pronašli **email adrese**, **procurele kredencijale** i **procurele tajne** koji bi vam mogli doneti **veliku pobedu uz vrlo malo truda**.
9. **Pentestirali sve pronađene web sajtove**

## **Alati za potpuno automatizovano izviđanje**

Postoji nekoliko alata koji će obaviti deo predloženih radnji nad zadatim opsegom.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Pomalo zastareo i nije ažuriran



## References

- [1] [Jason Haddix – Metodologija lovca na bagove v4.0: Recon izdanje](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O faviconima: Od ikona pregledača do obaveštajnih podataka o površini napada](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Pretvaranje favicon.ico u oružje za BugBounties, OSINT i ko zna šta još](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Otkrivanje domena pomoću napada vremenske korelacije na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasivno preuzimanje: otkrivanje (i oponašanje) skupe kampanje za preuzimanje poddomena](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Jedinstvena metoda enumeracije poddomena](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Potpuni workflow za otkrivanje poddomena, 1. deo](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Potpuno automatizovano otkrivanje poddomena brute-force metodom pomoću Trickest workflow-a, 2. deo](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Snimak ekrana izlaza favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
