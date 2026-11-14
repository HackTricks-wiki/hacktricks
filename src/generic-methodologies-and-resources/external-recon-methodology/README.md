# Metodologija spoljnog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje imovine

> Rečeno vam je da je sve što pripada nekoj kompaniji u scope-u i želite da utvrdite šta ta kompanija zaista poseduje.

Cilj ove faze je da utvrdimo sve **kompanije koje poseduje glavna kompanija**, a zatim i svu **imovinu** tih kompanija. Da bismo to uradili:<sup>[[1]](#references)</sup>

1. Pronađite akvizicije glavne kompanije; tako ćete utvrditi koje su kompanije u scope-u.
2. Pronađite ASN (ako postoji) svake kompanije; tako ćete utvrditi IP opsege koje svaka kompanija poseduje.
3. Koristite reverse whois pretrage da biste pronašli druge unose (nazive organizacija, domene...) povezane s prvim unosom (ovo se može raditi rekurzivno).
4. Koristite druge tehnike, kao što su Shodan `org` i `ssl` filteri, da biste potražili drugu imovinu (trik sa `ssl` može se primenjivati rekurzivno).

Za predaju od otkrivenih poddomena do HTTP crawling-a i otkrivanja portova pogledajte [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Akvizicije**

Pre svega, treba da utvrdimo koje **druge kompanije poseduje glavna kompanija**.\
Jedna mogućnost je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **potražite** **glavnu kompaniju** i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija kupila.\
Druga mogućnost je da posetite stranicu glavne kompanije na **Wikipediji** i potražite **akvizicije**.\
Za javne kompanije proverite prijave **SEC/EDGAR**, stranice **investor relations** ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalne korporativne strukture i podružnice isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Dobro, u ovom trenutku trebalo bi da znate sve kompanije koje su u scope-u. Hajde da vidimo kako da pronađemo njihovu imovinu.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstveni broj** koji **Internet Assigned Numbers Authority (IANA)** dodeljuje **autonomnom sistemu** (AS).\
**AS** se sastoji od **blokova** **IP adresa** sa jasno definisanom politikom pristupa spoljnim mrežama. Njima upravlja jedna organizacija, ali mogu se sastojati od više operatora.

Važno je utvrditi da li je **kompaniji dodeljen neki ASN** kako biste pronašli njene **IP opsege.** Bilo bi korisno izvršiti **testiranje ranjivosti** nad svim **hostovima** u **scope-u** i **potražiti domene** na tim IP adresama.\
Možete **pretraživati** po **nazivu** kompanije, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kom se kompanija nalazi, ove veze mogu biti korisne za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno su sve** korisne informacije **(IP opsezi i Whois)** već dostupne na prvoj vezi.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Takođe, enumeration u okviru [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatski agregira i sumira ASN-ove na kraju skeniranja.

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

Možete takođe pronaći IP opsege organizacije koristeći [ASNLookup](https://asnlookup.com/), koji ima ograničen besplatan API plan.

### **Traženje ranjivosti**

U ovom trenutku znamo **sve resurse unutar scope-a**, pa ako imate dozvolu, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da biste pronašli** otvorene portove **i, u zavisnosti od toga šta pronađete, pogledati u ovoj knjizi kako da pentestujete razne servise koji možda rade.**\
**Takođe, vredi napomenuti da možete pripremiti i liste** podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar scope-a i njihove resurse; vreme je da pronađemo domene unutar scope-a.

_Imajte na umu da pomoću tehnika predloženih u nastavku možete pronaći i poddomene, a te informacije ne treba potcenjivati._

Prvo treba da potražite **glavni domen** (ili domene) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse DNS lookups** nad tim **IP adresama kako biste pronašli još domena unutar scope-a**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i [SecurityTrails](https://securitytrails.com/), mada je za pristup istorijskim DNS podacima potreban plaćeni plan.\
Za velike opsege korisni su alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), koji automatizuju reverse lookup-ove i obogaćivanje podataka.

### **Reverse Whois (loop)**

U okviru **whois** podataka možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **email adrese**, brojevi telefona... Međutim, još je zanimljivije to što možete pronaći **dodatne resurse povezane s kompanijom** ako izvršite **reverse whois pretrage na osnovu nekog od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista email adresa).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatan** web interfejs; API se plaća.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Plaća se
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Ograničen besplatan API pristup za aktuelne DNS podatke/poddomene; za istorijske podatke i reverse lookup pretrage potreban je plaćeni plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 besplatnih API kredita nakon registracije; nakon toga se plaća.

Ovaj zadatak možete automatizovati pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink)(potreban je whoxy API ključ).\
Možete izvršiti i automatsko otkrivanje reverse whois podataka pomoću alata [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovom tehnikom možete otkriti dodatna imena domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako na 2 različite stranice pronađete **isti ID istog trackera**, možete pretpostaviti da **obema stranicama** **upravlja isti tim**.\
Na primer, ako na nekoliko stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji omogućavaju pretragu na osnovu ovih trackera i drugih podataka:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Plaćena** web i API usluga ([cene](https://www.stackscan.com/pricing)); trenutno nije oglašen besplatan plan. Možete pretraživati na osnovu bilo kog dostupnog asset-a, ne samo ID-jeva trackera: putanje do skripti, naziva self-hosted bundle-a ili hosta sa kog se učitava asset, da biste pronašli sve sajtove na kojima se nalazi.

API vraća stack za jedan domen, što je korisno za potvrdu da kandidat asset pripada istom skupu resursa:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Vraća svaku otkrivenu tehnologiju zajedno sa njenom kategorijom. Pivotiranje preko asseta trenutno je dostupno samo za web, dok API omogućava pretragu po domenu.

### **Favicon**

Da li ste znali da možemo da pronađemo povezane domene i poddomene naše mete tako što ćemo potražiti isti hash favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Rezultati alata Favihash korišćeni za otkrivanje domena koji dele isti hash favicon ikone](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, Favihash nam omogućava da otkrijemo domene koji imaju isti hash favicon ikone kao naš cilj.

![Izlaz alata Favihash korišćen za otkrivanje domena sa istim hashom favicon ikone](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati hash favicon ikone kao pivot u Shodan-u ili FOFA-i da biste pronašli druge izložene instance iste tehnologije.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ovako možete da izračunate favicon hash veb-sajta (MMH3 nad base64-encoded bajtovima favicon-a):

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

Možete dobiti i hash-eve favicon-a na velikoj skali pomoću alata [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim pivotirati u Shodan/Censys.

Tretirajte otiske favicon-a kao naznake i proverite ih pomoću okolnih signala.<sup>[[3]](#references)[[4]](#references)</sup>

- **Tretirajte hash kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su sudari, ponovo korišćene ikone i namerno lažiranje.
- **Proverite više od** `/favicon.ico`: pregledajte putanje framework-a/build-a, manifest datoteke, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, ugrađene data URL-ove i HTML oznake `<link rel="icon">`.
- **Statički resursi mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno zatražite ikonu i pregledajte `ETag`, `Last-Modified`, preusmerenja i zaglavlja keša.
- **Proverite podudaranja pomoću okolnih signala**: uporedite naslov, hash HTML-a/tela, zaglavlja, subjekte/SAN-ove TLS sertifikata, komponente proizvoda i izložene portove.
- **Grupišite po hash-u HTML-a/tela**: dosledan šablon pojačava pouzdanost otiska; različiti šabloni ukazuju na generičku ili deljenu ikonu.
- **Tretirajte hash koji se pojavljuje uz nepovezane potpise, portove i proizvode kao mogući honeypot ili placeholder.**
- **Kod dvosmislenih ciljeva uporedite stvarnu stranicu sa nepostojećom putanjom**, kao što je `/_favicon_probe_<8-hex>`; podudarni odgovori hostinga ili parkiranog domena mogu objasniti zajedničku ikonu.
- **Započnite trijažu pomoću Nuclei pravila za detekciju ili javnih skupova podataka** koji povezuju hash-eve favicon-a sa proizvodima i CPE-ovima.
- **Imajte na umu ograničenja pokrivenosti zasnovane na IP adresama**: površine iza CDN-a, rutirane preko SNI-ja, anycast i površine dostupne samo preko domena možda nedostaju u skupovima podataka sličnim Shodanu.

### **Autorsko pravo / jedinstveni niz**

Pretražite veb-stranice i pronađite **nizove koji mogu biti zajednički različitim veb-sajtovima unutar iste organizacije**. Dobar primer može biti **tekst o autorskim pravima**. Zatim potražite taj niz na **Google-u**, u drugim **browser-ima** ili čak u **Shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT vreme**

Uobičajeno je imati cron posao kao što je

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

da biste obnovili sve sertifikate na serveru istovremeno. Povezivanje vremenskih oznaka sertifikata ili pozicija u certificate transparency logovima može otkriti povezane domene.<sup>[[6]](#references)</sup>

Koristite i **certificate transparency** logove direktno:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o Mail DMARC-u

Možete koristiti veb-sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da biste pronašli **domene i poddomene koji dele iste DMARC informacije**.\
Još jedna korisna usluga je [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Napушteni A zapis može ponovo postati dostupan kada cloud provajder dodeli IP adresu drugom korisniku. U navedenom istraživanju prikazan je oportunistički postupak u kom se pokreće instanca i njena adresa povezuje sa podacima iz passive DNS-a; scenarije preuzimanja testirajte samo u okviru odobrenog opsega.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće korake otkrivanja svaki put kada pronađete novi domen: svaki rezultat može otkriti dodatna imena iz sertifikata, veze iz passive DNS-a, podudaranja favicona i identifikatore organizacija koji nisu bili vidljivi u početnom unosu.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Pošto već znate naziv organizacije koja poseduje IP prostor, te podatke možete da pretražite na Shodanu pomoću: `org:"Tesla, Inc."` Proverite pronađene hostove da biste otkrili nova neočekivana imena domena u TLS sertifikatu.

Možete da pristupite **TLS sertifikatu** glavne veb-stranice, pribavite **naziv organizacije**, a zatim pretražite taj naziv u **TLS sertifikatima** svih veb-stranica poznatih **Shodanu** pomoću filtera: `ssl:"Tesla Motors"` ili upotrebite alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomaine**; prilično je impresivan.

**Passive DNS / Istorijski DNS**

Podaci iz Passive DNS-a su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili mogu biti preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji neki slučaj [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete neki **domen sa IP adresom različitom** od onih koje ste već otkrili tokom pronalaženja sredstava, trebalo bi da obavite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihovo „napadanje“**.\
_Imajte na umu da je domen ponekad hostovan na IP adresi koju klijent ne kontroliše, pa nije u opsegu; budite pažljivi._

## Poddomeni

> Znamo sve kompanije u opsegu, sva sredstva svake kompanije i sve domene povezane sa kompanijama.

Vreme je da pronađemo sve moguće poddomene za svaki pronađeni domen.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i u pronalaženju poddomena.

### **DNS**

Pokušajmo da pronađemo **poddomaine** iz **DNS** zapisa. Trebalo bi da pokušamo i **Zone Transfer** (ako je ranjiv, prijavite ga).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Za API-je i platforme koje pokrivaju infrastrukturu, reputaciju, evidenciju curenja podataka i obogaćivanje podataka izvan otkrivanja poddomena, pogledajte [katalog API-ja za izviđanje i obaveštajne podatke o pretnjama](reconnaissance-and-threat-intelligence-apis.md).

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

Postoje **i drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za njihovo pronalaženje, kao što je:

- [**IP.THC.ORG**](https://ip.thc.org) besplatan API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB besplatni API**](https://github.com/jonluca/Anubis-DB)

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

- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove za bilo koji domen sa AlienVault-ovog Open Threat Exchange-a, Wayback Machine-a i Common Crawl-a.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Pretražuju veb u potrazi za JS datotekama i iz njih izdvajaju poddomene.

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

Ovaj projekat besplatno nudi **sve poddomene povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/Moaaz-0x/chaospy), ili čak pristupiti scope-u koji koristi ovaj projekat: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Poređenje** mnogih ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hajde da pokušamo da pronađemo nove **poddomene** pomoću brute-force napada na DNS servere, koristeći moguće nazive poddomena.

Za ovu aktivnost biće vam potrebne neke **uobičajene wordliste za poddomene**, kao što su:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrebne su vam i IP adrese dobrih DNS resolvera. Da biste napravili listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i filtrirati ih pomoću [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Možete koristiti i: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno obavljao DNS brute-force. Veoma je brz, ali je sklon lažno pozitivnim rezultatima.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je omotač oko `massdns`, napisan u Go-u, koji omogućava enumeraciju validnih poddomena pomoću aktivnog brute-force-a, kao i razrešavanje poddomena uz obradu wildcard zapisa i jednostavan ulazno-izlazni rad.

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

Nakon što pronađete poddomene koristeći otvorene izvore i brute-forcing, možete generisati izmene pronađenih poddomena kako biste pokušali da pronađete još više. U tu svrhu korisno je nekoliko alata:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Generiše permutacije na osnovu domena i poddomena.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Generiše permutacije na osnovu domena i poddomena.
  - goaltdns **wordlist** za permutacije možete pronaći [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka s permutacijama, gotator će koristiti sopstvenu.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Pored generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno pomenute alate).
  - **wordlist** za altdns permutacije možete preuzeti [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za permutacije, mutacije i izmene poddomena. Ovaj alat će brute force-om pronaći rezultat (ne podržava DNS wildcard).
  - Listu reči za permutacije pomoću dmut-a možete preuzeti [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena, **generiše nova potencijalna imena poddomena** prema navedenim obrascima kako bi pokušao da otkrije još poddomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči obrasce nalik regularnim izrazima iz otkrivenih poddomena i generiše kandidate za razrešavanje.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force otkrivanje poddomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što je prilagođena lista reči ili istorijski DNS/TLS zapisi, da bi precizno generisao više odgovarajućih naziva domena i dalje ih proširivao u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.

```
echo www | subzuf facebook.com
```

### **Tok otkrivanja poddomena**

Primeri Trickest workflow-a kombinuju OSINT, DNS brute force i faze permutacija za ponovljivo nabrajanje poddomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više veb-stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa veb-stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** potražiti domene na toj IP adresi ili pokušati **brute force naziva VHost domena na toj IP adresi**.

#### OSINT

Možete pronaći neke **VHosts na IP adresama pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki poddomen sakriven na veb-serveru, možete pokušati da ga pronađete brute force metodom:

Za vhosts zasnovane na imenima, fuzz-ujte `Host` zaglavlje i koristite ffuf-ovu automatsku kalibraciju da biste filtrirali podrazumevani odgovor.<sup>[[2]](#references)</sup>

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

Ponekad ćete naići na stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada se u zaglavlju _**Origin**_ navede važeći domen/poddomen. U takvim slučajevima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **poddomene**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute force bucketova**

Dok tražite **subdomene**, obratite pažnju na to da li **pokazuju** na neki **bucket**; ako je tako, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pošto ćete u ovom trenutku znati sve domene unutar opsega, pokušajte i da [**brute force-om pronađete moguće nazive bucketova i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Praćenje**

Možete **pratiti** da li se kreiraju **novi poddomeni** domena tako što ćete pratiti **Certificate Transparency** logove, kao što to radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite da li postoje mogući [**subdomain takeover-i**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **poddomen** pokazuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **poddomen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja sredstava, trebalo bi da obavite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći trikove za njihov „napad“**.\
_Napomena: ponekad se poddomen hostuje na IP adresi koju klijent ne kontroliše, pa nije u opsegu. Budite pažljivi._

## IP adrese

U početnim koracima možda ste **pronašli neke IP opsege, domene i poddomene**.\
Vreme je da **prikupite sve IP adrese iz tih opsega** i za **domene/poddomene (DNS upiti).**

Pomoću servisa kao što je sledeći možete pronaći i **ranije IP adrese koje su koristili domeni i poddomeni**. Klijent je možda i dalje vlasnik tih IP adresa (a one vam mogu pomoći da pronađete [**CloudFlare zaobilazne metode**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (za istorijske DNS/IP podatke potreban je plaćeni plan)

Pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host) možete proveriti i koji domeni pokazuju na određenu IP adresu.

### **Traženje ranjivosti**

**Skenirajte portove na svim IP adresama koje ne pripadaju CDN-ovima** (jer je veoma verovatno da tamo nećete pronaći ništa zanimljivo). Na otkrivenim pokrenutim servisima možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Potraga za web serverima

> Pronašli smo sve kompanije i njihova sredstva i znamo IP opsege, domene i poddomene u opsegu. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već obavili **recon IP adresa i otkrivenih domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo pogledati neke **brze trikove za pronalaženje web servera** u opsegu.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da obavite i **skeniranje ranjivosti** i **portova** (**ako je to dozvoljeno** opsegom).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću alata [**masscan možete pronaći ovde**](../pentesting-network/index.html#http-port-discovery).\
Još jedan jednostavan alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Dovoljno je da prosledite listu domena, a alat će pokušati da se poveže na portove 80 (http) i 443 (https). Takođe možete navesti i druge portove koje treba isprobati:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Sada kada ste otkrili **sve web servere** u okviru scope-a (među **IP** adresama kompanije i svim **domenima** i **poddomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo pojednostaviti stvari i početi tako što ćemo napraviti snimke ekrana svih njih. Već samim **pregledom** **glavne stranice** možete pronaći **neobične** endpoint-e koji su **podložniji** tome da budu **ranjivi**.

Da biste sproveli ovu ideju, možete koristiti [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zatim možete upotrebiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da obradi sve **snimke ekrana** i kaže vam **šta verovatno sadrži ranjivosti**, a šta ne.

## Public Cloud Assets

Da biste pronašli potencijalnu cloud imovinu koja pripada kompaniji, trebalo bi da **počnete listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i wordliste **uobičajenih reči koje se koriste u nazivima bucket-a**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim bi trebalo da pomoću tih reči generišete **permutacije** (za više informacija pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Sa dobijenim wordlistama možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da prilikom traženja Cloud Assets-a treba da **tražite više od samih bucket-a u AWS-u**.

### **Traženje ranjivosti**

Ako pronađete stvari kao što su **javno dostupni bucket-i ili izložene cloud funkcije**, trebalo bi da im **pristupite** i pokušate da utvrdite šta vam nude i da li možete da ih zloupotrebite.

## Emails

Sa **domenima** i **poddomenima** u scope-u, imate praktično sve što vam je **potrebno da počnete da tražite email adrese**. Ovo su **API-ji** i **alati** koji su mi se najbolje pokazali u pronalaženju email adresa neke kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - uz API-je
- API od [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API od [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API od [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

Email adrese će vam kasnije dobro doći za **brute-force napade na web prijave i auth servise** (kao što je SSH). Potrebne su i za **phishing**. Pored toga, ovi API-ji će vam dati još više **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Credential Leaks

Pomoću **domena,** **poddomena** i **email adresa** možete početi da tražite akreditive koji su ranije procureli i pripadaju tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** akreditive, to je veoma lak uspeh.

## Secrets Leaks

Credential leaks su povezani sa hakovanjima kompanija tokom kojih su **osetljive informacije procurele i bile prodate**. Međutim, kompanije mogu biti pogođene i **drugim leak-ovima** čije informacije nisu u tim bazama podataka:

### Github Leaks

Akreditive i API-je može se pronaći u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade u toj github kompaniji.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repo-e** neke **organizacije** i njenih **developera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/gitleaks/gitleaks) nad njima.

**Leakos** se može koristiti i za pokretanje **gitleaks** nad svim tekstualnim **URL-ovima koje mu prosledite**, jer ponekad i **web stranice sadrže secrets**.

#### Github Dorks

Pogledajte stranicu [GitHub dorks and leaks](github-leaked-secrets.md) da biste pronašli potencijalne **GitHub dorks** za pretragu organizacije.

### Pastes Leaks

Ponekad napadači ili zaposleni **objave sadržaj kompanije na paste sajtu**. Taj sadržaj može, ali i ne mora da sadrži **osetljive informacije**, ali svakako vredi pretražiti.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) za istovremenu pretragu više od 80 paste sajtova.

### Google Dorks

Stari, ali zlata vredni Google dorks uvek su korisni za pronalaženje **izloženih informacija koje tu ne bi trebalo da budu**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete izabrati svojih omiljenih 10 ili koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji pokušavaju da pretraže celu bazu podataka pomoću običnog Google browser-a nikada neće završiti, jer će vas Google vrlo brzo blokirati._

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** akreditive ili API tokene, to je veoma lak uspeh.

## Public Code Vulnerabilities

Ako ste otkrili da kompanija ima **open-source kod**, možete ga **analizirati** i tražiti **ranjivosti**.

**U zavisnosti od jezika**, možete koristiti različite **alate**; pogledajte listu [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji vam omogućavaju da **skenirate javne repozitorijume**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje bug hunter-i pronađu nalazi se u **web aplikacijama**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**. Te informacije možete [**pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Želim posebno da pomenem i odeljak [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će pronaći veoma osetljive ranjivosti, korisni su za uključivanje u **workflow-e radi prikupljanja početnih informacija o web-u.**

## Recapitulation

> Čestitamo! Do ovog trenutka ste već obavili **svo osnovno enumerisanje**. Da, osnovno je, jer se može uraditi još mnogo enumerisanja (videćemo još trikova kasnije).

Do sada ste:

1. Pronašli sve **kompanije** u scope-u
2. Pronašli svu **imovinu** koja pripada kompanijama (i obavili skeniranje ranjivosti ako je u scope-u)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **poddomaine** tih domena (da li je moguća subdomain takeover?)
5. Pronašli sve **IP** adrese (sa i **bez CDN-ova**) u scope-u.
6. Pronašli sve **web servere** i napravili njihove **snimke ekrana** (ima li nečeg neobičnog što vredi detaljnije pogledati?)
7. Pronašli svu **potencijalnu public cloud imovinu** koja pripada kompaniji.
8. Pronašli **email adrese**, **credential leaks** i **secret leaks** koji bi mogli da vam donesu **veliki uspeh uz vrlo malo truda**.
9. Obavili **pentesting svih pronađenih web sajtova**

## **Full Recon Automatic Tools**

Postoji nekoliko alata koji će izvršiti deo predloženih aktivnosti nad datim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Malo je zastareo i nije ažuriran



## References

- [1] [Jason Haddix – Metodologija bug hunter-a v4.0: Recon izdanje](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O favicon-ima: od ikona browser-a do obaveštajnih podataka o napadnoj površini](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Pretvaranje favicon.ico u oružje za BugBounties, OSINT i svašta drugo](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Otkrivanje domena pomoću napada korelacijom vremena na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasivno preuzimanje: otkrivanje (i emuliranje) skupe kampanje za preuzimanje poddomena](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: jedinstven metod enumeracije poddomena](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Kompletan workflow za otkrivanje poddomena, 1. deo](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Kompletno otkrivanje poddomena brute-force metodom pomoću automatizovanog Trickest workflow-a, 2. deo](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Snimak ekrana izlaza alata favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
