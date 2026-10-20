# Metodologija spoljnog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje imovine

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji u scope-u i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da utvrdimo sve **kompanije u vlasništvu glavne kompanije**, a zatim i svu **imovinu** tih kompanija. Da bismo to uradili, treba da:<sup>[[1]](#references)</sup>

1. Pronađemo akvizicije glavne kompanije; tako ćemo utvrditi koje su kompanije u scope-u.
2. Pronađemo ASN (ako postoji) za svaku kompaniju; tako ćemo utvrditi IP opsege koje poseduje svaka kompanija.
3. Koristimo reverse whois pretrage da bismo pronašli druge zapise (nazive organizacija, domene...) povezane sa prvim (ovo se može raditi rekurzivno).
4. Koristimo druge tehnike, poput Shodan `org` i `ssl` filtera, za traženje druge imovine (trik sa `ssl` može se primenjivati rekurzivno).

### **Akvizicije**

Pre svega, treba da saznamo koje su **druge kompanije u vlasništvu glavne kompanije**.\
Jedna mogućnost je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **potražite** **glavnu kompaniju** i **kliknete** na „**acquisitions**“. Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga mogućnost je da posetite stranicu glavne kompanije na **Wikipedia**-i i potražite **acquisitions**.\
Za javna preduzeća proverite **SEC/EDGAR filings**, stranice za **investor relations** ili lokalne registre privrednih društava (npr. **Companies House** u UK).\
Za globalne korporativne strukture i podružnice isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku trebalo bi da znate koje su sve kompanije u scope-u. Hajde da utvrdimo kako da pronađemo njihovu imovinu.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstveni broj** koji **Internet Assigned Numbers Authority (IANA)** dodeljuje **autonomnom sistemu** (AS).\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa spoljnim mrežama i kojima upravlja jedna organizacija, ali može da obuhvata više operatora.

Važno je utvrditi da li je **kompaniji dodeljen neki ASN**, kako bismo pronašli njene **IP opsege**. Bilo bi korisno sprovesti **testiranje ranjivosti** nad svim **hostovima** u **scope-u** i **potražiti domene** unutar ovih IP opsega.\
Možete da pretražujete po **nazivu** kompanije, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kojem se kompanija nalazi, ove veze mogu biti korisne za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno su sve** korisne informacije **(IP opsezi i Whois)** već dostupne na prvoj vezi.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-ova** enumeracija automatski agregira i sumira ASN-ove na kraju skeniranja.

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

Takođe možete pronaći IP opsege organizacije pomoću [ASNLookup](https://asnlookup.com/), koji ima ograničen besplatni API paket.

### **Traženje ranjivosti**

U ovom trenutku znamo **sve resurse u opsegu**, pa ako vam je dozvoljeno, možete pokrenuti **skener ranjivosti** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) na svim hostovima.\
Takođe možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da biste pronašli** otvorene portove **i, u zavisnosti od onoga što pronađete, trebalo bi da** pogledate u ovoj knjizi kako da pentestirate različite moguće pokrenute servise.\
**Takođe, vredi napomenuti da možete pripremiti liste podrazumevanih korisničkih imena i** lozinki **i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije u opsegu i njihove resurse; vreme je da pronađemo domene u opsegu.

_Imajte na umu da pomoću sledećih predloženih tehnika možete pronaći i poddomene, i da ne treba potcenjivati te informacije._

Pre svega, trebalo bi da potražite **glavni domen** (ili domene) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse DNS lookups** nad tim **IP adresama kako biste pronašli dodatne domene u opsegu**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i [SecurityTrails](https://securitytrails.com/), iako je za pristup istorijskim DNS podacima potreban plaćeni plan.\
Za velike opsege, alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) korisni su za automatizaciju reverse lookup-a i obogaćivanje podataka.

### **Reverse Whois (loop)**

U **whois** podacima možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **adrese e-pošte**, brojevi telefona... Još zanimljivije je to što možete pronaći **dodatnu imovinu povezanu sa kompanijom** ako izvršite **reverse whois pretrage na osnovu bilo kog od tih polja** (na primer, druge whois registracije u kojima se pojavljuje ista adresa e-pošte).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatan** web interfejs; API se plaća.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Plaća se
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Ograničen besplatan API pristup za aktuelne DNS podatke/poddomene; za istorijske podatke i reverse pretrage potreban je plaćeni plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 besplatnih API kredita pri registraciji; nakon toga se plaća.

Ovaj zadatak možete automatizovati pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink) (potreban je whoxy API ključ).\
Možete obaviti i automatsko otkrivanje pomoću reverse whois-a uz [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovom tehnikom možete otkrivati dodatna imena domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako pronađete **isti ID istog trackera** na 2 različite stranice, možete pretpostaviti da **obe stranice** **vodi isti tim**.\
Na primer, ako na više stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji omogućavaju pretragu po ovim i drugim trackerima:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Plaćena** web i API usluga ([cene](https://www.stackscan.com/pricing)); trenutno se ne oglašava besplatan plan. Pretražujte na osnovu bilo kog resursa koji se poslužuje, a ne samo ID-jeva trackera: putanje skripti, naziva lokalno hostovanih bundle-ova ili hosta sa kog se učitava resurs; rezultati prikazuju sve sajtove koji ga sadrže.

API vraća tehnološki stek za jedan domen, što je korisno za potvrdu da kandidatni resurs pripada istoj infrastrukturi:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Vraća svaku detektovanu tehnologiju zajedno sa njenom kategorijom. Pivotiranje kroz asset-e trenutno je dostupno samo za web; API omogućava pretragu po domenu.

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja tako što ćemo potražiti isti hash favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti favicon icon hash kao naš target.

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati favicon hash kao Shodan ili FOFA pivot da biste pronašli druge izložene instance iste tehnologije.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ovako možete da izračunate hash favicon-a veb-sajta (MMH3 nad base64-kodiranim bajtovima favicon-a):

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

Možete dobiti i favicon hash vrednosti u velikom obimu pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim tražiti povezane rezultate u Shodan/Censys.

Favicon fingerprintove tretirajte kao tragove i proverite ih pomoću okolnih signala.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash tretirajte kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su kolizioni slučajevi, ponovo korišćene ikone i namerno lažiranje.
- **Proverite više od** `/favicon.ico`: pregledajte putanje frameworka/builda, manifest fajlove, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL-ove i HTML `<link rel="icon">` tagove.
- **Statički resursi mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno zatražite ikonu i proverite `ETag`, `Last-Modified`, redirekcije i cache zaglavlja.
- **Proverite podudaranja pomoću okolnih signala**: uporedite title, HTML/body hash, zaglavlja, TLS certificate subjects/SANs, komponente proizvoda i izložene portove.
- **Grupišite prema HTML/body hash-u**: dosledan template jača fingerprint; različiti template-i ukazuju na generičku ili deljenu ikonu.
- **Hash koji se pojavljuje uz nepovezane potpise, portove i proizvode tretirajte kao mogući honeypot ili placeholder.**
- **Kod nejasnih ciljeva uporedite stvarnu stranicu sa nepostojećom putanjom**, kao što je `/_favicon_probe_<8-hex>`; podudarni odgovori hosting platforme ili parking stranice mogu objasniti deljenu ikonu.
- **Za početnu trijažu koristite Nuclei detection pravila ili javne skupove podataka** koji povezuju favicon hash vrednosti sa proizvodima i CPE-ovima.
- **Imajte na umu ograničenja pokrivenosti zasnovane na IP adresama**: površine iza CDN-a, rutirane putem SNI-ja, anycast i samo domenom dostupne površine možda nisu obuhvaćene skupovima podataka sličnim Shodan-u.

### **Autorsko pravo / jedinstveni string**

Pretražite veb-stranice i potražite **stringove koji mogu biti zajednički različitim veb-sajtovima iste organizacije**. Dobar primer može biti **copyright string**. Zatim potražite taj string na **Google-u**, u drugim **pretraživačima** ili čak na **Shodan-u**: `shodan search http.html:"Copyright string"`

### **Vreme CRT-a**

Uobičajeno je imati cron job kao što je GITHUB:VEVENT

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

da bi se svi sertifikati na serveru obnovili istovremeno. Povezivanje vremenskih oznaka sertifikata ili pozicija u certificate-transparency logovima može otkriti povezane domene.<sup>[[6]](#references)</sup>

Takođe, koristite direktno logove **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o Mail DMARC-u

Možete koristiti veb-sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da biste pronašli **domene i poddomene koji dele iste DMARC informacije**.\
Još jedna korisna usluga je [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Napušteni A zapis može postati dostupan kada cloud provajder ponovo dodeli IP adresu. U navedenom istraživanju prikazan je oportunistički postupak koji podiže instancu i povezuje njenu adresu sa podacima iz pasivnog DNS-a; scenarije takeover-a testirajte samo u okviru odobrenog opsega.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće postupke otkrivanja svaki put kada pronađete novi domen: svaki rezultat može otkriti dodatna imena sertifikata, odnose u pasivnom DNS-u, podudaranja favicon-a i identifikatore organizacije koji nisu bili vidljivi iz početnog domena.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Pošto već znate naziv organizacije koja poseduje IP prostor, te podatke možete pretraživati u Shodan-u pomoću: `org:"Tesla, Inc."` Proverite da li među pronađenim hostovima postoje neočekivani novi domeni u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne veb-stranice, preuzeti **naziv organizacije**, a zatim potražiti taj naziv u **TLS sertifikatima** svih veb-stranica poznatih servisu **Shodan** pomoću filtera: `ssl:"Tesla Motors"` ili upotrebiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomene**; zaista je odličan.

**Passive DNS / Historical DNS**

Podaci iz pasivnog DNS-a odlični su za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili koje je moguće preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete **domen sa IP adresom koja se razlikuje** od onih koje ste već pronašli tokom otkrivanja imovine, trebalo bi da obavite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći trikove za njihovo „napadanje“**.\
_Imajte na umu da je domen ponekad hostovan na IP adresi koju klijent ne kontroliše, pa nije u opsegu; budite oprezni._

## Poddomeni

> Znamo sve kompanije u opsegu, svu imovinu svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene za svaki pronađeni domen.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i u pronalaženju poddomena.

### **DNS**

Pokušajmo da pronađemo **poddomene** u **DNS** zapisima. Trebalo bi da pokušamo i sa **Zone Transfer**-om (ako je ranjiv, prijavite ga).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Za API-je i platforme koje obuhvataju infrastrukturu, reputaciju, evidenciju breach-eva i obogaćivanje podataka izvan otkrivanja poddomena, pogledajte [katalog API-ja za izviđanje i obaveštajne podatke o pretnjama](reconnaissance-and-threat-intelligence-apis.md).

Najbrži način da dođete do velikog broja poddomena jeste pretraga eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate podesite API ključeve):


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

Postoje **i drugi zanimljivi alati/API-jevi** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za njihovo pronalaženje, kao što su:

- [**IP.THC.ORG**](https://ip.thc.org) besplatni API

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

- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove sa AlienVault-ovog Open Threat Exchange-a, Wayback Machine-a i Common Crawl-a za dati domen.

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

- [**SecurityTrails**](https://securitytrails.com/) nudi ograničen besplatan API pristup aktuelnim DNS podacima i podacima o poddomenima; za istorijske DNS/IP podatke potreban je plaćeni paket.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ovaj projekat besplatno nudi **sve poddomene povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i pomoću alata [chaospy](https://github.com/Moaaz-0x/chaospy), ili čak pristupiti scope-u koji koristi ovaj projekat: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Poređenje** mnogih od ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomenе** izvođenjem brute-force napada na DNS servere pomoću mogućih naziva poddomena.

Za ovu aktivnost biće vam potrebne neke **uobičajene wordliste poddomena, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrebne su vam i IP adrese dobrih DNS resolvera. Da biste napravili listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i filtrirati ih pomoću alata [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Možete koristiti i: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno obavljao DNS brute-force. Veoma je brz, ali je sklon lažno pozitivnim rezultatima.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je omotač oko `massdns`, napisan u Go-u, koji omogućava enumeraciju validnih poddomena pomoću aktivnog bruteforce-a, kao i razrešavanje poddomena uz obradu wildcard-a i jednostavnu podršku za ulaz i izlaz.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhrono brute force isprobavanje naziva domena.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Drugi DNS Brute-Force krug

Nakon što pronađete poddomene koristeći otvorene izvore i brute-forcing, možete generisati varijacije pronađenih poddomena i pokušati da pronađete još njih. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
  - **wordlist** za permutacije u goaltdns-u možete preuzeti [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka sa permutacijama, gotator će koristiti sopstvenu.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno pomenute alate).
  - **Wordlist** sa altdns permutacijama možete pronaći [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će brute force-om pronaći rezultat (ne podržava DNS wildcard).
  - Wordlist za dmut permutacije možete preuzeti [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena poddomena** prema zadatim obrascima, kako bi pokušao da otkrije još poddomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči obrasce nalik regex-u iz otkrivenih poddomena i generiše kandidatska imena za DNS razrešavanje.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force subdomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što su prilagođeni wordlist ili istorijski DNS/TLS zapisi, kako bi precizno generisao još odgovarajućih naziva domena i dalje ih proširivao u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.

```
echo www | subzuf facebook.com
```

### **Tok rada za otkrivanje poddomena**

Primeri Trickest tokova rada kombinuju OSINT, DNS brute force i faze permutacija za ponovljivo enumerisanje poddomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / virtuelni hostovi**

Ako ste pronašli IP adresu koja sadrži **jednu ili više veb-stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa veb-stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** potražiti domene na toj IP adresi ili tako što ćete **brute force-om isprobavati nazive VHost domena na toj IP adresi**.

#### OSINT

Neke **VHostove na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da neki poddomen može biti skriven na veb-serveru, možete pokušati da ga pronađete brute force-om:

Kod vhostova zasnovanih na nazivu, fuzz-ujte `Host` zaglavlje i koristite ffuf-ovu automatsku kalibraciju za filtriranje podrazumevanog odgovora.<sup>[[2]](#references)</sup>

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

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je u zaglavlju _**Origin**_ postavljen validan domen/poddomen. U ovim scenarijima možete da zloupotrebite ovo ponašanje da biste **otkrili** nove **poddomene**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Dok tražite **subdomene**, obratite pažnju na to da li **pokazuju** na neki tip **bucket-a** i, ako je tako, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene u scope-u, pokušajte da [**brute force-ujete moguća imena bucket-a i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoring**

Možete **pratiti** da li se kreiraju **novi poddomeni** domena tako što ćete nadgledati **Certificate Transparency** logove, što radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite da li postoje mogući [**subdomain takeover-i**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomen** pokazuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **subdomen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asseta, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: ponekad je subdomen hostovan na IP adresi koju klijent ne kontroliše, pa nije u scope-u. Budite oprezni._

## IPs

Tokom početnih koraka možda ste **pronašli neke IP opsege, domene i poddomene**.\
Vreme je da **prikupite sve IP adrese iz tih opsega**, kao i one za **domene/podd omene (DNS upiti)**.

Pomoću servisa kao što je sledeći možete pronaći i **prethodne IP adrese koje su koristili domeni i poddomeni**. Klijent možda i dalje poseduje te IP adrese (što bi vam moglo pomoći da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (za istorijske DNS/IP podatke potreban je plaćeni plan)

Možete i da proverite koji domeni pokazuju na određenu IP adresu pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Skenirajte portove svih IP adresa koje ne pripadaju CDN-ovima** (jer je mala verovatnoća da ćete tamo pronaći nešto zanimljivo). Na otkrivenim pokrenutim servisima možda ćete **pronaći ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Potraga za web serverima

> Pronašli smo sve kompanije i njihove assete, kao i IP opsege, domene i poddomene u scope-u. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već obavili **recon IP adresa i pronađenih domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo pogledati neke **brze trikove za pronalaženje web servera** u scope-u.

Imajte na umu da je ovo **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **skeniranje ranjivosti** i **portova** (**ako je dozvoljeno** scope-om).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću [**masscan** možete pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još neki praktični alati za pronalaženje web servera su [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Potrebno je samo da prosledite listu domena, a alat će pokušati da se poveže na portove 80 (http) i 443 (https). Pored toga, možete navesti i druge portove koje treba isprobati:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Snimci ekrana**

Sada kada ste otkrili **sve web servere** u opsegu (među **IP** adresama kompanije i svim **domenima** i **poddomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo pojednostaviti stvari i početi tako što ćemo napraviti snimke ekrana svih njih. Samo **pogledom** na **glavnu stranicu** možete pronaći **neobične** endpoint-e koji su **podložniji** tome da budu **ranjivi**.

Da biste sproveli ovu ideju, možete koristiti [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete pokrenuti [**eyeballer**](https://github.com/BishopFox/eyeballer) nad svim **snimcima ekrana** da biste saznali **šta verovatno sadrži ranjivosti**, a šta ne.

## Javni cloud resursi

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, **počnite od liste ključnih reči po kojima se kompanija može prepoznati**. Na primer, za kripto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i liste **uobičajenih reči koje se koriste u nazivima bucket-a**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, pomoću tih reči generišite **permutacije** (više informacija potražite u odeljku [**Drugi krug DNS brute-force-a**](#second-dns-bruteforce-round)).

Za dobijene liste reči možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da pri traženju cloud resursa treba da **tražite više od samih bucket-a u AWS-u**.

### **Traženje ranjivosti**

Ako pronađete nešto poput **otvorenih bucket-a ili izloženih cloud funkcija**, pristupite im i proverite šta nude i da li ih možete zloupotrebiti.

## Email adrese

Uz **domene** i **poddomaine** u opsegu, imate praktično sve što vam je **potrebno da počnete da tražite email adrese**. Ovo su **API-ji** i **alati** koji su mi se pokazali kao najefikasniji za pronalaženje email adresa zaposlenih u kompaniji:

- [**theHarvester**](https://github.com/laramies/theHarvester) - uz API-je
- API za [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API za [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API za [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

Email adrese će vam kasnije dobro doći za **brute-force napade na web prijave i auth servise** (kao što je SSH). Potrebne su i za **phishing**. Pored toga, ovi API-ji će vam dati još više **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Curenja kredencijala

Uz **domene,** **poddomaine** i **email adrese** možete početi da tražite kredencijale koji su ranije procureli, a pripadaju tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** kredencijale, to je veoma laka pobeda.

## Curenja tajni

Curenja kredencijala povezana su sa upadima u kompanije tokom kojih su **osetljive informacije procurile i bile prodate**. Međutim, kompanije mogu biti pogođene i **drugim curenjima** čiji podaci nisu u tim bazama:

### Curenja sa GitHub-a

Kredencijali i API-ji mogu procureti u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu kompaniju na GitHub-u.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** neke **organizacije** i njenih **programera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/gitleaks/gitleaks) nad njima.

**Leakos** se može koristiti i za pokretanje **gitleaks-a** nad svim **tekstualnim URL-ovima** koji su mu prosleđeni, jer ponekad i **web stranice sadrže tajne**.

#### GitHub dorks

Pogledajte stranicu [GitHub dorks and leaks](github-leaked-secrets.md) da biste pronašli potencijalne **GitHub dorks** za pretragu organizacije.

### Curenja sa paste sajtova

Ponekad napadači ili zaposleni **objave sadržaj kompanije na paste sajtu**. Taj sadržaj može, ali i ne mora da sadrži **osetljive informacije**, ali svakako vredi potražiti ga.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) za istovremenu pretragu na više od 80 paste sajtova.

### Google dorks

Stari, ali zlatni Google dorks uvek su korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu dostupne**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete izabrati svojih omiljenih 10 upita ili koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji pokušavaju da pretraže celu bazu preko uobičajenog Google pregledača neće završiti, jer će vas Google vrlo brzo blokirati._

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** kredencijale ili API tokene, to je veoma laka pobeda.

## Ranjivosti u javnom kodu

Ako otkrijete da kompanija ima **open-source kod**, možete ga **analizirati** i tražiti **ranjivosti**.

**U zavisnosti od jezika**, možete koristiti različite **alate**; pogledajte listu [alata za pregled izvornog koda](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji vam omogućavaju da **skenirate javne repozitorijume**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologija pentestiranja web aplikacija**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje pronađu bug hunter-i nalazi se u **web aplikacijama**, pa bih u ovom trenutku želeo da predstavim **metodologiju testiranja web aplikacija**. [**Više informacija možete pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Želim posebno da pomenem odeljak [**Open-source alati za automatizovano skeniranje web aplikacija**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će pronaći veoma ozbiljne ranjivosti, korisni su kada ih uključite u **workflows kako biste prikupili početne informacije o web aplikacijama.**

## Rezime

> Čestitamo! Do ovog trenutka ste obavili **sve osnovno izviđanje**. Da, ovo je osnovno jer se može obaviti još mnogo izviđanja (kasnije ćemo videti dodatne trikove).

Do sada ste:

1. Pronašli sve **kompanije** u opsegu
2. Pronašli sve **resurse** koji pripadaju tim kompanijama (i obavili skeniranje ranjivosti ako je to u opsegu)
3. Pronašli sve **domene** koji pripadaju tim kompanijama
4. Pronašli sve **poddomaine** tih domena (ima li preuzimanja poddomena?)
5. Pronašli sve **IP** adrese (sa **CDN-ova** i bez njih) u opsegu.
6. Pronašli sve **web servere** i napravili njihove **snimke ekrana** (ima li nečeg neobičnog što vredi detaljnije istražiti?)
7. Pronašli sve **potencijalne javne cloud resurse** koji pripadaju kompaniji.
8. Pronašli **email adrese**, **curenja kredencijala** i **curenja tajni** koji vam mogu doneti **veliku pobedu uz vrlo malo truda**.
9. **Pentestovali sve pronađene web aplikacije**

## **Alati za potpuno automatizovano izviđanje**

Postoji više alata koji će obaviti deo predloženih radnji nad zadatim opsegom.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Pomalo zastareo i više se ne ažurira

## References

- [1] [Jason Haddix – Metodologija bug hunter-a v4.0: izviđanje](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O favicon-ima: od ikonica pregledača do obaveštajnih podataka o površini napada](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Pretvaranje favicon.ico u oružje za Bug Bounties, OSINT i još mnogo toga](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Otkrivanje domena pomoću napada vremenske korelacije na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasivno preuzimanje: otkrivanje (i oponašanje) skupe kampanje za preuzimanje poddomena](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: jedinstven metod enumeracije poddomena](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Potpuni workflow za otkrivanje poddomena, prvi deo](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Potpuno automatizovano otkrivanje poddomena brute-force metodom pomoću Trickest workflow-a, drugi deo](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Snimak ekrana izlaza alata favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
