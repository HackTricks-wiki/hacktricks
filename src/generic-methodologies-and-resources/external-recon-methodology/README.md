# Metodologija eksternog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje resursa

Za kategorizovan spisak dodatnih OSINT projekata i projekata za otkrivanje veb-sadržaja pogledajte [Alati i resursi trećih strana](../third-party-tools-and-resources.md#osint).

> Rečeno vam je da je sve što pripada nekoj kompaniji u opsegu i želite da utvrdite šta ta kompanija zaista poseduje.

Cilj ove faze je da pronađemo sve **kompanije u vlasništvu glavne kompanije**, a zatim sve **resurse** tih kompanija. Da bismo to uradili, potrebno je da:<sup>[[1]](#references)</sup>

1. Pronađemo akvizicije glavne kompanije, što će nam dati kompanije koje su u opsegu.
2. Pronađemo ASN svake kompanije (ako ga ima), što će nam dati IP opsege u vlasništvu svake kompanije.
3. Koristimo reverse whois pretrage da bismo pronašli druge unose (nazive organizacija, domene...) povezane sa prvim unosom (ovo se može raditi rekurzivno).
4. Koristimo druge tehnike, kao što su Shodan `org`i `ssl`filteri, za pretragu drugih resursa (trik sa `ssl` može se koristiti rekurzivno).

Za postepenu predaju od razrešenih poddomena do HTTP crawlovanja i otkrivanja portova pogledajte [Metodologiju pentestiranja](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Akvizicije**

Pre svega, treba da saznamo **koje su druge kompanije u vlasništvu glavne kompanije**.\
Jedna mogućnost je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju** i kliknete na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga mogućnost je da posetite stranicu glavne kompanije na **Wikipediji** i potražite **akvizicije**.\
Za javne kompanije proverite dokumentaciju **SEC/EDGAR**, stranice za **odnose s investitorima** ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalne korporativne strukture i podružnice isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku bi trebalo da znate sve kompanije koje su u opsegu. Hajde da vidimo kako da pronađemo njihove resurse.

### **ASN-ovi**

Broj autonomnog sistema (**ASN**) je **jedinstveni broj** koji **Internet Assigned Numbers Authority (IANA)** dodeljuje **autonomnom sistemu** (AS).\
**AS** se sastoji od **blokova** **IP adresa** sa jasno definisanom politikom pristupa eksternim mrežama. Njima upravlja jedna organizacija, ali mogu obuhvatati više operatera.

Korisno je utvrditi da li je **kompaniji dodeljen neki ASN** kako bismo pronašli njene **IP opsege**. Korisno je sprovesti **testiranje ranjivosti** nad svim **hostovima** u **opsegu** i **potražiti domene** na tim IP adresama.\
Možete **pretraživati** po **nazivu** kompanije, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kom se kompanija nalazi, ove veze mogu biti korisne za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se sve** korisne informacije **(IP opsezi i Whois)** već nalaze na prvoj vezi.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-ov** enumeration automatski agregira i sažima ASN-ove na kraju skeniranja.

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

Možete pronaći i IP opsege organizacije pomoću alata [ASNLookup](https://asnlookup.com/), koji ima ograničeni besplatni API paket.

### **Traženje ranjivosti**

U ovom trenutku znamo **sva sredstva obuhvaćena opsegom**, pa ako imate dozvolu, možete pokrenuti neki **skener ranjivosti** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Možete pokrenuti i neka [**skeniranja portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti usluge kao što su** Shodan, Censys ili ZoomEye **da biste pronašli** otvorene portove **i, u zavisnosti od toga šta pronađete, trebalo bi da** pogledate u ovoj knjizi kako da pentestujete različite moguće pokrenute usluge.\
**Takođe, vredi napomenuti da možete pripremiti i liste** podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete usluge pomoću alata [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Znamo sve kompanije obuhvaćene opsegom i njihova sredstva; vreme je da pronađemo domene obuhvaćene opsegom.

_Imajte na umu da pomoću tehnika predloženih u nastavku možete pronaći i poddomene i da te informacije ne treba potcenjivati._

Pre svega, trebalo bi da potražite **glavni domen** svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse DNS lookup** nad tim **IP adresama kako biste pronašli još domena obuhvaćenih opsegom**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i [SecurityTrails](https://securitytrails.com/), mada su za istorijske DNS podatke potrebni plaćeni planovi.\
Za velike opsege, alati poput [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) korisni su za automatizaciju reverse lookup-a i obogaćivanje podataka.

### **Reverse Whois (loop)**

U **whois** podacima možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **imejl adrese**, brojevi telefona... Još zanimljivije je to što možete pronaći **još asseta povezanih sa kompanijom** ako obavite **reverse whois lookups na osnovu bilo kog od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista imejl adresa).\
Možete koristiti online alate poput:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatan** web interfejs; API se plaća.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Plaća se
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Ograničen besplatan API pristup za aktuelne DNS/subdomene; za istorijske i reverse lookup-ove potreban je plaćeni plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 besplatnih API kredita nakon registracije; nakon toga se plaća.

Ovaj zadatak možete automatizovati pomoću [**DomLink** ](https://github.com/vysecurity/DomLink) (potreban je whoxy API ključ).\
Možete obaviti i automatsko otkrivanje reverse whois podataka pomoću [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovom tehnikom možete otkriti još naziva domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako na 2 različite stranice pronađete **isti ID istog trackera**, možete pretpostaviti da **obema stranicama** **upravlja isti tim**.\
Na primer, ako na nekoliko stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji omogućavaju pretragu po ovim trackerima i drugim podacima:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Plaća se**; web i API usluga ([cene](https://www.stackscan.com/pricing)); trenutno se ne oglašava besplatan plan. Pivotirajte na bilo kom assetu koji se isporučuje, a ne samo na ID-jevima trackera: putanji skripte, nazivu samostalno hostovanog bundle-a ili hostu sa kog se asset učitava; rezultat prikazuje svaku stranicu na kojoj se nalazi

API vraća stack za jedan domen, što je korisno za potvrdu da kandidatni asset pripada istoj infrastrukturi:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Vraća svaku detektovanu tehnologiju zajedno sa njenom kategorijom. Asset pivoting je trenutno dostupan samo za web, dok API omogućava pretragu po domenu.

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja tako što ćemo potražiti isti hash favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash rezultati korišćeni za otkrivanje domena koji dele isti favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti favicon hash kao naš cilj.

![Favihash izlaz korišćen za otkrivanje domena sa istim favicon hash-om](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati favicon hash kao Shodan ili FOFA pivot da biste pronašli druge izložene instance iste tehnologije.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ovo je način na koji možete **izračunati hash favicon-a** veb-stranice (MMH3 nad **base64-kodiranim** bajtovima favicon-a):

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

Takođe možete pribaviti favicon hash-eve u velikom obimu pomoću alata [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim pretraživati Shodan/Censys na osnovu njih.

Favicon otiske tretirajte kao tragove i proverite ih pomoću okolnih signala.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash tretirajte kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su sudari hash-eva, ponovna upotreba ikonica i namerno lažiranje.
- **Proverite više od** `/favicon.ico`: pregledajte putanje framework-a/build-a, manifest datoteke, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL-ove i HTML `<link rel="icon">` oznake.
- **Statički resursi mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno zatražite ikonicu i proverite `ETag`, `Last-Modified`, preusmeravanja i cache zaglavlja.
- **Proverite podudaranja pomoću okolnih signala**: uporedite naslov, HTML/body hash, zaglavlja, subjekte/SAN-ove TLS sertifikata, komponente proizvoda i izložene portove.
- **Grupišite po HTML/body hash-u**: dosledan šablon pojačava pouzdanost otiska; različiti šabloni ukazuju na generičku ili zajedničku ikonicu.
- **Hash koji se pojavljuje uz nepovezane potpise, portove i proizvode tretirajte kao mogući honeypot ili rezervnu ikonicu.**
- **Kod nejasnih ciljeva uporedite stvarnu stranicu sa nepostojećom putanjom**, kao što je `/_favicon_probe_<8-hex>`; podudarni odgovori hosting-a ili parking stranice mogu objasniti zajedničku ikonicu.
- **Za početnu trijažu koristite Nuclei pravila za detekciju ili javne skupove podataka** koji povezuju favicon hash-eve sa proizvodima i CPE-ovima.
- **Imajte na umu nedostatak pokrivenosti usmerene na IP adrese**: površine iza CDN-a, usmeravane preko SNI-ja, anycast i površine dostupne samo preko domena mogu nedostajati u skupovima podataka nalik Shodan-u.

### **Autorsko pravo / jedinstveni string**

Pretražite veb-stranice i pronađite **stringove koji se mogu pojavljivati na različitim veb-sajtovima iste organizacije**. Dobar primer može biti **string o autorskim pravima**. Zatim potražite taj string na **Google-u**, u drugim **pregledačima** ili čak na **Shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT vreme**

Uobičajeno je imati cron posao kao što je

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

da bi se obnovili svi sertifikati na serveru istovremeno. Povezivanje vremenskih oznaka sertifikata ili pozicija u logovima transparentnosti sertifikata može otkriti povezane domene.<sup>[[6]](#references)</sup>

Takođe direktno koristite logove **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o DMARC-u za poštu

Možete koristiti veb-sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da biste pronašli **domene i poddomene koji dele iste DMARC informacije**.\
Još jedna korisna usluga je [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Napušteni A zapis može postati dostupan kada cloud provajder ponovo dodeli IP adresu. Istraživanje na koje se upućuje opisuje oportunistički tok rada koji obezbeđuje instancu i povezuje njenu adresu sa podacima pasivnog DNS-a; scenarije preuzimanja testirajte samo u okviru ovlašćenog opsega.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće korake za otkrivanje svaki put kada pronađete novi domen: svaki rezultat može otkriti dodatna imena sertifikata, veze pasivnog DNS-a, podudaranja favicon ikona i identifikatore organizacije koji nisu bili vidljivi u početnom unosu.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Kao što već znate naziv organizacije koja poseduje IP prostor, te podatke možete pretraživati u Shodan-u koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove da biste otkrili neočekivane domene u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne veb-stranice, pribaviti **naziv organizacije**, a zatim pretražiti taj naziv u **TLS sertifikatima** svih veb-stranica poznatih **Shodan-u** pomoću filtera: `ssl:"Tesla Motors"` ili koristiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomenе**; zaista je odličan.

**Pasivni DNS / Istorijski DNS**

Podaci pasivnog DNS-a odlični su za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili se mogu preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji neki slučaj [preuzimanja domena](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete neki **domen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja imovine, trebalo bi da obavite **osnovno skeniranje ranjivosti** (pomoću alata Nessus ili OpenVAS) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih usluga, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Imajte na umu da je domen ponekad hostovan na IP adresi koju klijent ne kontroliše, pa nije u opsegu; budite oprezni._

## Poddomeni

> Znamo sve kompanije u opsegu, svu imovinu svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i u pronalaženju poddomena

### **DNS**

Pokušajmo da pronađemo **poddомene** iz **DNS** zapisa. Trebalo bi da pokušamo i sa **Zone Transfer** (ako je ranjiv, prijavite to).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Za API-je i platforme koje obuhvataju infrastrukturu, reputaciju, evidenciju o kompromitacijama i obogaćivanje podataka izvan otkrivanja poddomena, pogledajte [katalog API-ja za izviđanje i obaveštajne podatke o pretnjama](reconnaissance-and-threat-intelligence-apis.md).

Najbrži način da pronađete veliki broj poddomena jeste pretraživanje eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate podesite API ključeve):


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

Postoje **i drugi zanimljivi alati/API-ji** koji mogu biti korisni za pronalaženje poddomena, iako nisu direktno specijalizovani za njihovo pronalaženje, kao što je:

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

- [**gau**](https://github.com/lc/gau)**:** pribavlja poznate URL-ove sa AlienVault's Open Threat Exchange, Wayback Machine-a i Common Crawl-a za dati domen.

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

- [**SecurityTrails**](https://securitytrails.com/) nudi ograničen besplatan API pristup aktuelnim DNS podacima i podacima o subdomainima; za istorijske DNS/IP podatke potreban je plaćeni plan.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ovaj projekat besplatno nudi **sve subdomaine povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/Moaaz-0x/chaospy), ili čak pristupiti opsegu koji koristi ovaj projekat: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Poređenje** mnogih od ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **subdomaine** tako što ćemo brute-force metodom isprobavati moguća imena subdomena na DNS serverima.

Za ovu aktivnost biće vam potrebne neke **uobičajene liste reči za subdomene, poput**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrebne su vam i IP adrese dobrih DNS resolvera. Da biste napravili listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i upotrebiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je omogućio efikasan DNS brute-force. Veoma je brz, ali je sklon lažno pozitivnim rezultatima.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je omotač oko `massdns`, napisan u Go jeziku, koji omogućava enumeraciju važećih poddomena aktivnim brute-force metodom, kao i razrešavanje poddomena uz obradu wildcard zapisa i jednostavnu podršku za ulaz i izlaz.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhrono brute force testiranje naziva domena.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Drugi DNS Brute-Force krug

Nakon što pronađete poddomene koristeći otvorene izvore i brute-force, možete generisati njihove varijacije kako biste pokušali da pronađete još poddomena. U tu svrhu korisno je nekoliko alata:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
  - **wordlist** za goaltdns permutacije možete preuzeti [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka s permutacijama, gotator će koristiti svoju.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Pored generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno pomenute alate).
  - **wordlist** sa altdns permutacijama možete preuzeti [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će brute force-om isprobati rezultat (ne podržava DNS wildcard).
  - Listu reči za dmut permutacije možete pronaći [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena generiše nove potencijalne nazive poddomena prema navedenim obrascima kako bi pokušao da otkrije još poddomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči obrasce nalik regularnim izrazima iz otkrivenih poddomena i generiše nazive kandidata za razrešavanje.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force otkrivanje poddomena, povezan sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što su prilagođena wordlist-a ili istorijski DNS/TLS zapisi, za precizno generisanje dodatnih odgovarajućih naziva domena i njihovo dalje proširivanje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.

```
echo www | subzuf facebook.com
```

### **Tok rada za otkrivanje poddomena**

Primeri Trickest workflow-a kombinuju OSINT, DNS brute force i faze permutacija za ponovljivo enumerisanje poddomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više veb-stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa veb-stranicama na toj IP adresi** tako što ćete potražiti domene na određenoj IP adresi u **OSINT izvorima** ili izvršiti **brute force naziva VHost domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki poddomen skriven na veb-serveru, možete pokušati da ga pronađete brute force metodom:

Za vhosts zasnovane na imenu, fuzz-ujte zaglavlje `Host` i koristite ffuf-ovu auto-calibration funkciju da biste filtrirali podrazumevani odgovor.<sup>[[2]](#references)</sup>

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

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je u zaglavlju _**Origin**_ navedena važeća domena/poddomena. U ovakvim scenarijima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **poddomene**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute force bucket-a**

Dok tražite **subdomene**, obratite pažnju na to da li **pokazuju** na neki **bucket** i, u tom slučaju, [**proverite dozvole**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene obuhvaćene scope-om, pokušajte da [**brute force-ujete moguće nazive bucket-a i proverite dozvole**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Praćenje**

Možete da **pratite** da li se kreiraju **novi poddomeni** neke domene tako što ćete pratiti **Certificate Transparency** Logs, kao što to radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite da li postoje mogući [**subdomain takeover-i**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **poddomen** pokazuje na neki **S3 bucket**, [**proverite dozvole**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Ako pronađete **poddomen sa IP adresom koja se razlikuje** od onih koje ste već pronašli tokom otkrivanja asset-a, trebalo bi da pokrenete **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i izvršite [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: ponekad se poddomen nalazi na IP adresi koju klijent ne kontroliše, pa nije u scope-u; budite oprezni._

## IP adrese

U početnim koracima ste možda **pronašli neke IP opsege, domene i poddomene**.\
Vreme je da **prikupite sve IP adrese iz tih opsega**, kao i IP adrese za **domene/poddomene (DNS upiti).**

Pomoću servisa kao što je ovaj možete pronaći i **ranije IP adrese koje su koristile domene i poddomeni**. Te IP adrese možda još uvek pripadaju klijentu (i možda će vam omogućiti da pronađete [**CloudFlare bypass-e**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**SecurityTrails**](https://securitytrails.com/) (za istorijske DNS/IP podatke potreban je plaćeni plan)

Pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host) možete i da proverite koje domene pokazuju na određenu IP adresu.

### **Traženje ranjivosti**

**Skenirajte portove na svim IP adresama koje ne pripadaju CDN-ovima** (jer je veoma verovatno da tamo nećete pronaći ništa zanimljivo). Na otkrivenim pokrenutim servisima možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/index.html) **o skeniranju hostova.**

## Pronalaženje web servera

> Pronašli smo sve kompanije i njihovu imovinu i znamo IP opsege, domene i poddomene obuhvaćene scope-om. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili **recon IP adresa i otkrivenih domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo pogledati neke **brze trikove za pronalaženje web servera** unutar scope-a.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **skeniranje ranjivosti** i **portova** (**ako je to dozvoljeno** scope-om).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću alata [**masscan** možete pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još neki jednostavni alati za traženje web servera su [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Dovoljno je da im prosledite listu domena, pa će pokušati da se povežu na portove 80 (http) i 443 (https). Možete navesti i druge portove koje želite da provere:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Snimci ekrana**

Sada kada ste otkrili **sve web servere** u opsegu (među **IP adresama** kompanije i svim njenim **domenima** i **poddomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo pojednostaviti stvari i početi tako što ćemo napraviti snimke ekrana svih njih. Već **pogledom** na **glavnu stranicu** možete pronaći **neobične** endpoint-e koji su **podložniji** ranjivostima.

Za ovo možete koristiti [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zatim možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da obradi sve **snimke ekrana** i ukaže vam na to **šta verovatno sadrži ranjivosti**, a šta ne.

## Javni Cloud resursi

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, trebalo bi da **počnete od liste ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju mogli biste da koristite reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i wordliste **uobičajenih reči koje se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim bi od tih reči trebalo da napravite **permutacije** (za više informacija pogledajte [**Drugi krug DNS brute-force-a**](#second-dns-bruteforce-round)).

Na dobijenim wordlistama možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da prilikom traženja Cloud resursa treba da **tražite više od samih bucket-a u AWS-u**.

### **Traženje ranjivosti**

Ako pronađete nešto poput **otvorenih bucket-a ili izloženih cloud funkcija**, trebalo bi da im **pristupite** i proverite šta nude i da li možete da ih zloupotrebite.

## Email adrese

Pomoću **domena** i **poddomena** u opsegu imate skoro sve što vam je **potrebno da počnete da tražite email adrese**. Ovo su **API-ji** i **alati** koji su mi se pokazali najkorisnijim za pronalaženje email adresa kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-jima
- API servisa [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API servisa [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API servisa [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

Email adrese će vam kasnije dobro doći za **brute-force napade na web prijave i auth servise** (kao što je SSH). Potrebne su i za **phishing**. Pored toga, ovi API-ji će vam dati još **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Curenje akreditiva

Pomoću **domena**, **poddomena** i **email adresa** možete početi da tražite akreditive koji su ranije procureli i povezani su s tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** akreditive, to je veoma lak dobitak.

## Curenje tajni

Curenje akreditiva povezano je s hakovanjem kompanija, pri čemu su **osetljive informacije procurele i prodate**. Međutim, kompanije mogu biti pogođene i **drugim curenjima**, čije se informacije ne nalaze u tim bazama podataka:

### Github curenja

Akreditivi i API-ji mogu procuriti u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu kompaniju na Github-u.\
Možete koristiti alat [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** neke **organizacije** i njenih **programera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/gitleaks/gitleaks) nad njima.

**Leakos** se može koristiti i za pokretanje alata **gitleaks** nad svim **tekstualnim URL-ovima** koji su mu prosleđeni, jer i **web stranice ponekad sadrže tajne**.

#### Github dorks

Pogledajte stranicu [GitHub dorks and leaks](github-leaked-secrets.md) da biste pronašli potencijalne **GitHub dorks** za pretragu organizacije.

### Curenja na paste sajtovima

Ponekad napadači ili zaposleni **objave sadržaj kompanije na paste sajtu**. Taj sadržaj može, ali i ne mora da sadrži **osetljive informacije**, ali ga svakako vredi potražiti.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da istovremeno pretražujete više od 80 paste sajtova.

### Google dorks

Stari, ali zlatni Google dorks uvek su korisni za pronalaženje **izloženih informacija koje tu ne bi trebalo da budu**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno da pokrenete. Zato možete izabrati svojih omiljenih 10 ili koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji pokušavaju da pretraže celu bazu podataka koristeći običan Google pregledač nikada neće završiti, jer će vas Google vrlo brzo blokirati._

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** akreditive ili API tokene, to je veoma lak dobitak.

## Ranjivosti u javnom kodu

Ako ste otkrili da kompanija ima **open-source kod**, možete ga **analizirati** i potražiti **ranjivosti**.

**U zavisnosti od jezika**, možete koristiti različite **alate**; pogledajte spisak [alata za pregled izvornog koda](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji omogućavaju **skeniranje javnih repozitorijuma**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologija za pentesting web aplikacija**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje pronađu bug hunter-i nalazi se u **web aplikacijama**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**. Te informacije možete [**pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Želim posebno da pomenem odeljak [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će pronaći veoma osetljive ranjivosti, korisni su za uključivanje u **workflow-e radi prikupljanja početnih informacija o webu.**

## Rekapitulacija

> Čestitamo! Do ovog trenutka ste obavili **svo osnovno izviđanje**. Da, osnovno je, jer se može obaviti još mnogo izviđanja (videćemo još trikova kasnije).

Do sada ste:

1. Pronašli sve **kompanije** u opsegu
2. Pronašli svu **imovinu** koja pripada kompanijama (i obavili skeniranje ranjivosti ako je u opsegu)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **poddome** tih domena (ima li subdomain takeover-a?)
5. Pronašli sve **IP adrese** (sa **CDN-ova** i van njih) u opsegu.
6. Pronašli sve **web servere** i napravili njihove **snimke ekrana** (ima li nečeg neobičnog što vredi detaljnije proveriti?)
7. Pronašli sve **potencijalne javne cloud resurse** koji pripadaju kompaniji.
8. Pronašli **email adrese**, **procurele akreditive** i **procurele tajne** koje vam mogu doneti **veliki dobitak uz malo truda**.
9. Obavili **pentesting svih pronađenih web stranica**

## **Alati za potpuno automatizovan recon**

Postoji nekoliko alata koji će obaviti deo predloženih aktivnosti nad zadatim opsegom.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Pomalo zastareo i nije ažuriran



## References

- [1] [Jason Haddix – Metodologija bug hunter-a, v4.0: Recon izdanje](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O favicon-ima: od ikona pregledača do obaveštajnih podataka o napadnoj površini](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Pretvaranje favicon.ico u oružje za BugBounties, OSINT i još mnogo toga](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Otkrivanje domena pomoću napada vremenske korelacije na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasivno preuzimanje: otkrivanje (i simulacija) skupe kampanje za preuzimanje poddomena](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: jedinstvena metoda za enumeraciju poddomena](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Potpuni workflow za otkrivanje poddomena, 1. deo](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Potpuno automatizovano otkrivanje poddomena brute-force metodom uz Trickest workflow, 2. deo](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Snimak ekrana rezultata alata favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
