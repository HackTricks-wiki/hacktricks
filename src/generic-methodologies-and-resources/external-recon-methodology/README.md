# Metodologija za eksterni izviđanje

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje resursa

> Rečeno vam je da je sve što pripada nekoj kompaniji u okviru scope-a i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađete sve **kompanije koje su u vlasništvu glavne kompanije**, a zatim i sve **resurse** tih kompanija. Da biste to uradili:<sup>[[1]](#references)</sup>

1. Pronađite akvizicije glavne kompanije; tako ćete dobiti kompanije koje su u scope-u.
2. Pronađite ASN (ako postoji) svake kompanije; tako ćete dobiti IP opsege koji pripadaju svakoj kompaniji.
3. Koristite reverse whois pretrage da biste pronašli druge unose (nazive organizacija, domene...) povezane sa prvim (ovo može da se radi rekurzivno).
4. Koristite druge tehnike, poput Shodan `org` i `ssl` filtera, da biste pronašli druge resurse (trik sa `ssl` može da se radi rekurzivno).

### **Akvizicije**

Pre svega, treba da saznamo koje su **druge kompanije u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **potražite** **glavnu kompaniju** i **kliknete** na „**acquisitions**“. Tamo ćete videti druge kompanije koje je glavna kompanija kupila.\
Druga opcija je da posetite stranicu glavne kompanije na **Wikipediji** i potražite **akvizicije**.\
Za javne kompanije proverite **SEC/EDGAR prijave**, stranice za **odnose sa investitorima** ili lokalne registre privrednih subjekata (npr. **Companies House** u UK).\
Za globalna stabla kompanija i zavisna društva isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku trebalo bi da znate sve kompanije koje su u scope-u. Hajde da vidimo kako da pronađemo njihove resurse.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstveni broj** koji **Internet Assigned Numbers Authority (IANA)** dodeljuje **autonomnom sistemu** (AS).\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa spoljnim mrežama. Njima upravlja jedna organizacija, ali mogu biti sastavljeni od više operatera.

Vredi proveriti da li je kompaniji **dodeljen neki ASN** kako biste pronašli njene **IP opsege**. Bilo bi korisno izvršiti **testiranje ranjivosti** nad svim **hostovima** unutar **scope-a** i **potražiti domene** unutar tih IP adresa.\
Možete da pretražujete po **nazivu** kompanije, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kom se kompanija nalazi, ove veze mogu biti korisne za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno su sve** korisne informacije **(IP opsezi i Whois)** već dostupne na prvoj vezi.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Takođe, enumeracija pomoću [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatski agregira i sažima ASN-ove na kraju skeniranja.

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

U ovom trenutku znamo **sva sredstva unutar opsega**, pa ako imate dozvolu, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti neke [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da biste pronašli** otvorene portove **i, u zavisnosti od toga šta pronađete, trebalo bi da pogledate u ovoj knjizi kako da pentestujete različite moguće servise koji su pokrenuti.**\
**Takođe, vredi pomenuti da možete pripremiti i neke liste** podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforcujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar opsega i njihova sredstva; vreme je da pronađemo domene unutar opsega.

_Napomena: pomoću tehnika predloženih u nastavku možete pronaći i poddomene, a te informacije ne treba potcenjivati._

Pre svega, trebalo bi da potražite **glavni domen** (ili domene) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse dns lookups** nad tim **IP adresama kako biste pronašli još domena unutar opsega**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možeš da koristiš i online alat: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege korisni su alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), koji automatizuju reverse lookup i obogaćivanje podataka.

### **Reverse Whois (loop)**

U okviru **whois** zapisa možeš da pronađeš mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **imejl adrese**, brojevi telefona... Još je zanimljivije to što možeš da pronađeš **dodatnu infrastrukturu povezanu sa kompanijom** ako obaviš **reverse whois pretragu** po bilo kom od tih polja (na primer, druge whois registre u kojima se pojavljuje ista imejl adresa).\
Možeš da koristiš online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatan** web, API se naplaćuje.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Plaća se
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Plaća se (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Plaća se
- [https://securitytrails.com/](https://securitytrails.com/) - Plaća se (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Plaća se (API)

Ovaj zadatak možeš da automatizuješ pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink) (zahteva whoxy API ključ).\
Možeš i automatski da otkrivaš povezane whois zapise pomoću alata [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imaj na umu da ovom tehnikom možeš da otkrivaš dodatna imena domena svaki put kada pronađeš novi domen.**

### **Trackeri**

Ako pronađeš **isti ID istog trackera** na 2 različite stranice, možeš da pretpostaviš da **obe stranice** **vodi isti tim**.\
Na primer, ako na nekoliko stranica vidiš isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji ti omogućavaju da pretražuješ ove i druge trackere:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove na osnovu zajedničke analitike/trackera)
- [**StackScan**](https://www.stackscan.com) - **Besplatan nivo** (Web i API). Omogućava pivotiranje po bilo kom isporučenom resursu, ne samo po ID-jevima trackera: putanji skripte, nazivu samostalno hostovanog bundle-a ili hostu sa kog se učitava resurs, i vraća svaki sajt na kom se nalazi

API vraća tehnološki stack za jedan domen, što je korisno za potvrdu da potencijalni resurs pripada istoj organizacionoj infrastrukturi:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Vraća svaku detektovanu tehnologiju zajedno s njenom kategorijom. Asset pivoting je trenutno dostupan samo za web, dok API podržava pretragu po domenu.

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja tako što ćemo potražiti istu hash vrednost favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash rezultati korišćeni za otkrivanje domena koji dele isti hash favicon ikone](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti hash favicon ikone kao naša meta.

![favihash izlaz korišćen za otkrivanje domena sa istim hashom favicon ikone](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati hash favicon ikone kao pivot u Shodan-u ili FOFA-i da biste pronašli druge izložene instance iste tehnologije.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ovako možete **izračunati hash favicon-a web-sajta** (MMH3 nad **base64-encoded** bajtovima favicon-a):

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

Takođe možete pribaviti hash vrednosti favicon-a u velikom obimu pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim pivotirati kroz Shodan/Censys.

Favicon otiske tretirajte kao tragove i proverite ih pomoću pratećih signala.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash tretirajte kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su sudari, ponovna upotreba ikonica i namerno lažiranje.
- **Proverite više od** `/favicon.ico`: pregledajte putanje framework/build, manifest datoteke, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, ugrađene data URL-ove i HTML oznake `<link rel="icon">`.
- **Statički resursi mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno zatražite ikonicu i proverite `ETag`, `Last-Modified`, preusmerenja i zaglavlja keša.
- **Proverite podudaranja pomoću pratećih signala**: uporedite naslov, hash HTML-a/tela, zaglavlja, subjekte/SAN-ove TLS sertifikata, komponente proizvoda i izložene portove.
- **Grupišite prema hash-u HTML-a/tela**: dosledan šablon jača otisak; različiti šabloni ukazuju na generičku ili zajedničku ikonicu.
- **Hash koji se pojavljuje uz nepovezane potpise, portove i proizvode tretirajte kao mogući honeypot ili zamenski sadržaj.**
- **Kod dvosmislenih ciljeva uporedite stvarnu stranicu sa nepostojećom putanjom**, kao što je `/_favicon_probe_<8-hex>`; isti odgovori hostinga ili parkirane domene mogu objasniti zajedničku ikonicu.
- **Za početnu trijažu koristite Nuclei pravila za detekciju ili javne skupove podataka** koji povezuju hash vrednosti favicon-a sa proizvodima i CPE-ovima.
- **Imajte u vidu nedostatak IP-centričnog pokrivanja**: površine iza CDN-a, rutirane preko SNI-ja, anycast i samo domenom određene površine možda nisu obuhvaćene skupovima podataka sličnim Shodan-u.

### **Autorska prava / jedinstveni string**

Pretražite veb-stranice i pronađite **stringove koji bi mogli biti zajednički različitim veb-sajtovima u istoj organizaciji**. Dobar primer može biti **string autorskih prava**. Zatim potražite taj string na **Google-u**, u drugim **pregledačima** ili čak u **Shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron posao kao što je

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

da biste istovremeno obnovili sve sertifikate na serveru. Poređenje vremenskih oznaka sertifikata ili njihovih pozicija u certificate-transparency logovima može otkriti povezane domene.<sup>[[6]](#references)</sup>

Takođe, direktno koristite **certificate transparency** logove:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o DMARC-u za poštu

Možete da koristite veb-sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da biste pronašli **domene i poddomene koji dele iste DMARC informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Pasivno preuzimanje**

Napustiti A zapis može ponovo postati dostupan kada cloud provajder dodeli IP adresu drugom korisniku. Istraživanje na koje se upućuje prikazuje oportunistički postupak koji kreira instancu i poredi njenu adresu sa podacima pasivnog DNS-a; scenarije preuzimanja testirajte samo u okviru odobrenog opsega.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće postupke otkrivanja svaki put kada pronađete novi domen: svaki rezultat može otkriti dodatna imena sertifikata, veze pasivnog DNS-a, podudaranja favicon-a i identifikatore organizacije koji nisu bili vidljivi na osnovu početnog domena.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Pošto već znate ime organizacije koja poseduje IP opseg, te podatke možete da pretražite na Shodanu koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove i potražite neočekivane nove domene u TLS sertifikatu.

Možete da pristupite **TLS sertifikatu** glavne veb-stranice, pribavite **ime organizacije**, a zatim potražite to ime u **TLS sertifikatima** svih veb-stranica poznatih **Shodanu** pomoću filtera: `ssl:"Tesla Motors"` ili alata kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) je alat koji pronalazi **domene povezane** sa glavnim domenom i njihove **poddomene**; zaista je sjajan.

**Pasivni DNS / Istorijski DNS**

Podaci pasivnog DNS-a su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili mogu da se preuzmu. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji [preuzimanje domena](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako nije preskup) i obavestite kompaniju.

Ako pronađete **domen sa IP adresom koja se razlikuje** od onih koje ste već otkrili tokom pronalaženja sredstava, trebalo bi da pokrenete **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Imajte na umu da je domen ponekad hostovan na IP adresi koju klijent ne kontroliše, pa nije u opsegu. Budite oprezni._

## Poddomeni

> Znamo sve kompanije u opsegu, sva sredstva svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i u pronalaženju poddomena

### **DNS**

Pokušajmo da pronađemo **podd domene** iz **DNS** zapisa. Trebalo bi da pokušamo i sa **Zone Transfer** (ako je ranjiv, prijavite ga).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Najbrži način da pribavite veliki broj poddomena jeste pretraga spoljašnjih izvora. Najčešće korišćeni **alati** su:


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

Postoje i **drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za pronalaženje poddomena, kao što je:

- [**IP.THC.ORG**](https://ip.thc.org) besplatan API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za pribavljanje poddomena.

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**JLDC besplatni API**](https://jldc.me/anubis/subdomains/google.com)

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

- [**gau**](https://github.com/lc/gau)**:** pribavlja poznate URL-ove sa AlienVault-ovog Open Threat Exchange-a, Wayback Machine-a i Common Crawl-a za bilo koji domen.

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

- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu poddomena i istorije IP adresa
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ovaj projekat besplatno nudi **sve poddomene povezane s bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy), ili pristupiti skupu domena koji koristi ovaj projekat: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Poređenje** mnogih od ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomene** brute-force napadom na DNS servere, koristeći moguće nazive poddomena.

Za ovu aktivnost biće vam potrebne neke **uobičajene wordliste poddomena, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe će vam biti potrebne IP adrese dobrih DNS resolvera. Da biste napravili listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i filtrirati ih pomoću [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Možete koristiti i: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

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

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je omotač za `massdns`, napisan u Go jeziku, koji omogućava enumeraciju validnih poddomena pomoću aktivnog bruteforce-a, kao i razrešavanje poddomena uz obradu wildcard-a i jednostavnu podršku za ulazne i izlazne podatke.

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

- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
  - [**Ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt) možete preuzeti **wordlist** za goaltdns permutacije.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka sa permutacijama, gotator će koristiti svoju.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno pomenute alate).
  - **wordlist** sa permutacijama za altdns možete pronaći [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za permutacije, mutacije i izmene poddomena. Ovaj alat će brute force-om isprobati rezultate (ne podržava DNS wildcard).
  - Wordlist sa permutacijama za dmut možete pronaći [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nove potencijalne nazive subdomains** prema navedenim obrascima kako bi pokušao da otkrije još subdomains.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči obrasce nalik regex-u iz otkrivenih subdomains i generiše kandidatne nazive za razrešavanje.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force poddomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dati skup ulaznih podataka, kao što su prilagođena wordlist lista ili istorijski DNS/TLS zapisi, da bi precizno sintetizovao više odgovarajućih naziva domena i dalje ih proširivao u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.

```
echo www | subzuf facebook.com
```

### **Tok rada za otkrivanje poddomena**

Primeri Trickest tokova rada kombinuju OSINT, DNS brute force i faze permutacija za ponovljivu enumeraciju poddomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više veb-stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa veb-stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** potražiti domene na IP adresi ili **brute-force-ovati nazive VHost domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki poddomen skriven na veb-serveru, možete pokušati da ga pronađete brute force-om:

Za vhosts zasnovane na nazivu, fuzz-ujte zaglavlje `Host` i koristite ffuf-ovu automatsku kalibraciju da biste filtrirali podrazumevani odgovor.<sup>[[2]](#references)</sup>

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
> Ovom tehnikom možda ćete čak moći da pristupite internim/skrivenim endpointima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je u zaglavlju _**Origin**_ postavljen važeći domen/poddomen. U ovim scenarijima možete da zloupotrebite ovo ponašanje da biste **otkrili** nove **poddome­ne**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Dok tražite **subdomene**, obratite pažnju na to da li neki **pokazuje** na neku vrstu **bucket-a** i, ako je tako, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar scope-a, pokušajte da [**brute force-ujete moguće nazive bucket-a i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Praćenje**

Možete **pratiti** da li se kreiraju **novi poddomeni** domena tako što ćete pratiti dnevnike **Certificate Transparency**, kao što to radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite da li je moguć [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomen** pokazuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete **subdomen sa IP adresom različitom** od onih koje ste već otkrili tokom otkrivanja asset-a, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: ponekad je subdomen hostovan na IP adresi koju klijent ne kontroliše, pa nije u scope-u. Budite oprezni._

## IP adrese

U početnim koracima ste možda **pronašli neke IP opsege, domene i poddomene**.\
Vreme je da **prikupite sve IP adrese iz tih opsega**, kao i one za **domene/poddomenе (DNS upiti).**

Pomoću servisa iz sledećih **besplatnih API-ja** možete pronaći i **IP adrese koje su domene i poddomeni ranije koristili**. Klijent je možda i dalje vlasnik tih IP adresa (što vam može pomoći da pronađete [**CloudFlare bypass-e**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Možete i da proverite koji domeni pokazuju na određenu IP adresu pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Skenirajte portove na svim IP adresama koje ne pripadaju CDN-ovima** (jer je malo verovatno da ćete tamo pronaći nešto zanimljivo). Među otkrivenim pokrenutim servisima možda ćete **pronaći ranjivosti**.

**Pronađite** [**uputstvo**](../pentesting-network/index.html) **o skeniranju hostova.**

## Potraga za web serverima

> Pronašli smo sve kompanije i njihovu infrastrukturu, a znamo i IP opsege, domene i poddomene unutar scope-a. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili **recon nad otkrivenim IP adresama i domenima**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo pogledati neke **brze trikove za traženje web servera** unutar scope-a.

Imajte na umu da je ovo **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **skeniranje ranjivosti** i **portova** (**ako je dozvoljeno** u okviru scope-a).

[**Brz metod** za otkrivanje **otvorenih portova** na **web** serverima pomoću alata **masscan** možete pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan praktičan alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Dovoljno je da prosledite listu domena, a alat će pokušati da se poveže na portove 80 (http) i 443 (https). Možete navesti i druge portove koje treba isprobati:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Snimci ekrana**

Sada kada ste otkrili **sve web servere** u okviru scope-a (među **IP** adresama kompanije i svim **domenima** i **poddomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo pojednostaviti stvar i početi tako što ćemo napraviti snimke ekrana svih njih. Već samim **pregledom** **glavne stranice** možete pronaći **neobične** endpoint-e koji su **podložniji** **ranjivostima**.

Da biste sproveli ovu ideju, možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete zatim upotrebiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da obradi sve **snimke ekrana** i kaže vam **šta verovatno sadrži ranjivosti**, a šta ne.

## Javni Cloud resursi

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, trebalo bi da **počnete od liste ključnih reči koje identifikuju tu kompaniju**. Na primer, za kripto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i liste reči sa **uobičajenim nazivima koji se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, od tih reči generišite **permutacije** (za više informacija pogledajte [**Drugi krug DNS brute-force-a**](#second-dns-bruteforce-round)).

Sa dobijenim listama reči možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da prilikom potrage za Cloud resursima treba da **tražite i druge stvari, a ne samo bucket-e u AWS-u**.

### **Traženje ranjivosti**

Ako pronađete nešto poput **otvorenih bucket-a ili izloženih cloud funkcija**, trebalo bi da im **pristupite**, proverite šta nude i da li možete da ih zloupotrebite.

## Email adrese

Uz **domene** i **poddomenе** obuhvaćene scope-om, imate praktično sve što vam je **potrebno da počnete da tražite email adrese**. Sledeći **API-ji** i **alati** pokazali su se najboljim za pronalaženje email adresa neke kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-jima
- API servisa [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API servisa [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API servisa [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

Email adrese će kasnije biti korisne za **brute-force web prijava i auth servisa** (kao što je SSH). Potrebne su i za **phishing**. Pored toga, ovi API-ji pružiće vam još **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Curenje kredencijala

Uz **domene,** **poddomenе** i **email adrese** možete početi da tražite kredencijale koji su ranije procureli i povezani su sa tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** kredencijale, to je veoma laka pobeda.

## Curenje tajni

Curenje kredencijala povezano je sa hakerskim napadima na kompanije, tokom kojih su **poverljive informacije procurele i bile prodate**. Međutim, kompanije mogu biti pogođene i **drugim curenjima** čije informacije nisu u tim bazama podataka:

### Curenje na Github-u

Kredencijali i API-ji mogu procureti u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu github kompaniju.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** neke **organizacije** i njenih **programera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se može koristiti i za pokretanje **gitleaks**-a nad svim **tekstualnim URL-ovima** koji mu se proslede, jer ponekad i **web stranice sadrže tajne**.

#### Github dork-ovi

Pogledajte stranicu [GitHub dork-ovi i curenja](github-leaked-secrets.md) da biste pronašli potencijalne **GitHub dork-ove** za pretragu organizacije.

### Curenje na paste sajtovima

Ponekad napadači, ali i zaposleni, **objave sadržaj kompanije na paste sajtu**. On može, ali ne mora da sadrži **poverljive informacije**, ali svakako vredi pretražiti takve sajtove.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da istovremeno pretražujete više od 80 paste sajtova.

### Google dork-ovi

Stari, ali zlata vredni Google dork-ovi uvek su korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu dostupne**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno da pokrenete. Zato možete izdvojiti svojih omiljenih 10 upita ili koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da biste ih sve pokrenuli**.

_Napomena: alati koji pokušavaju da pretraže celu bazu pomoću običnog Google pregledača nikada neće završiti, jer će vas Google vrlo brzo blokirati._

### **Traženje ranjivosti**

Ako pronađete **važeće procurele** kredencijale ili API tokene, to je veoma laka pobeda.

## Ranjivosti u javnom kodu

Ako ste otkrili da kompanija ima **open-source kod**, možete ga **analizirati** i tražiti **ranjivosti**.

**U zavisnosti od jezika** postoje različiti **alati** koje možete koristiti; pogledajte listu [alata za pregled izvornog koda](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji omogućavaju **skeniranje javnih repozitorijuma**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologija pentestiranja web aplikacija**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje otkriju bug hunter-i nalazi se u **web aplikacijama**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**. [**Ove informacije možete pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Želim posebno da pomenem odeljak [**Open-source alati za automatizovano skeniranje web aplikacija**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako od njih ne treba očekivati da pronađu veoma osetljive ranjivosti, korisni su za uključivanje u **workflows radi dobijanja početnih informacija o web aplikacijama.**

## Rekapitulacija

> Čestitamo! Do ovog trenutka ste već obavili **svo osnovno izviđanje**. Da, osnovno je, jer se može obaviti još mnogo izviđanja (kasnije ćemo videti još trikova).

Do sada ste:

1. Pronašli sve **kompanije** obuhvaćene scope-om
2. Pronašli sve **resurse** koji pripadaju kompanijama (i obavili vuln scan ako je u scope-u)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **poddomenе** tih domena (ima li subdomain takeover-a?)
5. Pronašli sve **IP** adrese (sa **CDN-ova** i van njih) obuhvaćene scope-om.
6. Pronašli sve **web servere** i napravili njihove **snimke ekrana** (ima li nečeg neobičnog što vredi detaljnije pogledati?)
7. Pronašli sve **potencijalne javne cloud resurse** koji pripadaju kompaniji.
8. Pronašli **email adrese**, **procurele kredencijale** i **procurele tajne** koje bi vam lako mogle doneti **veliku pobedu**.
9. **Pentestirali sve pronađene web aplikacije**

## **Alati za potpuno automatizovano izviđanje**

Postoji nekoliko alata koji će izvršiti deo predloženih radnji nad datim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Malo je zastareo i nije ažuriran

## References

- [1] [Jason Haddix – Metodologija lova na bagove v4.0: Izviđačka edicija](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O favicon-ima: od ikonica pregledača do obaveštajnih podataka o napadnoj površini](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Pretvaranje favicon.ico u oružje za BugBounties, OSINT i još mnogo toga](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Otkrivanje domena pomoću napada vremenske korelacije na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasivno preuzimanje: otkrivanje (i emulacija) skupe kampanje za preuzimanje poddomena](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: jedinstvena metoda enumeracije poddomena](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Kompletan workflow za otkrivanje poddomena, 1. deo](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Kompletno otkrivanje poddomena brute-force metodom pomoću automatizovanog Trickest workflow-a, 2. deo](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Snimak ekrana izlaza alata favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
