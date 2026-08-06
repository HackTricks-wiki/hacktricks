# Metodologija spoljnog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje asseta

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji u obuhvatu i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađemo sve **kompanije u vlasništvu glavne kompanije**, a zatim i sve **assete** tih kompanija. Da bismo to uradili:

1. Pronaći akvizicije glavne kompanije; to će nam dati kompanije koje su u obuhvatu.
2. Pronaći ASN svake kompanije (ako postoji); to će nam dati IP opsege koje svaka kompanija poseduje.
3. Koristiti reverse whois pretrage za pronalaženje drugih zapisa (nazivi organizacija, domeni...) povezanih sa prvom kompanijom (ovo se može raditi rekurzivno).
4. Koristiti druge tehnike, kao što su Shodan `org` i `ssl` filteri, za pretragu drugih asseta (trik sa `ssl` može se raditi rekurzivno).

### **Akvizicije**

Pre svega, moramo da saznamo koje **druge kompanije su u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju** i kliknete na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga opcija je da posetite stranicu glavne kompanije na **Wikipedia**-i i pretražite **acquisitions**.\
Za javne kompanije proverite **SEC/EDGAR filings**, stranice za **odnose sa investitorima** ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalna korporativna stabla i podružnice isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku bi trebalo da znate sve kompanije koje su u obuhvatu. Hajde da utvrdimo kako da pronađemo njihove assete.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstveni broj** koji **autonomnom sistemu** (AS) dodeljuje **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa spoljnim mrežama i kojima upravlja jedna organizacija, ali se mogu sastojati od više operatora.

Zanimljivo je utvrditi da li je **kompaniji dodeljen neki ASN** kako bismo pronašli njene **IP opsege.** Biće korisno izvršiti **test ranjivosti** nad svim **hostovima** unutar **obuhvata** i **potražiti domene** unutar ovih IP adresa.\
Možete **pretraživati** po **nazivu kompanije**, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona kompanije, ovi linkovi mogu biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa).** U svakom slučaju, verovatno se sve **korisne informacije** (IP opsezi i Whois) već nalaze na prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, enumeration alata [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatski agregira i sažima ASN-ove na kraju skeniranja.
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
IP opsege organizacije možete pronaći i pomoću [http://asnlookup.com/](http://asnlookup.com) (ima besplatan API).\
IP i ASN domena možete pronaći pomoću [http://ipv4info.com/](http://ipv4info.com).

### **Traženje ranjivosti**

U ovom trenutku znamo **sve assete unutar scope-a**, pa, ako vam je dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **kako biste pronašli** otvorene portove, **a u zavisnosti od onoga što pronađete, trebalo bi** da pogledate u ovoj knjizi kako da pentestujete različite moguće servise koji rade.\
**Takođe, vredno je pomenuti da možete pripremiti i** liste podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar scope-a i njihove assete; vreme je da pronađemo domene unutar scope-a.

_Napomena: pomoću sledećih predloženih tehnika možete pronaći i subdomene, a te informacije ne treba potcenjivati._

Pre svega, trebalo bi da pronađete **glavni domen**(e) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse DNS lookups** nad tim **IP adresama kako biste pronašli više domena unutar scope-a**. Pokušajte da koristite neki DNS server žrtve ili neki dobro poznati DNS server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i online alat: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege, alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) korisni su za automatizaciju reverse lookup-a i obogaćivanje podataka.

### **Reverse Whois (loop)**

U okviru **whois** podataka možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **email adrese**, brojevi telefona... Ali još je zanimljivije to što možete pronaći **dodatne assete povezane sa kompanijom** ako izvršite **reverse whois lookup prema bilo kom od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista email adresa).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatan** web, API nije besplatan.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Nije besplatno (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nije besplatno (API)

Ovaj zadatak možete automatizovati pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API ključ).\
Takođe možete izvršiti automatsko otkrivanje pomoću reverse whois-a koristeći [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje dodatnih naziva domena svaki put kada pronađete novi domen.**

### **Trackeri**

Ako pronađete **isti ID istog trackera** na 2 različite stranice, možete pretpostaviti da **obema stranicama** upravlja **isti tim**.\
Na primer, ako vidite isti **Google Analytics ID** ili isti **Adsense ID** na nekoliko stranica.

Postoje stranice i alati koji vam omogućavaju pretragu prema ovim trackerima i drugim podacima:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove na osnovu deljenih analytics/trackera)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja traženjem istog hash-a favicon ikonice? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako se koristi:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrivanje domena sa istim favicon icon hash-om](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti favicon icon hash kao naš target.

Pored toga, možete pretraživati i technologies koristeći favicon hash, kao što je objašnjeno u [**ovom blog postu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da, ako znate **hash favicon-a ranjive verzije web tehnologije**, možete pretraživati Shodan i **pronaći više ranjivih mesta**:<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ovako možete **izračunati hash favicon-a** web stranice (MMH3 nad **base64-kodiranim** bajtovima favicon-a):
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
You can also get favicon hash-eve at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

Korisne stvari koje treba zapamtiti pri korišćenju favicon fingerprint-a:<sup>[[3]](#references)[[4]](#references)</sup>

- **Tretirajte hash kao indikator, a ne kao dokaz**: MMH3 je kompaktan i kolizije su moguće; operatori takođe mogu zameniti favicon-e ili namerno koristiti obmanjujuću ikonu.
- **Proverite više od** `/favicon.ico`: mnogi proizvodi izlažu ikone u framework/build putanjama ili putem `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URL-ova ili HTML `<link rel="icon">` tagova. Sama putanja može fingerprint-ovati porodicu proizvoda.
- **Static fajlovi su često dostupni kada aplikacija nije**: WAF/SSO/IdP kontrole mogu štititi dynamic rute, ali i dalje izlagati static ikone. Uvek direktno zatražite favicon i proverite `ETag`, `Last-Modified`, redirects i cache headers zbog slabih naznaka verzije/build-a.
- **Validirajte podudaranja pomoću okolnih signala**: uporedite title, HTML/body hash, headers, TLS certificate subjects/SANs, Shodan/Censys komponente i exposed ports pre nego što zaključite da favicon identifikuje proizvod.
- **Grupišite prema HTML/body hash-u pri pivotovanju na velikoj skali**: ako se većina hostova koji dele favicon objedini u jedan page template, fingerprint je pouzdaniji; ako se isti hash deli na mnogo nepovezanih template-a, prednost dajte oznaci "generic/shared/honeypot" umesto oznake proizvoda.
- **Honeypot heuristika**: ako se isti favicon hash pojavljuje na mnogim nepovezanim HTML signatures, nasumičnim portovima i neusaglašenim proizvodima, tretirajte ga kao verovatni honeypot ili generic placeholder, a ne kao pravi product fingerprint.
- **Koristite 404 probe na nejasnim targetima**: u browser-u preuzmite stvarnu stranicu i nepostojeću putanju kao što je `/_favicon_probe_<8-hex>`. Podudarajući hosting-provider/parking responses često bolje objašnjavaju deljene favicon-e nego stvarno preklapanje proizvoda.
- **Bootstrap-ujte mappings iz detection rules**: Nuclei templates i javni favicon datasets mogu pružiti poznata `favicon` ↔ `product` ↔ `CPE` mappings koja su korisna za brzo triage-ovanje nakon objavljivanja CVE-a.
- **Napomena o coverage-u**: Shodan-style datasets su IP-centric. CDN-fronted, SNI-routed, anycast i domain-only surfaces mogu biti potcenjeni, tako da mali broj hit-ova **ne znači** mali broj stvarnih deployment-a.

### **Copyright / Uniq string**

Pretražite unutar web stranica **stringove koji mogu biti deljeni između različitih web stranica u istoj organizaciji**. **Copyright string** može biti dobar primer. Zatim potražite taj string na **google-u**, u drugim **browser-ima** ili čak u **shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da obnovi sve sertifikate domena na serveru. To znači da je, čak i ako CA korišćen za ovo ne postavi vreme generisanja u polje Validity time, moguće **pronaći domene koji pripadaju istoj kompaniji u certificate transparency logovima**.\
Pogledajte [**ovaj writeup za više informacija**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).<sup>[[6]](#references)</sup>

Takođe direktno koristite **certificate transparency** logove:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC informacije

Možete koristiti web stranicu kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i poddomene koji dele iste dmarc informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Očigledno je uobičajeno da ljudi dodele poddomene IP adresama koje pripadaju cloud provajderima i u nekom trenutku **izgube tu IP adresu, ali zaborave da uklone DNS zapis**. Zato ćete, jednostavnim **pokretanjem VM-a** u cloud-u (kao što je Digital Ocean), zapravo **preuzeti neke poddomene**.

[**Ovaj post**](https://kmsec.uk/blog/passive-takeover/) objašnjava priču o tome i predlaže skriptu koja **pokreće VM u DigitalOcean-u**, **uzima** **IPv4** adresu nove mašine i **pretražuje Virustotal u potrazi za zapisima poddomena** koji upućuju na nju.<sup>[[7]](#references)</sup>

### **Drugi načini**

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje dodatnih naziva domena svaki put kada pronađete novi domen.**

**Shodan**

Kao što već znate naziv organizacije koja poseduje IP prostor, te podatke možete pretražiti u shodan-u koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove u potrazi za novim neočekivanim domenima u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne web stranice, dobiti **Organisation name**, a zatim pretražiti taj naziv unutar **TLS sertifikata** svih web stranica poznatih servisu **shodan**, koristeći filter: `ssl:"Tesla Motors"` ili alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji pronalazi **domene povezane** sa glavnim domenom i njihove **poddomene**, prilično je impresivan.

**Passive DNS / Historical DNS**

Passive DNS podaci su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili mogu biti preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi određeni domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asset-a, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, u **ovoj knjizi možete pronaći neke trikove za njihov "napad"**.\
_Napomena: domen je ponekad hostovan unutar IP adrese koju klijent ne kontroliše, pa nije u scope-u; budite pažljivi._

## Poddomene

> Znamo sve kompanije koje su u scope-u, sve asset-e svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene za svaki pronađeni domen.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena takođe mogu pomoći u pronalaženju poddomena

### **DNS**

Pokušajmo da dobijemo **poddomene** iz **DNS** zapisa. Takođe bi trebalo da pokušamo sa **Zone Transfer**-om (Ako je ranjiv, trebalo bi da ga prijavite).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način za pronalaženje velikog broja poddomena jeste pretraga eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
Postoje **drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za pronalaženje poddomena, kao što su:

- [**IP.THC.ORG**](https://ip.thc.org) besplatan API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za dobijanje poddomena
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
- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove sa AlienVault-ovog Open Threat Exchange-a, Wayback Machine-a i Common Crawl-a za dati domen.
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
- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu poddomena i istorije IP adresa
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ovaj projekat besplatno nudi sve poddomene povezane sa **bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy), ili čak pristupiti opsegu koji koristi ovaj projekat [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Poređenje** mnogih od ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomenе** izvođenjem brute-force napada na DNS servere pomoću mogućih imena poddomena.

Za ovu radnju biće vam potrebne neke **uobičajene wordliste poddomena, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe su vam potrebne IP adrese pouzdanih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) za njihovo filtriranje. Možete koristiti i: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno izvodio DNS brute-force. Veoma je brz, ali je sklon lažno pozitivnim rezultatima.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko `massdns`, napisan u jeziku Go, koji omogućava enumeraciju validnih poddomena korišćenjem aktivnog bruteforce-a, kao i razrešavanje poddomena uz rukovanje wildcard-ima i jednostavnu podršku za ulaz i izlaz.
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
### Druga DNS Brute-Force runda

Nakon pronalaženja poddomena korišćenjem open sources i brute-force metode, možete generisati izmene pronađenih poddomena kako biste pokušali da pronađete još više njih. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
- goaltdns **wordlist** za permutacije možete preuzeti [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako datoteka sa permutacijama nije navedena, gotator će koristiti sopstvenu.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno navedene alate).
- **wordlist** permutacija za altdns možete preuzeti [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvršavanje permutacija, mutacija i izmena subdomena. Ovaj alat će brute force-ovati rezultat (ne podržava DNS wildcard).
- dmut permutations wordlist možete pronaći [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena poddomena** na osnovu navedenih obrazaca kako bi pokušao da otkrije još poddomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovaj [**post**](https://cramppet.github.io/regulator/index.html), ali on će u osnovi uzeti **glavne delove** iz **otkrivenih poddomena** i kombinovati ih kako bi pronašao još poddomena.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force pronalaženje poddomena, povezan sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što su prilagođeni wordlist ili istorijski DNS/TLS zapisi, kako bi precizno generisao dodatne odgovarajuće nazive domena i još ih proširivao u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Workflow za otkrivanje poddomena**

Pogledajte ovaj blog post koji sam napisao o tome kako da **automatizujete otkrivanje poddomena** sa domena pomoću **Trickest workflows**, tako da ne moram ručno da pokrećem veliki broj alata na svom računaru:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa web stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** tražiti domene na određenoj IP adresi ili tako što ćete raditi **brute-force naziva VHost domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki poddomen skriven na web serveru, možete pokušati da ga otkrijete brute-force metodom:

Kada **IP adresa preusmerava na hostname** (name-based vhosts), fuzzujte `Host` header direktno i dozvolite alatu ffuf da **automatski kalibriše** rezultate kako bi istakao odgovore koji se razlikuju od podrazumevanog vhost-a:<sup>[[2]](#references)</sup>
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

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je u zaglavlju _**Origin**_ postavljen validan domen/poddomen. U ovim scenarijima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **poddomene**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Dok tražite **subdomains**, obratite pažnju na to da li neki **pointing** vodi ka bilo kojoj vrsti **bucket**, i u tom slučaju [**proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar scope-a, pokušajte da [**brute force-ujete moguće nazive bucket-a i proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Praćenje**

Možete **pratiti** da li se kreiraju **novi subdomains** nekog domena praćenjem **Certificate Transparency** Logova, što radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje vulnerabilities**

Proverite moguće [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomain** pokazuje na neki **S3 bucket**, [**proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **subdomain sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asset-a, trebalo bi da izvršite **basic vulnerability scan** (korišćenjem Nessus-a ili OpenVAS-a) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan** alata. U zavisnosti od toga koji servisi rade, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: ponekad je subdomain hostovan na IP adresi koju klijent ne kontroliše, pa nije u scope-u; budite pažljivi._

## IP adrese

U početnim koracima možda ste **pronašli neke IP opsege, domene i subdomains**.\
Vreme je da **prikupite sve IP adrese iz tih opsega** i za **domene/subdomains (DNS queries).**

Korišćenjem servisa iz sledećih **free apis** takođe možete pronaći **prethodne IP adrese koje su koristili domeni i subdomains**. Klijent je možda i dalje vlasnik tih IP adresa (i one vam mogu omogućiti da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti domene koji pokazuju na određenu IP adresu korišćenjem alata [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje vulnerabilities**

**Izvršite port scan svih IP adresa koje ne pripadaju CDN-ovima** (jer vrlo verovatno tamo nećete pronaći ništa interesantno). U otkrivenim aktivnim servisima možda ćete **moći da pronađete vulnerabilities**.

**Pronađite** [**guide**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Lov na web servere

> Pronašli smo sve kompanije i njihove asset-e i znamo IP opsege, domene i subdomains unutar scope-a. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili određeni **recon IP adresa i pronađenih domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo videti neke **brze trikove za traženje web servera** unutar scope-a.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **vulnerability** i **port scanning** (**ako je dozvoljeno** scope-om).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću alata [**masscan** može se pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan praktičan alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Potrebno je samo da prosledite listu domena, a alat će pokušati da se poveže na port 80 (http) i 443 (https). Dodatno, možete navesti da pokuša i sa drugim portovima:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve web servere** prisutne u scope-u (među **IP** adresama kompanije i svim **domenima** i **subdomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo pojednostaviti stvari i početi tako što ćemo napraviti screenshots svih njih. Samim **gledanjem** **glavne stranice** možete pronaći **čudne** endpoint-e koji su **skloniji** da budu **vulnerable**.

Za sprovođenje predložene ideje možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) preko svih **screenshots** kako bi vam rekao **šta verovatno sadrži vulnerabilities**, a šta ne.

## Public Cloud Assets

Da biste pronašli potencijalne cloud assets koji pripadaju kompaniji, trebalo bi da **počnete sa listom keywords koji identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i wordlists sa **uobičajenim rečima koje se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, pomoću tih reči treba da generišete **permutations** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlists možete koristiti tools kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da prilikom traženja Cloud Assets treba da **tražite više od samo bucket-a u AWS-u**.

### **Looking for vulnerabilities**

Ako pronađete stvari kao što su **open bucket-i ili izložene cloud functions**, trebalo bi da im **pristupite** i pokušate da utvrdite šta vam nude i da li možete da ih zloupotrebite.

## Emails

Sa **domenima** i **subdomenima** unutar scope-a u osnovi imate sve što vam **treba da počnete da tražite emails**. Ovo su **APIs** i **tools** koji su mi se najbolje pokazali za pronalaženje emails neke kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa APIs
- API od [**https://hunter.io/**](https://hunter.io/) (free version)
- API od [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API od [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails će vam kasnije biti korisni za **brute-force web login-a i auth services** (kao što je SSH). Takođe su potrebni za **phishings**. Osim toga, ovi APIs će vam dati još više **informacija o osobi** koja stoji iza email-a, što je korisno za phishing campaign.

## Credential Leaks

Sa **domenima,** **subdomenima** i **emails** možete početi da tražite credentials koji su u prošlosti leak-ovani, a pripadaju tim emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ako pronađete **valid leaked** credentials, to je veoma laka pobeda.

## Secrets Leaks

Credential leaks su povezani sa hack-ovima kompanija kod kojih su **sensitive information leak-ovane i prodate**. Međutim, kompanije mogu biti pogođene i **drugim leak-ovima** čije se informacije ne nalaze u tim bazama:

### Github Leaks

Credentials i APIs mogu biti leak-ovani u **public repositories** same **kompanije** ili **user-a** koji rade u toj github kompaniji.\
Možete koristiti **tool** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **public repos** neke **organizacije** i njenih **developera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti za pokretanje **gitleaks** nad svim **text** sadržajem koji se nalazi na **URL-ovima prosleđenim** alatu, jer i **web pages ponekad sadrže secrets**.

#### Github Dorks

Pogledajte i ovu **stranicu** za potencijalne **github dorks** koje možete pretraživati i u organizaciji koju napadate:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad će napadači ili samo zaposleni **objaviti sadržaj kompanije na paste sajtu**. To može, ali i ne mora, sadržati **sensitive information**, ali je veoma zanimljivo pretražiti takav sadržaj.\
Možete koristiti tool [**Pastos**](https://github.com/carlospolop/Pastos) za istovremenu pretragu više od 80 paste sajtova.

### Google Dorks

Stari, ali dobri google dorks su uvek korisni za pronalaženje **izloženih informacija koje tamo ne bi trebalo da se nalaze**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete izabrati svojih omiljenih 10 ili koristiti **tool kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: tools koji očekuju da pokrenu celu bazu koristeći regularni Google browser nikada neće završiti, jer će vas google veoma brzo blokirati._

### **Looking for vulnerabilities**

Ako pronađete **valid leaked** credentials ili API tokene, to je veoma laka pobeda.

## Public Code Vulnerabilities

Ako otkrijete da kompanija ima **open-source code**, možete ga **analizirati** i potražiti **vulnerabilities**.

**U zavisnosti od jezika**, postoje različiti **tools** koje možete koristiti:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Postoje i besplatni services koji omogućavaju da **skenirate public repositories**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Većina vulnerabilities** koje bug hunters pronađu nalazi se unutar **web applications**, pa bih u ovom trenutku želeo da govorim o **web application testing methodology**, a [**ove informacije možete pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem sekciju [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da pronađu veoma osetljive vulnerabilities, korisni su za njihovo uključivanje u **workflows kako bi se dobile početne web informacije.**

## Recapitulation

> Čestitam! U ovom trenutku ste već obavili **svu osnovnu enumeraciju**. Da, osnovna je zato što se može obaviti još mnogo enumeracije (više trikova ćemo videti kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar scope-a
2. Pronašli sve **asset-e** koji pripadaju kompanijama (i obavili određeni vuln scan ako je u scope-u)
3. Pronašli sve **domen-e** koji pripadaju kompanijama
4. Pronašli sve **subdomen-e** tih domena (da li postoji subdomain takeover?)
5. Pronašli sve **IP** adrese (sa i **bez CDN-ova**) unutar scope-a.
6. Pronašli sve **web servere** i napravili njihov **screenshot** (da li postoji nešto čudno što vredi detaljnije pogledati?)
7. Pronašli sve **potencijalne public cloud assets** koji pripadaju kompaniji.
8. **Emails**, **credential leaks** i **secret leaks** koji vam mogu veoma lako doneti **veliku pobedu**.
9. **Pentesting svih web-ova koje ste pronašli**

## **Full Recon Automatic Tools**

Postoji više tools koji će obaviti deo predloženih aktivnosti nad datim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Malo star i nije ažuriran

## References

- [1] Svi besplatni courses od [**@Jhaddix**](https://twitter.com/Jhaddix), kao što je [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [@Asm0d3us - Weaponizing Favicon Ico For Bugbounties Osint And What Not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [swarm.ptsecurity.com - Discovering Domains Via A Time Correlation Attack](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [kmsec.uk - Passive Takeover](https://kmsec.uk/blog/passive-takeover)
- [8] [cramppet.github.io - Regulator - Index](https://cramppet.github.io/regulator/index.html)

{{#include ../../banners/hacktricks-training.md}}
