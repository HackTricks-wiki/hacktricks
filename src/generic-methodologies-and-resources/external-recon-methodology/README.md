# Metodologija eksternog recon-a

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje asseta

> Dakle, rečeno vam je da je sve što pripada određenoj kompaniji u scope-u i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađemo sve **kompanije u vlasništvu glavne kompanije**, a zatim i sve **asset-e** tih kompanija. Da bismo to uradili, potrebno je da:<sup>[[1]](#references)</sup>

1. Pronađemo akvizicije glavne kompanije, čime dobijamo kompanije koje su u scope-u.
2. Pronađemo ASN (ako postoji) svake kompanije, čime dobijamo IP opsege koje svaka kompanija poseduje.
3. Koristimo reverse whois pretrage za pronalaženje drugih zapisa (naziva organizacija, domena...) povezanih sa prvim zapisom (ovo se može raditi rekurzivno).
4. Koristimo druge tehnike, kao što su shodan `org`i `ssl`filteri, za pretragu drugih asseta (trik sa `ssl` može se raditi rekurzivno).

### **Akvizicije**

Pre svega, potrebno je da saznamo koje su **druge kompanije u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju** i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija kupila.\
Druga opcija je da posetite **Wikipedia** stranicu glavne kompanije i pretražite **acquisitions**.\
Za javne kompanije proverite **SEC/EDGAR filings**, stranice za odnose sa investitorima (**investor relations**) ili lokalne registre kompanija (npr. **Companies House** u Ujedinjenom Kraljevstvu).\
Za globalna stabla kompanija i podružnice isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku bi trebalo da znate sve kompanije koje su u scope-u. Hajde da utvrdimo kako da pronađemo njihove assete.

### **ASN-ovi**

Broj autonomnog sistema (**ASN**) je **jedinstveni broj** koji **autonomnom sistemu** (AS) dodeljuje **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa eksternim mrežama i kojima upravlja jedna organizacija, ali se mogu sastojati od više operatora.

Zanimljivo je utvrditi da li je **kompaniji dodeljen neki ASN** kako bismo pronašli njene **IP opsege.** Bilo bi korisno izvršiti **test ranjivosti** nad svim **hostovima** unutar **scope-a** i **potražiti domene** unutar tih IP adresa.\
Možete **pretraživati** prema nazivu kompanije, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kojem se kompanija nalazi, ovi linkovi mogu biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se sve** korisne informacije **(IP opsezi i Whois)** već nalaze na prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, enumeracija alata [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatski objedinjuje i sažima ASN-ove na kraju skeniranja.
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

U ovom trenutku znamo **sva sredstva unutar scope-a**, pa, ako vam je dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da pronađete** otvorene portove, **a u zavisnosti od onoga što pronađete, trebalo bi** da pogledate u ovoj knjizi kako da pentestujete različite moguće servise koji rade.\
**Takođe vredi napomenuti da možete pripremiti i neke** liste podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar scope-a i njihova sredstva; vreme je da pronađemo domene unutar scope-a.

_Imajte na umu da pomoću sledećih predloženih tehnika možete pronaći i poddomene i da te informacije ne treba potcenjivati._

Pre svega, trebalo bi da pronađete **glavni domen** svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse DNS lookups** nad tim **IP adresama kako biste pronašli još domena unutar scope-a**. Pokušajte da koristite neki DNS server žrtve ili neki dobro poznati DNS server (1.1.1.1, 8.8.8.8)
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

U okviru **whois** podataka možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **email adrese**, brojevi telefona... Ali još je zanimljivije to što možete pronaći **dodatne assete povezane sa kompanijom** ako izvršite **reverse whois lookups na osnovu bilo kog od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista email adresa).\
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
Takođe možete izvršiti automatsko otkrivanje pomoću reverse whois-a uz [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje dodatnih naziva domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako pronađete **isti ID istog tracker-a** na 2 različite stranice, možete pretpostaviti da **obe stranice** **održava isti tim**.\
Na primer, ako vidite isti **Google Analytics ID** ili isti **Adsense ID** na nekoliko stranica.

Postoje stranice i alati koji vam omogućavaju pretragu na osnovu ovih tracker-a i drugih podataka:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove na osnovu zajedničke analitike/tracker-a)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja traženjem iste hash vrednosti favicon ikonice? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Jednostavno rečeno, favihash će nam omogućiti da otkrijemo domene koje imaju isti hash favicon ikone kao naš cilj.

![Izlaz favihash alata korišćen za otkrivanje domena sa istim favicon hashom](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati favicon hash kao Shodan ili FOFA pivot da biste pronašli druge izložene instance iste tehnologije.<sup>[[5]](#references)</sup>
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
Možete dobiti i favicon hash-eve na velikom broju ciljeva pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim pivotirati kroz Shodan/Censys.

Tretirajte favicon fingerprint-e kao indikacije i proverite ih pomoću okolnih signala.<sup>[[3]](#references)[[4]](#references)</sup>

- **Tretirajte hash kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su sudari, ponovna upotreba ikona i namerno lažiranje.
- **Proverite više od** `/favicon.ico`: pregledajte framework/build putanje, manifest fajlove, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL-ove i HTML `<link rel="icon">` tagove.
- **Static assets mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno pošaljite zahtev za ikonu i pregledajte `ETag`, `Last-Modified`, redirects i cache headere.
- **Validirajte podudaranja pomoću okolnih signala**: uporedite title, HTML/body hash, headere, subjekte/SAN-ove TLS sertifikata, product komponente i izložene portove.
- **Grupišite prema HTML/body hash-u**: konzistentan template jača fingerprint; različiti template-i ukazuju na generičku ili deljenu ikonu.
- **Hash koji se pojavljuje kroz nepovezane signatures, portove i products tretirajte kao potencijalni honeypot ili placeholder.**
- **Kod nejasnih ciljeva uporedite stvarnu stranicu sa nepostojećom putanjom** kao što je `/_favicon_probe_<8-hex>`; podudarajući hosting ili parking odgovori mogu objasniti deljenu ikonu.
- **Započnite trijažu pomoću Nuclei detection rules ili javnih datasets** koji povezuju favicon hash-eve sa products i CPE-ovima.
- **Imajte na umu prazninu u IP-centric pokrivenosti**: CDN-fronted, SNI-routed, anycast i domain-only površine možda nedostaju u Shodan-like datasets.

### **Copyright / Jedinstveni string**

Pretražite unutar web stranica **string-ove koji mogu biti deljeni između različitih web sajtova iste organizacije**. **copyright string** može biti dobar primer. Zatim pretražite taj string u **google-u**, drugim **browserima** ili čak u **shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT vreme**

Uobičajeno je imati cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da biste obnovili sve sertifikate na serveru u isto vreme. Korelacija vremenskih oznaka sertifikata ili pozicija u certificate-transparency logovima može otkriti povezane domene.<sup>[[6]](#references)</sup>

Takođe direktno koristite **certificate transparency** logove:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije iz Mail DMARC-a

Možete koristiti veb-sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i poddomene koji dele iste dmarc informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Napušteni A zapis može postati dostupan kada cloud provajder ponovo dodeli IP adresu. Navedeno istraživanje pokazuje oportunistički workflow koji kreira instancu i korelira njenu adresu sa podacima iz passive DNS-a; scenarije takeover-a testirajte samo u okviru autorizovanog opsega.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće discovery pivote svaki put kada pronađete novi domen: svaki rezultat može otkriti dodatna imena sertifikata, passive-DNS relacije, favicon podudaranja i identifikatore organizacije koji nisu bili vidljivi iz originalnog seed-a.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Kao što već znate ime organizacije koja poseduje IP prostor. Te podatke možete pretražiti u shodan-u pomoću: `org:"Tesla, Inc."` Proverite pronađene hostove u potrazi za novim neočekivanim domenima u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne veb-stranice, dobiti **naziv organizacije**, a zatim pretražiti taj naziv unutar **TLS sertifikata** svih veb-stranica poznatih alatu **shodan** pomoću filtera: `ssl:"Tesla Motors"` ili koristiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomene**, prilično je neverovatan.

**Passive DNS / Historical DNS**

Passive DNS podaci su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se još uvek razrešavaju ili mogu biti preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi određeni domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asseta, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: domen je ponekad hostovan unutar IP adrese koju klijent ne kontroliše, pa nije u opsegu; budite oprezni._

## Poddomene

> Znamo sve kompanije unutar opsega, sve assete svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i pri pronalaženju poddomena

### **DNS**

Pokušajmo da dobijemo **poddomene** iz **DNS** zapisa. Takođe bi trebalo da pokušamo sa **Zone Transfer** (ako je ranjiv, treba ga prijaviti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način da se pronađe veliki broj poddomena jeste pretraga spoljnih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za pronalaženje poddomena
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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Skeniraju web tražeći JS fajlove i iz njih izdvajaju poddomene.
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

Ovaj projekat besplatno nudi **sve poddomene povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy), ili čak pristupiti scope-u koji ovaj projekat koristi na adresi [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Poređenje** mnogih od ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomene** izvođenjem brute-force napada na DNS servere pomoću mogućih naziva poddomena.

Za ovu radnju biće vam potrebne neke **wordlist-e sa uobičajenim poddomenima, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe su vam potrebne IP adrese dobrih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera, možete preuzeti resolvere sa adrese [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) za njihovo filtriranje. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno izvršavao DNS brute-force. Veoma je brz, ali je sklon lažno pozitivnim rezultatima.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko alata `massdns`, napisan u programskom jeziku Go, koji omogućava enumeraciju važećih poddomena korišćenjem aktivnog bruteforce-a, kao i razrešavanje poddomena uz obradu wildcard-a i jednostavnu podršku za ulaz i izlaz.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhroni brute force imena domena.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga DNS Brute-Force runda

Nakon pronalaženja poddomena pomoću open sources i brute-forcinga, možete generisati varijacije pronađenih poddomena kako biste pokušali da pronađete još više njih. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
- goaltdns permutacije možete preuzeti kao **wordlist** [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako datoteka sa permutacijama nije navedena, gotator će koristiti sopstvenu.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Pored generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno komentarisane alate).
- altdns **wordlist** sa permutacijama možete pronaći [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će brute force-ovati rezultat (ne podržava DNS wildcard).
- dmut wordlist sa permutacijama možete pronaći [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena poddomena** prema navedenim obrascima kako bi pokušao da otkrije više poddomena.

#### Pametno generisanje permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči obrasce nalik regex-u iz otkrivenih poddomena i generiše imena kandidata za rezoluciju.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force pronalaženje poddomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što su prilagođena wordlista ili istorijski DNS/TLS zapisi, da precizno generiše dodatna odgovarajuća imena domena i da ih dalje proširuje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Workflow za otkrivanje subdomena**

Primeri Trickest workflow-a kombinuju OSINT, DNS brute force i faze permutacija za ponovljivo enumerisanje subdomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju subdomenima, možete pokušati da **pronađete druge subdomene sa web stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** potražiti domene na određenoj IP adresi ili izvršiti **brute force VHost naziva domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki subdomen sakriven na web serveru, možete pokušati da ga pronađete brute force metodom:

Za vhost-ove zasnovane na nazivu, fuzz-ujte `Host` header i koristite ffuf-ovu automatsku kalibraciju za filtriranje podrazumevanog odgovora.<sup>[[2]](#references)</sup>
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
> Ovom tehnikom možda ćete čak moći da pristupite internim/skivenim endpoint-ima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je validan domen/poddomen postavljen u zaglavlju _**Origin**_. U ovim scenarijima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **poddomeне**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Tokom traženja **subdomena**, obratite pažnju na to da li **pokazuju** na neki tip **bucket-a**, i u tom slučaju [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar scope-a, pokušajte da [**brute force-ujete moguće nazive bucket-a i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Možete **nadgledati** da li se kreiraju **nove poddomene** domena tako što nadgledate **Certificate Transparency** Logs, što [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) radi.

### **Traženje ranjivosti**

Proverite moguće [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomen** pokazuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete **subdomen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asseta, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i određeno [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, u **ovoj knjizi možete pronaći neke trikove za njihovo „napadanje“**.\
_Napomena: ponekad je subdomen hostovan unutar IP adrese koja nije pod kontrolom klijenta, pa nije u scope-u; budite pažljivi._

## IP adrese

U početnim koracima ste možda **pronašli neke IP opsege, domene i poddomene**.\
Vreme je da **prikupite sve IP adrese iz tih opsega**, kao i za **domene/poddomene (DNS upiti).**

Korišćenjem servisa iz sledećih **besplatnih API-ja** takođe možete pronaći **prethodne IP adrese koje su koristili domeni i poddomeni**. Ove IP adrese su možda i dalje u vlasništvu klijenta (i mogu vam omogućiti da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti domene koji pokazuju na određenu IP adresu koristeći alat [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Skenirajte portove na svim IP adresama koje ne pripadaju CDN-ovima** (jer najverovatnije tamo nećete pronaći ništa zanimljivo). U otkrivenim aktivnim servisima možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Lov na web servere

> Pronašli smo sve kompanije i njihove assete i znamo IP opsege, domene i poddomene unutar scope-a. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili određeni **recon IP adresa i pronađenih domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo videti neke **brze trikove za traženje web servera** unutar scope-a.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **skeniranje ranjivosti** i **skeniranje portova** (**ako je dozvoljeno** scope-om).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću alata [**masscan** može se pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan jednostavan alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Potrebno je samo da prosledite listu domena, a alat će pokušati da se poveže na port 80 (http) i 443 (https). Takođe možete navesti da pokuša i sa drugim portovima:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve web servere** koji se nalaze u scope-u (među **IP** adresama kompanije i svim **domenima** i **subdomenima**), verovatno **ne znate odakle da počnete**. Zato pojednostavimo stvari i počnimo tako što ćemo napraviti screenshots svih njih. Samim **gledanjem** u **glavnu stranicu** možete pronaći **čudne** endpointe koji su skloniji tome da budu **vulnerable**.

Da biste sproveli predloženu ideju, možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) nad svim **screenshots** da biste utvrdili **šta verovatno sadrži vulnerabilities**, a šta ne.

## Javni Cloud resursi

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, trebalo bi da **počnete sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Takođe će vam biti potrebne wordlists sa **uobičajenim rečima koje se koriste u bucketima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, pomoću tih reči, trebalo bi da generišete **permutacije** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlistama možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da, kada tražite Cloud Assets, treba da **tražite više od samih bucket-a u AWS-u**.

### **Traženje vulnerabilities**

Ako pronađete stvari kao što su **otvoreni bucket-i ili izložene cloud funkcije**, trebalo bi da im **pristupite** i pokušate da utvrdite šta vam nude i da li možete da ih zloupotrebite.

## Email adrese

Sa **domenima** i **subdomenima** koji su u scope-u, praktično imate sve što vam je **potrebno da počnete da tražite email adrese**. Ovo su **API-ji** i **alati** koji su se meni najbolje pokazali za pronalaženje email adresa kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-jima
- API za [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API za [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API za [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje vulnerabilities**

Email adrese će vam kasnije biti korisne za **brute-force web login-a i auth servisa** (kao što je SSH). Takođe su potrebne za **phishings**. Pored toga, ovi API-ji će vam pružiti još **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domenima,** **subdomenima** i **email adresama** možete početi da tražite credentials koji su ranije leak-ovani, a pripadaju tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje vulnerabilities**

Ako pronađete **validne leaked** credentials, to je veoma laka pobeda.

## Secrets Leaks

Credential leaks povezani su sa hackovima kompanija, gde su **osetljive informacije leak-ovane i prodate**. Međutim, kompanije mogu biti pogođene i **drugim leaks**, čije informacije nisu u tim bazama:

### Github Leaks

Credentials i API-ji mogu biti leak-ovani u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu GitHub kompaniju.\
Možete koristiti **tool** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repo-e** neke **organizacije** i njenih **developera**, a zatim da automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti za pokretanje **gitleaks** nad svim **tekstom** koji se nalazi na **URL-ovima prosleđenim** alatu, jer i **web stranice ponekad sadrže secrets**.

#### Github Dorks

Pogledajte stranicu [GitHub dorks and leaks page](github-leaked-secrets.md) za potencijalne **GitHub dorks** upite koje možete pretraživati u organizaciji.

### Pastes Leaks

Ponekad napadači ili samo zaposleni **objave sadržaj kompanije na paste sajtu**. On može, ali i ne mora, sadržati **osetljive informacije**, ali je veoma zanimljivo pretražiti ga.\
Možete koristiti tool [**Pastos**](https://github.com/carlospolop/Pastos) za istovremenu pretragu više od 80 paste sajtova.

### Google Dorks

Stari, ali odlični Google dorks upiti uvek su korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu tamo**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete izabrati svojih omiljenih 10 upita ili koristiti **tool kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji pokušavaju da pokrenu celu bazu koristeći standardni Google browser nikada neće završiti, jer će vas Google vrlo brzo blokirati._

### **Traženje vulnerabilities**

Ako pronađete **validne leaked** credentials ili API tokene, to je veoma laka pobeda.

## Vulnerabilities u javnom kodu

Ako otkrijete da kompanija ima **open-source kod**, možete ga **analizirati** i tražiti **vulnerabilities** u njemu.

**U zavisnosti od jezika**, postoje različiti **alati** koje možete koristiti; pogledajte listu [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji vam omogućavaju da **skenirate javne repozitorijume**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologija za Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Većina vulnerabilities** koje bug hunters pronalaze nalazi se unutar **web aplikacija**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**, a te [**informacije možete pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem odeljak [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da pronađu veoma osetljive vulnerabilities, korisni su za implementaciju u **workflows kako bi se dobile početne informacije o web-u.**

## Rekapitulacija

> Čestitamo! U ovom trenutku ste već obavili **svu osnovnu enumeraciju**. Da, osnovna je zato što se može obaviti još mnogo enumeracije (kasnije ćemo videti još trikova).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar scope-a
2. Pronašli sve **resurse** koji pripadaju kompanijama (i obavili vuln scan ako je u scope-u)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **subdomene** tih domena (da li je neki subdomain takeover moguć?)
5. Pronašli sve **IP** adrese (sa i **bez CDN-ova**) unutar scope-a.
6. Pronašli sve **web servere** i napravili **screenshot** za svaki od njih (da li postoji nešto čudno što vredi detaljnije istražiti?)
7. Pronašli sve potencijalne javne cloud resurse koji pripadaju kompaniji.
8. **Email adrese**, **credential leaks** i **secret leaks** koji vam mogu veoma lako doneti **veliku pobedu**.
9. **Obavili Pentesting svih pronađenih web sajtova**

## **Automatski alati za Full Recon**

Postoji nekoliko alata koji će obaviti deo predloženih radnji nad datim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Prilično star i nije ažuriran

## References

- [1] [Jason Haddix – Metodologija bug huntera v4.0: Recon izdanje](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O favicon-ima: od ikonica browsera do obaveštajnih podataka o attack surface-u](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico za BugBounties, OSINT i još mnogo toga](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Otkrivanje domena putem napada vremenske korelacije na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasivni takeover: otkrivanje (i emulacija) skupe kampanje subdomain takeover-a](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Jedinstvena metoda enumeracije subdomena](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Kompletan workflow za otkrivanje subdomena, prvi deo](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Kompletno brute-force otkrivanje subdomena pomoću automatizovanog Trickest workflow-a, drugi deo](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot favihash output-a](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
