# Metodologija spoljnog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje asseta

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji unutar scope-a i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađemo sve **kompanije u vlasništvu matične kompanije**, a zatim i sve **assete** tih kompanija. Da bismo to uradili:

1. Pronaći akvizicije matične kompanije, što će nam dati kompanije unutar scope-a.
2. Pronaći ASN svake kompanije, ako postoji, što će nam dati IP opsege u vlasništvu svake kompanije
3. Koristiti reverse whois lookups za pretragu drugih zapisa (nazivi organizacija, domeni...) povezanih sa prvom kompanijom (ovo se može raditi rekurzivno)
4. Koristiti druge tehnike, kao što su shodan `org`and `ssl`filters, za pretragu drugih asseta (trik sa `ssl` može se raditi rekurzivno).

### **Akvizicije**

Pre svega, potrebno je da saznamo koje su **druge kompanije u vlasništvu matične kompanije**.\
Jedna mogućnost je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **matičnu kompaniju** i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je matična kompanija kupila.\
Druga mogućnost je da posetite stranicu **Wikipedia** matične kompanije i pretražite **acquisitions**.\
Za javne kompanije proverite **SEC/EDGAR filings**, stranice za **odnose sa investitorima** ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalna korporativna stabla i podružnice, isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku bi trebalo da znate sve kompanije unutar scope-a. Hajde da utvrdimo kako da pronađemo njihove assete.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstveni broj** dodeljen **autonomnom sistemu** (AS) od strane **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa eksternim mrežama i kojima upravlja jedna organizacija, ali mogu biti sastavljeni od više operatora.

Zanimljivo je proveriti da li je **kompaniji dodeljen neki ASN**, kako bismo pronašli njene **IP opsege.** Bilo bi korisno izvršiti **testiranje ranjivosti** nad svim **hostovima** unutar **scope-a** i **potražiti domene** unutar ovih IP adresa.\
Možete **pretraživati** po **nazivu kompanije**, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kojem se kompanija nalazi, ovi linkovi mogu biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se sve** korisne informacije **(IP opsezi i Whois)** već nalaze na prvom linku.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-ova**
enumeracija automatski prikuplja i sažima ASN-ove na kraju skeniranja.
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

U ovom trenutku znamo **sve assete unutar opsega**, pa, ako vam je dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **kako biste pronašli** otvorene portove **i, u zavisnosti od onoga što pronađete, trebalo bi da** pogledate u ovoj knjizi kako da pentestujete različite moguće servise koji rade.\
**Takođe, vredelo bi pomenuti da možete pripremiti i** liste podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar opsega i njihove assete; vreme je da pronađemo domene unutar opsega.

_Imajte na umu da pomoću sledećih predloženih tehnika možete pronaći i poddomene i da te informacije ne treba potcenjivati._

Pre svega, trebalo bi da pronađete **glavni domen**(e) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da obavite **reverse dns lookups** nad tim **IP adresama kako biste pronašli još domena unutar opsega**. Pokušajte da koristite neki DNS server žrtve ili neki dobro poznati DNS server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i online alat: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege korisni su alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), koji automatizuju reverse lookups i obogaćivanje podataka.

### **Reverse Whois (petlja)**

Unutar **whois** podataka možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **email adrese**, brojevi telefona... Ali još je zanimljivije to što možete pronaći **dodatne assete povezane sa kompanijom** ako obavite **reverse whois lookups na osnovu bilo kog od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista email adresa).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - Besplatan **Web**, API nije besplatan.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Nije besplatno (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nije besplatno (API)

Ovaj zadatak možete automatizovati pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API ključ).\
Možete obaviti i automatsko otkrivanje pomoću reverse whois-a koristeći [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje novih naziva domena svaki put kada pronađete novi domen.**

### **Trackeri**

Ako pronađete **isti ID istog trackera** na 2 različite stranice, možete pretpostaviti da su **obe stranice** pod upravljanjem **istog tima**.\
Na primer, ako na nekoliko stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji vam omogućavaju pretragu na osnovu ovih i drugih trackera:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove na osnovu zajedničkih analytics/trackers podataka)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja traženjem istog favicon icon hash-a? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako se koristi:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrivanje domena sa istim hashom favicon ikonice](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti hash favicon ikonice kao naš target.

Pored toga, pomoću hasha favicon ikonice možete pretraživati i tehnologije, kao što je objašnjeno u [**ovom blog postu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da, ako znate **hash favicon ikonice ranjive verzije određene web tehnologije**, možete pretražiti Shodan i **pronaći još ranjivih mesta**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ovako možete **izračunati hash favicon-a** web stranice (MMH3 nad **base64-enkodiranim** bajtovima favicon-a):
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
Favicon hash-eve možete dobiti i na velikoj skali pomoću alata [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim izvršiti pivot u Shodan/Censys.

Korisne stvari koje treba imati na umu pri korišćenju favicon fingerprint-a:

- **Tretirajte hash kao indikator, a ne kao dokaz**: MMH3 je kompaktan i kolizije su moguće; operateri takođe mogu zameniti favicon ili namerno koristiti ikonu koja dovodi u zabludu.
- **Proverite više od** `/favicon.ico`: mnogi proizvodi izlažu ikone u framework/build putanjama ili putem `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URL-ova ili HTML `<link rel="icon">` tagova. Sama putanja može fingerprint-ovati familiju proizvoda.
- **Static fajlovi su često dostupni kada aplikacija nije**: WAF/SSO/IdP kontrole mogu štititi dinamičke rute, ali i dalje izlagati static ikone. Uvek direktno zahtevajte favicon i proverite `ETag`, `Last-Modified`, redirects i cache headere zbog slabih nagoveštaja o verziji/build-u.
- **Validirajte podudaranja pomoću okolnih signala**: uporedite title, HTML/body hash, headere, TLS certificate subjects/SANs, Shodan/Censys komponente i exposed portove pre nego što zaključite da favicon identifikuje proizvod.
- **Grupišite prema HTML/body hash-u pri pivotovanju na velikoj skali**: ako se većina hostova koji dele favicon svede na jedan page template, fingerprint je pouzdaniji; ako se isti hash deli na mnogo nepovezanih template-a, prednost dajte oznaci "generic/shared/honeypot" umesto oznake proizvoda.
- **Honeypot heuristika**: ako se isti favicon hash pojavljuje na velikom broju nepovezanih HTML potpisa, random portova i međusobno suprotstavljenih proizvoda, tretirajte ga kao verovatni honeypot ili generic placeholder, a ne kao stvarni product fingerprint.
- **Koristite 404 probe za nejasne targete**: u browser-u učitajte stvarnu stranicu i nepostojeću putanju kao što je `/_favicon_probe_<8-hex>`. Podudarni hosting-provider/parking odgovori često bolje objašnjavaju deljene favicon-e nego stvarno preklapanje proizvoda.
- **Bootstrap-ujte mappings iz detection rules**: Nuclei templates i javni favicon dataset-i mogu obezbediti poznate `favicon` ↔ `product` ↔ `CPE` mappings, korisne za brzo triage postupanje nakon objavljivanja CVE-ova.
- **Napomena o coverage-u**: Shodan-style dataset-i su IP-centric. Površine iza CDN-a, SNI-routed, anycast i domain-only površine mogu biti potcenjene, zato mali broj hit-ova **ne znači** malu deployment zastupljenost u stvarnom svetu.

### **Copyright / Uniq string**

Pretražite unutar web stranica **string-ove koji mogu biti zajednički različitim web sajtovima u istoj organizaciji**. **Copyright string** može biti dobar primer. Zatim potražite taj string u **Google-u**, drugim **browser-ima** ili čak u **Shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da obnovi sve sertifikate domena na serveru. To znači da je, čak i ako CA korišćen za ovo ne postavlja vreme generisanja u polje Validity time, moguće **pronaći domene koji pripadaju istoj kompaniji u certificate transparency logovima**.\
Pogledajte ovaj [**writeup za više informacija**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Takođe direktno koristite **certificate transparency** logove:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o Mail DMARC-u

Možete koristiti web sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i poddomene koji dele iste DMARC informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Očigledno je uobičajeno da ljudi dodele poddomene IP adresama koje pripadaju cloud provajderima i da u nekom trenutku **izgube tu IP adresu, ali zaborave da uklone DNS zapis**. Zbog toga ćete, jednostavnim **pokretanjem VM-a** u nekom cloud-u (kao što je Digital Ocean), zapravo **preuzeti neke poddomene**.

[**Ovaj post**](https://kmsec.uk/blog/passive-takeover/) objašnjava priču o tome i predlaže skriptu koja **pokreće VM u DigitalOcean-u**, **dobavlja** **IPv4** adresu nove mašine i **pretražuje Virustotal u potrazi za zapisima poddomena** koji upućuju na nju.

### **Drugi načini**

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje novih naziva domena svaki put kada pronađete novi domen.**

**Shodan**

Kao što već znate naziv organizacije kojoj pripada IP prostor. Te podatke možete pretražiti u shodan-u pomoću: `org:"Tesla, Inc."` Proverite pronađene hostove u potrazi za novim neočekivanim domenima u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne web stranice, dobaviti naziv **Organisation** i zatim pretražiti taj naziv unutar **TLS sertifikata** svih web stranica poznatih alatu **shodan**, pomoću filtera: `ssl:"Tesla Motors"` ili koristiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) je alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomene**, prilično je impresivan.

**Pasivni DNS / Istorijski DNS**

Podaci o pasivnom DNS-u su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili mogu biti preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi određeni domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asseta, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću alata Nessus ili OpenVAS), kao i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću alata **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: ponekad je domen hostovan unutar IP adrese koju klijent ne kontroliše, pa nije u scope-u; budite oprezni._

## Poddomeni

> Znamo sve kompanije koje su u scope-u, sve assete svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i pri pronalaženju poddomena

### **DNS**

Pokušajmo da dobijemo **poddomenе** iz **DNS** zapisa. Takođe bi trebalo da pokušamo **Zone Transfer** (ako je ranjiv, trebalo bi da ga prijavite).
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
Postoje **drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje subdomena, mogu biti korisni za pronalaženje subdomena, kao što su:

- [**IP.THC.ORG**](https://ip.thc.org) besplatan API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za dobavljanje poddomena
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
- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove sa AlienVault Open Threat Exchange, Wayback Machine i Common Crawl servisa za bilo koji domen.
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

Ovaj projekat besplatno nudi sve poddomene povezane sa **bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy), ili čak pristupiti scope-u koji koristi ovaj projekat: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Poređenje** mnogih od ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomena** izvođenjem brute-force napada na DNS servere, koristeći moguće nazive poddomena.

Za ovu radnju biće vam potrebne neke **wordliste uobičajenih poddomena, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe će vam biti potrebne IP adrese kvalitetnih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

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
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko alata `massdns`, napisan u go jeziku, koji vam omogućava da enumerišete važeće poddomene koristeći aktivni bruteforce, kao i da razrešavate poddomene uz rukovanje wildcard zapisima i jednostavnu podršku za ulaz i izlaz.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhronu brute force pretragu imena domena.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Drugi DNS Brute-Force krug

Nakon pronalaženja poddomena korišćenjem otvorenih izvora i brute-force metode, možete generisati varijacije pronađenih poddomena kako biste pokušali da pronađete još više njih. Za ovu svrhu korisno je nekoliko alata:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
- goaltdns **wordlist** sa permutacijama možete preuzeti [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako datoteka sa permutacijama nije navedena, gotator će koristiti sopstvenu.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno navedene komentarisane alate).
- altdns permutacije **wordlist** možete preuzeti [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će izvršiti brute force rezultata (ne podržava DNS wildcard).
- dmut permutations wordlist možete preuzeti [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nove potencijalne nazive poddomena** prema navedenim obrascima kako bi pokušao da otkrije još poddomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovu [**objavu**](https://cramppet.github.io/regulator/index.html), ali on će u osnovi uzeti **glavne delove** iz **otkrivenih poddomena** i kombinovati ih kako bi pronašao još poddomena.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force pronalaženje poddomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dati skup ulaznih podataka, kao što je prilagođena wordlista ili istorijski DNS/TLS zapisi, da precizno generiše još odgovarajućih imena domena i dodatno ih proširuje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Workflow za otkrivanje subdomena**

Pogledajte ovaj blog post koji sam napisao o tome kako da **automatizujete otkrivanje subdomena** sa domena koristeći **Trickest workflows**, tako da ne moram ručno da pokrećem veliki broj alata na svom računaru:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju subdomenima, možete pokušati da **pronađete druge subdomene sa web stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** potražiti domene na određenoj IP adresi ili izvršiti **brute-force naziva VHost domena na toj IP adresi**.

#### OSINT

Možete pronaći neke **VHosts na IP adresama koristeći** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili druge API-je**.

**Brute Force**

Ako sumnjate da je neki subdomen skriven na web serveru, možete pokušati da izvršite brute force:

Kada **IP adresa preusmerava na hostname** (name-based vhosts), direktno fuzzujte `Host` header i dozvolite alatu ffuf da izvrši **auto-calibrate**, kako bi istakao odgovore koji se razlikuju od podrazumevanog vhost-a:
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

Ponekad ćete pronaći stranice koje vraćaju _**Access-Control-Allow-Origin**_ header samo kada je validan domen/poddomen postavljen u _**Origin**_ header-u. U ovim scenarijima možete zloupotrebiti ovo ponašanje da **otkrijete** nove **poddomene**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force Buckets**

Dok tražite **subdomains**, obratite pažnju na to da li neki **pokazuje** na bilo koju vrstu **bucket-a**, i u tom slučaju [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar scope-a, pokušajte da [**brute force-ujete moguća imena bucket-a i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoring**

Možete **nadgledati** da li se kreiraju **novi subdomains** nekog domena tako što pratite **Certificate Transparency** Logs, što radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite moguće [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomain** pokazuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **subdomain sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja asset-a, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Napomena: ponekad je subdomain hostovan na IP adresi koju klijent ne kontroliše, pa nije u scope-u; budite oprezni._

## IP adrese

U početnim koracima ste možda **pronašli neke opsege IP adresa, domene i subdomains**.\
Vreme je da **prikupite sve IP adrese iz tih opsega**, kao i IP adrese za **domene/subdomains (DNS upiti).**

Korišćenjem servisa iz sledećih **besplatnih API-ja** možete pronaći i **prethodne IP adrese koje su koristili domeni i subdomains**. Te IP adrese i dalje mogu biti u vlasništvu klijenta (i mogu vam omogućiti da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti domene koji pokazuju na određenu IP adresu pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Skenirajte portove svih IP adresa koje ne pripadaju CDN-ovima** (jer tamo vrlo verovatno nećete pronaći ništa zanimljivo). U pronađenim pokrenutim servisima možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Lov na web servere

> Pronašli smo sve kompanije i njihove asset-e i znamo opsege IP adresa, domene i subdomains unutar scope-a. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili određeni **recon IP adresa i pronađenih domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo videti neke **brze trikove za pronalaženje web servera** unutar scope-a.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **skeniranje ranjivosti** i **port scanning** (takođe, **ako je dozvoljeno** scope-om).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću alata [**masscan** možete pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan praktičan alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Prosleđujete mu listu domena i on će pokušati da se poveže na port 80 (http) i 443 (https). Dodatno, možete navesti i druge portove koje treba pokušati:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Snimci ekrana**

Sada kada ste otkrili **sve web servere** prisutne u scope-u (među **IP** adresama kompanije i svim **domenima** i **subdomenima**), verovatno **ne znate odakle da počnete**. Zato hajde da to pojednostavimo i počnemo tako što ćemo napraviti snimke ekrana svih njih. Samim **gledanjem** **glavne stranice** možete pronaći **čudne** endpoint-e koji su **podložniji** tome da budu **ranjivi**.

Da biste sproveli predloženu ideju, možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) nad svim **snimcima ekrana** kako bi vam rekao **šta verovatno sadrži ranjivosti**, a šta ne.

## Javni Cloud resursi

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, trebalo bi da **počnete sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i wordlist-e **uobičajenih reči koje se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, pomoću tih reči treba da generišete **permutacije** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlist-ama možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da prilikom traženja Cloud resursa treba da **tražite više od samih bucket-a u AWS-u**.

### **Traženje ranjivosti**

Ako pronađete stvari kao što su **otvoreni bucket-i ili izložene cloud funkcije**, trebalo bi da im **pristupite** i pokušate da utvrdite šta vam nude i da li možete da ih zloupotrebite.

## Email adrese

Sa **domenima** i **subdomenima** unutar scope-a praktično imate sve što vam je **potrebno da počnete sa traženjem email adresa**. Ovo su **API-ji** i **alati** koji su se meni pokazali kao najbolji za pronalaženje email adresa kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-jima
- API od [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API od [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API od [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

Email adrese će vam kasnije biti korisne za **brute-force web login-a i auth servisa** (kao što je SSH). Takođe su potrebne za **phishing**. Pored toga, ovi API-ji će vam pružiti još **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domenima,** **subdomenima** i **email adresama** možete početi da tražite credentials koji su ranije leaked i koji pripadaju tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće leaked** credentials, to je veoma laka pobeda.

## Secrets Leaks

Credential leaks povezani su sa hack-ovima kompanija kod kojih su **osetljive informacije leaked i prodate**. Međutim, kompanije mogu biti pogođene i **drugim leak-ovima** čije informacije nisu u tim bazama podataka:

### Github Leaks

Credentials i API-ji mogu biti leaked u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu github kompaniju.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repo-e** jedne **organizacije** i njenih **developera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti za pokretanje alata **gitleaks** nad svim **tekstualnim** URL-ovima prosleđenim alatu, jer i **web stranice ponekad sadrže secrets**.

#### Github Dorks

Pogledajte i ovu **stranicu** za potencijalne **github dorks** koje možete pretražiti i u organizaciji koju napadate:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad će napadači ili samo zaposleni **objaviti sadržaj kompanije na paste sajtu**. On može, ali i ne mora sadržati **osetljive informacije**, ali je veoma zanimljivo pretražiti ga.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) za istovremenu pretragu više od 80 paste sajtova.

### Google Dorks

Stari, ali odlični Google dorks su uvek korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu tamo**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete izabrati svojih omiljenih 10 ili koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji pokušavaju da koriste celu bazu kroz standardni Google browser nikada neće završiti, jer će vas Google veoma brzo blokirati._

### **Traženje ranjivosti**

Ako pronađete **važeće leaked** credentials ili API tokene, to je veoma laka pobeda.

## Ranjivosti javnog koda

Ako otkrijete da kompanija ima **open-source kod**, možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**U zavisnosti od jezika**, možete koristiti različite **alate**:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Postoje i besplatni servisi koji omogućavaju **skeniranje javnih repozitorijuma**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje bug hunter-i pronalaze nalazi se unutar **web aplikacija**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**; ove informacije možete [**pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem sekciju [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će pronaći veoma osetljive ranjivosti, korisni su za implementaciju u **workflow-e kako bi se dobile početne informacije o web-u.**

## Rekapitulacija

> Čestitamo! Do ovog trenutka ste već obavili **svo osnovno enumerisanje**. Da, osnovno je, jer se može obaviti još mnogo enumeracije (više trikova ćemo videti kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar scope-a
2. Pronašli sve **resurse** koji pripadaju kompanijama (i obavili vuln scan ako je u scope-u)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **subdomene** domena (da li postoji subdomain takeover?)
5. Pronašli sve **IP adrese** (sa i **bez CDN-ova**) unutar scope-a.
6. Pronašli sve **web servere** i napravili njihov **snimak ekrana** (da li postoji nešto čudno što vredi detaljnije pogledati?)
7. Pronašli sve potencijalne javne cloud resurse koji pripadaju kompaniji.
8. **Email adrese**, **credential leaks** i **secret leaks** koji bi vam veoma lako mogli doneti **veliku pobedu**.
9. Obavili **Pentesting nad svim pronađenim web sajtovima**

## **Alati za potpunu automatsku recon fazu**

Postoji nekoliko alata koji će obaviti deo predloženih radnji nad datim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Prilično star i nije ažuriran

## **Reference**

- Svi besplatni kursevi autora [**@Jhaddix**](https://twitter.com/Jhaddix), kao što je [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
