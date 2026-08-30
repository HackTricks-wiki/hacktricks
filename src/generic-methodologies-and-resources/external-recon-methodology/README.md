# Metodologija eksternog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje asseta

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji unutar scope-a i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađemo sve **kompanije u vlasništvu glavne kompanije**, a zatim i sve **asset-e** tih kompanija. Da bismo to uradili, potrebno je:<sup>[[1]](#references)</sup>

1. Pronaći akvizicije glavne kompanije; to će nam pokazati kompanije unutar scope-a.
2. Pronaći ASN, ako postoji, za svaku kompaniju; to će nam dati IP opsege u vlasništvu svake kompanije.
3. Koristiti reverse whois pretrage za pronalaženje drugih zapisa (nazivi organizacija, domeni...) povezanih sa prvim zapisom (ovo se može raditi rekurzivno).
4. Koristiti druge tehnike, kao što su Shodan `org`i `ssl`filteri, za pretragu drugih asseta (`ssl` trik se može koristiti rekurzivno).

### **Akvizicije**

Pre svega, potrebno je da saznamo koje su **druge kompanije u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju** i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija kupila.\
Druga opcija je da posetite stranicu glavne kompanije na **Wikipedia** i potražite **acquisitions**.\
Za javne kompanije proverite **SEC/EDGAR filings**, stranice za **investor relations** ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalna korporativna stabla i podružnice pokušajte sa **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazom **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku bi trebalo da znate sve kompanije unutar scope-a. Hajde da utvrdimo kako da pronađemo njihove assete.

### **ASNs**

Broj autonomnog sistema (**ASN**) je **jedinstveni broj** koji **autonomnom sistemu** (AS) dodeljuje **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** sa jasno definisanom politikom pristupa eksternim mrežama, kojima upravlja jedna organizacija, ali ih može činiti više operatora.

Zanimljivo je utvrditi da li je **kompaniji dodeljen neki ASN**, kako bismo pronašli njene **IP opsege.** Bilo bi korisno izvršiti **test ranjivosti** nad svim **hostovima** unutar **scope-a** i **potražiti domene** unutar tih IP adresa.\
Možete **pretraživati** po nazivu **kompanije**, po **IP adresi** ili po **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kojem se kompanija nalazi, ovi linkovi mogu biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se sve** korisne informacije **(IP opsezi i Whois)** već nalaze na prvom linku.**
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
IP adresu i ASN domena možete pronaći pomoću [http://ipv4info.com/](http://ipv4info.com).

### **Traženje ranjivosti**

U ovom trenutku znamo **sve assete unutar scope-a**, pa, ako vam je dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da pronađete** otvorene portove **i, u zavisnosti od onoga što pronađete, trebalo bi** da pogledate u ovoj knjizi kako se obavlja pentest nekoliko mogućih servisa koji rade.\
**Takođe, vredi pomenuti da možete pripremiti i neke** liste podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar scope-a i njihove assete; vreme je da pronađemo domene unutar scope-a.

_Imajte na umu da pomoću sledećih predloženih tehnika možete pronaći i subdomene i da te informacije ne treba potcenjivati._

Pre svega, trebalo bi da pronađete **glavni domen**(e) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse dns lookups** nad tim **IP adresama kako biste pronašli još domena unutar scope-a**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i online alat: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege korisni su alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), koji automatizuju reverse lookups i obogaćivanje podataka.

### **Reverse Whois (loop)**

Unutar **whois** podataka možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **email adrese**, brojevi telefona... Međutim, još je zanimljivije to što možete pronaći **dodatne assete povezane sa kompanijom** ako izvršite **reverse whois lookups** na osnovu nekog od tih polja (na primer, druge whois registre u kojima se pojavljuje ista email adresa).\
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
Možete izvršiti i automatsko otkrivanje putem reverse whois-a pomoću alata [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje dodatnih naziva domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako pronađete **isti ID istog tracker-a** na 2 različite stranice, možete pretpostaviti da **obe stranice** kontroliše **isti tim**.\
Na primer, ako vidite isti **Google Analytics ID** ili isti **Adsense ID** na nekoliko stranica.

Postoje stranice i alati koji omogućavaju pretragu na osnovu ovih tracker-a i drugih podataka:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove na osnovu zajedničkih analytics/tracker podataka)
- [**StackScan**](https://www.stackscan.com) - **Besplatni paket** (Web i API). Pivotiranje je moguće na osnovu bilo kog posluživanog asseta, ne samo ID-jeva tracker-a: putanje skripte, naziva self-hosted bundle-a ili hosta sa kog se asset učitava; alat vraća svaki sajt koji ga sadrži

API vraća stack za jedan domen, što je korisno za potvrdu da određeni asset pripada istom okruženju:
```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
"https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```
Vraća svaku otkrivenu tehnologiju zajedno sa njenom kategorijom. Asset pivoting je trenutno ograničen samo na web, dok API pokriva pretragu po domenu.

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja tako što ćemo potražiti isti hash favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako se koristi:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![Favihash rezultati korišćeni za otkrivanje domena koji dele isti favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash će nam omogućiti da otkrijemo domene koji imaju isti favicon hash kao naš cilj.

![favihash izlaz korišćen za otkrivanje domena sa istim favicon hashom](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati favicon hash kao Shodan ili FOFA pivot da biste pronašli druge izložene instance iste tehnologije.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ovako možete **izračunati hash favicon-a** web-stranice (MMH3 nad **base64-kodiranim** bajtovima favicon-a):
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
Favicon hash-ove možete dobiti i u velikom obimu pomoću alata [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim izvršiti pivot u Shodan/Censys.

Favicon fingerprint-e tretirajte kao tragove i potvrdite ih okolnim signalima.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash tretirajte kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su sudari, ponovo korišćene ikone i namerno spoofovanje.
- **Proverite više od** `/favicon.ico`: pregledajte putanje framework-a/build-a, manifest datoteke, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL-ove i HTML `<link rel="icon">` tagove.
- **Static assets mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno zahtevajte ikonu i pregledajte `ETag`, `Last-Modified`, redirects i cache headere.
- **Potvrdite podudaranja okolnim signalima**: uporedite title, HTML/body hash, headere, subjekte/SAN-ove TLS sertifikata, komponente proizvoda i exposed portove.
- **Grupišite prema HTML/body hash-u**: dosledan template ojačava fingerprint; različiti template-i ukazuju na generičku ili deljenu ikonu.
- **Hash koji se pojavljuje kroz nepovezane signatures, portove i proizvode tretirajte kao potencijalni honeypot ili placeholder.**
- **Kod dvosmislenih targeta uporedite stvarnu stranicu sa nepostojećom putanjom**, kao što je `/_favicon_probe_<8-hex>`; podudarajući hosting ili parking odgovori mogu objasniti deljenu ikonu.
- **Započnite trijažu pomoću Nuclei detection rules ili javnih dataset-ova** koji povezuju favicon hash-ove sa proizvodima i CPE-ovima.
- **Imajte na umu gap u IP-centric coverage-u**: površine iza CDN-a, SNI-routed, anycast i domain-only površine mogu nedostajati u dataset-ovima sličnim Shodan-u.

### **Copyright / Jedinstveni string**

Pretražite unutar web stranica **stringove koji bi mogli biti deljeni između različitih web sajtova u istoj organizaciji**. **Copyright string** može biti dobar primer. Zatim potražite taj string u **google-u**, u drugim **browserima** ili čak u **shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da obnovite sve certificates na serveru u isto vreme. Korelacija timestamps certificates ili pozicija u certificate-transparency logovima može otkriti povezane domene.<sup>[[6]](#references)</sup>

Takođe direktno koristite **certificate transparency** logove:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC informacije

Možete koristiti web stranicu kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i subdomene koji dele iste DMARC informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Naputšteni A record može postati dostupan kada cloud provider ponovo dodeli IP. Navedeno istraživanje prikazuje oportunistički workflow koji kreira instancu i koreliše njenu adresu sa passive DNS podacima; scenarije takeover-a testirajte samo unutar autorizovanog scope-a.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće discovery pivote kad god pronađete novi domen: svaki rezultat može otkriti dodatna imena certificates, passive-DNS odnose, favicon podudaranja i identifikatore organizacije koji nisu bili vidljivi iz originalnog seed-a.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Pošto već znate ime organizacije koja poseduje IP prostor, te podatke možete pretražiti u shodan-u koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove da biste pronašli nove, neočekivane domene u TLS certificate-u.

Možete pristupiti **TLS certificate-u** glavne web stranice, dobiti **Organisation name**, a zatim pretražiti to ime unutar **TLS certificates** svih web stranica poznatih **shodan-u** pomoću filtera: `ssl:"Tesla Motors"` ili koristiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji pronalazi **domene povezane** sa glavnim domenom i njihove **subdomene**, prilično je neverovatan.

**Passive DNS / Historical DNS**

Passive DNS podaci su odlični za pronalaženje **starih i zaboravljenih record-a** koji se i dalje razrešavaju ili mogu biti preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Traženje vulnerabilities**

Proverite da li postoji neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen**, ali je **izgubila vlasništvo** nad njim. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom različitom** od onih koje ste već pronašli tokom assets discovery-ja, trebalo bi da izvršite **basic vulnerability scan** (korišćenjem Nessus-a ili OpenVAS-a) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji services rade, u **ovoj knjizi možete pronaći trikove za njihovo „napadanje“**.\
_Napomena: ponekad je domen hostovan unutar IP adrese koja nije pod kontrolom klijenta, pa nije u scope-u; budite oprezni._

## Subdomains

> Znamo sve kompanije unutar scope-a, sve assets svake kompanije i sve domene povezane sa kompanijama.

Vreme je da pronađemo sve moguće subdomains za svaki pronađeni domen.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu pomoći i u pronalaženju subdomains-a

### **DNS**

Pokušajmo da dobijemo **subdomains** iz **DNS** record-a. Takođe bi trebalo da pokušamo **Zone Transfer** (Ako je ranjiv, trebalo bi da ga prijavite).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način da dođete do velikog broja poddomena jeste pretraga eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
- [**RapidDNS**](https://rapiddns.io) besplatni API
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
- [**gau**](https://github.com/lc/gau)**:** dohvata poznate URL-ove iz AlienVault-ovog Open Threat Exchange-a, Wayback Machine-a i Common Crawl-a za dati domen.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Skeniraju web u potrazi za JS datotekama i iz njih izdvajaju subdomene.
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
- [**Censys pronalazač poddomena**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu subdomain-a i istorije IP adresa
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ovaj projekat nudi **besplatno sve subdomain-e povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy) ili čak pristupiti scope-u koji koristi ovaj projekat: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Poređenje** mnogih od ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **subdomain-e** izvođenjem brute-force napada na DNS servere pomoću mogućih naziva subdomain-a.

Za ovu radnju biće vam potrebne neke **uobičajene wordlist-e subdomain-a, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe su vam potrebne IP adrese pouzdanih DNS resolver-a. Da biste generisali listu pouzdanih DNS resolver-a, možete preuzeti resolver-e sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) za njihovo filtriranje. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno izvršavao DNS brute-force. Veoma je brz, ali je sklon pojavi false positive rezultata.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko alata `massdns`, napisan u jeziku Go, koji omogućava enumeraciju važećih poddomena korišćenjem aktivnog bruteforce-a, kao i razrešavanje poddomena uz obradu wildcard-a i jednostavnu podršku za ulaz i izlaz.
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

Nakon pronalaženja poddomena pomoću otvorenih izvora i brute-forcinga, možete generisati izmene pronađenih poddomena kako biste pokušali da pronađete još više njih. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Na osnovu domena i poddomena generiše permutacije.
- goaltdns permutacije **wordlist** možete preuzeti [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka sa permutacijama, gotator će koristiti sopstvenu.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno pomenute alate).
- altdns permutacije možete dobiti u [**wordlist**](https://github.com/infosec-au/altdns/blob/master/words.txt) datoteci **ovde**.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutations, mutations i alteration poddomena. Ovaj alat će brute force-ovati rezultat (ne podržava DNS wildcard).
- Wordlist za dmut permutations možete preuzeti [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena subdomena** na osnovu navedenih obrazaca, kako bi pokušao da otkrije više subdomena.

#### Generisanje pametnih permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči obrasce nalik regex-u iz otkrivenih subdomena i generiše kandidate za imena koja treba razrešiti.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force pronalaženje poddomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što su prilagođena wordlist-a ili istorijski DNS/TLS zapisi, da precizno generiše dodatna odgovarajuća imena domena i dalje ih proširuje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Primeri Trickest workflow-a kombinuju OSINT, DNS brute force i faze permutacija za ponovljivu enumeraciju subdomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili nekoliko web stranica** koje pripadaju subdomenima, možete pokušati da **pronađete druge subdomene sa web stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** potražiti domene na određenoj IP adresi ili izvršiti **brute-forcing VHost imena domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki subdomen skriven na web serveru, možete pokušati da ga pronađete brute force metodom:

Za VHost-ove zasnovane na imenima, fuzz-ujte `Host` header i koristite ffuf auto-kalibraciju za filtriranje podrazumevanog odgovora.<sup>[[2]](#references)</sup>
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
> Pomoću ove tehnike možda ćete čak moći da pristupite internim/skrivenim endpointima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je u zaglavlju _**Origin**_ postavljen validan domen/poddomen. U ovim scenarijima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **poddomene**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Tokom traženja **subdomain-a**, obratite pažnju na to da li neki **pointing** vodi ka bilo kojoj vrsti **bucket-a** i u tom slučaju [**proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar scope-a, pokušajte da [**brute force-ujete moguće nazive bucket-a i proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoring**

Možete **monitor-ovati** da li se kreiraju **novi subdomain-i** nekog domena praćenjem **Certificate Transparency** Logs, što radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite moguće [**subdomain takeover-e**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomain** pokazuje na neki **S3 bucket**, [**proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **subdomain sa IP adresom različitom** od onih koje ste već pronašli tokom asset discovery-ja, trebalo bi da izvršite **basic vulnerability scan** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji su services pokrenuti, u **ovoj knjizi možete pronaći neke trikove za njihov „attack“**.\
_Napomena: ponekad se subdomain hostuje na IP adresi koju client ne kontroliše, pa nije u scope-u; budite oprezni._

## IP adrese

U početnim koracima ste možda **pronašli neke IP ranges, domene i subdomain-e**.\
Vreme je da **prikupite sve IP adrese iz tih ranges** i za **domene/subdomain-e (DNS queries).**

Korišćenjem services iz sledećih **free APIs** takođe možete pronaći **prethodno korišćene IP adrese domena i subdomain-a**. Ove IP adrese možda još uvek pripadaju client-u (i mogu vam omogućiti da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti koji domeni pokazuju na određenu IP adresu pomoću tool-a [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Izvršite port scan svih IP adresa koje ne pripadaju CDN-ovima** (jer tamo najverovatnije nećete pronaći ništa zanimljivo). U otkrivenim services koji su pokrenuti možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**guide**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Potraga za web serverima

> Pronašli smo sve kompanije i njihove asset-e i znamo IP ranges, domene i subdomain-e unutar scope-a. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili određeni **recon IP adresa i pronađenih domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo videti neke **brze trikove za traženje web servera** unutar scope-a.

Imajte na umu da će ovo biti **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **vulnerability** i **port scanning** (**ako je dozvoljeno** scope-om).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću [**masscan** možete pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan praktičan tool za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Prosleđujete mu listu domena i on će pokušati da se poveže na port 80 (http) i 443 (https). Dodatno, možete navesti da pokuša i sa drugim portovima:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Snimci ekrana**

Sada kada ste otkrili **sve web servere** prisutne u scope-u (među **IP** adresama kompanije i svim **domenima** i **subdomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo pojednostaviti stvari i početi tako što ćemo napraviti snimke ekrana svih njih. Samim **pregledom** **glavne stranice** možete pronaći **čudne** endpoint-e koji su skloniji da budu **vulnerable**.

Za sprovođenje predložene ideje možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Takođe, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) nad svim **snimcima ekrana** kako bi vam rekao **šta verovatno sadrži vulnerabilities**, a šta ne.

## Javni Cloud Assets

Da biste pronašli potencijalne cloud assets koji pripadaju kompaniji, trebalo bi da **počnete sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i wordlists sa **uobičajenim rečima koje se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, pomoću tih reči treba da generišete **permutations** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlists možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da, kada tražite Cloud Assets, treba da **tražite više od samih bucket-a u AWS-u**.

### **Traženje vulnerabilities**

Ako pronađete stvari kao što su **open bucket-i ili izložene cloud funkcije**, trebalo bi da im **pristupite** i pokušate da vidite šta vam nude i da li možete da ih abuse-ujete.

## Email adrese

Sa **domenima** i **subdomenima** unutar scope-a praktično imate sve što vam je **potrebno da počnete da tražite email adrese**. Ovo su **API-ji** i **alati** koji su mi se najbolje pokazali za pronalaženje email adresa kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-jima
- API od [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API od [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API od [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje vulnerabilities**

Email adrese će vam kasnije biti korisne za **brute-force web login-a i auth servisa** (kao što je SSH). Takođe su potrebne za **phishing**. Osim toga, ovi API-ji će vam dati još više **informacija o osobi** koja stoji iza email adrese, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domenima,** **subdomenima** i **email adresama** možete početi da tražite credentials koji su ranije leaked i pripadaju tim email adresama:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje vulnerabilities**

Ako pronađete **valid leaked** credentials, to je veoma laka pobeda.

## Secrets Leaks

Credential leaks su povezani sa hack-ovima kompanija u kojima su **sensitive informacije leaked i prodate**. Međutim, kompanije mogu biti pogođene i **drugim leak-ovima** čije se informacije ne nalaze u tim bazama:

### Github Leaks

Credentials i API-ji mogu biti leaked u **public repositories** same **kompanije** ili **korisnika** koji rade u toj Github kompaniji.\
Možete koristiti **tool** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **public repos** neke **organizacije** i njenih **developera**, a zatim automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti za pokretanje **gitleaks** nad svim **tekstom** koji se nalazi na **URL-ovima prosleđenim** alatu, jer ponekad i **web stranice sadrže secrets**.

#### Github Dorks

Pogledajte stranicu [GitHub dorks and leaks page](github-leaked-secrets.md) za potencijalne **GitHub dorks** koje možete pretražiti u organizaciji.

### Pastes Leaks

Ponekad će napadači ili samo zaposleni **objaviti sadržaj kompanije na paste sajtu**. To može, ali i ne mora, sadržati **sensitive informacije**, ali je veoma interesantno pretražiti takav sadržaj.\
Možete koristiti tool [**Pastos**](https://github.com/carlospolop/Pastos) za pretragu više od 80 paste sajtova istovremeno.

### Google Dorks

Stari, ali kvalitetni Google dorks su uvek korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu tamo**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete izabrati svojih omiljenih 10 ili koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji pokušavaju da pokrenu celu bazu koristeći standardni Google browser nikada neće završiti, jer će vas Google veoma brzo blokirati._

### **Traženje vulnerabilities**

Ako pronađete **valid leaked** credentials ili API tokene, to je veoma laka pobeda.

## Vulnerabilities u javnom kodu

Ako otkrijete da kompanija poseduje **open-source kod**, možete ga **analizirati** i tražiti **vulnerabilities** u njemu.

**U zavisnosti od jezika**, postoje različiti **alati** koje možete koristiti; pogledajte listu [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji omogućavaju **skeniranje javnih repozitorijuma**, kao što su:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Većina vulnerabilities** koje bug hunters pronađu nalazi se unutar **web aplikacija**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**, a ove informacije možete [**pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem odeljak [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da pronađu veoma sensitive vulnerabilities, korisni su za uključivanje u **workflow-e radi dobijanja početnih informacija o web-u.**

## Rekapitulacija

> Čestitamo! U ovom trenutku ste već obavili **svu osnovnu enumeraciju**. Da, osnovna je zato što se može obaviti još mnogo enumeracije (više trikova ćemo videti kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar scope-a
2. Pronašli sve **asset-e** koji pripadaju kompanijama (i obavili vuln scan ako je u scope-u)
3. Pronašli sve **domaine** koji pripadaju kompanijama
4. Pronašli sve **subdomaine** tih domena (da li postoji subdomain takeover?)
5. Pronašli sve **IP adrese** (sa i **bez CDN-ova**) unutar scope-a.
6. Pronašli sve **web servere** i napravili njihove **snimke ekrana** (da li postoji nešto čudno što vredi detaljnije istražiti?)
7. Pronašli sve **potencijalne javne cloud assets** koji pripadaju kompaniji.
8. **Email adrese**, **credential leaks** i **secret leaks** koji vam mogu doneti **veliku pobedu veoma lako**.
9. Obavili **pentesting svih pronađenih web sajtova**

## **Alati za potpunu automatsku recon analizu**

Postoji nekoliko alata koji će izvršiti deo predloženih radnji nad datim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Pomalo star i nije ažuriran

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
