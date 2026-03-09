# Metodologija External Recon

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje imovine

> Dakle, rekli su ti da je sve što pripada nekoj kompaniji u scope-u, i želiš da utvrdiš šta ta kompanija zapravo poseduje.

Cilj ove faze je da se dobiju sve **kompanije koje glavna kompanija poseduje** i zatim svi **assets** tih kompanija. Da bismo to postigli, uradićemo:

1. Pronaći akvizicije glavne kompanije — to će nam dati kompanije koje su u scope-u.
2. Pronaći ASN (ako postoji) svake kompanije — to će nam dati IP opsege koje svaka kompanija poseduje.
3. Koristiti reverse whois pretrage da tražimo druge entitete (nazive organizacija, domene...) povezane sa prvim unosom (ovo se može raditi rekurzivno).
4. Koristiti druge tehnike kao što su shodan `org`and `ssl`filters da tražimo druge assets (ssl trik se može raditi rekurzivno).

### **Akvizicije**

Pre svega, treba da znamo koje **druge kompanije glavna kompanija poseduje**.\
Jedna opcija je da posetiš [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražiš** **glavnu kompaniju**, i **klikneš** na "**acquisitions**". Tamo ćeš videti druge kompanije koje je glavna kompanija akvizirala.\
Druga opcija je da posetiš stranicu glavne kompanije na **Wikipedia** i potražiš sekciju o **acquisitions**.\
Za javne kompanije, proveri **SEC/EDGAR filings**, stranice za **investor relations**, ili lokalne registry kompanija (npr. **Companies House** u UK).\
Za globalne korporativne strukture i filijale, probaj **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, u ovom trenutku bi trebalo da znaš sve kompanije koje su u scope-u. Hajde da utvrdimo kako da pronađemo njihove assets.

### **ASNs**

An autonomous system number (**ASN**) je **jedinstveni broj** dodeljen jednom **autonomous system** (AS) od strane **Internet Assigned Numbers Authority (IANA)**.\
Jedan **AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku za pristupanje eksternim mrežama i koji su administrativno vođeni od strane jedne organizacije, ali mogu obuhvatiti više operatora.

Zanimljivo je proveriti da li kompanija ima dodeljen neki **ASN** kako bismo pronašli njene **IP opsege.** Bilo bi korisno izvršiti **vulnerability test** nad svim **hostovima** unutar **scope-a** i **tražiti domene** unutar tih IP-ova.\
Možeš **pretraživati** po imenu kompanije, po **IP** ili po **domain** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona kompanije, sledeći linkovi mogu biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). U svakom slučaju, verovatno će sva korisna informacija (IP opsezi i Whois)** već biti prikazana na prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration automatski agregira i sažima ASNs na kraju scan-a.
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
Možete naći IP opsege organizacije takođe koristeći [http://asnlookup.com/](http://asnlookup.com) (ima besplatan API).\
Možete naći IP i ASN domena koristeći [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

U ovom trenutku znamo **all the assets inside the scope**, tako da, ako vam je dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti neke [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) ili koristiti servise kao što su Shodan, Censys, ili ZoomEye da pronađete open ports, i u zavisnosti od onoga što pronađete trebali biste pogledati u ovoj knjizi kako da pentest nekoliko servisa koji rade.\
**Takođe, vredi pomenuti da možete pripremiti neke** default username **and** passwords **lists i pokušati da** bruteforce services sa [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar opsega i njihove resurse, vreme je da pronađemo domene unutar opsega.

_Poznajte da u sledećim predloženim tehnikama takođe možete pronaći subdomene i da ta informacija ne treba biti potcenjena._

Pre svega trebalo bi da tražite **main domain**(s) svake kompanije. Na primer, za _Tesla Inc._ biće _tesla.com_.

### **Reverse DNS**

Kada pronađete sve IP opsege domena, možete pokušati da izvršite **reverse dns lookups** na tim **IPs da biste pronašli više domena unutar opsega**. Pokušajte da koristite neki dns server žrtve ili neki dobro poznat dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
You can also use a online tool for this info: [http://ptrarchive.com/](http://ptrarchive.com).\
For large ranges, tools like [**massdns**](https://github.com/blechschmidt/massdns) and [**dnsx**](https://github.com/projectdiscovery/dnsx) are useful to automate reverse lookups and enrichment.

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
You can use online tools like:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Besplatno** web, API nije besplatan.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Nije besplatno (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nije besplatno (API)

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
For example, if you see the same **Google Analytics ID** or the same **Adsense ID** on several pages.

There are some pages and tools that let you search by these trackers and more:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Did you know that we can find related domains and subdomains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrijte domene sa istim favicon icon hash-om](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti favicon icon hash kao naš cilj.

Pored toga, možete pretraživati tehnologije koristeći favicon hash, kao što je objašnjeno u [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da, ako znate **hash favicon-a ranjive verzije web tehnologije**, možete ga pretražiti u shodan i **pronaći više ranjivih mesta**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ovako možete da **izračunate favicon hash** veb-sajta:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
Takođe možete dobiti favicon hashes masovno pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) i zatim pivot u Shodan/Censys.

### **Copyright / Jedinstveni string**

Pretražite unutar web stranica **stringove koji bi mogli biti deljeni između različitih sajtova iste organizacije**. **string o autorskim pravima** može biti dobar primer. Zatim pretražite taj string u **google**, u drugim **pretraživačima** ili čak u **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da se obnove svi domain certificates na serveru. To znači da čak i ako CA koja je korišćena za to ne postavi vreme kada je sertifikat generisan u Validity polju, moguće je **pronaći domene koji pripadaju istoj kompaniji u certificate transparency logs**.\
Pogledajte ovaj [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Takođe koristite **certificate transparency** logs direktno:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Možete koristiti veb poput [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i poddomene koje dele iste dmarc informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Izgleda da je često praksa da ljudi dodeljuju poddomene na IP adrese koje pripadaju cloud provajderima i u jednom trenutku **izgube tu IP adresu ali zaborave da uklone DNS zapis**. Dakle, samo **spawning a VM** u cloud-u (kao Digital Ocean) zapravo može dovesti do **preuzimanja nekih poddomena**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) priča jednu takvu priču i predlaže skriptu koja **spawns a VM in DigitalOcean**, **dobija** **IPv4** nove mašine, i **pretražuje u Virustotal za zapise poddomena** koji na nju pokazuju.

### **Ostali načini**

**Napomena da možete koristiti ovu tehniku da otkrijete više domena svaki put kad nađete novi domen.**

**Shodan**

Pošto već znate ime organizacije koja poseduje IP prostor, možete pretraživati po tom podatku u shodan koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove za nove neočekivane domene u TLS certificate.

Možete pristupiti **TLS certificate** glavne web stranice, dobiti **Organisation name** i potom tražiti to ime unutar **TLS certificates** svih web stranica koje je poznat **shodan** koristeći filter: `ssl:"Tesla Motors"` ili koristiti alat kao [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) je alat koji traži **domains related** sa glavnim domenom i njihove **subdomains**, prilično odličan.

**Passive DNS / Historical DNS**

Passive DNS podaci su sjajni za pronalaženje **starih i zaboravljenih zapisa** koji i dalje rezolvuju ili koje je moguće preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Proverite za neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen** ali su **izgubili vlasništvo**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako nađete bilo koji **domain with an IP different** od onih koje ste već pronašli u asset discovery, trebalo bi da izvršite **basic vulnerability scan** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) sa **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, u **this book** možete naći neke trikove da ih "attack"-ujete.\
_Napomena: ponekad je domen hostovan unutar IP-a koji nije pod kontrolom klijenta, tako da nije u scope-u, budite pažljivi._

## Subdomains

> Znamo sve kompanije unutar scope-a, sve asset-e svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće subdomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki od alata i tehnika za pronalaženje domena takođe mogu pomoći pri pronalaženju subdomena

### **DNS**

Pokušajmo da dobijemo **subdomains** iz **DNS** zapisa. Takođe treba pokušati i **Zone Transfer** (ako je ranjiv, treba to prijaviti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način da se dobije veliki broj poddomena je pretraživanje eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
Postoje još **zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje subdomena, mogu biti korisni za pronalaženje subdomena, kao što su:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za dobijanje subdomena
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC besplatan API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** pribavlja poznate URL-ove iz AlienVault's Open Threat Exchange, Wayback Machine i Common Crawl za bilo koji domen.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Oni pretražuju web u potrazi za JS fajlovima i odatle izvlače poddomene.
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
- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu subdomains i IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

This project offers for **free all the subdomains related to bug-bounty programs**. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

You can find a **comparison** of many of these tools here: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **subdomains** brute-forcing DNS servers koristeći moguće subdomain names.

For this action you will need some **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

I takođe IPs dobrih DNS resolvers. Da biste generisali listu trusted DNS resolvers možete preuzeti resolvers sa [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je izvodio efikasan DNS brute-force. Veoma je brz, međutim sklon false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko `massdns`, napisan u go, koji vam omogućava da izlistate validne subdomene koristeći aktivni bruteforce, kao i da rešavate subdomene sa wildcard handling i jednostavnom input-output podrškom.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za brute force imena domena asinhrono.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Drugi krug DNS brute-force

Nakon što pronađete subdomene koristeći javne izvore i brute-forcing, možete generisati izmene pronađenih subdomena kako biste pokušali pronaći još. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i subdomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Za date domene i poddomene generiše permutacije.
- Možete dobiti goaltdns permutations **wordlist** u [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i subdomena generiše permutacije. Ako nije naznačen fajl sa permutacijama, gotator će koristiti svoj.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Pored generating subdomains permutations, može ih i pokušati resolve-ovati (ali je bolje koristiti prethodno pomenute alate).
- altdns permutations **wordlist** možete preuzeti na [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će brute force-ovati rezultat (ne podržava dns wild card).
- Možete preuzeti dmut permutations wordlist [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena generiše **nova potencijalna imena subdomains** na osnovu navedenih obrazaca kako bi pokušao otkriti više subdomains.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovaj [**post**](https://cramppet.github.io/regulator/index.html) ali on će u suštini izvući **glavne delove** iz **discovered subdomains** i kombinovati ih da pronađe više subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je subdomain brute-force fuzzer uparen sa izuzetno jednostavnim, ali efikasnim DNS reponse-guided algorithm. Koristi provided set of input data, poput tailored wordlist-a ili historical DNS/TLS records, da precizno sintetizuje više odgovarajućih domain names i dalje ih proširuje u loop na osnovu informacija prikupljenih tokom DNS scan-a.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Pogledaj ovu objavu na blogu koju sam napisao o tome kako da **automate the subdomain discovery** iz domena koristeći **Trickest workflows** tako da ne moram ručno da pokrećem gomilu alata na svom računaru:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ako pronađete IP adresu koja sadrži **one or several web pages** belonging to subdomains, možete pokušati da **find other subdomains with webs in that IP** tako što ćete tražiti u **OSINT sources** domene na toj IP ili **brute-forcing VHost domain names in that IP**.

#### OSINT

Možete pronaći neke **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**.

**Brute Force**

Ako sumnjate da je neki subdomain sakriven na web serveru, možete pokušati da ga brute force-ate:

Kada **IP redirects to a hostname** (name-based vhosts), fuzz-ujte `Host` header direktno i pustite ffuf da **auto-calibrate** kako bi istakao odgovore koji se razlikuju od default vhost-a:
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
> Korišćenjem ove tehnike možda ćete čak moći da pristupite internim/skrivenim endpoint-ima.

### **CORS Brute Force**

Ponekad ćete naići na stranice koje vraćaju header _**Access-Control-Allow-Origin**_ samo kada je u _**Origin**_ header postavljen važeći domain/subdomain. U takvim slučajevima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Dok tražite **subdomains**, obratite pažnju da li se oni **pointing** na bilo koju vrstu **bucket**, i u tom slučaju [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene u opsegu, pokušajte da [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Možete pratiti da li se kreiraju **nove subdomains** nekog domena prateći **Certificate Transparency** Logs, kao što radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Proverite moguće [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako se **subdomain** usmerava na neki **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **subdomain with an IP different** od onih koje ste već našli tokom assets discovery, trebalo bi da izvršite **basic vulnerability scan** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, u **ovoj knjizi možete pronaći neke trikove kako ih 'napasti'**.\
_Napomena da ponekad subdomain hostuje IP koji nije pod kontrolom klijenta, tako da nije u opsegu — budite oprezni._

## IPs

U početnim koracima možda ste pronašli neke IP opsege, domene i **subdomains**.\
Vreme je da prikupite sve IP adrese iz tih opsega i za domene/**subdomains** (DNS upiti).

Korišćenjem servisa iz sledećih **free apis** takođe možete pronaći **previous IPs used by domains and subdomains**. Ove IP adrese možda i dalje pripadaju klijentu (i mogu vam omogućiti da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti domene koji pokazuju na određenu IP adresu koristeći alat [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

Skenirajte portove svih IP adresa koje ne pripadaju CDN-ovima (jer tamo verovatno nećete naći ništa zanimljivo). U otkrivenim pokrenutim servisima možda ćete moći da pronađete ranjivosti.

Pronađite [**guide**](../pentesting-network/index.html) o tome kako skenirati hostove.

## Web servers hunting

> Pronašli smo sve kompanije i njihove resurse i znamo IP opsege, domene i subdomains unutar opsega. Vreme je da tražimo web servere.

U prethodnim koracima verovatno ste već izvršili deo **recon of the IPs and domains discovered**, tako da možda već imate **already found all the possible web servers**. Međutim, ako to nije slučaj, sada ćemo pogledati nekoliko **fast tricks to search for web servers** unutar opsega.

Imajte na umu da je ovo usmereno na pronalaženje web aplikacija, pa biste takođe trebali izvršiti skeniranje ranjivosti i skeniranje portova (ako to scope dozvoljava).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Još jedan koristan alat za pronalaženje web servera su [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Dovoljno je da pošaljete listu domena i oni će pokušati da se povežu na port 80 (http) i 443 (https). Dodatno, možete odrediti da probaju i druge portove:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve web servere** koji su u obimu (među **IP-ovima** kompanije i svim **domenima** i **subdomenima**) verovatno **ne znate gde da počnete**. Zato, hajde da pojednostavimo i počnemo tako što ćemo napraviti snimke ekrana svih njih. Samo pregledom **početne stranice** možete pronaći **čudne** endpoint-e koji su **podložniji** da budu **ranjivi**.

Za realizaciju ove ideje možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete potom koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da prođete kroz sve **screenshots** i da vam kaže **šta verovatno sadrži ranjivosti**, a šta ne.

## Public Cloud Assets

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji trebate **početi sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Takođe će vam trebati wordlist-e od **uobičajenih reči korišćenih u buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, sa tim rečima treba da generišete **permutacije** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlist-ama možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Zapamtite da pri traženju Cloud Assets treba **tražiti više od samih buckets u AWS**.

### **Looking for vulnerabilities**

Ako nađete stvari kao što su **open buckets or cloud functions exposed** treba ih **pristupiti** i pokušati da vidite šta vam nude i da li ih možete zloupotrebiti.

## Emails

Sa **domenima** i **subdomenima** unutar obima, imate praktično sve što vam treba da **počnete tražiti email-ove**. Ovo su **API-ji** i **alati** koji su mi najbolje radili za pronalaženje email-ova kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Email-ovi će vam kasnije koristiti za **brute-force web logina i auth servisa** (kao što je SSH). Takođe, potrebni su za **phishing** kampanje. Pored toga, ovi API-ji će vam dati i dodatne **informacije o osobi** iza email-a, što je korisno za phishing.

## Credential Leaks

Sa **domenima,** **subdomenima**, i **email-ovima** možete početi da tražite kredencijale koji su u prošlosti bili leaked i koji pripadaju tim email-ovima:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ako pronađete **valid leaked** credentials, to je veoma lak i brz pogodak.

## Secrets Leaks

Credential leaks se odnose na hakovanja kompanija gde je **sensitive information was leaked and sold**. Međutim, kompanije mogu biti pogođene i drugim leak-ovima čije informacije nisu u tim bazama:

### Github Leaks

Credentials i API tokeni mogu biti leaked u **public repositories** kompanije ili korisnika koji rade za tu github kompaniju.\
Možete koristiti **tool** [**Leakos**](https://github.com/carlospolop/Leakos) da **download**-ujete sve **public repos** jedne **organization** i njenih **developers** i automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti da pokrene **gitleaks** protiv svih **text** pruženih **URLs passed** jer ponekad i **web pages also contains secrets**.

#### Github Dorks

Pogledajte i ovu **page** za potencijalne **github dorks** koje biste mogli pretražiti u organizaciji koju target-ujete:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad napadači ili zaposleni objave **company content na paste site**. To možda sadrži ili ne sadrži **sensitive information**, ali je veoma interesantno za pretraživanje.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da pretražite više od 80 paste sajtova istovremeno.

### Google Dorks

Stari ali korisni google dorks su uvek korisni za pronalaženje **exposed information that shouldn't be there**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **thousands** mogućih upita koje ne možete ručno da pokrenete. Dakle, možete izabrati svojih omiljenih 10 ili možete koristiti **tool kao** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih pokrenete sve**.

_Napomena: alati koji pokušavaju da pokrenu celu bazu koristeći regularni Google browser će vrlo brzo biti blokirani od strane google-a._

### **Looking for vulnerabilities**

Ako pronađete **valid leaked** credentials ili API tokene, to je veoma lak i brz pogodak.

## Public Code Vulnerabilities

Ako utvrdite da kompanija ima **open-source code** možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**U zavisnosti od jezika** postoje različiti **alati** koje možete koristiti:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Postoje i besplatne usluge koje vam omogućavaju da **scan public repositories**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Većina ranjivosti koje pronalaze bug hunter-i se nalazi unutar **web applications**, pa bih sada želeo da govorim o **web application testing methodology**, a možete [**pronaći ove informacije ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim da posebno pomenem sekciju [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će vam naći vrlo osetljive ranjivosti, korisni su za implementaciju u **workflows radi početnih web informacija.**

## Recapitulation

> Čestitke! U ovom trenutku ste već izvršili **svu osnovnu enumeraciju**. Da, osnovna je jer se može uraditi još mnogo više (videćemo više trikova kasnije).

Dakle, već ste:

1. Pronašli sve **companies** unutar obima
2. Pronašli sve **assets** koji pripadaju kompanijama (i izvršili neki vuln scan ako su u scope)
3. Pronašli sve **domains** koji pripadaju kompanijama
4. Pronašli sve **subdomains** domena (bilo koja subdomain takeover?)
5. Pronašli sve **IPs** (iz i **ne iz CDNs**) unutar obima.
6. Pronašli sve **web servers** i napravili **screenshot** njih (ima li nešto čudno što vredi dublje pogledati?)
7. Pronašli sve **potencijalne public cloud assets** koji pripadaju kompaniji.
8. **Emails**, **credentials leaks**, i **secret leaks** koji vam mogu dati **velik pogodak veoma lako**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Postoji nekoliko alata koji će izvršiti deo predloženih akcija protiv zadatog obima.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
