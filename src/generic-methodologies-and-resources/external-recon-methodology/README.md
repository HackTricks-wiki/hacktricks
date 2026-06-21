# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje imovine

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji u scope-u, i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da se dobiju sve **kompanije u vlasništvu glavne kompanije** a zatim i sva **imovina** tih kompanija. Da bismo to uradili, mi ćemo:

1. Pronaći akvizicije glavne kompanije, to će nam dati kompanije u scope-u.
2. Pronaći ASN (ako postoji) svake kompanije, to će nam dati IP opsege u vlasništvu svake kompanije
3. Koristiti reverse whois upite da potražimo druge unose (nazive organizacija, domene...) povezane sa prvim (ovo može da se radi rekurzivno)
4. Koristiti druge tehnike kao što su shodan `org` i `ssl` filteri za traženje druge imovine (`ssl` trik se može raditi rekurzivno).

### **Akvizicije**

Pre svega, treba da znamo koje su **druge kompanije u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju**, i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga opcija je da posetite Wikipedia stranicu glavne kompanije i potražite **acquisitions**.\
Za javne kompanije, proverite **SEC/EDGAR filings**, stranice za **investor relations**, ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalna korporativna stabla i podružnice, probajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i **GLEIF LEI** bazu podataka ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, u ovom trenutku trebalo bi da znate sve kompanije u scope-u. Hajde da vidimo kako da pronađemo njihovu imovinu.

### **ASN-ovi**

Autonomous system number (**ASN**) je **jedinstveni broj** koji dodeljuje **autonomous system** (AS) autoritet **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku za pristup spoljnim mrežama i kojima upravlja jedna organizacija, ali mogu biti sastavljeni od više operatera.

Zanimljivo je utvrditi da li je kompaniji dodeljen neki ASN kako bi se pronašli njeni **IP opsezi.** Biće korisno izvršiti **vulnerability test** nad svim **hostovima** unutar **scope-a** i **potražiti domene** unutar tih IP adresa.\
Možete **pretraživati** po nazivu kompanije, po **IP** ili po **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona kompanije, ovi linkovi mogu biti korisni za prikupljanje više podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se sve** korisne informacije **(IP opsezi i Whois)** već nalaze na prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration automatski agregira i sumira ASN-ove na kraju skeniranja.
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Traženje ranjivosti**

U ovom trenutku znamo **sve assete unutar scope-a**, tako da, ako je dozvoljeno, možete pokrenuti neki **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti neke [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da pronađete** otvorene portove **i u zavisnosti od onoga što pronađete trebalo bi da** pogledate u ovu knjigu kako biste pentestovali nekoliko mogućih servisa koji rade.\
**Takođe, vredi napomenuti da možete pripremiti i neke** default username **i** passwords **liste i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaini

> Znamo sve kompanije unutar scope-a i njihove assete, vreme je da pronađemo domene unutar scope-a.

_Imajte na umu da u sledećim tehnikama takođe možete pronaći subdomene i da tu informaciju ne treba potcenjivati._

Pre svega trebalo bi da potražite **glavni domain(e)** svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP range-ove domena, možete pokušati da izvršite **reverse dns lookups** nad tim **IP adresama kako biste pronašli više domena unutar scope-a**. Pokušajte da koristite neki dns server žrtve ili neki dobro poznat dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Za ovo da bi radilo, administrator mora ručno da omogući PTR.\
Takođe možete koristiti online alat za ove informacije: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege, alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) su korisni za automatizaciju reverse lookups i obogaćivanje podataka.

### **Reverse Whois (loop)**

Unutar **whois** zapisa možete pronaći mnogo zanimljivih **informacija** kao što su **naziv organizacije**, **adresa**, **emailovi**, brojevi telefona... Ali još zanimljivije je da možete pronaći **više asseta povezanih sa kompanijom** ako izvršite **reverse whois lookups po bilo kom od tih polja** (na primer drugi whois registri gde se pojavljuje isti email).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatno** web, API nije besplatan.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Nije besplatno (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nije besplatno (API)

Ovaj zadatak možete automatizovati koristeći [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API ključ).\
Takođe možete izvršiti određeno automatsko reverse whois otkrivanje pomoću [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Napomena da ovu tehniku možete koristiti da otkrijete više domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako pronađete isti ID istog trackera na 2 različite stranice, možete pretpostaviti da obe stranice **upravljaju isti tim**.\
Na primer, ako vidite isti **Google Analytics ID** ili isti **Adsense ID** na više stranica.

Postoje neke stranice i alati koji vam omogućavaju pretragu po ovim trackerima i još mnogo toga:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezana mesta preko deljenih analytics/trackers)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja gledajući isti hash ikone favicon? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash će nam omogućiti da otkrijemo domene koje imaju isti favicon icon hash kao naša meta.

Štaviše, možete takođe pretraživati tehnologije koristeći favicon hash kao što je objašnjeno u [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da, ako znate **hash favicon-a ranjive verzije web tehnologije** možete pretražiti da li je u shodan i **pronaći više ranjivih mesta**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ovako možete **izračunati favicon hash** web stranice:
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
Takođe možete da dobijete favicon hash-ove u velikom obimu pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) i zatim da pivotirate u Shodan/Censys.

### **Copyright / Uniq string**

Pretražite unutar web stranica **stringove koji bi mogli da budu zajednički različitim veb sajtovima u istoj organizaciji**. **copyright string** može biti dobar primer. Zatim pretražite taj string u **google**, u drugim **browserima** ili čak u **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je da postoji cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Passive DNS data is great to find **old and forgotten records** that still resolve or that can be taken over. Look at:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

> [!TIP]
> Note that some of the tools and techniques to find domains can also help to find subdomains

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način da se dođe do velikog broja subdomain-ova je pretraga u eksternim izvorima. Najčešće korišćeni **tools** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
Postoje **drugi zanimljivi alati/API-jevi** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za pronalaženje poddomena, kao što su:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za dobijanje subdomena
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove iz AlienVault Open Threat Exchange, Wayback Machine i Common Crawl za bilo koji dati domen.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Oni pretražuju web tražeći JS fajlove i iz njih izdvajaju subdomene.
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
- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu subdomain-a i IP istorije
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ovaj projekat besplatno nudi sve subdomain-e povezane sa bug-bounty programima. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy) ili čak pristupiti scope-u koji koristi ovaj projekat [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Možete pronaći **poređenje** mnogih od ovih alata ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hajde da pokušamo da pronađemo nove **subdomain-e** brute-forcing-om DNS servera koristeći moguće nazive subdomain-a.

Za ovu radnju biće vam potrebne neke **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe i IP adrese dobrih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je izveo efikasan DNS brute-force. Veoma je brz, međutim sklon je lažnim pozitivama.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko `massdns`, napisan u go, koji omogućava enumeraciju validnih subdomain-ova pomoću aktivnog bruteforce-a, kao i rešavanje subdomain-ova uz wildcard handling i jednostavnu input-output podršku.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhrono brute force-ovanje domena.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Drugi krug DNS brute-force-a

Nakon što ste pronašli poddomene koristeći otvorene izvore i brute-force, možete generisati varijacije pronađenih poddomena kako biste pokušali da pronađete još više. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Datih domena i poddomena generiše permutacije.
- Možete preuzeti goaltdns permutacije **wordlist** [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Datih domains i subdomains, generiše permutacije. Ako nije naveden fajl sa permutacijama, gotator će koristiti svoj.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija subdomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno komentarisane alate).
- Možete dobiti altdns permutacije **wordlist** u [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će izvršiti brute force nad rezultatom (ne podržava DNS wild card).
- Možete dobiti dmut permutacijski wordlist [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena poddomena** prema navedenim obrascima kako bi pokušao da otkrije više poddomena.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitaj ovaj [**post**](https://cramppet.github.io/regulator/index.html), ali će uglavnom uzeti **glavne delove** iz **otkrivenih poddomena** i pomešati ih kako bi pronašao više poddomena.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je subdomain brute-force fuzzer uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi zadati skup ulaznih podataka, kao što su prilagođena wordlist ili istorijski DNS/TLS zapisi, da precizno sintetiše još odgovarajućih domenских imena i dalje ih proširuje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Workflow za otkrivanje subdomena**

Pogledaj ovaj blog post koji sam napisao o tome kako da **automatizuješ otkrivanje subdomena** sa domena koristeći **Trickest workflows** tako da ne moram ručno da pokrećem gomilu alata na svom računaru:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ako pronađeš IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju subdomenima, možeš pokušati da **pronađeš druge subdomene sa webovima na toj IP adresi** tako što ćeš tražiti u **OSINT izvorima** domene na IP adresi ili **brute-forcing VHost naziva domena na toj IP adresi**.

#### OSINT

Možeš pronaći neke **VHosts u IP adresama koristeći** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili druge API-je**.

**Brute Force**

Ako sumnjaš da je neki subdomain skriven na web serveru, možeš pokušati da ga brute force-uješ:

Kada **IP preusmerava na hostname** (name-based vhosts), direktno fuzz-uj `Host` header i pusti ffuf da se **auto-kalibriše** kako bi istakao odgovore koji se razlikuju od default vhost-a:
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
> Sa ovom tehnikom možda čak možete da pristupite internim/sakrivenim endpoint-ovima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju header _**Access-Control-Allow-Origin**_ samo kada je važeći domen/subdomen postavljen u header-u _**Origin**_. U ovim scenarijima, možete zloupotrebiti ovo ponašanje da **otkrijete** nove **subdomene**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Dok tražite **subdomains**, obratite pažnju da li nešto **pokazuje** ka nekoj vrsti **bucket**, i u tom slučaju [**proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene u okviru scope, pokušajte da [**brute force-ujete moguća imena bucket-a i proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Možete da **monitor**-ujete da li se **novi subdomains** nekog domena kreiraju praćenjem **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) radi.

### **Looking for vulnerabilities**

Proverite moguće [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomain** pokazuje na neki **S3 bucket**, [**proverite permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete bilo koji **subdomain sa IP adresom različitom** od onih koje ste već pronašli tokom assets discovery, trebalo bi da uradite **basic vulnerability scan** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, možete u ovoj knjizi pronaći neke trikove da ih "attack"-ujete.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

U početnim koracima možda ste **pronašli neke IP ranges, domene i subdomains**.\
Vreme je da **prikupite sve IP adrese iz tih ranges** i za **domene/subdomains (DNS queries).**

Korišćenjem servisa iz sledećih **free apis** možete takođe pronaći **prethodne IP adrese koje su koristile domene i subdomains**. Ove IP adrese i dalje mogu biti u vlasništvu klijenta (i mogu vam omogućiti da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti koji domeni pokazuju na određenu IP adresu koristeći alat [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan-ujte sve IP adrese koje ne pripadaju CDN-ovima** (jer tamo vrlo verovatno nećete pronaći ništa interesantno). Na servisima koji su otkriveni tokom rada možete **pronaći vulnerabilities**.

**Pronađite** [**guide**](../pentesting-network/index.html) **o tome kako da skenirate hostove.**

## Web servers hunting

> Pronašli smo sve kompanije i njihove assets i znamo IP ranges, domene i subdomains unutar scope-a. Vreme je da tražimo web servere.

U prethodnim koracima ste verovatno već uradili neka **recon**-ovanja otkrivenih IP adresa i domena, pa ste možda već **pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo videti neke **brze trikove za traženje web servera** unutar scope-a.

Molimo, imajte u vidu da će ovo biti **orijentisano na otkrivanje web apps**, tako da bi trebalo da uradite i **vulnerability** i **port scanning** takođe (**ako je dozvoljeno** scope-om).

Brz metod za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću [**masscan** može se naći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan prijateljski alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Samo prosledite listu domena i on će pokušati da se poveže na port 80 (http) i 443 (https). Dodatno, možete navesti da pokuša i druge portove:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve web servere** prisutne u opsegu (među **IP adresama** kompanije i svim **domenima** i **poddomenima**) verovatno **ne znate odakle da krenete**. Zato, hajde da to pojednostavimo i počnemo tako što ćemo napraviti screenshotove svih njih. Samo tako što ćete **baciti pogled** na **glavnu stranicu** možete pronaći **čudne** endpointe koji su **skloniji** da budu **ranjivi**.

Da biste sproveli predloženu ideju možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Takođe, možete zatim koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da pregleda sve **screenshotove** i kaže vam **šta verovatno sadrži ranjivosti**, a šta ne.

## Public Cloud Assets

Da biste pronašli potencijalne cloud assets koji pripadaju kompaniji, trebalo bi da **počnete sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za kripto kompaniju mogli biste koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Takođe će vam trebati wordlist-e od **uobičajenih reči koje se koriste u buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, sa tim rečima trebalo bi da generišete **permutacije** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlist-ima možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Zapamtite da, kada tražite Cloud Assets, trebalo bi da t**ražite više od samih buckets u AWS**.

### **Looking for vulnerabilities**

Ako pronađete stvari kao što su **otvoreni buckets ili izložene cloud funkcije**, trebalo bi da im **pristupite** i pokušate da vidite šta vam nude i da li ih možete zloupotrebiti.

## Emails

Sa **domenima** i **poddomenima** unutar opsega, praktično imate sve što vam je **potrebno da počnete da tražite email adrese**. Ovo su **API-jevi** i **alati** koji su se za mene pokazali kao najbolji za pronalaženje email adresa neke kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API od [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API od [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API od [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Looking for vulnerabilities**

Email adrese će kasnije dobro doći za **brute-force web prijave i auth servise** (kao što je SSH). Takođe su potrebne za **phishings**. Pored toga, ovi API-jevi će vam dati još više **informacija o osobi** iza email adrese, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domenima,** **poddomenima** i **email adresama** možete početi da tražite credential-e koji su ranije leak-ovani i pripadaju tim email adresama:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ako pronađete **važeće leak-ovane** credential-e, ovo je veoma lak uspeh.

## Secrets Leaks

Credential leaks su povezani sa hakovanjima kompanija gde su **osetljive informacije leak-ovane i prodavane**. Međutim, kompanije mogu biti pogođene i drugim leak-ovima čije informacije nisu u tim bazama podataka:

### Github Leaks

Credentials i API-jevi mogu biti leak-ovani u **javnim repozitorijumima** kompanije ili korisnika koji rade u toj github kompaniji.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repo-e** neke **organizacije** i njenih **programera** i automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti za pokretanje **gitleaks** nad svim **text** URL-ovima koji su mu **prosleđeni**, jer ponekad **web stranice takođe sadrže secrets**.

#### Github Dorks

Pogledajte i ovu **stranicu** za potencijalne **github dorks** koje biste takođe mogli da pretražujete u organizaciji koju napadate:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad napadači ili samo zaposleni objave sadržaj kompanije na paste sajtu. Ovo može, ali i ne mora da sadrži **osetljive informacije**, ali je veoma zanimljivo pretražiti to.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) za pretragu na više od 80 paste sajtova istovremeno.

### Google Dorks

Stari, ali zlatni google dorks su uvek korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu tu**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Zato možete uzeti svojih omiljenih 10 ili možete koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih pokrenete sve**.

_Napomena: alati koji očekuju da pokrenu celu bazu koristeći regularni Google browser nikada neće završiti, jer će vas Google veoma brzo blokirati._

### **Looking for vulnerabilities**

Ako pronađete **važeće leak-ovane** credential-e ili API tokene, ovo je veoma lak uspeh.

## Public Code Vulnerabilities

Ako otkrijete da kompanija ima **open-source code**, možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**U zavisnosti od jezika** postoje različiti **alati** koje možete koristiti:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Postoje i besplatni servisi koji omogućavaju da **skenirate javne repozitorijume**, kao što su:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje pronalaze bug hunteri nalazi se unutar **web aplikacija**, pa bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**, a ove informacije možete [**pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem sekciju [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne bi trebalo da očekujete da vam pronađu veoma osetljive ranjivosti, korisni su za integraciju u **workflow-e** kako biste imali neke početne web informacije.

## Recapitulation

> Čestitamo! U ovom trenutku ste već uradili **svu osnovnu enumeraciju**. Da, osnovnu, jer može da se uradi još mnogo više enumeracije (videćemo više trikova kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar opsega
2. Pronašli sve **asset-e** koji pripadaju kompanijama (i izvršili neki vuln scan ako je u opsegu)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **poddomenе** domena (neki subdomain takeover?)
5. Pronašli sve **IP adrese** (i iz **CDN-ova** i **van** njih) unutar opsega.
6. Pronašli sve **web servere** i napravili **screenshot** njih (nešto čudno što vredi dubljeg pregleda?)
7. Pronašli sve **potencijalne javne cloud assets** koji pripadaju kompaniji.
8. **Email adrese**, **credential leaks** i **secret leaks** koji vam mogu doneti **veliku pobedu veoma lako**.
9. **Pentesting svih webova koje ste pronašli**

## **Full Recon Automatic Tools**

Postoji nekoliko alata koji će izvršiti deo predloženih radnji nad datim opsegom.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Malo star i nije ažuriran

## **References**

- Svi besplatni kursevi od [**@Jhaddix**](https://twitter.com/Jhaddix) kao što je [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
