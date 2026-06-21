# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje assets

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji u scope-u, i želite da otkrijete šta ta kompanija zapravo poseduje.

Cilj ove faze je da se dobiju sve **kompanije u vlasništvu glavne kompanije** a zatim i svi **assets** tih kompanija. Da bismo to uradili, uradićemo sledeće:

1. Pronaći akvizicije glavne kompanije, to će nam dati kompanije unutar scope-a.
2. Pronaći ASN (ako postoji) za svaku kompaniju, to će nam dati IP opsege koje poseduje svaka kompanija
3. Koristiti reverse whois lookups da bismo pretražili druge unose (nazive organizacija, domene...) povezane sa prvim (ovo se može raditi rekurzivno)
4. Koristiti druge tehnike kao što su shodan `org`and `ssl`filteri za pretragu drugih assets (``ssl`` trik se može raditi rekurzivno).

### **Akvizicije**

Pre svega, treba da znamo koje su **druge kompanije u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju** i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga opcija je da posetite **Wikipedia** stranicu glavne kompanije i potražite **acquisitions**.\
Za javne kompanije, proverite **SEC/EDGAR filings**, stranice za **investor relations**, ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalne korporativne stabla i podružnice, probajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i **GLEIF LEI** bazu ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, u ovom trenutku bi trebalo da znate sve kompanije unutar scope-a. Hajde da otkrijemo kako da pronađemo njihove assets.

### **ASNs**

Autonomous system number (**ASN**) je **jedinstveni broj** dodeljen **autonomous system-u** (AS) od strane **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** koje imaju jasno definisanu politiku za pristup eksternim mrežama i administrira ih jedna organizacija, ali mogu biti sastavljene od nekoliko operatora.

Zanimljivo je otkriti da li je kompaniji dodeljen neki ASN kako bi se pronašli njeni **IP opsezi.** Biće korisno izvršiti **vulnerability test** nad svim **hostovima** unutar **scope-a** i **tražiti domene** unutar tih IP adresa.\
Možete **pretraživati** po **nazivu** kompanije, po **IP** ili po **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona kompanije, ovi linkovi mogu biti korisni za prikupljanje više podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno sve** korisne informacije **(IP opsezi i Whois)** već se pojavljuju u prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration automatski agregira i sumira ASNs na kraju skeniranja.
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
Možete pronaći IP opsege organizacije i koristeći [http://asnlookup.com/](http://asnlookup.com) (ima free API).\
Možete pronaći IP i ASN domena koristeći [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

U ovom trenutku znamo **sva sredstva unutar scope-a**, pa ako ste ovlašćeni, možete pokrenuti **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti neke [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys ili ZoomEye **da pronađete** open ports **i u zavisnosti od onoga što pronađete trebalo bi da** pogledate u ovoj knjizi kako da pentestujete nekoliko mogućih servisa koji rade.\
**Takođe, vredno je pomenuti da možete pripremiti i neke** default username **i** passwords **liste i pokušati da** bruteforce-ujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Znamo sve kompanije unutar scope-a i njihova sredstva, vreme je da pronađemo domene unutar scope-a.

_Imajte na umu da u sledećim predloženim tehnikama takođe možete pronaći subdomains i da tu informaciju ne treba potcenjivati._

Pre svega trebalo bi da tražite **glavni domain(e)** svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse dns lookups** nad tim **IP adresama da biste pronašli više domena unutar scope-a**. Pokušajte da koristite neki dns server žrtve ili neki dobro poznat dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Za ovo da bi radilo, administrator mora ručno da omogući PTR.\
Možete takođe da koristite online alat za ove informacije: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege, alati kao [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) su korisni za automatizaciju reverse lookups i enrichment.

### **Reverse Whois (loop)**

Unutar jednog **whois**-a možete pronaći mnogo zanimljivih **informacija** kao što su **naziv organizacije**, **adresa**, **emailovi**, brojevi telefona... Ali još zanimljivije je da možete pronaći **više asseta povezanih sa kompanijom** ako uradite **reverse whois lookups po bilo kom od tih polja** (na primer drugi whois registri gde se pojavljuje isti email).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatno** web, nije besplatan API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Nije besplatno (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nije besplatno (API)

Ovaj zadatak možete automatizovati koristeći [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API key).\
Takođe možete izvršiti i automatsko reverse whois otkrivanje pomoću [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje više domain names svaki put kada pronađete novi domain.**

### **Trackers**

Ako pronađete isti ID istog tracker-a na 2 različite stranice, možete pretpostaviti da su **obe stranice** upravljane od strane istog tima.\
Na primer, ako na nekoliko stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje neke stranice i alati koji vam omogućavaju pretragu po ovim tracker-ima i još mnogo toga:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove preko deljenih analytics/trackers)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i subdomene našoj meti gledanjem istog hash-a favicon ikonice? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrivanje domena sa istim hash-om ikone favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash će nam omogućiti da otkrijemo domene koji imaju isti hash favicon ikone kao naša meta.

Pored toga, takođe možete pretraživati tehnologije koristeći hash favicon-a, kao što je objašnjeno u [**ovom blog postu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da, ako znate **hash favicon-a ranjive verzije neke web tehnologije**, možete pretražiti u shodanu i **pronaći više ranjivih mesta**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ovako možete **izračunati hash favicon-a** veba:
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
Takođe možete dobiti favicon hash-eve u velikom obimu pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) i zatim pivotirati u Shodan/Censys.

### **Copyright / Uniq string**

Pretražite unutar web stranica **stringove koji bi mogli biti deljeni između različitih webs u istoj organizaciji**. **Copyright string** može biti dobar primer. Zatim pretražite taj string u **google**, u drugim **browserima** ili čak u **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao što je
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

Možete koristiti web kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da biste pronašli **domains and subdomain sharing the same dmarc information**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

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

Najbrži način da se dođe do velikog broja subdomena je pretraga eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate podesite API ključeve):

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
Postoje **drugi zanimljivi alati/API-jevi** koji, čak i ako nisu direktno specijalizovani za pronalaženje subdomena, mogu biti korisni za pronalaženje subdomena, kao što su:

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
- [**RapidDNS**](https://rapiddns.io) free API
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
- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove iz AlienVault-ovog Open Threat Exchange, Wayback Machine-a i Common Crawl-a za bilo koji dati domen.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Oni pretražuju web u potrazi za JS fajlovima i iz njih izvlače subdomene.
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
- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu subdomena i IP istorije
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ovaj projekat besplatno nudi sve subdomaine povezane sa bug-bounty programima. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy) ili čak pristupiti scope-u koji koristi ovaj projekat [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Možete pronaći **poređenje** mnogih ovih alata ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hajde da pokušamo da pronađemo nove **subdomains** brute-forcing-om DNS servera koristeći moguće nazive subdomena.

Za ovu radnju biće vam potrebne neke **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

I takođe IP adrese dobrih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera možete preuzeti resolvere sa [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

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
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko `massdns`, napisan u go, koji omogućava da enumerišeš validne subdomene koristeći active bruteforce, kao i da resolve-uješ subdomene uz wildcard handling i laku input-output podršku.
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
### Druga runda DNS brute-force

Nakon što ste pronašli poddomene koristeći open source izvore i brute-forcing, možete generisati varijacije pronađenih poddomena kako biste pokušali da pronađete još više. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Datih domena i subdomena generiše permutacije.
- Možeš dobiti goaltdns permutations **wordlist** [**ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dati domeni i subdomeni generiše permutacije. Ako nije navedena permutation file, gotator će koristiti svoju.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Pored generisanja permutacija subdomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno komentarisane alate).
- Možete preuzeti altdns permutacije **wordlist** [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će brute force-ovati rezultat (ne podržava dns wild card).
- Možete preuzeti dmut permutation wordlist [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena poddomena** prema navedenim obrascima kako bi pokušao da otkrije više poddomena.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovaj [**post**](https://cramppet.github.io/regulator/index.html), ali ukratko on uzima **glavne delove** iz **otkrivenih poddomena** i kombinuje ih kako bi pronašao još poddomena.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je subdomain brute-force fuzzer uparen sa izuzetno jednostavnim, ali efikasnim DNS response-guided algoritmom. Koristi dati skup ulaznih podataka, poput prilagođene wordlist ili istorijskih DNS/TLS zapisa, kako bi precizno sintetisao još odgovarajućih domain name-ova i dodatno ih proširio u petlji na osnovu informacija prikupljenih tokom DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Pogledajte ovaj blog post koji sam napisao o tome kako da **automatizujete otkrivanje subdomena** iz domena koristeći **Trickest workflows** tako da ne moram ručno da pokrećem gomilu alata na svom računaru:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ako pronađete IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju subdomenima, možete pokušati da **pronađete druge subdomenе sa veb sadržajem na toj IP adresi** tako što ćete pretražiti **OSINT izvore** za domene na IP adresi ili tako što ćete **brute-force-ovati nazive VHost domena na toj IP adresi**.

#### OSINT

Možete pronaći neke **VHostove na IP adresama koristeći** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili druge API-je**.

**Brute Force**

Ako sumnjate da je neki subdomain sakriven na web serveru, možete pokušati da ga brute-force-ujete:

Kada **IP preusmerava na hostname** (name-based vhosts), fuzz-ujte direktno `Host` header i pustite ffuf da se **auto-kalibriše** kako bi istakao odgovore koji se razlikuju od default vhost-a:
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
> Sa ovom tehnikom možda ćete čak moći da pristupite internim/sakrivenim endpoint-ovima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je važeći domen/subdomen postavljen u zaglavlju _**Origin**_. U ovim scenarijima, možete zloupotrebiti ovo ponašanje da **otkrijete** nove **subdomenove**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Dok tražiš **subdomains**, obrati pažnju da li neki od njih **pointing** na bilo kakav **bucket**, i u tom slučaju [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćeš u ovom trenutku znati sve domene unutar scope-a, pokušaj da [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Možeš da **monitor** da li se kreiraju **new subdomains** nekog domena prateći **Certificate Transparency** logove; to radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Proveri moguće [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomain** pokazuje na neki **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađeš bilo koji **subdomain with an IP different** od onih koje si već pronašao u asset discovery-ju, treba da uradiš **basic vulnerability scan** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, u **ovoj knjizi** možeš naći neke trikove da ih **"attack"**.\
_Napomena: ponekad je subdomain hostovan na IP adresi nad kojom klijent nema kontrolu, pa to nije u scope-u, budi pažljiv._

## IPs

U početnim koracima možda si **pronašao neke IP range-ove, domene i subdomene**.\
Vreme je da **prikupiš sve IP adrese iz tih range-ova** i za **domene/subdomene (DNS queries).**

Korišćenjem servisa iz sledećih **free apis** takođe možeš pronaći **previous IPs used by domains and subdomains**. Ove IP adrese možda su i dalje u vlasništvu klijenta (i mogu ti omogućiti da pronađeš [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možeš proveriti koji domeni pokazuju na određenu IP adresu pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (jer tamo vrlo verovatno nećeš naći ništa zanimljivo). Na servisima koji su otkriveni u radu možda ćeš **moći da pronađeš vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Pronašli smo sve kompanije i njihove resurse i znamo IP range-ove, domene i subdomene unutar scope-a. Vreme je da tražimo web servere.

U prethodnim koracima si verovatno već uradio neko **recon** nad otkrivenim IP adresama i domenima, pa si možda već **pronašao sve moguće web servere**. Međutim, ako nisi, sada ćemo videti neke **brze trikove za traženje web servera** unutar scope-a.

Napomena: ovo će biti **oriented for web apps discovery**, tako da bi trebalo da uradiš i **vulnerability** i **port scanning** takođe (**ako scope to dozvoljava**).

Brz metod za otkrivanje **otvorenih portova** vezanih za **web** servere pomoću [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Još jedan praktičan alat za pronalaženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Samo proslediš listu domena i alat će pokušati da se poveže na port 80 (http) i 443 (https). Dodatno, možeš naznačiti da pokuša i druge portove:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve web servere** prisutne u scope-u (među **IP adresama** kompanije i svim **domenima** i **subdomenima**) verovatno **ne znate odakle da počnete**. Zato, hajde da to pojednostavimo i krenemo tako što ćemo napraviti screenshot-ove svih njih. Samim **pogledom** na **glavnu stranicu** možete pronaći **čudne** endpoint-e koji su više **skloni** da budu **ranjivi**.

Da biste sproveli predloženu ideju, možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Takođe, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da prođete kroz sve **screenshot-ove** i odredi šta je **verovatno da sadrži ranjivosti**, a šta nije.

## Public Cloud Assets

Da biste pronašli potencijalne cloud assete koji pripadaju kompaniji, trebalo bi da **počnete sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Takođe će vam biti potrebne wordlist-e sa **uobičajenim rečima koje se koriste u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, sa tim rečima treba da generišete **permutacije** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlist-ama možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Zapamtite da, kada tražite Cloud Assets, treba d l**ook for more than just buckets in AWS**.

### **Looking for vulnerabilities**

Ako pronađete stvari kao što su **otvoreni bucket-i ili izložene cloud funkcije**, trebalo bi da im **pristupite** i pokušate da vidite šta nude i da li možete da ih zloupotrebite.

## Emails

Sa **domenima** i **subdomenima** unutar scope-a, praktično imate sve što vam je **potrebno da počnete sa traženjem email adresa**. Ovo su **API-ji** i **alati** koji su se meni najbolje pokazali za pronalaženje email adresa kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Email adrese će kasnije dobro doći za **brute-force web login-a i auth servisa** (kao što je SSH). Takođe, potrebne su za **phishing**. Štaviše, ovi API-ji će vam dati i još više **informacija o osobi** iza email adrese, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domenima,** **subdomenima** i **email-ovima** možete početi da tražite credential-e koji su ranije procureli i pripadaju tim email adresama:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ako pronađete **važeće procurele** credential-e, to je veoma lak uspeh.

## Secrets Leaks

Credential leak-ovi su povezani sa hakovima kompanija gde su **senzitivne informacije procurile i bile prodate**. Međutim, kompanije mogu biti pogođene i drugim leak-ovima čije informacije nisu u tim bazama:

### Github Leaks

Credential-i i API-ji mogu procureti u **javnim repozitorijumima** **kompanije** ili korisnika koji rade za tu github kompaniju.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** neke **organizacije** i njenih **developer-a** i da automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** takođe može da se koristi za pokretanje **gitleaks** nad svim **tekstom** koji daju **prosleđeni URL-ovi**, jer ponekad **web stranice takođe sadrže secrets**.

#### Github Dorks

Pogledajte i ovu **stranicu** za potencijalne **github dorks** koje takođe možete pretraživati u organizaciji koju napadate:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad napadači ili samo radnici će **objaviti sadržaj kompanije na paste sajtu**. To može, ali i ne mora, da sadrži **senzitivne informacije**, ali je veoma zanimljivo pretražiti to.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da pretražujete više od 80 paste sajtova istovremeno.

### Google Dorks

Stari ali zlatni google dorks su uvek korisni za pronalaženje **izloženih informacija koje tu ne bi trebalo da budu**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno da pokrenete. Zato možete uzeti svojih omiljenih 10 ili možete koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih pokrenete sve**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

Ako pronađete **važeće procurele** credential-e ili API tokene, to je veoma lak uspeh.

## Public Code Vulnerabilities

Ako ste otkrili da kompanija ima **open-source code**, možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**U zavisnosti od jezika** postoje različiti **alati** koje možete koristiti:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Postoje i besplatne usluge koje omogućavaju da **skenirate javne repozitorijume**, kao što su:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje pronalaze bug hunter-i nalazi se unutar **web aplikacija**, pa bih ovde želeo da govorim o **metodologiji testiranja web aplikacija**, a ove informacije možete [**pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem sekciju [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će pronaći veoma senzitivne ranjivosti, korisni su za implementaciju u **workflow-ove** kako biste dobili početne web informacije.

## Recapitulation

> Čestitamo! U ovom trenutku ste već sproveli **svu osnovnu enumeraciju**. Da, osnovnu, jer može da se uradi još mnogo više enumeracije (videćemo još trikova kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar scope-a
2. Pronašli sve **asset-e** koji pripadaju kompanijama (i izvršili neki vuln scan ako je u scope-u)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **subdomene** domena (neki subdomain takeover?)
5. Pronašli sve **IP adrese** (i **iz CDNs** i **izvan CDNs**) unutar scope-a.
6. Pronašli sve **web servere** i napravili **screenshot**-ove od njih (nešto čudno vredno dubljeg pregleda?)
7. Pronašli sve **potencijalne javne cloud assete** koji pripadaju kompaniji.
8. **Email-ove**, **credential leaks**, i **secret leaks** koji vam mogu doneti **veliku pobedu veoma lako**.
9. **Pentesting svih webova koje ste pronašli**

## **Full Recon Automatic Tools**

Postoji nekoliko alata koji će izvršiti deo predloženih akcija nad datim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Malo star i nije ažuriran

## **References**

- Svi besplatni kursevi od [**@Jhaddix**](https://twitter.com/Jhaddix) kao [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
