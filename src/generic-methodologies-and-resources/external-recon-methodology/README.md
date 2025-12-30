# Metodologija External Recon

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje imovine

> Dakle, rečeno vam je da je sve što pripada nekoj kompaniji unutar scope-a, i želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da prikupimo sve **kompanije koje su u vlasništvu glavne kompanije** i potom svu **imovinu** tih kompanija. Da bismo to postigli, uradićemo sledeće:

1. Pronađite akvizicije glavne kompanije — to će nam dati kompanije koje su unutar scope-a.
2. Pronađite ASN (ako postoji) za svaku kompaniju — to će nam dati IP ranges koje svaka kompanija poseduje
3. Koristite reverse whois lookups da pretražite druge unose (organisation names, domains...) povezane sa prvim (ovo se može raditi rekurzivno)
4. Koristite druge tehnike kao što su shodan `org` i `ssl` filteri da pronađete druge imovine (the `ssl` trick se može raditi rekurzivno).

### **Akvizicije**

Prvo, potrebno je znati koje **druge kompanije su u vlasništvu glavne kompanije**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** glavnu kompaniju i **kliknete** na "**akvizicije**". Tamo ćete videti druge kompanije koje je glavna kompanija stekla.\
Druga opcija je da posetite stranicu **Wikipedia** glavne kompanije i potražite **akvizicije**.\
Za javne kompanije, proverite **SEC/EDGAR filings**, stranice **investor relations**, ili lokalne korporativne registre (npr. **Companies House** u UK).\
Za globalne korporativne strukture i podružnice, probajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> OK, u ovom trenutku trebalo bi da znate sve kompanije unutar scope-a. Hajde da utvrdimo kako da pronađemo njihovu imovinu.

### **ASNs**

An autonomous system number (**ASN**) je **jedinstveni broj** dodeljen **autonomous systemu** (AS) od strane **Internet Assigned Numbers Authority (IANA)**.\
AS se sastoji od **blokova** **IP addresses** koje imaju jasno definisanu politiku pristupa eksternim mrežama i kojima upravlja jedna organizacija, ali mogu ih činiti više operatora.

Vredno je utvrditi da li kompanija ima dodeljen **ASN** kako bismo pronašli njene **IP ranges**. Bilo bi korisno izvršiti **vulnerability test** nad svim **hosts** unutar **scope**-a i pretražiti **domains** u tim IP-ovima.\
Možete **pretraživati** po imenu kompanije, po **IP** ili po **domain** na [**https://bgp.he.net/**](https://bgp.he.net), [**https://bgpview.io/**](https://bgpview.io/) ili [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona kompanije, ovi linkovi mogu biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). U svakom slučaju, verovatno su svi** korisni podaci **(IP ranges and Whois)** već dostupni na prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration automatski agregira i sumira ASNs na kraju skeniranja.
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

At this point we know **svi resursi unutar opsega**, so if you are allowed you could launch some **skener ranjivosti** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise kao što su** Shodan, Censys, ili ZoomEye **da biste pronašli** otvorene portove **i u zavisnosti od onoga što pronađete trebalo bi da** pogledate u ovoj knjizi kako da pentestujete nekoliko mogućih servisa koji rade.\
**Takođe, vredno je napomenuti da možete pripremiti neke** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Znamo sve kompanije unutar opsega i njihove resurse, vreme je da pronađemo domene unutar opsega.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Da bi ovo radilo, administrator mora ručno da omogući PTR.\
Takođe možete koristiti online alat za ovu informaciju: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike rangove, alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) su korisni za automatizaciju reverse lookup-ova i obogaćivanje.

### **Reverse Whois (loop)**

U okviru **whois** zapisa možete pronaći mnogo zanimljivih **informacija** kao što su **ime organizacije**, **adresa**, **emailovi**, telefonski brojevi... Ali ono što je još interesantnije jeste da možete pronaći **više asseta povezanih sa kompanijom** ako izvršite **reverse whois upite po bilo kojem od tih polja** (na primer druge whois registracije gde se pojavljuje isti email).\
Možete koristiti online alate kao što su:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Besplatno** web, API nije besplatan.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - **Nije besplatno**
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **Nije besplatno** (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - **Nije besplatno**
- [https://securitytrails.com/](https://securitytrails.com/) - **Nije besplatno** (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - **Nije besplatno** (API)

Možete automatizovati ovaj zadatak koristeći [**DomLink** ](https://github.com/vysecurity/DomLink) (zahteva whoxy API key).\
Takođe možete izvesti automatsko reverse whois otkrivanje pomoću [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovu tehniku možete koristiti za otkrivanje više domena svaki put kada pronađete novi domen.**

### **Trackeri**

Ako pronađete **isti ID istog trackera** na 2 različite stranice, možete pretpostaviti da su **obe stranice** **upravljane istim timom**.\
Na primer, ako vidite isti **Google Analytics ID** ili isti **Adsense ID** na više stranica.

Postoje stranice i alati koji vam omogućavaju pretragu po tim trackerima i još više:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene cilja tražeći isti hash favicon ikonice? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako se koristi:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrijte domene sa istim favicon icon hash-om](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash će nam omogućiti da otkrijemo domene koje imaju isti favicon icon hash kao naš cilj.

Osim toga, možete pretraživati tehnologije koristeći favicon hash kako je objašnjeno u [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da, ako znate **hash of the favicon of a vulnerable version of a web tech** možete ga potražiti u shodan i **find more vulnerable places**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Evo kako možete **calculate the favicon hash** web sajta:
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
Takođe možete dobiti favicon hashes na velikoj skali pomoću [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) i zatim pivot u Shodan/Censys.

### **Autorsko pravo / Jedinstveni niz**

Pretražite unutar web stranica **nizove koji bi mogli biti deljeni između različitih webova iste organizacije**. **Autorski niz** može biti dobar primer. Zatim pretražite taj niz u **google**, u drugim **pretraživačima** ili čak u **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao što je
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da obnovi sve sertifikate domena na serveru. To znači da čak i ako CA koji je izdao sertifikat ne postavi vreme kada je generisan u Validity polju, moguće je **pronaći domene koji pripadaju istoj kompaniji u certificate transparency logs**.\
Pogledajte ovaj [**writeup za više informacija**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Takođe koristite **certificate transparency** logs direktno:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC informacije

Možete koristiti veb sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i poddomene koji dele iste dmarc informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Izgleda da je često da ljudi dodeljuju poddomene IP adresama koje pripadaju cloud provajderima i u nekom trenutku **izgube tu IP adresu ali zaborave da uklone DNS zapis**. Dakle, jednostavnim **pokretanjem VM-a** u cloudu (kao Digital Ocean) zapravo ćete **preuzeti neke poddomene**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) objašnjava priču o tome i predlaže skript koji **pokreće VM u DigitalOcean**, **dohvata** **IPv4** nove mašine, i **pretražuje VirusTotal za zapise poddomena** koji pokazuju na nju.

### **Other ways**

**Imajte na umu da možete koristiti ovu tehniku da otkrijete više domena svaki put kada pronađete novi domen.**

**Shodan**

Ako već znate ime organizacije koja poseduje IP prostor, možete pretraživati shodan koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove za nove neočekivane domene u TLS sertifikatu.

Možete pristupiti **TLS certificate** glavne web stranice, dobiti **ime organizacije** i potom pretražiti to ime unutar **TLS certificates** svih web stranica poznatih preko **shodan** koristeći filter: `ssl:"Tesla Motors"` ili upotrebiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) je alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomene**, prilično impresivno.

**Passive DNS / Historical DNS**

Passive DNS podaci su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se još uvek rešavaju ili koje je moguće preuzeti. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Proverite za neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neki domen** ali su **izgubili vlasništvo**. Jednostavno ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom drugačijom** od onih koje ste već našli u otkrivanju resursa, trebalo bi da izvršite **osnovni vulnerability scan** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) sa **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, u **ovoj knjizi možete naći neke trikove kako ih "napasti"**.\
_Napomena: ponekad je domen hostovan na IP adresi koju klijent ne kontroliše, tako da nije u obuhvatu — budite oprezni._

## Subdomeni

> Znamo sve kompanije unutar obuhvata, sve resurse svake kompanije i sve domene povezane sa tim kompanijama.

[!TIP]
> Zapamtite da neki alati i tehnike za pronalaženje domena takođe mogu pomoći u pronalaženju poddomena

### **DNS**

Pokušajmo da dobijemo **poddomene** iz **DNS** zapisa. Trebalo bi takođe pokušati i **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način da dobijete veliki broj poddomena je pretraživanje eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
Postoje **drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje subdomena, mogu biti korisni za otkrivanje subdomena, kao što su:

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
- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove iz AlienVault's Open Threat Exchange, Wayback Machine i Common Crawl za bilo koji dati domen.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Pretražuju internet tražeći JS files i iz njih izvlače subdomene.
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
- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu subdomains i istorije IP adresa
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ovaj projekat besplatno pruža sve subdomains vezane za bug-bounty programe. Ovim podacima možete pristupiti i koristeći [chaospy](https://github.com/dr-0x0x/chaospy) ili čak pristupiti scope-u koji koristi ovaj projekat [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Možete pronaći **upoređenje** mnogih ovih alata ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo pronaći nove **subdomains** brute-forcing DNS servere koristeći moguće nazive subdomena.

Za ovu radnju biće vam potrebni neki **uobičajeni subdomains wordlists**, kao što su:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrebni su vam i IP-ovi dobrih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera možete preuzeti resolvere sa [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučljiviji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je izvodio efikasan DNS brute-force. Veoma je brz, međutim sklon je lažno pozitivnim rezultatima.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper oko `massdns`, napisan u go, koji vam omogućava da enumerišete validne subdomains koristeći active bruteforce, kao i da rešavate subdomains sa wildcard handling i jednostavnom input-output podrškom.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio da asinhrono brute force-uje nazive domena.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga DNS Brute-Force runda

Nakon što pronađete subdomains koristeći open sources i brute-forcing, možete generisati varijacije pronađenih subdomains da biste pokušali otkriti još. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domains i subdomains generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Za date domene i poddomene generiše permutacije.
- Možete preuzeti **wordlist** permutacija za goaltdns [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije naznačen fajl sa permutacijama, gotator će koristiti svoj.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Pored generisanja permutacija poddomena, može pokušati i da ih razreši (ali je bolje koristiti prethodno pomenute alate).
- Možete preuzeti altdns permutations **wordlist** [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena subdomena. Ovaj alat će brute force rezultate (ne podržava dns wild card).
- Možete preuzeti dmut permutations wordlist [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena generiše **nova potencijalna subdomains imena** prema naznačenim obrascima kako bi pokušao da otkrije više subdomains.

#### Pametno generisanje permutacija

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovaj [**post**](https://cramppet.github.io/regulator/index.html), ali u suštini će izdvojiti **glavne delove** iz **otkrivenih subdomains** i pomešati ih da bi pronašao više subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je subdomain brute-force fuzzer uparen sa izuzetno jednostavnim ali efikasnim DNS reponse-guided algoritmom. Koristi prosleđeni skup ulaznih podataka, kao što su prilagođeni wordlist ili istorijski DNS/TLS zapisi, da precizno sintetizuje više odgovarajućih domain names i dalje ih proširuje u petlji na osnovu informacija prikupljenih tokom DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Pogledajte ovaj blog post koji sam napisao o tome kako da **automatizujem subdomain discovery** iz domena koristeći **Trickest workflows**, tako da ne moram ručno da pokrećem gomilu alata na svom računaru:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ako pronađete IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju subdomains, možete pokušati da **pronađete druge subdomains sa sajtovima na toj IP adresi** pretraživanjem **OSINT sources** za domene na toj IP adresi ili pomoću **brute-forcing VHost domain names**.

#### OSINT

Možete pronaći neke **VHosts u IP-ovima koristeći** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili druge API-je**.

**Brute Force**

Ako sumnjate da je neki subdomain skriven na web serveru, možete pokušati da ga brute force-ate:
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
> Sa ovom tehnikom čak možete pristupiti internal/hidden endpoints.

### **CORS Brute Force**

Ponekad ćete naići na stranice koje vraćaju samo header _**Access-Control-Allow-Origin**_ kada je u headeru _**Origin**_ podešen validan domain/subdomain. U tim scenarijima možete zloupotrebiti ovo ponašanje da biste **otkrili** nove **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Dok tražite **subdomains**, obratite pažnju da li su one **pointing** na neki tip **bucket**, i u tom slučaju [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene unutar opsega, pokušajte da [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorovanje**

Možete **monitor** da li se kreiraju **new subdomains** nekog domena praćenjem **Certificate Transparency** logova, kao što radi [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite moguće [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako se **subdomain** **pointing** na neki **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako nađete bilo koji **subdomain with an IP different** od onih koje ste već našli tokom asset discovery, trebalo bi da uradite **basic vulnerability scan** (koristeći Nessus ili OpenVAS) i neki [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) koristeći **nmap/masscan/shodan**. U zavisnosti od servisa koji rade, u **this book some tricks to "attack" them** можете naći trikove kako ih testirati.\
_Napomena: ponekad je subdomain hostovan na IP adresi koja nije kontrolisana od strane klijenta, pa nije u scope-u — budite oprezni._

## IPs

U početnim koracima možda ste **found some IP ranges, domains and subdomains**.\
Vreme je da **recollect all the IPs from those ranges** i za **domains/subdomains (DNS queries).**

Koristeći servise iz sledećih **free apis** takođe možete pronaći **previous IPs used by domains and subdomains**. Ove IP adrese i dalje mogu biti u vlasništvu klijenta (i mogu vam pomoći da pronađete [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti koji domeni pokazuju na određenu IP adresu koristeći alat [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

Skenirajte portove svih IP adresa koje ne pripadaju CDN-ovima (jer verovatno tamo nećete naći ništa interesantno). U otkrivenim pokrenutim servisima možda ćete moći da pronađete ranjivosti.

Pronađite [**guide**](../pentesting-network/index.html) o tome kako skenirati hostove.

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

U prethodnim koracima verovatno ste već uradili recon IP-ova i domena koje ste otkrili, tako da možda već imate sve moguće web servere. Međutim, ako to niste uradili, sada ćemo videti neke brze trikove za pronalaženje web servera unutar opsega.

Imajte na umu da će ovo biti orijentisano na otkrivanje web aplikacija, pa bi trebalo da izvršite i skeniranje ranjivosti i portova (**ako je dozvoljeno** u scope-u).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Još jedan praktičan alat za pronalaženje web servera su [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Jednostavno prosledite listu domena i oni će pokušati da se povežu na port 80 (http) i 443 (https). Dodatno, možete navesti da pokuša i druge portove:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Snimci ekrana**

Sada kada ste otkrili **all the web servers** prisutne u scope (među **IPs** kompanije i svim **domains** i **subdomains**) verovatno **ne znate odakle da počnete**. Dakle, pojednostavimo i počnimo sa pravljenjem screenshots svih njih. Samo pregledom **main page** možete naći **weird** endpoints koji su skloniji da budu **vulnerable**.

Za realizaciju ove ideje možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete koristiti i [**eyeballer**](https://github.com/BishopFox/eyeballer) da pregledate sve **screenshots** i kažete vam **šta verovatno sadrži ranjivosti**, a šta ne.

## Javni Cloud resursi

Da biste pronašli potencijalne cloud assets koji pripadaju jednoj kompaniji, treba da **počnete sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za crypto kompaniju možete koristiti reči kao što su: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Takođe će vam trebati wordlists uobičajenih reči koje se koriste u buckets:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, sa tim rečima treba da generišete **permutations** (pogledajte [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim wordlist-ovima možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Zapamtite da pri traženju Cloud Assets treba da gledate **više od samih buckets u AWS**.

### **Traženje ranjivosti**

Ako nađete stvari kao što su **open buckets ili cloud functions exposed**, treba da im **pristupite** i pokušate da vidite šta vam nude i da li ih možete iskoristiti.

## Emails

Sa **domains** i **subdomains** koji su u scope-u imate praktično sve što vam treba da **počnete da tražite emails**. Ovo su **APIs** i **tools** koji su mi najbolje radili za pronalaženje email-ova kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Traženje ranjivosti**

Emails će vam kasnije biti korisni za **brute-force web logins i auth services** (kao što je SSH). Takođe, potrebni su za **phishings**. Pored toga, ovi API-ji će vam dati i više **informacija o osobi** iza email-a, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domains,** **subdomains**, i **emails** možete početi da tražite credentials koje su u prošlosti procurile i koje pripadaju tim email-ovima:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako nađete **valid leaked** credentials, to je veoma lak i vredan uspeh.

## Secrets Leaks

Credential leaks su vezani za napade na kompanije gde su **sensitive information** procurele i prodate. Međutim, kompanije mogu biti pogođene i drugim vrstama leaks čije informacije nisu u tim bazama:

### Github Leaks

Credentials i API-ji mogu biti procureli u **public repositories** kompanije ili korisnika koji rade za tu github kompaniju.\
Možete koristiti **tool** [**Leakos**](https://github.com/carlospolop/Leakos) da **download**-ujete sve **public repos** jedne **organization** i njenih **developers** i automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se takođe može koristiti da pokrene **gitleaks** protiv svih **text** datih **URLs** koje mu se proslede, jer ponekad **web pages takođe sadrže secrets**.

#### Github Dorks

Pogledajte i ovu **stranicu** za potencijalne **github dorks** koje takođe možete pretraživati u organizaciji koju napadate:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad napadači ili čak zaposleni objave **company content** na paste sajtu. To može, ali i ne mora, da sadrži **sensitive information**, ali je vrlo interesantno to pretražiti.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da pretražite više od 80 paste sajtova u isto vreme.

### Google Dorks

Stari ali dobri google dorks su uvek korisni za pronalaženje **exposed information koja ne bi trebalo da bude tu**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **thousands** mogućih upita koje ne možete ručno da pokrenete. Dakle, možete uzeti svojih omiljenih 10 ili možete koristiti **tool kao** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena: alati koji očekuju da pokrenu celu bazu koristeći regularni Google browser nikada neće završiti jer će vas google vrlo brzo blokirati._

### **Traženje ranjivosti**

Ako nađete **valid leaked** credentials ili API tokens, to je veoma lak i vredan uspeh.

## Public Code Vulnerabilities

Ako ustanovite da kompanija ima **open-source code**, možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**U zavisnosti od jezika** postoje različiti **tools** koje možete koristiti:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Postoje i besplatne servise koji vam omogućavaju da **skenirate public repositories**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Većina ranjivosti koje nalaze bug hunteri leži unutar **web applications**, tako da bih u ovom trenutku želeo da govorim o metodologiji testiranja web aplikacija, a možete [**pronaći te informacije ovde**](../../network-services-pentesting/pentesting-web/index.html).

Takođe želim posebno da pomenem sekciju [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će vam pronaći veoma osetljive ranjivosti, korisni su za uključivanje u **workflows** kako biste dobili neku početnu web informaciju.

## Recapitulation

> Čestitamo! U ovom trenutku ste već obavili **svu osnovnu enumeraciju**. Da, osnovnu zato što se može uraditi mnogo više enumeracije (videćemo više trikova kasnije).

Dakle, već ste:

1. Pronašli sve **companies** u scope-u
2. Pronašli sve **assets** koji pripadaju kompanijama (i izvršili neki vuln scan ako je u scope-u)
3. Pronašli sve **domains** koje pripadaju kompanijama
4. Pronašli sve **subdomains** domena (ima li mogućnosti za subdomain takeover?)
5. Pronašli sve **IPs** (i iz i ne iz CDN-ova) unutar scope-a.
6. Pronašli sve **web servers** i napravili **screenshot**-ove istih (ima li nešto čudno što vredi dublje istražiti?)
7. Pronašli sve potencijalne public cloud assets koji pripadaju kompaniji.
8. **Emails**, **credentials leaks**, i **secret leaks** koji vam mogu brzo doneti veliki uspeh.
9. **Pentesting** svih web-ova koje ste pronašli

## **Full Recon Automatic Tools**

Postoji nekoliko alata koji će izvršiti deo predloženih akcija nad zadatim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
