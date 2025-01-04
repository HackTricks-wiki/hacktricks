# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje sredstava

> Tako su vam rekli da je sve što pripada nekoj kompaniji unutar opsega, i želite da saznate šta ta kompanija zapravo poseduje.

Cilj ove faze je da se dobiju sve **kompanije koje poseduje glavna kompanija** i zatim sva **sredstva** ovih kompanija. Da bismo to postigli, uradićemo sledeće:

1. Pronaći akvizicije glavne kompanije, to će nam dati kompanije unutar opsega.
2. Pronaći ASN (ako postoji) svake kompanije, to će nam dati IP opsege koje poseduje svaka kompanija.
3. Koristiti obrnute whois pretrage da tražimo druge unose (imena organizacija, domene...) povezane sa prvim (ovo se može raditi rekurzivno).
4. Koristiti druge tehnike kao što su shodan `org` i `ssl` filteri da tražimo druga sredstva (trik sa `ssl` se može raditi rekurzivno).

### **Akvizicije**

Prvo, treba da znamo koje **druge kompanije poseduje glavna kompanija**.\
Jedna opcija je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **pretražite** **glavnu kompaniju**, i **kliknite** na "**akvizicije**". Tamo ćete videti druge kompanije koje je glavna kompanija akvizirala.\
Druga opcija je da posetite **Wikipedia** stranicu glavne kompanije i potražite **akvizicije**.

> U redu, u ovom trenutku trebali biste znati sve kompanije unutar opsega. Hajde da saznamo kako da pronađemo njihova sredstva.

### **ASN-ovi**

Broj autonomnog sistema (**ASN**) je **jedinstveni broj** dodeljen **autonomnom sistemu** (AS) od strane **Internet Assigned Numbers Authority (IANA)**.\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku za pristup spoljnim mrežama i kojima upravlja jedna organizacija, ali se mogu sastojati od više operatera.

Zanimljivo je saznati da li je **kompanija dodelila neki ASN** da bi pronašla svoje **IP opsege.** Bilo bi zanimljivo izvršiti **test ranjivosti** protiv svih **hostova** unutar **opsega** i **tražiti domene** unutar ovih IP adresa.\
Možete **pretraživati** po imenu kompanije, po **IP-u** ili po **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**U zavisnosti od regiona kompanije, ovi linkovi bi mogli biti korisni za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno su sve** korisne informacije **(IP opsezi i Whois)** već prikazane u prvom linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeracija poddomena automatski agregira i sumira ASN-ove na kraju skeniranja.
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
Možete pronaći IP opsege organizacije takođe koristeći [http://asnlookup.com/](http://asnlookup.com) (ima besplatan API).\
Možete pronaći IP i ASN domena koristeći [http://ipv4info.com/](http://ipv4info.com).

### **Traženje ranjivosti**

U ovom trenutku znamo **sve resurse unutar opsega**, tako da, ako imate dozvolu, možete pokrenuti neki **skener ranjivosti** (Nessus, OpenVAS) na svim hostovima.\
Takođe, možete pokrenuti neke [**port skenove**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti usluge kao što je** shodan **da pronađete** otvorene portove **i u zavisnosti od onoga što pronađete, trebali biste** pogledati u ovu knjigu kako da pentestujete nekoliko mogućih usluga koje se izvode.\
**Takođe, vredi napomenuti da možete pripremiti neke** liste podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforce-ujete usluge sa [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije unutar opsega i njihove resurse, vreme je da pronađemo domene unutar opsega.

_Molimo vas, imajte na umu da u sledećim predloženim tehnikama možete takođe pronaći poddomene i da te informacije ne bi trebale biti potcenjene._

Prvo što treba da uradite je da potražite **glavnu domenu**(e) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Obrnuti DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **obrnute dns pretrage** na tim **IP-ovima kako biste pronašli više domena unutar opsega**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Takođe možete koristiti online alat za ove informacije: [http://ptrarchive.com/](http://ptrarchive.com)

### **Obrnuti Whois (loop)**

Unutar **whois** možete pronaći mnogo zanimljivih **informacija** kao što su **ime organizacije**, **adresa**, **emailovi**, brojevi telefona... Ali ono što je još zanimljivije je da možete pronaći **više sredstava povezanih sa kompanijom** ako izvršite **obrnute whois pretrage po bilo kojem od tih polja** (na primer, druge whois registre gde se isti email pojavljuje).\
Možete koristiti online alate kao što su:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Besplatno** web, nije besplatan API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno

Možete automatizovati ovaj zadatak koristeći [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API ključ).\
Takođe možete izvršiti neku automatsku obrnutu whois otkrivanje sa [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da možete koristiti ovu tehniku da otkrijete više imena domena svaki put kada pronađete novi domen.**

### **Trackers**

Ako pronađete **isti ID istog trackera** na 2 različite stranice, možete pretpostaviti da su **obe stranice** **upravlja iste ekipe**.\
Na primer, ako vidite isti **Google Analytics ID** ili isti **Adsense ID** na nekoliko stranica.

Postoje neke stranice i alati koji vam omogućavaju da pretražujete po ovim trackerima i još:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Da li ste znali da možemo pronaći povezane domene i poddomene našeg cilja tražeći isti hash favicon ikone? Ovo je upravo ono što alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2) radi. Evo kako ga koristiti:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - otkrijte domene sa istim favicon ikonom hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash će nam omogućiti da otkrijemo domene koje imaju isti favicon ikonu hash kao naš cilj.

Štaviše, možete takođe pretraživati tehnologije koristeći favicon hash kao što je objašnjeno u [**ovom blog postu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To znači da ako znate **hash favicon-a ranjive verzije web tehnologije** možete pretraživati u shodan-u i **pronaći više ranjivih mesta**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ovako možete **izračunati favicon hash** veba:
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
### **Copyright / Uniq string**

Pretražujte unutar web stranica **nizove koji se mogu deliti između različitih webova u istoj organizaciji**. **Copyright string** može biti dobar primer. Zatim pretražujte taj niz u **google-u**, u drugim **pregledačima** ili čak u **shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Uobičajeno je imati cron job kao
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
da obnovite sve sertifikate domena na serveru. To znači da čak i ako CA koja se koristi za ovo ne postavi vreme kada je generisan u vremenu važenja, moguće je **pronaći domene koje pripadaju istoj kompaniji u logovima transparentnosti sertifikata**.\
Pogledajte ovaj [**izveštaj za više informacija**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Mail DMARC informacije

Možete koristiti veb sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da pronađete **domene i poddomene koje dele iste DMARC informacije**.

### **Pasivno preuzimanje**

Očigledno je uobičajeno da ljudi dodeljuju poddomene IP adresama koje pripadaju provajderima u oblaku i u nekom trenutku **izgube tu IP adresu, ali zaborave da uklone DNS zapis**. Stoga, samo **pokretanjem VM** u oblaku (kao što je Digital Ocean) zapravo ćete **preuzeti neke poddomene**.

[**Ovaj post**](https://kmsec.uk/blog/passive-takeover/) objašnjava priču o tome i predlaže skriptu koja **pokreće VM u DigitalOcean**, **dobija** **IPv4** nove mašine i **pretražuje u Virustotal-u za zapise poddomena** koji upućuju na nju.

### **Ostali načini**

**Napomena da možete koristiti ovu tehniku da otkrijete više imena domena svaki put kada pronađete novu domenu.**

**Shodan**

Kao što već znate ime organizacije koja poseduje IP prostor. Možete pretraživati po tim podacima u shodanu koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove za nove neočekivane domene u TLS sertifikatu.

Možete pristupiti **TLS sertifikatu** glavne veb stranice, dobiti **ime organizacije** i zatim pretraživati to ime unutar **TLS sertifikata** svih veb stranica poznatih od strane **shodan** sa filtrima: `ssl:"Tesla Motors"` ili koristiti alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) je alat koji traži **domene povezane** sa glavnom domenom i **poddomenama** njih, prilično neverovatno.

### **Traženje ranjivosti**

Proverite za neki [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi neku domenu** ali su **izgubili vlasništvo**. Samo je registrujte (ako je dovoljno jeftina) i obavestite kompaniju.

Ako pronađete neku **domenu sa IP-jem koji se razlikuje** od onih koje ste već pronašli u otkrivanju sredstava, trebali biste izvršiti **osnovno skeniranje ranjivosti** (koristeći Nessus ili OpenVAS) i neko [**port skeniranje**](../pentesting-network/index.html#discovering-hosts-from-the-outside) sa **nmap/masscan/shodan**. U zavisnosti od toga koji servisi rade, možete pronaći u **ovoj knjizi neke trikove za "napad" na njih**.\
&#xNAN;_&#x4E;ote da ponekad domena je hostovana unutar IP-a koji nije pod kontrolom klijenta, tako da nije u opsegu, budite oprezni._

## Poddomene

> Znamo sve kompanije unutar opsega, sve resurse svake kompanije i sve domene povezane sa kompanijama.

Vreme je da pronađemo sve moguće poddomene svake pronađene domene.

> [!TIP]
> Napomena da neki od alata i tehnika za pronalaženje domena mogu takođe pomoći u pronalaženju poddomena

### **DNS**

Pokušajmo da dobijemo **poddomene** iz **DNS** zapisa. Takođe bismo trebali pokušati za **Zone Transfer** (Ako je ranjiv, trebali biste to prijaviti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najbrži način da se dobiju mnogi poddomeni je pretraga u spoljnim izvorima. Najčešće korišćeni **tools** su sledeći (za bolje rezultate konfigurišite API ključeve):

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
Postoje **drugi zanimljivi alati/API** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za pronalaženje poddomena, kao što su:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za dobijanje poddomena
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC besplatan API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL adrese iz AlienVault-ovog Open Threat Exchange, Wayback Machine-a i Common Crawl-a za bilo koju datu domenu.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Oni pretražuju web u potrazi za JS datotekama i izvode poddomene odatle.
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

Ovaj projekat nudi **besplatno sve poddomene povezane sa bug-bounty programima**. Ove podatke možete pristupiti i koristeći [chaospy](https://github.com/dr-0x0x/chaospy) ili čak pristupiti opsegu koji koristi ovaj projekat [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Možete pronaći **uporedbu** mnogih od ovih alata ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomenе** brute-forcing DNS servere koristeći moguće nazive poddomena.

Za ovu akciju biće vam potrebne neke **uobičajene liste reči poddomena kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Takođe, IP adrese dobrih DNS resolvera. Da biste generisali listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i koristiti [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) da ih filtrirate. Ili možete koristiti: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučiviji alati za DNS brute-force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno izvršavao DNS brute-force. Veoma je brz, međutim sklon je lažnim pozitivnim rezultatima.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Mislim da koristi samo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je omotač oko `massdns`, napisan u go, koji vam omogućava da enumerišete validne poddomene koristeći aktivni bruteforce, kao i da rešavate poddomene sa obradom wildcard-a i jednostavnom podrškom za ulaz-izlaz.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinkrono brute force napad na imena domena.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda DNS brute-force

Nakon što ste pronašli poddomene koristeći otvorene izvore i brute-forcing, možete generisati varijacije pronađenih poddomena kako biste pokušali da pronađete još više. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dajući domene i poddomene generiše permutacije.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dati domeni i poddomeni generišite permutacije.
- Možete dobiti goaltdns permutacije **wordlist** **ovde** [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dati domene i poddomene generiše permutacije. Ako nije naznačen fajl sa permutacijama, gotator će koristiti svoj.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Osim generisanja permutacija poddomena, može pokušati da ih reši (ali je bolje koristiti prethodno pomenute alate).
- Možete dobiti altdns permutacije **wordlist** u [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će izvršiti brute force na rezultat (ne podržava dns wild card).
- Možete dobiti dmut permutacije rečnik [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nova potencijalna imena poddomena** na osnovu naznačenih obrazaca kako bi pokušao da otkrije više poddomena.

#### Pametna generacija permutacija

- [**regulator**](https://github.com/cramppet/regulator): Za više informacija pročitajte ovaj [**post**](https://cramppet.github.io/regulator/index.html), ali će u suštini uzeti **glavne delove** iz **otkrivenih poddomena** i mešati ih kako bi pronašao više poddomena.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force subdomena uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi pruženi skup ulaznih podataka, kao što su prilagođena lista reči ili istorijski DNS/TLS zapisi, da precizno sintetiše više odgovarajućih imena domena i dodatno ih proširuje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.
```
echo www | subzuf facebook.com
```
### **Workflow za Otkriće Poddomena**

Pogledajte ovaj blog post koji sam napisao o tome kako da **automatizujem otkrivanje poddomena** sa domena koristeći **Trickest workflows** tako da ne moram ručno da pokrećem gomilu alata na svom računaru:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtuelni Hostovi**

Ako ste pronašli IP adresu koja sadrži **jednu ili više web stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa web stranicama na toj IP adresi** tražeći u **OSINT izvorima** za domene na IP-u ili **brute-forcing VHost imena domena na toj IP adresi**.

#### OSINT

Možete pronaći neke **VHost-ove na IP-ovima koristeći** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili druge API-je**.

**Brute Force**

Ako sumnjate da neki poddomen može biti skriven na web serveru, možete pokušati da ga brute force-ujete:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> Ovom tehnikom možda ćete moći da pristupite internim/skrivenim krajnjim tačkama.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju samo zaglavlje _**Access-Control-Allow-Origin**_ kada je validna domena/poddomena postavljena u _**Origin**_ zaglavlju. U ovim scenarijima, možete iskoristiti ovo ponašanje da **otkrijete** nove **poddomenе**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force za Buckete**

Dok tražite **subdomene**, obratite pažnju da li se **upučuju** na bilo koju vrstu **bucketa**, i u tom slučaju [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Takođe, kako ćete u ovom trenutku znati sve domene unutar opsega, pokušajte da [**brute force-ujete moguće nazive bucketa i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorisanje**

Možete **monitorisati** da li su **nove subdomene** domena kreirane praćenjem **Certificate Transparency** logova [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite moguće [**preuzimanje subdomena**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **subdomena** upućuje na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/).

Ako pronađete neku **subdomenu sa IP-om koji se razlikuje** od onih koje ste već pronašli u otkrivanju resursa, trebali biste izvršiti **osnovno skeniranje ranjivosti** (koristeći Nessus ili OpenVAS) i neko [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) sa **nmap/masscan/shodan**. U zavisnosti od usluga koje se pokreću, možete pronaći u **ovoj knjizi neke trikove za "napad" na njih**.\
&#xNAN;_&#x4E;ote da ponekad subdomena je hostovana unutar IP-a koji nije pod kontrolom klijenta, tako da nije u opsegu, budite oprezni._

## IP-ovi

U početnim koracima možda ste **pronašli neke IP opsege, domene i subdomene**.\
Vreme je da **prikupite sve IP-ove iz tih opsega** i za **domene/subdomene (DNS upiti).**

Koristeći usluge iz sledećih **besplatnih API-ja**, takođe možete pronaći **prethodne IP-ove korišćene od strane domena i subdomena**. Ovi IP-ovi možda još uvek pripadaju klijentu (i mogu vam omogućiti da pronađete [**CloudFlare zaobilaženja**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Takođe možete proveriti domene koje upućuju na određenu IP adresu koristeći alat [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Skenirajte sve IP-ove koji ne pripadaju CDN-ima** (jer verovatno nećete pronaći ništa zanimljivo tamo). U otkrivenim uslugama možda ćete **moći da pronađete ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/) **o tome kako skenirati hostove.**

## Lov na web servere

> Pronašli smo sve kompanije i njihove resurse i znamo IP opsege, domene i subdomene unutar opsega. Vreme je da tražimo web servere.

U prethodnim koracima verovatno ste već izvršili neku **recon analizu otkrivenih IP-ova i domena**, tako da ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo videti neke **brze trikove za pretragu web servera** unutar opsega.

Molimo vas da napomenete da će ovo biti **orijentisano na otkrivanje web aplikacija**, tako da biste trebali **izvršiti skeniranje ranjivosti** i **skeniranje portova** takođe (**ako je dozvoljeno** od strane opsega).

**Brza metoda** za otkrivanje **otvorenih portova** povezanih sa **web** serverima koristeći [**masscan** može se pronaći ovde](../pentesting-network/index.html#http-port-discovery).\
Još jedan prijateljski alat za pretragu web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Samo prosledite listu domena i pokušaće da se poveže na port 80 (http) i 443 (https). Pored toga, možete naznačiti da pokušate druge portove:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sada kada ste otkrili **sve web servere** prisutne u opsegu (među **IP adresama** kompanije i svim **domenima** i **poddomenama**) verovatno **ne znate odakle da počnete**. Zato, hajde da to pojednostavimo i počnemo tako što ćemo praviti snimke ekrana svih njih. Samo gledajući **glavnu stranicu** možete pronaći **čudne** krajnje tačke koje su više **podložne** da budu **ranjive**.

Da biste sproveli predloženu ideju, možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete koristiti [**eyeballer**](https://github.com/BishopFox/eyeballer) da pregledate sve **screenshotove** i da vam kaže **šta verovatno sadrži ranjivosti**, a šta ne.

## Public Cloud Assets

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, trebali biste **početi sa listom ključnih reči koje identifikuju tu kompaniju**. Na primer, za kripto kompaniju možete koristiti reči kao što su: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Takođe će vam biti potrebne liste reči **uobičajenih reči korišćenih u bucket-ima**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim, sa tim rečima trebali biste generisati **permutacije** (proverite [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) za više informacija).

Sa dobijenim listama reči možete koristiti alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Zapamtite da kada tražite Cloud resurse, trebali biste **gledati više od samo bucket-a u AWS-u**.

### **Looking for vulnerabilities**

Ako pronađete stvari kao što su **otvoreni bucket-i ili izložene cloud funkcije**, trebali biste **pristupiti njima** i pokušati da vidite šta vam nude i da li ih možete zloupotrebiti.

## Emails

Sa **domenima** i **poddomenama** unutar opsega, u suštini imate sve što vam **treba da počnete da tražite emailove**. Ovo su **API-ji** i **alati** koji su mi najbolje funkcionisali za pronalaženje emailova kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - sa API-ima
- API [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Looking for vulnerabilities**

Emailovi će kasnije biti korisni za **brute-force web prijave i autentifikacione usluge** (kao što je SSH). Takođe, potrebni su za **phishing**. Pored toga, ovi API-ji će vam dati još više **informacija o osobi** iza emaila, što je korisno za phishing kampanju.

## Credential Leaks

Sa **domenima,** **poddomenama** i **emailovima** možete početi da tražite kredencijale koji su procurili u prošlosti i koji pripadaju tim emailovima:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ako pronađete **validne procurile** kredencijale, ovo je vrlo lakša pobeda.

## Secrets Leaks

Procureni kredencijali su povezani sa hakovanjima kompanija gde je **osetljive informacije procurila i prodana**. Međutim, kompanije mogu biti pogođene i **drugim curenjima** čije informacije nisu u tim bazama podataka:

### Github Leaks

Kredencijali i API-ji mogu biti procurili u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu github kompaniju.\
Možete koristiti **alat** [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** jedne **organizacije** i njenih **razvijača** i automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) na njima.

**Leakos** se takođe može koristiti za pokretanje **gitleaks** protiv svih **tekstualnih** **URL-ova** koji su mu prosleđeni, jer ponekad **web stranice takođe sadrže tajne**.

#### Github Dorks

Proverite takođe ovu **stranicu** za potencijalne **github dorks** koje možete takođe tražiti u organizaciji koju napadate:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Ponekad napadači ili samo radnici će **objaviti sadržaj kompanije na paste sajtu**. Ovo može ili ne mora sadržati **osetljive informacije**, ali je veoma zanimljivo tražiti to.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da pretražujete više od 80 paste sajtova u isto vreme.

### Google Dorks

Stari, ali zlatni google dorks su uvek korisni za pronalaženje **izloženih informacija koje ne bi trebale biti tu**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno pokrenuti. Dakle, možete uzeti svojih omiljenih 10 ili možete koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih sve pokrenete**.

_Napomena da alati koji očekuju da pokrenu celu bazu koristeći regularni Google pretraživač nikada neće završiti jer će vas google vrlo brzo blokirati._

### **Looking for vulnerabilities**

Ako pronađete **validne procurile** kredencijale ili API tokene, ovo je vrlo laka pobeda.

## Public Code Vulnerabilities

Ako ste otkrili da kompanija ima **open-source kod**, možete ga **analizirati** i tražiti **ranjivosti** u njemu.

**U zavisnosti od jezika**, postoje različiti **alati** koje možete koristiti:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Takođe postoje besplatne usluge koje vam omogućavaju da **skenirate javne repozitorijume**, kao što su:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/)

**Većina ranjivosti** koje pronalaze lovci na greške se nalazi unutar **web aplikacija**, tako da bih u ovom trenutku želeo da govorim o **metodologiji testiranja web aplikacija**, a možete [**pronaći ove informacije ovde**](../../network-services-pentesting/pentesting-web/).

Takođe želim da posebno pomenem sekciju [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne biste trebali očekivati da će pronaći veoma osetljive ranjivosti, oni su korisni za implementaciju u **radne tokove kako biste imali neke inicijalne web informacije.**

## Recapitulation

> Čestitamo! U ovom trenutku ste već izvršili **sve osnovne enumeracije**. Da, to je osnovno jer se može uraditi još mnogo više enumeracija (videćemo više trikova kasnije).

Dakle, već ste:

1. Pronašli sve **kompanije** unutar opsega
2. Pronašli sve **resurse** koji pripadaju kompanijama (i izvršili neku skeniranje ranjivosti ako je u opsegu)
3. Pronašli sve **domen** koji pripadaju kompanijama
4. Pronašli sve **poddomen** domena (ima li preuzimanja poddomena?)
5. Pronašli sve **IP adrese** (iz i **ne iz CDN-a**) unutar opsega.
6. Pronašli sve **web servere** i napravili **screenshot** njih (ima li nešto čudno što vredi dubljeg pregleda?)
7. Pronašli sve **potencijalne javne cloud resurse** koji pripadaju kompaniji.
8. **Emailovi**, **curenje kredencijala**, i **curenje tajni** koji bi vam mogli doneti **veliku pobedu vrlo lako**.
9. **Pentesting svih web stranica koje ste pronašli**

## **Full Recon Automatic Tools**

Postoji nekoliko alata koji će izvršiti deo predloženih akcija protiv datog opsega.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Malo star i nije ažuriran

## **References**

- Svi besplatni kursevi [**@Jhaddix**](https://twitter.com/Jhaddix) kao što je [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
