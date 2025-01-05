# Eksterne Recon Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Bate ontdekkings

> Jy is gesê dat alles wat aan 'n maatskappy behoort binne die omvang is, en jy wil uitvind wat hierdie maatskappy eintlik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te verkry en dan al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:

1. Die verkrygings van die hoofmaatskappy vind, dit sal ons die maatskappye binne die omvang gee.
2. Die ASN (indien enige) van elke maatskappy vind, dit sal ons die IP-reekse wat deur elke maatskappy besit word, gee.
3. Omgekeerde whois-soektogte gebruik om ander inskrywings (organisasie name, domeine...) wat verband hou met die eerste een te soek (dit kan herhalend gedoen word).
4. Ander tegnieke soos shodan `org` en `ssl` filters gebruik om ander bates te soek (die `ssl` truuk kan herhalend gedoen word).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, **soek** na die **hoofmaatskappy**, en **klik** op "**verkrygings**". Daar sal jy ander maatskappye sien wat deur die hoof een verkry is.\
'n Ander opsie is om die **Wikipedia** bladsy van die hoofmaatskappy te besoek en te soek na **verkrygings**.

> Goed, op hierdie punt behoort jy al die maatskappye binne die omvang te ken. Kom ons kyk hoe om hul bates te vind.

### **ASNs**

'n Outonome stelselnommer (**ASN**) is 'n **unieke nommer** wat aan 'n **outonome stelsel** (AS) deur die **Internet Assigned Numbers Authority (IANA)** toegeken word.\
'n **AS** bestaan uit **blokke** van **IP adresse** wat 'n duidelik gedefinieerde beleid het vir toegang tot eksterne netwerke en word deur 'n enkele organisasie bestuur, maar kan uit verskeie operateurs bestaan.

Dit is interessant om te vind of die **maatskappy enige ASN toegeken het** om sy **IP-reekse** te vind. Dit sal interessant wees om 'n **kwesbaarheidstoets** teen al die **gasheers** binne die **omvang** uit te voer en **te soek na domeine** binne hierdie IP's.\
Jy kan **soek** volgens maatskappy **naam**, volgens **IP** of volgens **domein** in [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Afhangende van die streek van die maatskappy kan hierdie skakels nuttig wees om meer data te versamel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In elk geval, waarskynlik verskyn al die** nuttige inligting **(IP-reekse en Whois)** reeds in die eerste skakel.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** subdomein-opsomming aggregeer en som automatisch ASN's aan die einde van die skandering op.
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

### **Soek na kwesbaarhede**

Op hierdie punt weet ons **alle bates binne die omvang**, so as jy toegelaat word, kan jy 'n paar **kwesbaarheid skandeerders** (Nessus, OpenVAS) oor al die gasheer bekendstel.\
Ook, jy kan 'n paar [**poort skanderings**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **of gebruik dienste soos** shodan **om** oop poorte **te vind en afhangende van wat jy vind, moet jy** in hierdie boek kyk hoe om verskeie moontlike dienste wat loop, te pentest.\
**Ook, dit kan die moeite werd wees om te noem dat jy ook 'n paar** standaard gebruikersnaam **en** wagwoorde **lysies kan voorberei en probeer om** dienste te bruteforce met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeine

> Ons weet al die maatskappye binne die omvang en hul bates, dit is tyd om die domeine binne die omvang te vind.

_Please, let daarop dat jy in die volgende voorgestelde tegnieke ook subdomeine kan vind en daardie inligting nie onderskat moet word._

Eerstens moet jy soek na die **hoofdomein**(e) van elke maatskappy. Byvoorbeeld, vir _Tesla Inc._ gaan dit _tesla.com_ wees.

### **Reverse DNS**

Soos jy al die IP-reekse van die domeine gevind het, kan jy probeer om **reverse dns lookups** op daardie **IPs uit te voer om meer domeine binne die omvang te vind**. Probeer om 'n dns-bediener van die slagoffer of 'n bekende dns-bediener (1.1.1.1, 8.8.8.8) te gebruik.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Vir dit om te werk, moet die administrateur handmatig die PTR inskakel.\
Jy kan ook 'n aanlyn hulpmiddel vir hierdie inligting gebruik: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (lus)**

Binne 'n **whois** kan jy 'n baie interessante **inligting** vind soos **organisasie naam**, **adres**, **e-posse**, telefoonnommers... Maar wat selfs meer interessant is, is dat jy **meer bates wat met die maatskappy verband hou** kan vind as jy **reverse whois soektogte deur enige van daardie velde** uitvoer (byvoorbeeld ander whois registrasies waar dieselfde e-pos verskyn).\
Jy kan aanlyn hulpmiddels soos gebruik:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** web, nie gratis API nie.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie gratis nie
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie Gratis (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie Gratis

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(vereis 'n whoxy API-sleutel).\
Jy kan ook 'n paar outomatiese reverse whois ontdekking uitvoer met [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinnames te ontdek elke keer as jy 'n nuwe domein vind.**

### **Trackers**

As jy die **dieselfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy veronderstel dat **albei bladsye** **deur dieselfde span bestuur word**.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is 'n paar bladsye en hulpmiddels wat jou toelaat om deur hierdie trackers en meer te soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine aan ons teiken kan vind deur te soek na dieselfde favicon ikoon hash? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) hulpmiddel gemaak deur [@m4ll0k2](https://twitter.com/m4ll0k2) doen. Hier is hoe om dit te gebruik:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ontdek domeine met dieselfde favicon ikoon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, favihash sal ons toelaat om domeine te ontdek wat dieselfde favicon ikoon hash as ons teiken het.

Boonop kan jy ook tegnologieë soek met behulp van die favicon hash soos verduidelik in [**hierdie blogpos**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Dit beteken dat as jy die **hash van die favicon van 'n kwesbare weergawe van 'n web tegnologie** ken, jy kan soek in shodan en **meer kwesbare plekke vind**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Dit is hoe jy die **favicon-hash** van 'n web kan bereken:
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

Soek binne die webbladsye **stringe wat oor verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **kopieregstring** kan 'n goeie voorbeeld wees. Soek dan vir daardie string in **google**, in ander **blaaiers** of selfs in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Dit is algemeen om 'n cron job te hê soos
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
om al die domeinsertifikate op die bediener te hernu. Dit beteken dat selfs al stel die CA wat hiervoor gebruik word nie die tyd in wat dit gegenereer is in die Geldigheid tyd nie, dit moontlik is om **domeine wat aan dieselfde maatskappy behoort in die sertifikaat deursigtigheidslogs te vind**.\
Kyk na hierdie [**skrywe vir meer inligting**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Mail DMARC inligting

Jy kan 'n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of 'n hulpmiddel soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domeine en subdomeine wat dieselfde dmarc-inligting deel** te vind.

### **Passiewe Oorname**

Dit is blykbaar algemeen dat mense subdomeine aan IP's toewys wat aan wolkverskaffers behoort en op 'n sekere punt **daardie IP-adres verloor maar vergeet om die DNS-rekord te verwyder**. Daarom, net deur **'n VM te skep** in 'n wolk (soos Digital Ocean) sal jy eintlik **sommige subdomeine oorneem**.

[**Hierdie pos**](https://kmsec.uk/blog/passive-takeover/) verduidelik 'n storie daaroor en stel 'n skrip voor wat **'n VM in DigitalOcean skep**, **kry** die **IPv4** van die nuwe masjien, en **soek in Virustotal vir subdomeinrekords** wat daarna verwys.

### **Ander maniere**

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinnames te ontdek elke keer as jy 'n nuwe domein vind.**

**Shodan**

Soos jy reeds weet, die naam van die organisasie wat die IP-ruimte besit. Jy kan daarna soek in shodan met: `org:"Tesla, Inc."` Kyk na die gevonde gashere vir nuwe onverwagte domeine in die TLS-sertifikaat.

Jy kan die **TLS-sertifikaat** van die hoofwebblad toegang, die **Organisasienaam** verkry en dan vir daardie naam soek binne die **TLS-sertifikate** van al die webbladsye wat bekend is deur **shodan** met die filter: `ssl:"Tesla Motors"` of gebruik 'n hulpmiddel soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) is 'n hulpmiddel wat soek na **domeine wat verband hou** met 'n hoofdomein en **subdomeine** daarvan, baie indrukwekkend.

### **Soek na kwesbaarhede**

Kyk na 'n paar [domein oorname](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien gebruik 'n maatskappy **'n domein** maar hulle **het die eienaarskap verloor**. Registreer dit net (as dit goedkoop genoeg is) en laat die maatskappy weet.

As jy enige **domein met 'n IP anders** as diegene wat jy reeds in die batesontdekking gevind het, vind, moet jy 'n **basiese kwesbaarheidsskandering** uitvoer (met Nessus of OpenVAS) en 'n paar [**poortsken**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangende van watter dienste aan die gang is, kan jy in **hierdie boek 'n paar truuks vind om hulle te "aanval"**.\
_&#x4E;ote dat soms die domein gehos teen 'n IP wat nie deur die kliënt beheer word nie, so dit is nie in die omvang nie, wees versigtig._

## Subdomeine

> Ons weet van al die maatskappye binne die omvang, al die bates van elke maatskappy en al die domeine wat aan die maatskappye verband hou.

Dit is tyd om al die moontlike subdomeine van elke gevonde domein te vind.

> [!TIP]
> Let daarop dat sommige van die hulpmiddels en tegnieke om domeine te vind ook kan help om subdomeine te vind.

### **DNS**

Kom ons probeer om **subdomeine** van die **DNS** rekords te kry. Ons moet ook probeer vir **Zone Oordrag** (As kwesbaar, moet jy dit rapporteer).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die vinnigste manier om 'n groot aantal subdomeine te verkry, is om in eksterne bronne te soek. Die mees gebruikte **tools** is die volgende (vir beter resultate, konfigureer die API sleutels):

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
Daar is **ander interessante gereedskap/APIs** wat, selfs al is dit nie direk gespesialiseerd in die vind van subdomeine nie, nuttig kan wees om subdomeine te vind, soos:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Gebruik die API [https://sonar.omnisint.io](https://sonar.omnisint.io) om subdomeine te verkry
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC gratis API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) gratis API
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
- [**gau**](https://github.com/lc/gau)**:** haal bekende URL's van AlienVault se Open Threat Exchange, die Wayback Machine, en Common Crawl vir enige gegewe domein.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hulle skraap die web op soek na JS-lêers en onttrek subdomeine daaruit.
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
- [**Censys subdomein soeker**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) het 'n gratis API om subdomeine en IP-geskiedenis te soek
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Hierdie projek bied **gratis al die subdomeine wat verband hou met bug-bounty programme** aan. Jy kan ook toegang tot hierdie data verkry deur [chaospy](https://github.com/dr-0x0x/chaospy) of selfs toegang tot die omvang wat deur hierdie projek gebruik word [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan 'n **vergelyking** van baie van hierdie gereedskap hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomeine** te vind deur DNS-bedieners te brute-forse met moontlike subdomeinname.

Vir hierdie aksie sal jy 'n paar **gewone subdomein woordlyste soos** nodig hê:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP's van goeie DNS-resolvers. Om 'n lys van vertroude DNS-resolvers te genereer, kan jy die resolvers aflaai van [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan gebruik maak van: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole gereedskap vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste gereedskap wat 'n effektiewe DNS brute-force uitgevoer het. Dit is baie vinnig, maar dit is geneig tot vals positiewe.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ek dink hierdie een gebruik net 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is 'n wrapper rondom `massdns`, geskryf in go, wat jou toelaat om geldige subdomeine te enumereer deur aktiewe bruteforce, sowel as om subdomeine op te los met wildcard hantering en maklike invoer-uitvoer ondersteuning.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinnames asynchrone te brute force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Tweede DNS Brute-Force Ronde

Nadat jy subdomeine gevind het met behulp van oop bronne en brute-forcing, kan jy variasies van die gevonde subdomeine genereer om te probeer om selfs meer te vind. Verskeie gereedskap is nuttig vir hierdie doel:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Gegewe die domeine en subdomeine genereer permutasies.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Gegee die domeine en subdomeine, genereer permutasies.
- Jy kan goaltdns permutasies **woordlys** in [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegewe die domeine en subdomeine genereer permutasies. As daar nie 'n permutasielêer aangedui word nie, sal gotator sy eie een gebruik.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Behalwe om subdomein permutasies te genereer, kan dit ook probeer om hulle op te los (maar dit is beter om die vorige genoem gereedskap te gebruik).
- Jy kan altdns permutasies **woordlys** in [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Nog 'n hulpmiddel om permutasies, mutasies en verandering van subdomeine uit te voer. Hierdie hulpmiddel sal die resultaat brute force (dit ondersteun nie dns wild card nie).
- Jy kan dmut permutasies woordlys in [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Gebaseer op 'n domein, **genereer dit nuwe potensiële subdomeinnames** gebaseer op aangeduidde patrone om te probeer om meer subdomeine te ontdek.

#### Slim permutasiegenerasie

- [**regulator**](https://github.com/cramppet/regulator): Vir meer inligting lees hierdie [**pos**](https://cramppet.github.io/regulator/index.html), maar dit sal basies die **hoofddele** van die **ontdekte subdomeine** kry en dit meng om meer subdomeine te vind.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is 'n subdomein brute-force fuzzer gekoppel aan 'n uiters eenvoudige maar effektiewe DNS respons-geleide algoritme. Dit gebruik 'n verskafde stel invoerdata, soos 'n op maat gemaakte woordlys of historiese DNS/TLS rekords, om akkuraat meer ooreenstemmende domeinnames te sintetiseer en dit selfs verder in 'n lus uit te brei gebaseer op inligting wat tydens die DNS skandering versamel is.
```
echo www | subzuf facebook.com
```
### **Subdomein Ontdekking Werkvloei**

Kyk na hierdie blogpos wat ek geskryf het oor hoe om **subdomein ontdekking** van 'n domein te **automateer** met behulp van **Trickest werkvloei** sodat ek nie 'n klomp gereedskap handmatig op my rekenaar hoef te begin nie:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtuele Gashere**

As jy 'n IP-adres gevind het wat **een of verskeie webbladsye** bevat wat aan subdomeine behoort, kan jy probeer om **ander subdomeine met webbladsye in daardie IP** te **vind** deur in **OSINT bronne** te kyk vir domeine in 'n IP of deur **VHost domeinnaam in daardie IP te brute-force**.

#### OSINT

Jy kan 'n paar **VHosts in IPs vind met behulp van** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander API's**.

**Brute Force**

As jy vermoed dat 'n subdomein op 'n webbediener versteek kan wees, kan jy probeer om dit te brute-force:
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
> Met hierdie tegniek mag jy selfs toegang hê tot interne/verborgene eindpunte.

### **CORS Brute Force**

Soms sal jy bladsye vind wat slegs die kop _**Access-Control-Allow-Origin**_ teruggee wanneer 'n geldige domein/subdomein in die _**Origin**_ kop is. In hierdie scenario's kan jy hierdie gedrag misbruik om **nuwe** **subdomeine** te **ontdek**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Terwyl jy na **subdomeine** soek, hou 'n oog op of dit na enige tipe **emmer** **wys**, en in daardie geval [**kontroleer die toestemmings**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ook, aangesien jy op hierdie punt al die domeine binne die omvang sal weet, probeer om [**brute force moontlike emmername en kontroleer die toestemmings**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorisering**

Jy kan **monitor** of **nuwe subdomeine** van 'n domein geskep word deur die **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) te monitor.

### **Soek na kwesbaarhede**

Kontroleer vir moontlike [**subdomein oorneem**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomein** na 'n **S3-emmer** **wys**, [**kontroleer die toestemmings**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomein met 'n IP verskil** van diegene wat jy reeds in die batesontdekking gevind het, moet jy 'n **basiese kwesbaarheidsskandering** (met Nessus of OpenVAS) en 'n [**poortskaande**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** uitvoer. Afhangende van watter dienste aan die gang is, kan jy in **hierdie boek 'n paar truuks vind om hulle te "aanval"**.\
_&#x4E;ote dat soms die subdomein gehos teen 'n IP wat nie deur die kliënt beheer word nie, so dit is nie in die omvang nie, wees versigtig._

## IPs

In die aanvanklike stappe mag jy **sommige IP-reekse, domeine en subdomeine** **gevind het**.\
Dit is tyd om **al die IPs van daardie reekse te versamel** en vir die **domeine/subdomeine (DNS-vrae).**

Deur dienste van die volgende **gratis API's** te gebruik, kan jy ook **vorige IPs wat deur domeine en subdomeine gebruik is, vind**. Hierdie IPs mag steeds deur die kliënt besit word (en mag jou toelaat om [**CloudFlare omseilings**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook kyk vir domeine wat na 'n spesifieke IP-adres wys met die hulpmiddel [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Soek na kwesbaarhede**

**Poortskaande al die IPs wat nie aan CDN's behoort nie** (aangesien jy hoogs waarskynlik niks interessant daar sal vind nie). In die lopende dienste wat ontdek is, mag jy **in staat wees om kwesbaarhede te vind**.

**Vind 'n** [**gids**](../pentesting-network/index.html) **oor hoe om gashere te skandeer.**

## Webbedieners jag

> Ons het al die maatskappye en hul bates gevind en ons weet IP-reekse, domeine en subdomeine binne die omvang. Dit is tyd om na webbedieners te soek.

In die vorige stappe het jy waarskynlik al 'n paar **recon van die IPs en domeine ontdek** uitgevoer, so jy mag **al die moontlike webbedieners gevind het**. As jy egter nie, gaan ons nou 'n paar **vinnige truuks sien om webbedieners** binne die omvang te soek.

Neem asseblief kennis dat dit **georiënteer sal wees op webtoepassingsontdekking**, so jy moet ook **die kwesbaarheid** en **poortskaande** uitvoer (**indien toegelaat** deur die omvang).

'n **Vinnige metode** om **oop poorte** wat verband hou met **web** bedieners te ontdek, kan met [**masscan** hier gevind word](../pentesting-network/index.html#http-port-discovery).\
Nog 'n vriendelike hulpmiddel om na webbedieners te soek is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy gee net 'n lys van domeine en dit sal probeer om met poort 80 (http) en 443 (https) te verbind. Boonop kan jy aandui om ander poorte te probeer:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Skermskootte**

Nou dat jy **alle webbedieners** in die omvang ontdek het (tussen die **IP's** van die maatskappy en al die **domeine** en **subdomeine**) weet jy waarskynlik **nie waar om te begin nie**. Laat ons dit eenvoudig maak en begin net deur skermskootte van al hulle te neem. Net deur **na die hoofblad** te **kyk**, kan jy **vreemde** eindpunte vind wat meer **geneig** is om **kwulnerabel** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** gebruik.**

Boonop kan jy dan [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om oor al die **skermskootte** te loop om jou te vertel **wat waarskynlik kwulnerabiliteite bevat**, en wat nie.

## Publieke Wolk Bate

Om potensiële wolk bates wat aan 'n maatskappy behoort te vind, moet jy **begin met 'n lys van sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir 'n crypto-maatskappy kan jy woorde soos: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` gebruik.

Jy sal ook woordlyste van **gewone woorde wat in emmers gebruik word** benodig:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dan, met daardie woorde moet jy **permutasies** genereer (kyk na die [**Tweede Ronde DNS Brute-Force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordlyste kan jy gereedskap soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat wanneer jy na Wolk Bates soek, jy moet **kyk na meer as net emmers in AWS**.

### **Soek na kwulnerabiliteite**

As jy dinge soos **oop emmers of blootgestelde wolk funksies** vind, moet jy **hulle toegang** en probeer om te sien wat hulle jou bied en of jy hulle kan misbruik.

## E-posse

Met die **domeine** en **subdomeine** binne die omvang het jy basies alles wat jy **nodig het om te begin soek na e-posse**. Dit is die **API's** en **gereedskap** wat die beste vir my gewerk het om e-posse van 'n maatskappy te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met API's
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Soek na kwulnerabiliteite**

E-posse sal later handig te pas kom om **brute-force web aanmeldings en outentikasiedienste** (soos SSH) te doen. Ook, hulle is nodig vir **phishings**. Boonop sal hierdie API's jou selfs meer **inligting oor die persoon** agter die e-pos gee, wat nuttig is vir die phishing veldtog.

## Kredensiaal Lekke

Met die **domeine,** **subdomeine**, en **e-posse** kan jy begin soek na kredensiale wat in die verlede gelek het wat aan daardie e-posse behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Soek na kwulnerabiliteite**

As jy **geldige gelekte** kredensiale vind, is dit 'n baie maklike oorwinning.

## Geheime Lekke

Kredensiaal lekke is verwant aan hacks van maatskappye waar **sensitiewe inligting gelek en verkoop is**. egter, maatskappye mag geraak word deur **ander lekke** waarvan die inligting nie in daardie databasisse is nie:

### Github Lekke

Kredensiale en API's mag in die **openbare repositories** van die **maatskappy** of van die **gebruikers** wat vir daardie github maatskappy werk, gelek word.\
Jy kan die **gereedskap** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om **alle openbare repos** van 'n **organisasie** en sy **ontwikkelaars** af te laai en [**gitleaks**](https://github.com/zricethezav/gitleaks) daaroor outomaties te laat loop.

**Leakos** kan ook gebruik word om **gitleaks** teen alle **teks** te laat loop wat **URL's aan dit gegee** word, aangesien **webbladsye ook geheime kan bevat**.

#### Github Dorks

Kyk ook na hierdie **bladsy** vir potensiële **github dorks** wat jy ook in die organisasie wat jy aanval kan soek:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Paste Lekke

Soms sal aanvallers of net werkers **maatskappy-inhoud op 'n paste-webwerf publiseer**. Dit mag of mag nie **sensitiewe inligting** bevat nie, maar dit is baie interessant om daarna te soek.\
Jy kan die gereedskap [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om in meer as 80 paste-webwerwe gelyktydig te soek.

### Google Dorks

Ou maar goud google dorks is altyd nuttig om **blootgestelde inligting wat daar nie behoort te wees nie** te vind. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) verskeie **duisende** moontlike navrae bevat wat jy nie handmatig kan uitvoer nie. So, jy kan jou gunsteling 10 kies of jy kan 'n **gereedskap soos** [**Gorks**](https://github.com/carlospolop/Gorks) **gebruik om hulle almal uit te voer**.

_Ontspan dat die gereedskap wat verwag om die hele databasis met die gewone Google-blaaier te laat loop, nooit sal eindig nie, aangesien google jou baie vinnig sal blokkeer._

### **Soek na kwulnerabiliteite**

As jy **geldige gelekte** kredensiale of API tokens vind, is dit 'n baie maklike oorwinning.

## Publieke Kode Kwulnerabiliteite

As jy gevind het dat die maatskappy **open-source kode** het, kan jy dit **analiseer** en soek na **kwulnerabiliteite** daarin.

**Afhangende van die taal** is daar verskillende **gereedskap** wat jy kan gebruik:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Daar is ook gratis dienste wat jou toelaat om **openbare repositories** te **skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Metodologie**](../../network-services-pentesting/pentesting-web/index.html)

Die **meerderheid van die kwulnerabiliteite** wat deur foutjagters gevind word, is binne **webtoepassings**, so op hierdie punt wil ek graag oor 'n **webtoepassing toets metodologie** praat, en jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook 'n spesiale vermelding maak van die afdeling [**Web Geoutomatiseerde Skandeerders open source gereedskap**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), aangesien, as jy nie moet verwag dat hulle baie sensitiewe kwulnerabiliteite sal vind nie, hulle handig te pas kom om dit in **werkvloei te implementeer om 'n paar aanvanklike webinligting te hê.**

## Herhaling

> Geluk! Op hierdie punt het jy reeds **alle basiese enumerasie** uitgevoer. Ja, dit is basies omdat daar baie meer enumerasie gedoen kan word (sal later meer truuks sien).

So jy het reeds:

1. Alle **maatskappye** binne die omvang gevind
2. Alle **bates** wat aan die maatskappye behoort gevind (en 'n paar vuln skandeer as dit in omvang is)
3. Alle **domeine** wat aan die maatskappye behoort gevind
4. Alle **subdomeine** van die domeine gevind (enige subdomein oorneem?)
5. Alle **IP's** (van en **nie van CDNs**) binne die omvang gevind.
6. Alle **webbedieners** gevind en 'n **skermskoot** van hulle geneem (iets vreemd wat 'n dieper kyk werd is?)
7. Alle **potensiële publieke wolk bates** wat aan die maatskappy behoort gevind.
8. **E-posse**, **kredensiaal lekke**, en **geheime lekke** wat jou 'n **groot oorwinning baie maklik kan gee**.
9. **Pentesting al die webwerwe wat jy gevind het**

## **Volledige Recon Outomatiese Gereedskap**

Daar is verskeie gereedskap daar buite wat 'n deel van die voorgestelde aksies teen 'n gegewe omvang sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 'n bietjie oud en nie opgedateer nie

## **Verwysings**

- Alle gratis kursusse van [**@Jhaddix**](https://twitter.com/Jhaddix) soos [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
