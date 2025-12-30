# Eksterne Recon Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Assets ontdekkings

> Jy is vertel dat alles wat aan 'n maatskappy behoort binne die scope is, en jy wil uitvind wat hierdie maatskappy eintlik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te bekom en daarna al die **assets** van hierdie maatskappye. Om dit te doen, gaan ons:

1. Vind die verkrygings van die hoofmaatskappy, dit sal ons die maatskappye binne die scope gee.
2. Vind die ASN (indien enige) van elke maatskappy, dit sal ons die IP-reekse gee wat deur elke maatskappy besit word
3. Gebruik reverse whois lookups om na ander inskrywings (organisasie name, domains...) verwant aan die eerste te soek (dit kan rekursief gedoen word)
4. Gebruik ander tegnieke soos shodan `org` en `ssl` filters om na ander assets te soek (die `ssl` truuk kan rekursief gedoen word).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om na [https://www.crunchbase.com/](https://www.crunchbase.com) te gaan, **soek** vir die **hoofmaatskappy**, en **klik** op "**verkrygings**". Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
'N Ander opsie is om die **Wikipedia** bladsy van die hoofmaatskappy te besoek en te soek na **verkrygings**.\
Vir openbare maatskappye, kyk na **SEC/EDGAR filings**, **investor relations** pages, of plaaslike korporatiewe registere (bv., **Companies House** in die VK).\
Vir globale korporatiewe bome en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI** databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, op hierdie punt behoort jy al die maatskappye binne die scope te ken. Kom ons bepaal hoe om hul assets te vind.

### **ASNs**

'n autonomous system number (**ASN**) is 'n **unieke nommer** wat aan 'n **autonome stelsel** (AS) deur die **Internet Assigned Numbers Authority (IANA)** toegeken word.\
'n **AS** bestaan uit **blokke** van **IP addresses** wat 'n duidelik gedefinieerde beleid het vir toegang tot eksterne netwerke en word bestuur deur 'n enkele organisasie, maar kan uit verskeie operateurs bestaan.

Dit is interessant om te bepaal of die **maatskappy enige ASN toegewys het** om sy **IP ranges** te vind. Dit sal nuttig wees om 'n **vulnerability test** uit te voer teen al die **hosts** binne die **scope** en te **soek na domains** binne hierdie IP's.\
Jy kan **soek** op die maatskappy **naam**, op **IP** of op **domain** by [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die streek van die maatskappy kan hierdie skakels nuttig wees om meer data te versamel:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Hoe dit ook al sy, waarskynlik verskyn al die** nuttige inligting **(IP ranges and Whois)** reeds in die eerste skakel.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**se** enumeration outomaties aggregeer en opsom die ASNs aan die einde van die scan.
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
Jy kan die IP ranges van 'n organisasie ook vind deur [http://asnlookup.com/](http://asnlookup.com) te gebruik (dit het 'n gratis API).\
Jy kan die IP en ASN van 'n domein vind met [http://ipv4info.com/](http://ipv4info.com).

### **Op soek na kwetsbaarhede**

Op hierdie stadium ken ons **al die assets binne die scope**, so as jy toestemming het kan jy 'n **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) oor al die hosts laat loop.\
Ook kan jy [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) loods **of gebruik dienste soos** Shodan, Censys, of ZoomEye **om** open ports te vind **en afhangend van wat jy vind behoort jy** in hierdie boek te kyk hoe om verskeie moontlike dienste wat loop te pentest.\
**Ook, dit kan die moeite werd wees om te noem dat jy ook kan voorberei sommige** default username **en** passwords **lyste en probeer om te** bruteforce dienste met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeine

> Ons ken al die maatskappye binne die scope en hul assets, dit is tyd om die domeine binne die scope te vind.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

Eerstens moet jy kyk na die **hoofdomein**(e) van elke maatskappy. Byvoorbeeld, vir _Tesla Inc._ is dit _tesla.com_.

### **Reverse DNS**

Sodra jy al die IP ranges van die domeine gevind het, kan jy probeer om **reverse dns lookups** op daardie **IPs uit te voer om meer domeine binne die scope te vind**. Probeer om 'n dns server van die victim of 'n bekende dns server (1.1.1.1, 8.8.8.8) te gebruik.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Vir dit om te werk, moet die administrateur handmatig die PTR aktiveer.\
Jy kan ook 'n aanlyn hulpmiddel gebruik vir hierdie inligting: [http://ptrarchive.com/](http://ptrarchive.com).\
Vir groot reekse is gereedskap soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse-opsoeke en verryking te outomatiseer.

### **Reverse Whois (loop)**

In 'n **whois** kan jy baie interessante **inligting** vind soos **organisasie naam**, **adres**, **e-posadresse**, telefoonnommers... Maar wat nog meer interessant is, is dat jy **meer bates wat aan die maatskappy verwant is** kan vind as jy **reverse whois lookups by enige van daardie velde** uitvoer (byvoorbeeld ander whois rekords waar dieselfde e-pos verskyn).\
Jy kan aanlyn hulpmiddels gebruik soos:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Gratis** web, nie gratis API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie gratis
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis
- [https://securitytrails.com/](https://securitytrails.com/) - Nie gratis (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nie gratis (API)

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink) (vereis 'n whoxy API-sleutel).\
Jy kan ook sommige outomatiese reverse whois-ontdekkings uitvoer met [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Let wel dat jy hierdie tegniek kan gebruik om meer domeinnomme te ontdek elke keer as jy 'n nuwe domein vind.**

### **Trackers**

As jy dieselfde ID van dieselfde tracker op 2 verskillende bladsye vind, kan jy aanvaar dat **albei bladsye** deur dieselfde span bestuur word.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is 'n paar webbladsye en gereedskap wat jou toelaat om volgens hierdie trackers en meer te soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (vind verwante sites deur gedeelde analytics/trackers)

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine tot ons teiken kan vind deur na dieselfde favicon-ikoon hash te kyk? Dit is presies wat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) gereedskap gemaak deur [@m4ll0k2](https://twitter.com/m4ll0k2) doen. So gebruik jy dit:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ontdek domeine met dieselfde favicon ikoon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kortliks, favihash sal ons toelaat om domeine te ontdek wat dieselfde favicon ikoon hash as ons teiken het.

Verder kan jy ook tegnologieë soek met behulp van die favicon hash soos verduidelik in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Dit beteken dat as jy die **hash van die favicon van 'n kwesbare weergawe van 'n web tech** ken, jy dit in shodan kan soek en **meer kwesbare plekke vind**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Só kan jy **calculate the favicon hash** van 'n web:
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
Jy kan ook favicon hashes op skaal kry met [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) en dan pivot in Shodan/Censys.

### **Auteursreg / Unieke string**

Soek binne die webwerwe **stringe wat oor verskeie webwerwe in dieselfde organisasie gedeel kan word**. Die **auteursreg-string** kan 'n goeie voorbeeld wees. Soek dan na daardie string in **google**, in ander **browsers** of selfs in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Tyd**

Dit is algemeen om 'n cron job te hê soos
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
om al die domeinsertifikate op die bediener te hernu. Dit beteken dat selfs al stel die CA wat hiervoor gebruik is nie die tyd waarop dit gegenereer is in die Validity time nie, is dit moontlik om **domeine wat aan dieselfde maatskappy behoort in die certificate transparency logs te vind**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-inligting

Jy kan 'n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of 'n gereedskap soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domeine en subdomeine wat dieselfde dmarc-inligting deel** te vind.\
Andere nuttige hulpmiddels is [**spoofcheck**](https://github.com/BishopFox/spoofcheck) en [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Blykbaar is dit algemeen dat mense subdomeine aan IP's toeken wat aan cloudverskaffers behoort en op 'n stadium daardie IP-adres verloor, maar vergeet om die DNS-rekord te verwyder. Daarom, deur net 'n **spawning a VM** in 'n cloud (like Digital Ocean) te skep, sal jy eintlik **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) verduidelik 'n storie daaroor en stel 'n skrip voor wat **spawns a VM in DigitalOcean**, **gets** die **IPv4** van die nuwe masjien, en **searches in Virustotal for subdomain records** wat daarna wys.

### **Other ways**

**Let wel dat jy hierdie tegniek kan gebruik om meer domeinnomme te ontdek elke keer as jy 'n nuwe domein vind.**

**Shodan**

Aangesien jy reeds die naam van die organisasie wat die IP-ruimte besit ken, kan jy daardie data in shodan soek met: `org:"Tesla, Inc."` Kontroleer die gevonde hosts vir nuwe onverwagte domeine in die TLS certificate.

Jy kan die **TLS certificate** van die hoofwebblad benader, die **Organisation name** bekom en dan vir daardie naam soek binne die **TLS certificates** van al die webblaaie wat deur **shodan** bekend is met die filter : `ssl:"Tesla Motors"` of gebruik 'n gereedskap soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is 'n tool wat soek na **domains related** met 'n hoofdomein en **subdomains** daarvan, baie indrukwekkend.

**Passive DNS / Historical DNS**

Passive DNS-data is uitstekend om ou en vergete rekords te vind wat steeds oplos of wat oor geneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Kyk na 'n [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien gebruik 'n maatskappy 'n domein maar hulle het die eienaarskap verloor. Registreer dit net (as dit goedkoop genoeg is) en laat die maatskappy weet.

As jy 'n domein vind met 'n IP wat van die een verskil wat jy reeds in die assets discovery gevind het, moet jy 'n basiese kwesbaarheidsskandering uitvoer (met Nessus of OpenVAS) en 'n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangend van watter dienste loop, kan jy in hierdie boek truuks vind om dit te "attack".\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomeine

> Ons ken al die maatskappye binne die scope, al die assets van elke maatskappy en al die domeine wat met die maatskappye verband hou.

> [!TIP]
> Let wel dat sommige van die gereedskap en tegnieke om domeine te vind ook kan help om subdomeine te vind

### **DNS**

Kom ons probeer om **subdomeine** uit die **DNS**-rekords te kry. Ons moet ook probeer vir **Zone Transfer** (As dit kwesbaar is, moet jy dit rapporteer).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die vinnigste manier om baie subdomains te bekom, is om in eksterne bronne te soek. Die mees gebruikte **gereedskap** is die volgende (vir beter resultate, konfigureer die API keys):

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
Daar is **ander interessante tools/APIs** wat, selfs al is hulle nie direk gespesialiseer in die vind van subdomains nie, nuttig kan wees om subdomains te vind, soos:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Gebruik die API [https://sonar.omnisint.io](https://sonar.omnisint.io) om subdomains te verkry
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
- [**gau**](https://github.com/lc/gau)**:** haal bekende URLs van AlienVault's Open Threat Exchange, die Wayback Machine en Common Crawl vir enige gegewe domein.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hulle skandeer die web na JS files en onttrek subdomains daaruit.
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
- [**securitytrails.com**](https://securitytrails.com/) het 'n gratis API om na subdomains en IP-geskiedenis te soek
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Hierdie project bied **gratis alle subdomains wat verband hou met bug-bounty programs**. Jy kan ook toegang tot hierdie data kry deur [chaospy](https://github.com/dr-0x0x/chaospy) te gebruik of selfs toegang tot die scope wat deur hierdie project gebruik word by [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan 'n **vergelyking** van baie van hierdie tools hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomains** te vind deur DNS-servers te brute-force deur moontlike subdomain names te gebruik.

Vir hierdie aksie het jy 'n paar common subdomains wordlists nodig soos:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IPs van goeie DNS resolvers. Om 'n lys van vertroude DNS resolvers te genereer kan jy die resolvers aflaai vanaf [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole tools vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat 'n effektiewe DNS brute-force uitgevoer het. Dit is baie vinnig, maar dit is vatbaar vir vals positiewe.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ek dink hierdie een gebruik net 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is 'n wrapper rondom `massdns`, geskryf in go, wat jou toelaat om geldige subdomains te enumerate deur gebruik te maak van active bruteforce, sowel as om subdomains te resolve met wildcard handling en maklike input-output support.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinname asynchroon te brute force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Tweede DNS Brute-Force Rondte

Nadat jy subdomains gevind het met behulp van openbare bronne en brute-forcing, kan jy variasies van die gevonde subdomains genereer om nog meer te probeer vind. Verskeie tools is nuttig vir hierdie doel:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Neem die domains en subdomains as insette en genereer permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Gegee die domeine en subdomeine genereer permutasies.
- Jy kan die goaltdns permutasies **wordlist** kry by [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegewe die domeine en subdomeine genereer permutasies. As geen permutasielêer aangedui is nie, sal gotator sy eie gebruik.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Afgesien van die generering van subdomein-permutasies, kan dit ook probeer om hulle op te los (maar dit is beter om die hierbo genoemde tools te gebruik).
- Jy kan die altdns permutations **wordlist** kry by die skakel: [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Nog 'n tool om permutations, mutations en alteration van subdomains uit te voer. Hierdie tool sal die resultaat brute force (dit ondersteun nie dns wild card nie).
- Jy kan die dmut permutations wordlist kry by [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Gebaseer op 'n domain genereer dit **nuwe potensiële subdomain-name** gebaseer op aangegewe patrone om meer subdomains te probeer ontdek.

#### Slim permutasiegenerering

- [**regulator**](https://github.com/cramppet/regulator): Vir meer inligting lees hierdie [**artikel**](https://cramppet.github.io/regulator/index.html), maar dit haal basies die **hoofdele** van die **ontdekte subdomains** en meng dit om meer subdomains te vind.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is 'n subdomain brute-force fuzzer wat gekoppel is aan 'n uiters eenvoudige maar doeltreffende DNS-respons-geleide algoritme. Dit gebruik 'n verskafde stel insetdata, soos 'n aangepaste wordlist of historiese DNS/TLS rekords, om akkuraat meer ooreenstemmende domeinnomme te sintetiseer en dit verder in 'n lus uit te brei gebaseer op inligting wat tydens 'n DNS-scan versamel is.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Kyk na hierdie blogpos wat ek geskryf het oor hoe om die **subdomain discovery** te **outomatiseer** vanaf 'n domein met **Trickest workflows**, sodat ek nie handmatig 'n klomp gereedskap op my rekenaar hoef te begin nie:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

As jy 'n IP-adres gevind het wat **een of verskeie webblaaie** bevat wat by subdomains behoort, kan jy probeer om **ander subdomains met webwerwe op daardie IP te vind** deur in **OSINT-bronne** te kyk na domeine op daardie IP of deur **brute-forcing VHost domain names in that IP**.

#### OSINT

Jy kan sommige **VHosts in IPs vind deur** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander APIs** te gebruik.

**Brute Force**

As jy vermoed dat 'n subdomain in 'n webbediener versteek kan wees, kan jy probeer om dit te brute force:
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
> Met hierdie tegniek kan jy selfs toegang kry tot interne/verborge endpoints.

### **CORS Brute Force**

Soms sal jy bladsye vind wat net die header _**Access-Control-Allow-Origin**_ teruggee wanneer 'n geldige domein/subdomein in die _**Origin**_ header gestel is. In hierdie scenario's kan jy hierdie gedrag misbruik om **nuwe** **subdomeine** te **ontdek**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Terwyl jy na **subdomains** soek, hou 'n oog of dit na enige tipe **bucket** wys, en in daardie geval [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ook, aangesien jy op hierdie stadium al die domains binne die scope sal ken, probeer om [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitering**

Jy kan **moniteer** of **new subdomains** van 'n domain geskep word deur die **Certificate Transparency** Logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) doen.

### **Op soek na kwesbaarhede**

Gaan na moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na 'n **S3 bucket** wys, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomain with an IP different** vind van die IP's wat jy reeds in die assets discovery gevind het, moet jy 'n **basic vulnerability scan** (using Nessus or OpenVAS) en 'n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** uitvoer. Afhangend van watter dienste loop, kan jy in **this book some tricks to "attack" them** vind.\
_Let wel dat soms die subdomain op 'n IP gehost word wat nie deur die kliënt beheer word nie, so dit is nie in die scope nie — wees versigtig._

## IPs

In die aanvanklike stappe mag jy alreeds sekere **IP ranges, domains and subdomains** gevind het.\
Dit is tyd om al die **IPs uit daardie ranges** in te samel en ook vir die **domains/subdomains (DNS queries).**

Deur dienste van die volgende **gratis APIs** te gebruik, kan jy ook **previous IPs used by domains and subdomains** vind. Hierdie IPs mag steeds deur die kliënt besit word (en kan jou toelaat om [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook nagaan watter domains na 'n spesifieke IP wys met die tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Op soek na kwesbaarhede**

**Port scan all the IPs that doesn’t belong to CDNs** (aangesien jy waarskynlik niks interessant daar sal vind nie). In die ontdekte lopende dienste kan jy moontlik kwesbaarhede vind.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Soek na webservers

> Ons het al die maatskappye en hul assets gevind en ons ken die IP ranges, domains en subdomains binne die scope. Dit is tyd om na web servers te soek.

In die vorige stappe het jy waarskynlik reeds 'n mate van **recon of the IPs and domains discovered** gedoen, so jy mag al die moontlike web servers al gevind het. As jy dit nog nie gedoen het nie, gaan ons nou 'n paar vinnige truuks sien om web servers binne die scope te soek.

Neem asseblief kennis dat dit georiënteer is op web apps discovery, dus behoort jy ook **perform the vulnerability** en **port scanning** uit te voer (**if allowed** deur die scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Nog 'n vriendelike tool om na web servers te soek is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy gee bloot 'n lys domains en dit sal probeer koppel aan poort 80 (http) en 443 (https). Verder kan jy aandui om ander poorte te probeer:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Nou dat jy **all the web servers** ontdek het wat in die scope voorkom (onder die **IPs** van die maatskappy en al die **domains** en **subdomains**) weet jy waarskynlik **nie waar om te begin nie**. Maak dit eenvoudig en begin deur net screenshots van almal te neem. Deur net die **main page** te **bekyk** kan jy **weird** endpoints vind wat meer geneig is om **vulnerable** te wees.

Om die voorgestelde idee uit te voer kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** gebruik.**

Verder kan jy dan [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om al die **screenshots** te deursoek en te vertel wat waarskynlik **vulnerabilities** bevat, en wat nie.

## Public Cloud Assets

Om potensiële cloud assets wat aan 'n maatskappy behoort te vind, moet jy **begin met 'n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir 'n crypto maatskappy kan jy woorde gebruik soos: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Jy sal ook wordlists nodig hê van **common words used in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dan, met daardie woorde moet jy **permutations** genereer (kyk die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende wordlists kan jy tools soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat wanneer jy na Cloud Assets soek jy moet **look for more than just buckets in AWS**.

### **Looking for vulnerabilities**

As jy dinge vind soos **open buckets or cloud functions exposed** moet jy **access them** en probeer sien wat hulle jou bied en of jy dit kan abuse.

## Emails

Met die **domains** en **subdomains** binne die scope het jy basies alles wat jy **need to start searching for emails**. Hierdie is die **APIs** en **tools** wat vir my die beste gewerk het om e-posse van 'n maatskappy te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met APIs
- API van [**https://hunter.io/**](https://hunter.io/) (free version)
- API van [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API van [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

E-posse sal handig wees later om **brute-force web logins and auth services** (soos **SSH**) te doen. Ook is hulle nodig vir **phishings**. Verder sal hierdie APIs jou selfs meer **info about the person** agter die e-pos gee, wat nuttig is vir die phishing-veldtog.

## Credential Leaks

Met die **domains,** **subdomains**, en **emails** kan jy begin soek na credentials wat in die verlede ge-leak is en aan daardie e-posse behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

As jy **valid leaked** credentials vind, is dit 'n baie maklike win.

## Secrets Leaks

Credential leaks is verwant aan hacks van maatskappye waar **sensitive information was leaked and sold**. Maatskappye mag egter ook geraak word deur **ander leaks** waarvan die inligting nie in daardie databasisse is nie:

### Github Leaks

Credentials en APIs kan ge-leak wees in die **public repositories** van die **company** of van die **users** wat vir daardie github maatskappy werk.\
Jy kan die **tool** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om alle **public repos** van 'n **organization** en van sy **developers** af te **download** en automatisch [**gitleaks**](https://github.com/zricethezav/gitleaks) daaroor te laat loop.

**Leakos** kan ook gebruik word om **gitleaks** te laat loop teen al die **text** verskafde **URLs passed** aan dit aangesien soms **web pages also contains secrets**.

#### Github Dorks

Kyk ook hierdie **page** vir potensiële **github dorks** wat jy in die organisasie wat jy aanval kan soek:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Soms publiseer aanvallers of net werknemers maatskappy-inhoud op 'n paste site. Dit mag of mag nie **sensitive information** bevat nie, maar dit is baie interessant om daarna te soek.\
Jy kan die tool [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om in meer as 80 paste sites gelyktydig te soek.

### Google Dorks

Oud maar goud — google dorks is altyd nuttig om **exposed information that shouldn't be there** te vind. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) verskeie **thousands** van moontlike queries bevat wat jy nie handmatig kan hardloop nie. Dus, jy kan jou gunsteling 10 kies of 'n **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **gebruik om hulle almal te run**.

Let wel dat tools wat verwag om die hele database via die gewone Google browser te loop nooit sal klaarmaak nie aangesien google jou baie vinnig sal blokkeer.

### **Looking for vulnerabilities**

As jy **valid leaked** credentials of API tokens vind, is dit 'n baie maklike win.

## Public Code Vulnerabilities

As jy gevind het dat die maatskappy **open-source code** het, kan jy dit **analyse** en soek na **vulnerabilities** daarin.

**Afhangende van die language** is daar verskillende **tools** wat jy kan gebruik:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Daar is ook gratis dienste wat jou toelaat om **public repositories** te **scan**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **majority of the vulnerabilities** wat bug hunters vind lê binne **web applications**, so op hierdie punt wil ek praat oor 'n **web application testing methodology**, en jy kan [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook 'n spesiale noem maak van die afdeling [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), aangesien, alhoewel jy nie moet verwag dat hulle baie sensitiewe vulnerabilities vind nie, hulle handig is om in **workflows** geïmplementeer te word om 'n aanvanklike web-inligting te kry.

## Recapitulation

> Congratulations! Op hierdie stadium het jy reeds **all the basic enumeration** uitgevoer. Ja, dit is basic want baie meer enumeration kan gedoen word (ons sal later meer truuks sien).

So jy het reeds:

1. Gevind al die **companies** binne die scope
2. Gevind al die **assets** wat aan die companies behoort (en sommige vuln scan uitgevoer indien in scope)
3. Gevind al die **domains** wat aan die companies behoort
4. Gevind al die **subdomains** van die domains (any subdomain takeover?)
5. Gevind al die **IPs** (van en **not from CDNs**) binne die scope.
6. Gevind al die **web servers** en 'n **screenshot** daarvan geneem (iets weird wat 'n dieper kyk werd is?)
7. Gevind al die **potential public cloud assets** wat aan die maatskappy behoort.
8. **Emails**, **credentials leaks**, en **secret leaks** wat jou 'n **big win very easily** kan gee.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Daar is verskeie tools daar buite wat 'n deel van die voorgestelde aksies teen 'n gegewe scope sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 'n bietjie oud en nie geüpdate nie

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
