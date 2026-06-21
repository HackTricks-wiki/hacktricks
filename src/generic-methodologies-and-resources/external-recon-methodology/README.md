# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assetontdekkings

> So jy is vertel dat alles wat aan een of ander maatskappy behoort binne die scope is, en jy wil uitvind wat hierdie maatskappy eintlik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te verkry en dan al die **assets** van hierdie maatskappye. Om dit te doen, gaan ons:

1. Vind die acquisitions van die hoofmaatskappy, dit sal vir ons die maatskappye binne die scope gee.
2. Vind die ASN (indien enige) van elke maatskappy, dit sal vir ons die IP ranges gee wat deur elke maatskappy besit word
3. Gebruik reverse whois lookups om na ander entries (organisation names, domains...) wat verband hou met die eerste een te soek (dit kan rekursief gedoen word)
4. Gebruik ander tegnieke soos shodan `org`en `ssl`filters om na ander assets te soek (die `ssl` truuk kan rekursief gedoen word).

### **Acquisitions**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, na die **hoofmaatskappy** te **search**, en op "**acquisitions**" te **click**. Daar sal jy ander maatskappye sien wat deur die hoofeen acquired is.\
Nog 'n opsie is om die **Wikipedia**-bladsy van die hoofmaatskappy te besoek en na **acquisitions** te search.\
Vir openbare maatskappye, kyk na **SEC/EDGAR filings**, **investor relations** bladsye, of plaaslike korporatiewe registers (bv. **Companies House** in die VK).\
Vir globale korporatiewe bome en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI** databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, op hierdie stadium behoort jy al die maatskappye binne die scope te ken. Kom ons vind uit hoe om hulle assets te vind.

### **ASNs**

'n outonome stelselnommer (**ASN**) is 'n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan 'n **outonome stelsel** (AS) toegeken word.\
'n **AS** bestaan uit **blokke** van **IP addresses** wat 'n duidelik gedefinieerde beleid het vir toegang tot eksterne netwerke en word deur 'n enkele organisasie geadministreer, maar kan uit verskeie operators bestaan.

Dit is interessant om vas te stel of die **maatskappy enige ASN** toegewys het om sy **IP ranges** te vind. Dit sal interessant wees om 'n **vulnerability test** teen al die **hosts** binne die **scope** uit te voer en na **domains** binne hierdie IP's te kyk.\
Jy kan **search** volgens maatskappy **name**, volgens **IP** of volgens **domain** in [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die streek van die maatskappy kan hierdie links nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). In elk geval, waarskynlik verskyn al die** useful information **(IP ranges and Whois)** reeds in die eerste link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration versamel en som ASNs outomaties op aan die einde van die scan.
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
Jy kan ook die IP-reekse van ’n organisasie vind deur [http://asnlookup.com/](http://asnlookup.com) te gebruik (dit het ’n gratis API).\
Jy kan die IP en ASN van ’n domein vind met [http://ipv4info.com/](http://ipv4info.com).

### **Soek na kwesbaarhede**

Op hierdie punt weet ons **al die bates binne die scope**, so as jy toegelaat word, kan jy ’n **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) oor al die hosts laat loop.\
Ook kan jy ’n paar [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) laat loop **of dienste soos** Shodan, Censys, of ZoomEye **gebruik om** open ports **te vind, en afhangend van wat jy vind, behoort jy** in hierdie boek te kyk hoe om verskeie moontlike dienste wat loop te pentest.\
**Ook kan dit die moeite werd wees om te noem dat jy ook ’n paar** default username **en** passwords **lyste kan voorberei en probeer om** services met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) te bruteforce.

## Domains

> Ons ken al die maatskappye binne die scope en hul bates, nou is dit tyd om die domains binne die scope te vind.

_Let asseblief daarop dat jy in die volgende beoogde tegnieke ook subdomains kan vind en daardie inligting moet nie onderskat word nie._

Eerstens moet jy soek na die **main domain**(s) van elke maatskappy. Byvoorbeeld, vir _Tesla Inc._ gaan dit _tesla.com_ wees.

### **Reverse DNS**

Aangesien jy al die IP-reekse van die domains gevind het, kan jy probeer om **reverse dns lookups** op daardie **IPs uit te voer om meer domains binne die scope te vind**. Probeer om ’n dns server van die slagoffer of ’n bekende dns server (1.1.1.1, 8.8.8.8) te gebruik
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Vir dit om te werk, moet die administrateur die PTR handmatig aktiveer.\
Jy kan ook ’n aanlyn hulpmiddel vir hierdie inligting gebruik: [http://ptrarchive.com/](http://ptrarchive.com).\
Vir groot reekse is gereedskap soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en enrichment te outomatiseer.

### **Reverse Whois (loop)**

Binne ’n **whois** kan jy baie interessante **information** vind soos **organisation name**, **address**, **emails**, telefoonnommers... Maar wat selfs interessanter is, is dat jy **meer assets related to the company** kan vind as jy **reverse whois lookups** op enige van daardie velde doen (byvoorbeeld ander whois-registries waar dieselfde e-pos verskyn).\
Jy kan aanlyn tools soos die volgende gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
Jy kan ook ’n mate van outomatiese reverse whois discovery met [amass](https://github.com/OWASP/Amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domain names te ontdek elke keer as jy ’n nuwe domain vind.**

### **Trackers**

As jy die **selfde ID van die selfde tracker** op 2 verskillende pages vind, kan jy aanneem dat **albei pages** deur dieselfde team bestuur word.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie pages sien.

Daar is sommige pages en tools wat jou toelaat om volgens hierdie trackers en meer te soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Het jy geweet dat ons verwante domains en subdomains na ons target kan vind deur vir dieselfde favicon icon hash te kyk? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool, gemaak deur [@m4ll0k2](https://twitter.com/m4ll0k2), doen. Hier is hoe om dit te gebruik:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, favihash sal ons toelaat om domeine te ontdek wat dieselfde favicon-ikoon-hash as ons teiken het.

Verder kan jy ook tegnologieë soek deur die favicon-hash te gebruik, soos verduidelik in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Dit beteken dat as jy die **hash van die favicon van 'n kwesbare weergawe van 'n web tech** ken, jy kan soek of dit in shodan is en **meer kwesbare plekke vind**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Dit is hoe jy die **favicon hash** van ’n web kan bereken:
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
Jy kan ook favicon-hashes op skaal kry met [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) en dan pivot in Shodan/Censys.

### **Copyright / Uniq string**

Soek binne die webbladsye **strings wat tussen verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **copyright string** kan ’n goeie voorbeeld wees. Soek dan vir daardie string in **google**, in ander **browsers** of selfs in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Dit is algemeen om ’n cron job te hê soos
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
om al die domein-sertifikate op die bediener te vernuwe. Dit beteken dat selfs al stel die CA wat hiervoor gebruik is nie die tyd in die Validity-tyd wanneer dit gegenereer is nie, is dit moontlik om **domeine te vind wat aan dieselfde maatskappy behoort in die certificate transparency logs**.\
Kyk na hierdie [**writeup vir meer inligting**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Gebruik ook die **certificate transparency** logs direk:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Jy kan 'n web soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of 'n tool soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domeine en subdomeine wat dieselfde dmarc information deel** te vind.\
Ander nuttige tools is [**spoofcheck**](https://github.com/BishopFox/spoofcheck) en [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Blykbaar is dit algemeen dat mense subdomeine toewys aan IPs wat aan cloud providers behoort en op 'n stadium **daardie IP-adres verloor, maar vergeet om die DNS record te verwyder**. Daarom, deur net 'n **VM te skep** in 'n cloud (soos Digital Ocean), sal jy in werklikheid **sekere subdomein(s) oorneem**.

[**Hierdie post**](https://kmsec.uk/blog/passive-takeover/) verduidelik 'n store daaroor en stel 'n script voor wat **'n VM in DigitalOcean skep**, **die** **IPv4** van die nuwe masjien **kry**, en **in Virustotal na subdomain records soek** wat daarna verwys.

### **Other ways**

**Let daarop dat jy hierdie technique kan gebruik om meer domain names te ontdek elke keer as jy 'n nuwe domain vind.**

**Shodan**

Soos jy reeds die naam van die organisation wat die IP space besit, ken. Jy kan volgens daardie data in shodan soek met: `org:"Tesla, Inc."` Kyk die gevonde hosts na vir nuwe onverwachte domains in die TLS certificate.

Jy kan die **TLS certificate** van die hoofwebblad oopmaak, die **Organisation name** bekom en dan na daardie naam binne die **TLS certificates** van al die webblaaie soek wat deur **shodan** bekend is met die filter : `ssl:"Tesla Motors"` of gebruik 'n tool soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is 'n tool wat soek na **domains related** met 'n hoofdomain en hul **subdomains**, nogal indrukwekkend.

**Passive DNS / Historical DNS**

Passive DNS data is uitstekend om **ou en vergete records** te vind wat steeds resolve of oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Kyk vir sommige [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien gebruik een of ander company 'n domain maar hulle het die ownership verloor. Registreer dit net (as dit goedkoop genoeg is) en laat die company weet.

As jy enige **domain met 'n ander IP** vind as die een wat jy reeds in die assets discovery gevind het, moet jy 'n **basiese vulnerability scan** uitvoer (met Nessus of OpenVAS) en 'n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangende van watter services loop, kan jy in **hierdie boek** sommige tricks vind om hulle te "attack".\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

Dis tyd om al die moontlike subdomains van elke gevonde domain te vind.

> [!TIP]
> Let daarop dat sommige van die tools and techniques om domains te vind, ook kan help om subdomains te vind

### **DNS**

Kom ons probeer om **subdomains** uit die **DNS** records te kry. Ons moet ook **Zone Transfer** probeer (As dit kwesbaar is, moet jy dit rapporteer).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die vinnigste manier om baie subdomeine te verkry is om in eksterne bronne te soek. Die mees gebruikte **tools** is die volgende (vir beter resultate, stel die API-sleutels op):

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
Daar is **ander interessante tools/APIs** wat, selfs al is hulle nie direk gespesialiseerd in die vind van subdomains nie, nuttig kan wees om subdomains te vind, soos:

- [**IP.THC.ORG**](https://ip.thc.org) gratis API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Gebruik die API [https://sonar.omnisint.io](https://sonar.omnisint.io) om subdomeine te verkry
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** haal bekende URLs van AlienVault se Open Threat Exchange, die Wayback Machine, en Common Crawl vir enige gegewe domain.
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
- [**securitytrails.com**](https://securitytrails.com/) het ’n gratis API om na subdomeine en IP-geskiedenis te soek
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Hierdie projek bied **gratis al die subdomeine wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data kry met [chaospy](https://github.com/dr-0x0x/chaospy) of selfs die scope gebruik wat deur hierdie projek gebruik word [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan ’n **vergelyking** van baie van hierdie tools hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer nuwe **subdomeine** vind deur DNS-bedieners te brute-force met moontlike subdomeinnaam.

Vir hierdie aksie sal jy ’n paar **algemene subdomein woordlyste soos** nodig hê:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP's van goeie DNS-resolvers. Om ’n lys van betroubare DNS-resolvers te genereer, kan jy die resolvers aflaai van [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole tools vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat ’n doeltreffende DNS brute-force uitgevoer het. Dit is baie vinnig, maar dit is geneig tot vals positiewe.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik ek dink net 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is 'n wrapper around `massdns`, geskryf in go, wat jou toelaat om geldige subdomeine te enumerate met behulp van aktiewe bruteforce, asook subdomeine te resolve met wildcard handling en maklike input-output ondersteuning.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinname asinkroon te brute force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Tweede DNS Brute-Force Rondte

Nadat subdomeine met oop bronne en brute-forcing gevind is, kan jy variasies van die gevonde subdomeine genereer om nog meer te probeer vind. Verskeie tools is nuttig vir hierdie doel:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Gegee die domeine en subdomeine, genereer permutasies.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Gegee die domeine en subdomeine, genereer permutasies.
- Jy kan die goaltdns permutasies **woordelys** kry **hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegee die domains en subdomains, genereer permutasies. As geen permutasie-lêer aangedui is nie, sal gotator sy eie een gebruik.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Afgesien van die generering van subdomein-permutasies, kan dit hulle ook probeer oplos (maar dit is beter om die vorige gekommenteerde tools te gebruik).
- Jy kan die altdns-permutasies **woordelys** kry [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Nog ’n tool om permutasies, mutasies en veranderinge van subdomeine uit te voer. Hierdie tool sal die resultaat brute force (dit ondersteun nie dns wild card nie).
- Jy kan dmut-permutasies woordelys kry [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Gebaseer op ’n domein, **genereer nuwe moontlike subdomeinnaam** gebaseer op aangeduide patrone om meer subdomeine te probeer ontdek.

#### Slim permutasie-generering

- [**regulator**](https://github.com/cramppet/regulator): Vir meer inligting lees hierdie [**post**](https://cramppet.github.io/regulator/index.html) maar dit sal basies die **hoofdele** van die **ontdekte subdomeine** neem en dit meng om meer subdomeine te vind.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is ’n subdomein brute-force fuzzer gekoppel aan ’n geweldig eenvoudige maar effektiewe DNS-reaksie-geleide algoritme. Dit gebruik ’n verskafde stel invoerdata, soos ’n aangepaste woordelys of historiese DNS/TLS-rekords, om meer ooreenstemmende domeinname akkuraat te sintetiseer en dit nog verder uit te brei in ’n lus gebaseer op inligting wat tydens DNS-skandering ingesamel is.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Kyk na hierdie blogplasing wat ek geskryf het oor hoe om die **subdomain discovery** van 'n domain te **automatiseer** met **Trickest workflows** sodat ek nie handmatig 'n klomp tools op my rekenaar hoef te begin nie:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

As jy 'n IP-adres vind wat **een of meer web pages** bevat wat aan subdomains behoort, kan jy probeer om **ander subdomains met webs in daardie IP** te vind deur in **OSINT sources** te soek vir domains in 'n IP of deur **brute-forcing VHost domain names in that IP**.

#### OSINT

Jy kan sommige **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs** vind.

**Brute Force**

As jy vermoed dat 'n subdomain in 'n web server versteek kan wees, kan jy probeer om dit te brute force:

Wanneer die **IP redirects to a hostname** (name-based vhosts), fuzz die `Host` header direk en laat ffuf **auto-calibrate** om responses uit te lig wat verskil van die default vhost:
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
> Met hierdie tegniek kan jy selfs in staat wees om toegang te kry tot interne/verborgen endpoints.

### **CORS Brute Force**

Soms sal jy bladsye vind wat slegs die _**Access-Control-Allow-Origin**_ header terugstuur wanneer 'n geldige domain/subdomain in die _**Origin**_ header gestel is. In hierdie scenario's kan jy hierdie gedrag misbruik om nuwe **subdomains** te **ontdek**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Terwyl jy vir **subdomains** kyk, hou dop of dit na enige tipe **bucket** wys, en in daardie geval [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ook, aangesien jy teen hierdie punt al die domains binne die scope sal ken, probeer om [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Jy kan **monitor** of **new subdomains** van ’n domain geskep word deur die **Certificate Transparency** Logs te monitor [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Looking for vulnerabilities**

Kontroleer vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na ’n **S3 bucket** wys, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomain met ’n IP wat verskil** van die een wat jy reeds in die assets discovery gevind het, vind, moet jy ’n **basic vulnerability scan** uitvoer (met Nessus of OpenVAS) en ’n **port scan** [**met nmap/masscan/shodan**](../pentesting-network/index.html#discovering-hosts-from-the-outside). Afhangend van watter services loop, kan jy in **hierdie boek sommige truuks vind om hulle te "attack"**.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

In die aanvanklike stappe het jy dalk **’n paar IP ranges, domains en subdomains** gevind.\
Dis tyd om **al die IPs uit daardie ranges bymekaar te maak** en vir die **domains/subdomains (DNS queries).**

Deur services van die volgende **free apis** te gebruik, kan jy ook **vorige IPs vind wat deur domains en subdomains gebruik is**. Hierdie IPs kan steeds deur die client besit word (en kan jou toelaat om [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook vir domains kyk wat na ’n spesifieke IP address wys met die tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan al die IPs wat nie aan CDNs behoort nie** (want jy sal heel waarskynlik niks interessants daar vind nie). In die running services wat ontdek is, kan jy moontlik **vulnerabilities vind**.

**Vind ’n** [**guide**](../pentesting-network/index.html) **oor hoe om hosts te scan.**

## Web servers hunting

> Ons het al die companies en hul assets gevind en ons ken IP ranges, domains en subdomains binne die scope. Dis tyd om na web servers te soek.

In die vorige stappe het jy waarskynlik reeds sommige **recon van die IPs en domains wat ontdek is** uitgevoer, so jy het moontlik reeds **al die moontlike web servers gevind**. As jy dit egter nog nie gedoen het nie, gaan ons nou kyk na **vinnige truuks om na web servers te soek** binne die scope.

Neem asseblief kennis dat dit **gerig sal wees op web apps discovery**, so jy moet ook die **vulnerability** en **port scanning** uitvoer (**as dit deur die scope toegelaat word**).

’n **Vinnige metode** om **open ports** wat met **web** servers verband hou te ontdek met [**masscan** kan hier gevind word](../pentesting-network/index.html#http-port-discovery).\
Nog ’n vriendelike tool om na web servers te kyk is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy gee net ’n lys domains en dit sal probeer om aan port 80 (http) en 443 (https) te koppel. Bykomend kan jy aandui om ander ports te probeer:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Nou dat jy **al die web servers** ontdek het wat binne die scope val (tussen die **IPs** van die maatskappy en al die **domains** en **subdomains**) weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit dus eenvoudig en begin deur net skermgrepe van almal te neem. Deur net **na die hoofblad te kyk** kan jy **vreemde** endpoints vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** gebruik.**

Verder kan jy dan [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om al die **skermgrepe** te verwerk en jou te sê **wat waarskynlik kwesbaarhede bevat**, en wat nie.

## Public Cloud Assets

Om potensiële cloud assets te vind wat aan ’n maatskappy behoort, moet jy **begin met ’n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir ’n crypto-maatskappy kan jy woorde soos: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` gebruik.

Jy sal ook woordlyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dan moet jy met daardie woorde **permutations** genereer (kyk die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordlyste kan jy tools soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat wanneer jy na Cloud Assets soek, jy m**eer as net buckets in AWS moet soek**.

### **Looking for vulnerabilities**

As jy dinge vind soos **open buckets of cloud functions exposed** moet jy **hulle benader** en probeer sien wat hulle jou bied en of jy hulle kan abuse.

## Emails

Met die **domains** en **subdomains** binne die scope het jy basies alles wat jy **nodig het om te begin soek na emails**. Dit is die **APIs** en **tools** wat vir my die beste gewerk het om emails van ’n maatskappy te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met APIs
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Looking for vulnerabilities**

Emails sal later handig wees om **web logins en auth services** (soos SSH) te brute-force. Hulle is ook nodig vir **phishings**. Verder sal hierdie APIs jou selfs meer **info oor die persoon** agter die email gee, wat nuttig is vir die phishing campaign.

## Credential Leaks

Met die **domains,** **subdomains**, en **emails** kan jy begin soek na credentials wat in die verlede geleak is en aan daardie emails behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

As jy **geldige geleakte** credentials vind, is dit ’n baie maklike oorwinning.

## Secrets Leaks

Credential leaks hou verband met hacks van maatskappye waar **sensitiewe inligting geleak en verkoop** is. Maatskappye kan egter ook geraak word deur **ander leaks** waarvan die info nie in daardie databasisse is nie:

### Github Leaks

Credentials en APIs kan in die **public repositories** van die **maatskappy** of van die **gebruikers** wat vir daardie github-maatskappy werk, geleak wees.\
Jy kan die **tool** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om **al** die **public repos** van ’n **organization** en van sy **developers** af te laai en [**gitleaks**](https://github.com/zricethezav/gitleaks) outomaties daaroor te laat loop.

**Leakos** kan ook gebruik word om **gitleaks** teen al die **text** uit die **URLs passed** aan dit te laat loop, aangesien **web pages ook soms secrets bevat**.

#### Github Dorks

Kyk ook na hierdie **page** vir potensiële **github dorks** wat jy ook kan soek in die organization wat jy aanval:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Soms sal aanvallers of net werkers **maatskappy-inhoud in ’n paste site publiseer**. Dit mag al dan nie **sensitiewe inligting** bevat, maar dit is baie interessant om daarna te soek.\
Jy kan die tool [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om gelyktydig in meer as 80 paste sites te soek.

### Google Dorks

Ou, maar goud, google dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar behoort te wees nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) verskeie **duisende** moontlike queries bevat wat jy nie handmatig kan uitvoer nie. Daarom kan jy jou gunsteling 10 kies of jy kan ’n **tool soos** [**Gorks**](https://github.com/carlospolop/Gorks) **gebruik om hulle almal uit te voer**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

As jy **geldige geleakte** credentials of API tokens vind, is dit ’n baie maklike oorwinning.

## Public Code Vulnerabilities

As jy gevind het dat die maatskappy **open-source code** het, kan jy dit **analiseer** en na **kwesbaarhede** daarin soek.

**Afhangend van die taal** is daar verskillende **tools** wat jy kan gebruik:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Daar is ook gratis dienste wat jou toelaat om **public repositories te skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **meerderheid van die kwesbaarhede** wat deur bug hunters gevind word, is binne **web applications**, so op hierdie punt wil ek graag oor ’n **web application testing methodology** praat, en jy kan [**hier hierdie inligting vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook ’n spesiale vermelding maak van die afdeling [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want, al behoort jy nie te verwag dat hulle baie sensitiewe kwesbaarhede vir jou sal vind nie, is hulle handig om hulle in **workflows** te implementeer om aanvanklike web-inligting te kry.

## Recapitulation

> Baie geluk! Op hierdie punt het jy reeds **al die basiese enumerasie** uitgevoer. Ja, dit is basies omdat baie meer enumerasie gedoen kan word (ons sal later meer truuks sien).

So het jy reeds:

1. Al die **companies** binne die scope gevind
2. Al die **assets** wat aan die companies behoort gevind (en ’n vuln scan gedoen indien dit binne scope is)
3. Al die **domains** wat aan die companies behoort gevind
4. Al die **subdomains** van die domains gevind (enige subdomain takeover?)
5. Al die **IPs** (van en **nie van CDNs nie**) binne die scope gevind.
6. Al die **web servers** gevind en ’n **skermgreep** daarvan geneem (enigiets vreemd wat ’n dieper kyk werd is?)
7. Al die **potensiële public cloud assets** wat aan die maatskappy behoort gevind.
8. **Emails**, **credentials leaks**, en **secret leaks** wat jou baie maklik ’n **groot oorwinning** kan gee.
9. **Pentesting al die webs wat jy gevind het**

## **Full Recon Automatic Tools**

Daar is verskeie tools daar buite wat ’n deel van die voorgestelde aksies teen ’n gegewe scope sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - ’n Bietjie oud en nie opgedateer nie

## **References**

- Al die gratis kursusse van [**@Jhaddix**](https://twitter.com/Jhaddix) soos [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
