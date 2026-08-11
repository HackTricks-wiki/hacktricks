# Eksterne Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Bate-ontdekkings

> Daar is dus vir jou gesê dat alles wat aan een of ander maatskappy behoort binne die scope is, en jy wil uitvind wat hierdie maatskappy werklik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te verkry, en dan al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:

1. Die verkrygings van die hoofmaatskappy vind; dit sal ons die maatskappye binne die scope gee.
2. Die ASN (indien enige) van elke maatskappy vind; dit sal ons die IP-reekse gee wat deur elke maatskappy besit word.
3. Reverse whois lookups gebruik om na ander inskrywings (organisasiename, domains...) te soek wat met die eerste een verband hou (dit kan rekursief gedoen word).
4. Ander tegnieke soos shodan se `org`- en `ssl`-filters gebruik om na ander bates te soek (die `ssl`-truuk kan rekursief gedoen word).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, vir die **hoofmaatskappy** te **soek**, en op "**acquisitions**" te **klik**. Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
'n Ander opsie is om die **Wikipedia**-bladsy van die hoofmaatskappy te besoek en vir **acquisitions** te soek.\
Vir openbare maatskappye, gaan **SEC/EDGAR filings**, **investor relations**-bladsye, of plaaslike korporatiewe registers (bv. **Companies House** in die VK) na.\
Vir globale korporatiewe strukture en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI**-databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Goed, op hierdie punt behoort jy al die maatskappye binne die scope te ken. Kom ons vind uit hoe om hul bates te vind.

### **ASNs**

'n Autonomous System Number (**ASN**) is 'n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan 'n **autonomous system** (AS) toegeken word.\
'n **AS** bestaan uit **blokke** **IP-adresse** met 'n duidelik gedefinieerde beleid vir toegang tot eksterne netwerke, en word deur 'n enkele organisasie geadministreer, maar kan uit verskeie operators bestaan.

Dit is interessant om uit te vind of die **maatskappy enige ASN toegeken het** om sy **IP-reekse** te vind. Dit sal interessant wees om 'n **vulnerability test** teen al die **hosts** binne die **scope** uit te voer en na **domains** binne hierdie IP's te soek.\
Jy kan volgens maatskappy se **naam**, volgens **IP** of volgens **domain** soek by [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die streek van die maatskappy, kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In elk geval verskyn waarskynlik al die** nuttige inligting **(IP-reekse en Whois)** reeds in die eerste skakel.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** enumeration voeg outomaties ASNs saam en som dit aan die einde van die scan op.
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
Jy kan die IP-reekse van ’n organisasie ook met [http://asnlookup.com/](http://asnlookup.com) vind (dit het ’n gratis API).\
Jy kan die IP en ASN van ’n domein met [http://ipv4info.com/](http://ipv4info.com) vind.

### **Soek na kwesbaarhede**

Op hierdie stadium ken ons **al die bates binne die omvang**, dus, indien dit toegelaat word, kan jy ’n **kwesbaarheidskandeerder** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) oor al die gashere uitvoer.\
Jy kan ook [**poortskanderings**](../pentesting-network/index.html#discovering-hosts-from-the-outside) uitvoer **of dienste soos** Shodan, Censys of ZoomEye **gebruik om** oop poorte **te vind, en afhangend van wat jy vind, behoort jy** in hierdie boek te kyk hoe om verskeie moontlike dienste wat loop, te pentest.\
**Dit is ook die moeite werd om te noem dat jy sommige** verstekgebruikersnaam- **en** wagwoord-**lyste kan voorberei en probeer om dienste te** bruteforce met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Ons ken al die maatskappye binne die omvang en hul bates; dit is tyd om die domeine binne die omvang te vind.

_Let daarop dat jy met die volgende voorgestelde tegnieke ook subdomeine kan vind en dat daardie inligting nie onderskat moet word nie._

Eerstens moet jy die **hoofdomain**(e) van elke maatskappy soek. Byvoorbeeld, vir _Tesla Inc._ is dit _tesla.com_.

### **Reverse DNS**

Aangesien jy al die IP-reekse van die domeine gevind het, kan jy probeer om **reverse DNS lookups** op daardie **IP’s uit te voer om meer domeine binne die omvang te vind**. Probeer om ’n DNS-bediener van die slagoffer of ’n bekende DNS-bediener (1.1.1.1, 8.8.8.8) te gebruik.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Om dit te laat werk, moet die administrateur die PTR handmatig aktiveer.\
Jy kan ook ’n aanlynhulpmiddel vir hierdie inligting gebruik: [http://ptrarchive.com/](http://ptrarchive.com).\
Vir groot reekse is hulpmiddels soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en verryking te outomatiseer.

### **Reverse Whois (loop)**

Binne ’n **whois** kan jy baie interessante **inligting** vind, soos **organisasienaam**, **adres**, **e-posadresse**, telefoonnommers... Maar wat selfs interessanter is, is dat jy **meer bates wat met die maatskappy verband hou** kan vind as jy **reverse whois lookups volgens enige van daardie velde** uitvoer (byvoorbeeld ander whois-registers waar dieselfde e-posadres voorkom).\
Jy kan aanlynhulpmiddels soos die volgende gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web en API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** web, nie gratis API nie.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie gratis nie
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis nie (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis nie
- [https://securitytrails.com/](https://securitytrails.com/) - Nie gratis nie (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nie gratis nie (API)

Jy kan hierdie taak outomatiseer deur [**DomLink** ](https://github.com/vysecurity/DomLink) te gebruik (vereis ’n whoxy API-sleutel).\
Jy kan ook outomatiese reverse whois discovery met [amass](https://github.com/OWASP/Amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer wanneer jy ’n nuwe domein vind.**

### **Trackers**

As jy die **zelfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy aanneem dat **albei bladsye** deur **dieselfde span** bestuur word.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is sommige bladsye en hulpmiddels waarmee jy volgens hierdie trackers en meer kan soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (vind verwante webwerwe volgens gedeelde analytics/trackers)

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine vir ons teiken kan vind deur na dieselfde favicon-ikoonhash te soek? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)-hulpmiddel, wat deur [@m4ll0k2](https://twitter.com/m4ll0k2) gemaak is, doen. Hier is hoe om dit te gebruik:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Eenvoudig gestel, sal favihash ons in staat stel om domeine te ontdek wat dieselfde favicon-ikoon-hash as ons teiken het.

Gebruik ’n bekende favicon-hash as ’n Shodan- of FOFA-pivot om ander blootgestelde instansies van dieselfde tegnologie te vind.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Dit is hoe jy die **favicon-hash** van 'n webwerf kan **bereken** (MMH3 oor die **base64-geënkodeerde** favicon bytes):
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
Jy kan ook favicon-hashes op skaal kry met [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) en dan in Shodan/Censys pivot.

Behandel favicon-fingerprints as leidrade en valideer hulle met omliggende seine.<sup>[[3]](#references)[[4]](#references)</sup>

- **Behandel die hash as ’n aanduiding, nie as bewys nie**: MMH3 is kompak; collisions, hergebruikte ikone en doelbewuste spoofing is moontlik.
- **Probeer meer as** `/favicon.ico`: inspekteer framework/build-paaie, manifest-lêers, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data-URL’s en HTML `<link rel="icon">`-tags.
- **Statiese bates kan steeds bereikbaar wees agter WAF/SSO/IdP-kontroles**: versoek die ikoon direk en hersien `ETag`, `Last-Modified`, redirects en cache-headers.
- **Valideer matches met omliggende seine**: vergelyk die titel, HTML/body-hash, headers, TLS-sertifikaat-subjects/SANs, produkkomponente en blootgestelde poorte.
- **Cluster volgens HTML/body-hash**: ’n konsekwente template versterk die fingerprint; gemengde templates dui op ’n generiese of gedeelde ikoon.
- **Behandel ’n hash wat oor onverwante signatures, poorte en produkte voorkom as ’n moontlike honeypot of placeholder.**
- **Vergelyk op dubbelsinnige targets ’n werklike bladsy met ’n niebestaande pad** soos `/_favicon_probe_<8-hex>`; ooreenstemmende hosting- of parking-response kan die gedeelde ikoon verduidelik.
- **Begin triage met Nuclei-detection rules of publieke datasets** wat favicon-hashes aan produkte en CPE’s koppel.
- **Onthou die IP-sentriese coverage gap**: CDN-fronted, SNI-gerouteerde, anycast- en domein-alleen-oppervlakke kan in Shodan-agtige datasets ontbreek.

### **Kopiereg / Unieke string**

Soek binne die webblaaie na **strings wat oor verskillende webwerwe binne dieselfde organisasie gedeel kan word**. Die **kopiereg-string** kan ’n goeie voorbeeld wees. Soek dan vir daardie string in **Google**, in ander **blaaiers** of selfs in **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT-tyd**

Dit is algemeen om ’n cron job soos ’n
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
om alle sertifikate op ’n bediener gelyktydig te hernu. Die korrelasie van sertifikaattydstempels of posisies in certificate-transparency logs kan verwante domains openbaar.<sup>[[6]](#references)</sup>

Gebruik ook **certificate transparency** logs direk:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-inligting

Jy kan ’n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of ’n tool soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domains en subdomains wat dieselfde dmarc-inligting deel** te vind.\
Ander nuttige tools is [**spoofcheck**](https://github.com/BishopFox/spoofcheck) en [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

’n Verlate A-record kan bereikbaar word wanneer ’n cloud provider ’n IP hertoewys. Die verwysde navorsing demonstreer ’n opportunistiese workflow wat ’n instance voorsien en sy adres met passive DNS-data korreleer; toets takeover-scenario’s slegs binne die gemagtigde omvang.<sup>[[7]](#references)</sup>

### **Ander maniere**

**Shodan**

Aangesien jy reeds die naam van die organisasie ken wat die IP-spasie besit, kan jy volgens daardie data in shodan soek met: `org:"Tesla, Inc."` Kontroleer die gevonde hosts vir nuwe onverwagte domains in die TLS-sertifikaat.

Jy kan toegang tot die **TLS certificate** van die hoofwebblad verkry, die **Organisation name** bekom en dan binne die **TLS certificates** van al die webblaaie wat aan **shodan** bekend is vir daardie naam soek met die filter: `ssl:"Tesla Motors"` of ’n tool soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ’n tool wat soek na **domains verwant** aan ’n hoofdomein en **subdomains** daarvan; nogal indrukwekkend.

**Passive DNS / Historical DNS**

Passive DNS-data is uitstekend om **ou en vergete rekords** te vind wat steeds resolve of oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Soek na vulnerabilities**

Kyk vir ’n [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien **gebruik ’n maatskappy ’n domain**, maar hulle het **eienaarskap verloor**. Registreer dit net (indien goedkoop genoeg) en stel die maatskappy in kennis.

As jy enige **domain met ’n ander IP** as dié wat jy reeds tydens die assets discovery gevind het, opspoor, moet jy ’n **basic vulnerability scan** uitvoer (met Nessus of OpenVAS) en ’n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** doen. Afhangend van watter services loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "attack"**.\
_Let daarop dat die domain soms binne ’n IP gehuisves word wat nie deur die kliënt beheer word nie, en dus nie binne die scope val nie; wees versigtig._

## Subdomains

> Ons ken al die maatskappye binne die scope, al die bates van elke maatskappy en al die domains wat met die maatskappye verband hou.

Dit is tyd om al die moontlike subdomains van elke gevonde domain te vind.

> [!TIP]
> Let daarop dat sommige van die tools en tegnieke om domains te vind, ook kan help om subdomains te vind

### **DNS**

Kom ons probeer om **subdomains** uit die **DNS**-rekords te verkry. Ons moet ook **Zone Transfer** probeer (Indien dit vulnerable is, moet jy dit rapporteer).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die vinnigste manier om baie subdomeine te verkry, is om in eksterne bronne te soek. Die mees gebruikte **tools** is die volgende (vir beter resultate, stel die API-sleutels op):

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
Daar is **ander interessante tools/API's** wat, selfs al is hulle nie direk daarin gespesialiseerd om subdomeine te vind nie, nuttig kan wees om subdomeine te vind, soos:

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
- [**gau**](https://github.com/lc/gau)**:** haal bekende URL's van AlienVault se Open Threat Exchange, die Wayback Machine en Common Crawl vir enige gegewe domein.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hulle skandeer die web op soek na JS-lêers en onttrek subdomeine daaruit.
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
- [**Censys-subdomeinsoeker**](https://github.com/christophetd/censys-subdomain-finder)
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

Hierdie projek bied **gratis alle subdomeine wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data verkry deur [chaospy](https://github.com/dr-0x0x/chaospy), of selfs toegang verkry tot die scope wat deur hierdie projek gebruik word: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan ’n **vergelyking** van baie van hierdie tools hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomeine** te vind deur DNS-bedieners met moontlike subdomeinname te brute-force.

Vir hierdie aksie sal jy ’n paar **algemene subdomein-wordlists soos** die volgende benodig:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP’s van goeie DNS-resolvers. Om ’n lys van betroubare DNS-resolvers te genereer, kan jy die resolvers vanaf [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) aflaai en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan die volgende gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die tools wat die meeste vir DNS brute-force aanbeveel word, is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat effektiewe DNS brute-force uitgevoer het. Dit is baie vinnig, maar dit is geneig tot vals positiewe.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik, dink ek, net 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is ’n wrapper rondom `massdns`, geskryf in go, waarmee jy geldige subdomeine deur middel van aktiewe brute force kan enumeriseer, asook subdomeine met wildcard-hantering en maklike invoer-afvoerondersteuning kan resolve.
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
### Tweede DNS Brute-Force-ronde

Nadat jy subdomeine met behulp van oop bronne en brute-forcing gevind het, kan jy variasies van die gevonde subdomeine genereer om selfs meer te probeer vind. Verskeie tools is hiervoor nuttig:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Genereer permutasies gegewe die domeine en subdomeine.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Gegee die domeine en subdomeine, genereer permutasies.
- Jy kan goaltdns se permutasies-**wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegewe die domeine en subdomeine, genereer permutasies. Indien geen permutasielêer aangedui word nie, sal gotator sy eie een gebruik.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Benewens die generering van subdomein-permutasies, kan dit ook probeer om hulle op te los (maar dit is beter om die vorige, gekommentarieerde tools te gebruik).
- Jy kan altdns-permutasies se **wordlist** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Nog ’n tool om permutasies, mutasies en wysigings van subdomeine uit te voer. Hierdie tool sal die resultate brute force (dit ondersteun nie DNS-wildcards nie).
- Jy kan dmut se permutasies-woordelys [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Op grond van ’n domein **genereer dit nuwe potensiële subdomeinname** volgens aangeduide patrone om meer subdomeine te probeer ontdek.

#### Slim permutasie-generering

- [**regulator**](https://github.com/cramppet/regulator): Leer regex-agtige patrone uit ontdekte subdomeine en genereer kandidaatname om op te los.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is ’n subdomein-brute-force fuzzer wat met ’n uiters eenvoudige maar effektiewe DNS-response-guided algorithm gekombineer is. Dit gebruik ’n verskafte stel insetdata, soos ’n pasgemaakte wordlist of historiese DNS/TLS-records, om akkuraat meer ooreenstemmende domeinname te genereer en dit verder in ’n lus uit te brei op grond van inligting wat tydens die DNS-scan ingesamel is.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest-workflowvoorbeelde kombineer OSINT, DNS brute force en permutasiefases vir herhaalbare subdomain-enumerasie.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

As jy ’n IP-adres gevind het wat **een of verskeie webblaaie** bevat wat aan subdomains behoort, kan jy probeer om **ander subdomains met webblaaie op daardie IP te vind** deur in **OSINT-bronne** na domains op ’n IP te soek, of deur **VHost-domeinname op daardie IP te brute-force**.

#### OSINT

Jy kan sommige **VHosts in IP’s vind met** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander APIs**.

**Brute Force**

As jy vermoed dat ’n subdomain in ’n webserver versteek kan wees, kan jy probeer om dit te brute-force:

Vir naamgebaseerde vhosts, fuzz die `Host`-header en gebruik ffuf se outomatiese kalibrasie om die verstekrespons te filtreer.<sup>[[2]](#references)</sup>
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
> Met hierdie tegniek kan jy selfs toegang tot interne/versteekte endpoints verkry.

### **CORS Brute Force**

Soms sal jy bladsye vind wat slegs die header _**Access-Control-Allow-Origin**_ terugstuur wanneer ’n geldige domain/subdomain in die _**Origin**_-header gestel word. In hierdie scenario’s kan jy hierdie gedrag misbruik om nuwe **subdomains** te **ontdek**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Terwyl jy na **subdomains** soek, let daarop of dit na enige soort **bucket** **verwys**, en doen in daardie geval [**’n kontrolering van die permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Aangesien jy op hierdie stadium al die domains binne die scope sal ken, probeer ook om [**moontlike bucket-name te brute force en die permissions te kontroleer**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitering**

Jy kan **monitor** of **nuwe subdomains** van ’n domain geskep word deur die **Certificate Transparency** Logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Soek na kwesbaarhede**

Kontroleer vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na ’n **S3 bucket** verwys, [**kontroleer die permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomain met ’n ander IP** as dié wat jy reeds tydens die assets discovery gevind het, vind, moet jy ’n **basiese vulnerability scan** uitvoer (met Nessus of OpenVAS) en ’n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** doen. Afhangend van watter services loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "attack"**.\
_Neem kennis dat die subdomain soms binne ’n IP gehuisves word wat nie deur die kliënt beheer word nie, en dus nie binne die scope val nie; wees versigtig._

## IPs

In die aanvanklike stappe het jy moontlik **IP-ranges, domains en subdomains gevind**.\
Dit is tyd om **al die IPs uit daardie ranges te versamel**, asook dié vir die **domains/subdomains (DNS queries).**

Deur services van die volgende **gratis APIs** te gebruik, kan jy ook **vorige IPs vind wat deur domains en subdomains gebruik is**. Hierdie IPs behoort moontlik steeds aan die kliënt (en kan jou moontlik help om [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook kontroleer vir domains wat na ’n spesifieke IP-adres verwys deur die tool [**hakip2host**](https://github.com/hakluke/hakip2host) te gebruik.

### **Soek na kwesbaarhede**

**Doen ’n port scan op al die IPs wat nie aan CDNs behoort nie** (aangesien jy hoogs waarskynlik niks interessants daar sal vind nie). In die ontdekte running services kan jy moontlik **kwesbaarhede vind**.

**Vind ’n** [**guide**](../pentesting-network/index.html) **oor hoe om hosts te scan.**

## Soektog na web servers

> Ons het al die companies en hul assets gevind en ons ken die IP-ranges, domains en subdomains binne die scope. Dit is tyd om na web servers te soek.

In die vorige stappe het jy waarskynlik reeds ’n mate van **recon van die ontdekte IPs en domains uitgevoer**, en dus moontlik **al die moontlike web servers gevind**. As jy dit egter nie gedoen het nie, gaan ons nou ’n paar **vinnige truuks sien om web servers** binne die scope te vind.

Let asseblief daarop dat dit **vir web-app discovery georiënteer** sal wees, en dat jy ook **vulnerability** en **port scanning** moet uitvoer (**indien dit** deur die scope toegelaat word).

’n **Vinnige metode** om **oop ports** wat met **web** servers verband hou, deur [**masscan** te gebruik, kan hier gevind word](../pentesting-network/index.html#http-port-discovery).\
Nog ’n gebruikersvriendelike tool om na web servers te soek, is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy gee bloot ’n lys domains deur, waarna dit sal probeer om aan port 80 (http) en 443 (https) te koppel. Daarbenewens kan jy aandui dat dit ook ander ports moet probeer:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Skermkiekies**

Noudat jy **al die web servers** binne die scope ontdek het (onder die **IPs** van die maatskappy en al die **domains** en **subdomains**), weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit dus eenvoudig en begin deur net screenshots van almal te neem. Deur net na die **hoofblad** te **kyk**, kan jy **vreemde** endpoints vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** gebruik.**

Daarbenewens kan jy dan [**eyeballer**](https://github.com/BishopFox/eyeballer) oor al die **screenshots** laat loop om vir jou te sê **wat waarskynlik kwesbaarhede bevat**, en wat nie.

## Publieke Cloud Bates

Om potensiële cloud-bates te vind wat aan ’n maatskappy behoort, moet jy **begin met ’n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir ’n crypto-maatskappy kan jy woorde soos die volgende gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordelyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Daarna moet jy met daardie woorde **permutasies** genereer (kyk na die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordelyste kan jy tools soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat jy, wanneer jy na Cloud Assets soek, vir **meer as net buckets in AWS** moet **soek**.

### **Soek na kwesbaarhede**

As jy dinge soos **oop buckets of cloud functions wat blootgestel is** vind, moet jy **toegang daartoe verkry** en probeer vasstel wat hulle jou bied en of jy dit kan misbruik.

## E-posse

Met die **domains** en **subdomains** binne die scope het jy basies alles wat jy **nodig het om na e-posse te begin soek**. Dit is die **APIs** en **tools** wat die beste vir my gewerk het om ’n maatskappy se e-posse te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met APIs
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Soek na kwesbaarhede**

E-posse sal later handig te pas kom om **web logins en auth services te brute-force** (soos SSH). Hulle is ook nodig vir **phishings**. Boonop sal hierdie APIs jou selfs meer **inligting oor die persoon** agter die e-pos gee, wat nuttig is vir die phishing-veldtog.

## Credential Leaks

Met die **domains,** **subdomains** en **e-posse** kan jy begin soek na credentials wat in die verlede aan daardie e-posse behoort het en ge-leak is:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Soek na kwesbaarhede**

As jy **geldige credentials wat ge-leak is** vind, is dit ’n baie maklike oorwinning.

## Secrets Leaks

Credential leaks hou verband met hacks van maatskappye waar **sensitiewe inligting ge-leak en verkoop is**. Maatskappye kan egter deur **ander leaks** geraak word waarvan die inligting nie in daardie databasisse voorkom nie:

### Github Leaks

Credentials en APIs kan in die **publieke repositories** van die **maatskappy** of van die **users** wat by daardie github-maatskappy werk, ge-leak word.\
Jy kan die **tool** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **publieke repos** van ’n **organization** en sy **developers** af te laai en [**gitleaks**](https://github.com/zricethezav/gitleaks) outomaties daaroor te laat loop.

**Leakos** kan ook gebruik word om **gitleaks** teen al die **teks** van die **URLs wat daaraan verskaf word** te laat loop, aangesien **web pages** soms ook secrets bevat.

#### Github Dorks

Kyk na die [GitHub dorks and leaks page](github-leaked-secrets.md) vir potensiële **GitHub dorks** om in die organization te soek.

### Pastes Leaks

Soms sal aanvallers of bloot werknemers maatskappy-inhoud op ’n paste site **publiseer**. Dit mag of mag nie **sensitiewe inligting** bevat nie, maar dit is baie interessant om daarna te soek.\
Jy kan die tool [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om gelyktydig op meer as 80 paste sites te soek.

### Google Dorks

Ou maar steeds waardevolle Google dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar behoort te wees nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) etlike **duisende** moontlike queries bevat wat jy nie handmatig kan uitvoer nie. Jy kan dus jou gunsteling 10 kies, of jy kan ’n **tool soos** [**Gorks**](https://github.com/carlospolop/Gorks) gebruik **om almal uit te voer**.

_Neem kennis dat die tools wat verwag om die hele databasis met die gewone Google-browser uit te voer, nooit sal klaarmaak nie, aangesien Google jou baie, baie gou sal blokkeer._

### **Soek na kwesbaarhede**

As jy **geldige credentials of API tokens wat ge-leak is** vind, is dit ’n baie maklike oorwinning.

## Kwesbaarhede in Publieke Code

As jy ontdek dat die maatskappy **open-source code** het, kan jy dit **ontleed** en na **kwesbaarhede** daarin soek.

**Afhangende van die taal** is daar verskillende **tools** wat jy kan gebruik; sien die lys van [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Daar is ook gratis services waarmee jy **publieke repositories** kan **scan**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **meerderheid van die kwesbaarhede** wat deur bug hunters gevind word, is binne **web applications**, so op hierdie punt wil ek oor ’n **web application testing methodology** praat, en jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook spesiale vermelding maak van die afdeling [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede sal vind nie, is hulle handig om dit in **workflows te implementeer om aanvanklike web-inligting te verkry.**

## Herhaling

> Baie geluk! Op hierdie punt het jy reeds **al die basiese enumeration** uitgevoer. Ja, dit is basies omdat daar nog baie meer enumeration gedoen kan word (ons sal later meer tricks sien).

Jy het dus reeds:

1. Al die **maatskappye** binne die scope gevind
2. Al die **bates** wat aan die maatskappye behoort, gevind (en ’n vuln scan uitgevoer indien dit binne scope is)
3. Al die **domains** wat aan die maatskappye behoort, gevind
4. Al die **subdomains** van die domains gevind (enige subdomain takeover?)
5. Al die **IPs** (van en **nie van CDNs nie**) binne die scope gevind.
6. Al die **web servers** gevind en ’n **screenshot** daarvan geneem (enigiets vreemds wat ’n dieper ondersoek werd is?)
7. Al die **potensiële publieke cloud-bates** wat aan die maatskappy behoort, gevind.
8. **E-posse**, **credential leaks** en **secret leaks** gevind wat jou **baie maklik ’n groot oorwinning** kan gee.
9. **Pentesting** van al die webwerwe wat jy gevind het, uitgevoer

## **Volledige Outomatiese Recon Tools**

Daar is verskeie tools wat ’n deel van die voorgestelde aksies teen ’n gegewe scope kan uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - ’n Bietjie oud en nie opgedateer nie

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
{{#include ../../banners/hacktricks-training.md}}
