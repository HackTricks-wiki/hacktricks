# Eksterne Recon-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Ontdekking van bates

> Dus is jou gesê dat alles wat aan 'n maatskappy behoort binne die scope is, en jy wil uitvind wat hierdie maatskappy eintlik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te identifiseer en daarna al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:

1. Vind die overnames van die hoofmaatskappy — dit sal ons die maatskappye binne die scope gee.
2. Vind die ASN (indien enige) van elke maatskappy — dit sal ons die IP-reekse gee wat deur elke maatskappy besit word.
3. Gebruik reverse whois lookups om na ander inskrywings (organisasienaam, domeine...) te soek wat aan die eerste verwant is (dit kan rekursief gedoen word).
4. Gebruik ander tegnieke soos shodan `org` en `ssl` filters om na ander bates te soek (die `ssl` truuk kan rekursief uitgevoer word).

### **Overnames**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com), **soek** vir die **hoofmaatskappy**, en **klik** op "**acquisitions**". Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy aangekoop is.\
'n Ander opsie is om die **Wikipedia**-blad van die hoofmaatskappy te besoek en vir **acquisitions** te soek.\
Vir openbare maatskappye, kontroleer **SEC/EDGAR filings**, **investor relations** bladsye, of plaaslike korporatiewe registers (bv., **Companies House** in die VK).\
Vir globale maatskappy-bome en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI** databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, op hierdie stadium behoort jy alle maatskappye binne die scope te ken. Kom ons bepaal hoe om hul bates te vind.

### **ASNs**

'n Autonomous system number (**ASN**) is 'n **unieke nommer** wat aan 'n **autonomous system** (AS) deur die **Internet Assigned Numbers Authority (IANA)** toegewys word.\
'n **AS** bestaan uit **blokkies** van **IP addresses** wat 'n duidelik gedefinieerde beleid vir toegang tot eksterne netwerke het en deur 'n enkele organisasie bestuur word, maar kan uit meerdere operateurs bestaan.

Dit is nuttig om te vind of die **maatskappy enige ASN toegeken het** om sy **IP-reekse** te bepaal. Dit is sinvol om 'n **vulnerability test** teen al die **hosts** binne die **scope** uit te voer en na domeine binne hierdie IP's te soek.\
Jy kan **soek** op maatskappy **naam**, op **IP** of op **domein** by [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die streek van die maatskappy kan hierdie skakels nuttig wees om meer data te versamel:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). In elk geval verskyn waarskynlik al die** nuttige inligting **(IP ranges en Whois)** reeds in die eerste skakel.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**se** enumeration aggregeer outomaties ASNs en gee 'n opsomming daarvan aan die einde van die scan.
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
Jy kan die IP-reekse van 'n organisasie ook vind deur [http://asnlookup.com/](http://asnlookup.com) te gebruik (dit het 'n gratis API).\
Jy kan die IP en ASN van 'n domein vind deur [http://ipv4info.com/](http://ipv4info.com) te gebruik.

### **Op soek na kwesbaarhede**

Op hierdie punt ken ons **al die assets binne die scope**, so as jy toestemming het kan jy 'n **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) oor al die hosts laat loop.\
Ook kan jy [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) uitvoer of dienste soos Shodan, Censys, of ZoomEye gebruik **om** oop poorte te vind **en afhangend van wat jy vind moet jy** in hierdie boek kyk hoe om verskeie moontlike services te pentest.\
**Dit kan ook die moeite werd wees om voorhanden te hê** default username **en** passwords **lyste en te probeer om** bruteforce **dienste met** https://github.com/x90skysn3k/brutespray te doen. 

## Domeine

> Ons ken al die maatskappye binne die scope en hul assets, dit is tyd om die domeine binne die scope te vind.

_Please, let daarop dat jy in die volgende voorgestelde tegnieke ook subdomeine kan vind en daardie inligting nie onderskat moet word nie._

Eerstens moet jy soek na die **hoofdomein**(e) van elke maatskappy. Byvoorbeeld, vir _Tesla Inc._ sal dit _tesla.com_ wees.

### **Omgekeerde DNS**

Sodra jy al die IP-reekse van die domeine gevind het, kan jy probeer om **omgekeerde DNS-opsoeke** op daardie **IPs te doen om meer domeine binne die scope te vind**. Probeer om 'n dns server van die slagoffer of 'n bekende dns server (1.1.1.1, 8.8.8.8) te gebruik.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Daarvoor moet die administrateur handmatig die PTR aktiveer.\
Jy kan ook 'n aanlyn hulpmiddel gebruik vir hierdie inligting: [http://ptrarchive.com/](http://ptrarchive.com).\
Vir groot reekse is gereedskap soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en enrichment te outomatiseer.

### **Reverse Whois (loop)**

In 'n **whois** kan jy baie interessante **inligting** vind soos **organisasienaam**, **adres**, **e-posadresse**, telefoonnommers... Maar wat nog meer interessant is, is dat jy **meer bates verwant aan die maatskappy** kan vind as jy **reverse whois lookups** doen op enige van daardie velde (byvoorbeeld ander whois-registrasies waar dieselfde e-pos verskyn).\
Jy kan aanlyn gereedskap gebruik soos:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Gratis** web, nie gratis API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie gratis
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis
- [https://securitytrails.com/](https://securitytrails.com/) - Nie gratis (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nie gratis (API)

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink) (vereis 'n whoxy API sleutel).\
Jy kan ook outomatiese reverse whois-ontdekking uitvoer met [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer as jy 'n nuwe domein vind.**

### **Trackers**

As jy dieselfde ID van dieselfde tracker op 2 verskillende bladsye vind, kan jy aanvaar dat **albei bladsye** deur **dieselfde span** bestuur word.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is 'n paar bladsye en gereedskap wat jou toelaat om na hierdie trackers en meer te soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine tot ons teiken kan vind deur na dieselfde favicon-ikoon-hash te soek? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool gemaak deur [@m4ll0k2](https://twitter.com/m4ll0k2) doen. Hier’s hoe om dit te gebruik:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, favihash sal ons toelaat om domeine te ontdek wat dieselfde favicon icon hash as ons teiken het.

Verder kan jy ook tegnologieë deur die favicon hash soek soos verduidelik in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Dit beteken dat as jy die **hash van die favicon van 'n kwesbare weergawe van 'n web tech** ken, kan jy dit in shodan soek en **meer kwesbare plekke vind**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Dit is hoe jy die **favicon hash** van 'n webwerf kan bereken:
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
Jy kan ook favicon hashes op skaal kry met [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) en dan in Shodan/Censys pivot.

### **Kopiereg / Unieke string**

Soek binne die webbladsye **strings wat oor verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **kopiereg-string** kan 'n goeie voorbeeld wees. Soek dan na daardie string in **google**, in ander **browsers** of selfs in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Tyd**

Dit is algemeen om 'n cron job te hê soos
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
om al die domeinsertifikate op die server te hernu. Dit beteken dat, selfs as die CA wat hiervoor gebruik is nie die tyd van generering in die Validity time plaas nie, dit moontlik is om **domeine wat aan dieselfde maatskappy behoort in die certificate transparency logs te vind**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-inligting

Jy kan 'n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of 'n tool soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domeine en subdomeine te vind wat dieselfde DMARC-inligting deel**.\
Ander nuttige gereedskap is [**spoofcheck**](https://github.com/BishopFox/spoofcheck) en [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Dit is blykbaar algemeen dat mense subdomeine aan IP's toewys wat aan cloud providers behoort en op 'n stadium daardie IP-adres verloor maar vergeet om die DNS-rekord te verwyder. Daarom, deur net 'n **VM** in 'n cloud (soos Digital Ocean) te spawn, sal jy eintlik sommige subdomeine oorneem.

[**This post**](https://kmsec.uk/blog/passive-takeover/) verduidelik 'n verhaal daaroor en stel 'n script voor wat **'n VM in DigitalOcean spawn**, die **IPv4** van die nuwe masjien kry, en in **VirusTotal** soek vir subdomeinrekords wat daarna wys.

### **Other ways**

**Let wel dat jy hierdie tegniek kan gebruik om meer domeinnaam te ontdek elke keer as jy 'n nuwe domein vind.**

**Shodan**

Aangesien jy reeds die naam van die organisasie ken wat die IP-ruimte besit, kan jy volgens daardie data in shodan soek met: `org:"Tesla, Inc."` Kontroleer die gevonde hosts vir nuwe ongedachte domeine in die TLS certificate.

Jy kan die **TLS certificate** van die hoofwebblad benader, die **Organisation name** kry en dan daardie naam soek binne die **TLS certificates** van al die webblaaie wat deur **shodan** bekend is met die filter: `ssl:"Tesla Motors"` of 'n tool soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) is 'n tool wat kyk na **domeine wat verwant is** aan 'n hoofdomein en hul **subdomeine**, baie indrukwekkend.

**Passive DNS / Historical DNS**

Passive DNS-data is uitstekend om **oue en vergete rekords** te vind wat steeds oplos of wat oor geneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check vir [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien gebruik 'n maatskappy nog 'n domein maar het hulle die eienaarskap verloor. Registreer dit net (as dit goedkoop genoeg is) en laat die maatskappy weet.

As jy enige **domein met 'n ander IP** vind as die een wat jy reeds in die assets discovery gevind het, behoort jy 'n **basic vulnerability scan** uit te voer (gebruik Nessus of OpenVAS) en 'n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** te doen. Afhangend van watter dienste loop, kan jy in **this book** truuks vind om hulle te "attack".\
_Note dat soms die domein op 'n IP gehost word wat nie deur die kliënt beheer word nie, dus is dit nie in scope nie — wees versigtig._

## Subdomains

> Ons ken al die maatskappye binne die scope, al die assets van elke maatskappy en al die domeine wat aan die maatskappye verwant is.

> [!TIP]
> Let wel dat sommige van die tools en tegnieke om domeine te vind ook kan help om subdomeine te vind

### **DNS**

Kom ons probeer om **subdomeine** uit die **DNS**-rekords te kry. Ons moet ook probeer vir **Zone Transfer** (As dit kwesbaar is, moet jy dit rapporteer).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die vinnigste manier om baie subdomeine te kry, is deur in eksterne bronne te soek. Die mees gebruikte **tools** is die volgende (vir beter resultate, stel die API-sleutels in):

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
Daar is **ander interessante tools/APIs** wat, al is dit nie direk gespesialiseerd in die opsporing van subdomains nie, nuttig kan wees om subdomains te vind, soos:

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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hulle skraap die web af op soek na JS files en onttrek subdomains daaruit.
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
- [**securitytrails.com**](https://securitytrails.com/) het 'n gratis API om na subdomains en IP history te soek
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Hierdie projek bied gratis al die subdomains wat verband hou met bug-bounty programs. Jy kan ook toegang tot hierdie data kry met [chaospy](https://github.com/dr-0x0x/chaospy) of selfs toegang kry tot die scope wat deur hierdie projek gebruik word [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan 'n **vergelyking** van baie van hierdie tools hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomains** te vind deur DNS servers te brute-force met moontlike subdomain names.

Vir hierdie aksie sal jy 'n paar **common subdomains wordlists soos** nodig hê:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IPs van goeie DNS resolvers. Om 'n lys van betroubare DNS resolvers te genereer, kan jy die resolvers aflaai vanaf [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om dit te filter. Of jy kan gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbeveelde tools vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat 'n effektiewe DNS brute-force uitgevoer het. Dit is baie vinnig, maar dit is geneig tot false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik volgens my net 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is 'n wrapper rondom `massdns`, geskryf in go, wat jou toelaat om geldige subdomains te enumereer met active bruteforce, asook om subdomains op te los met wildcard handling en maklike input-output ondersteuning.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinname asynchronies te brute force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Tweede DNS Brute-Force Ronde

Nadat jy subdomeine met behulp van open bronne en brute-forcing gevind het, kan jy variasies van die gevonde subdomeine genereer om nog meer te vind. Verskeie tools is nuttig hiervoor:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Gegee die domeine en subdomeine, genereer permutasies.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Gegewe die domeine en subdomeine, genereer permutasies.
- Jy kan die goaltdns permutasies **wordlist** by [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegee die domeine en subdomeine, genereer permutasies. As geen permutasielêer aangedui is nie, sal gotator sy eie gebruik.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Afgesien daarvan dat dit subdomein-permutasies genereer, kan dit ook probeer om hulle op te los (maar dit is beter om die voorheen genoemde tools te gebruik).
- Jy kan die altdns-permutasies **wordlist** kry [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Nog 'n hulpmiddel om permutations, mutations en alteration van subdomains uit te voer. Hierdie hulpmiddel sal die resultate brute force (dit ondersteun nie dns wild card nie).
- Jy kan dmut permutations wordlist kry in [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Gebaseer op 'n domain genereer dit **nuwe potensiële subdomains name** gebaseer op aangeduide patrone om te probeer meer subdomains te ontdek.

#### Slim permutasie-generering

- [**regulator**](https://github.com/cramppet/regulator): Vir meer inligting lees hierdie [**post**](https://cramppet.github.io/regulator/index.html) maar dit sal basies die **hoofdele** van die **ontdekte subdomains** kry en dit meng om meer subdomains te vind.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is 'n subdomain brute-force fuzzer wat gekoppel is aan 'n uiters eenvoudige maar doeltreffende DNS-reaksie-geleide algoritme. Dit maak gebruik van 'n verskafde stel insetdata, soos 'n aangepaste wordlist of historiese DNS/TLS-rekords, om meer ooreenstemmende domeinname akkuraat te sintetiseer en dit verder in 'n lus uit te brei gebaseer op inligting wat tydens 'n DNS-skandering versamel is.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Kyk na hierdie blogpos wat ek geskryf het oor hoe om die **subdomain discovery** van 'n domein te **automate** deur **Trickest workflows** te gebruik, sodat ek nie handmatig 'n klomp tools op my rekenaar hoef te begin nie:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

As jy 'n IP-adres vind wat **een of verskeie web pages** bevat wat by subdomains behoort, kan jy probeer om **ander subdomains with webs in that IP** te vind deur in **OSINT sources** na domeine op daardie IP te kyk of deur **brute-forcing VHost domain names in that IP**.

#### OSINT

Jy kan 'n paar **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs** vind.

**Brute Force**

As jy vermoed dat 'n subdomain in 'n webbediener versteek kan wees, kan jy probeer om dit te brute force:

Wanneer die **IP redirects to a hostname** (name-based vhosts), fuzz die `Host` header direk en laat ffuf **auto-calibrate** om reaksies uit te lig wat van die standaard vhost verskil:
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
> Met hierdie tegniek mag jy selfs toegang tot internal/hidden endpoints kry.

### **CORS Brute Force**

Soms sal jy bladsye vind wat slegs die header _**Access-Control-Allow-Origin**_ terugstuur wanneer 'n geldige domain/subdomain in die _**Origin**_ header gestel is. In hierdie situasies kan jy hierdie gedrag misbruik om **nuwe** **subdomains** te **ontdek**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Terwyl jy na **subdomains** soek, hou dop of dit na enige tipe **bucket** **pointing**, en in daardie geval [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).\
Verder, aangesien jy op hierdie punt alle domeine binne die scope sal ken, probeer [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitering**

Jy kan **monitor** of **new subdomains** van 'n domein geskep word deur die **Certificate Transparency** Logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) doen.

### **Looking for vulnerabilities**

Kontroleer vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na 'n **S3 bucket** wys, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomain with an IP different** vind van die ones wat jy reeds in die assets discovery gevind het, moet jy 'n **basic vulnerability scan** uitvoer (gebruik Nessus of OpenVAS) en 'n paar [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangend van watter dienste loop, kan jy in **this book some tricks to "attack" them** vind.\
_Note dat soms die subdomain op 'n IP gehost word wat nie deur die kliënt beheer word nie, so dit is nie in die scope nie — wees versigtig._

## IPs

In die aanvanklike stappe mag jy reeds **found some IP ranges, domains and subdomains**.\
Dit is tyd om **recollect all the IPs from those ranges** en vir die **domains/subdomains (DNS queries).**

Deur dienste van die volgende **free apis** te gebruik kan jy ook **previous IPs used by domains and subdomains** vind. Hierdie IPs kan steeds aan die kliënt behoort (en kan jou toelaat om [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook vir domeine wat na 'n spesifieke IP verwys kyk met die tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (aangesien jy waarskynlik niks van belang daar sal vind nie). In die ontdekte lopende dienste mag jy **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Ons het al die maatskappye en hul assets gevind en ons ken IP ranges, domains en subdomains binne die scope. Dit is tyd om na web servers te soek.

In die vorige stappe het jy waarskynlik reeds 'n bietjie **recon of the IPs and domains discovered** gedoen, so jy mag **already found all the possible web servers** hê. Indien nie, gaan ons nou kyk na 'n paar **fast tricks to search for web servers** binne die scope.

Neem asseblief kennis dat dit **oriented for web apps discovery** sal wees, dus moet jy ook **perform the vulnerability** en **port scanning** doen (**if allowed** deur die scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Nog 'n vriendelike hulpmiddel om na web servers te kyk is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy gee net 'n lys domeine en dit sal probeer verbind na poort 80 (http) en 443 (https). Verder kan jy aandui om ander poorte te probeer:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Skermskote**

Nou dat jy **al die webbedieners** ontdek het wat binne die scope is (onder die **IPs** van die maatskappy en al die **domeine** en **subdomeine**) weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit eenvoudig en begin net deur skermskote van almal te neem. Deur net na die **hoofblad** te **kyk** kan jy vreemde endpoints vind wat meer geneig is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Verder kan jy dan [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om oor al die **skermskote** te loop en te sê wat waarskynlik **kwesbaarhede** bevat en wat nie.

## Publieke Cloud-bates

Om potensiële cloud-bates wat aan 'n maatskappy behoort te vind, moet jy **begin met 'n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir 'n crypto-maatskappy kan jy woorde soos gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordlyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dan, met daardie woorde moet jy **permutasies** genereer (kyk die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) vir meer info).

Met die resulterende woordlyste kan jy instrumente soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat wanneer jy na Cloud Assets soek jy **meer as net buckets in AWS** moet **kyk**.

### **Op soek na kwesbaarhede**

As jy dinge vind soos **oop buckets of cloud functions blootgestel** is, moet jy **toegang daartoe kry** en kyk wat hulle vir jou bied en of jy dit kan misbruik.

## E-posse

Met die **domeine** en **subdomeine** binne die scope het jy basies alles wat jy **nodig het om te begin soek na e-posse**. Dit is die **APIs** en **tools** wat vir my die beste gewerk het om e-posse van 'n maatskappy te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met APIs
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Op soek na kwesbaarhede**

E-posse sal later handig wees om **web logins en auth-dienste te brute-force** (soos SSH). Ook is hulle nodig vir **phishings**. Verder sal hierdie APIs jou selfs meer **inligting oor die persoon** agter die e-pos gee, wat nuttig is vir 'n phishingveldtog.

## Credential Leaks

Met die **domeine,** **subdomeine**, en **e-posse** kan jy begin soek na credentials leaked in die verlede wat aan daardie e-posse behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Op soek na kwesbaarhede**

As jy **geldige leaked** credentials vind, is dit 'n baie maklike wen.

## Geheime Leaks

Credential leaks hou verband met hacks van maatskappye waar **sensitiewe inligting leaked en verkoop** is. Maatskappye kan egter ook deur **ander leaks** geraak word waarvan die inligting nie in daardie databasisse is nie:

### Github Leaks

Credentials en API's kan in die **openbare repositories** van die **maatskappy** of van die **gebruikers** wat by daardie GitHub-maatskappy werk, leaked wees.\
Jy kan die **tool** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **public repos** van 'n **organization** en van sy **developers** af te laai en [**gitleaks**](https://github.com/zricethezav/gitleaks) outomaties oor hulle te laat hardloop.

**Leakos** kan ook gebruik word om **gitleaks** te laat hardloop teen al die **tekst** wat via **URLs** aan dit deurgegee word aangesien soms **webbladsye ook secrets bevat**.

#### Github Dorks

Kyk ook na hierdie **bladsy** vir potensiële **github dorks** wat jy in die organisasie wat jy aanval kan soek:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Soms publiseer aanvallers of net werknemers maatskappy-inhoud op 'n paste-site. Dit mag of mag nie **sensitiewe inligting** bevat nie, maar dit is baie interessant om daarvoor te soek.\
Jy kan die tool [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om in meer as 80 paste-sites gelyk te soek.

### Google Dorks

Oud maar goud — google dorks is altyd nuttig om **blootgestelde inligting wat nie daar hoort nie** te vind. Die probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) **duisende** moontlike queries bevat wat jy nie manueel kan hardloop nie. Dus kan jy jou gunsteling 10 kies of 'n **tool soos** [**Gorks**](https://github.com/carlospolop/Gorks) **gebruik om hulle almal te hardloop**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Op soek na kwesbaarhede**

As jy **geldige leaked** credentials of API tokens vind, is dit 'n baie maklike wen.

## Publieke Kode-Kwesbaarhede

As jy vind dat die maatskappy **open-source code** het, kan jy dit **analiseer** en soek na **kwesbaarhede** daarin.

**Afhangend van die taal** is daar verskillende **tools** wat jy kan gebruik:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Daar is ook gratis dienste wat jou toelaat om **openbare repositories** te **scan**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **meeste van die kwesbaarhede** wat bug hunters vind lê binne **web applications**, so op hierdie punt wil ek graag 'n **web application testing methodology** noem — jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook spesiaal verwys na die afdeling [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede sal vind nie, is hulle handig om in **workflows** te implementeer om 'n aanvanklike web-inligting te kry.

## Opsomming

> Gefeliciteerd! Op hierdie punt het jy reeds **al die basiese enumaration** gedoen. Ja, dit is basies omdat baie meer enumerasie gedoen kan word (ons sal later meer truuks sien).

So jy het reeds:

1. Gevind al die **maatskappye** binne die scope
2. Gevind al die **bates** wat aan die maatskappye behoort (en 'n paar vuln scans gedoen indien in scope)
3. Gevind al die **domeine** wat aan die maatskappye behoort
4. Gevind al die **subdomeine** van die domeine (enige subdomain takeover?)
5. Gevind al die **IPs** (van en **nie van CDNs** nie) binne die scope.
6. Gevind al die **webbedieners** en 'n **skermskoot** daarvan geneem (enigiets vreemd wat 'n dieper kyk werd is?)
7. Gevind al die **potensiële publieke cloud-bates** wat aan die maatskappy behoort.
8. **E-posse**, **credentials leaks**, en **secret leaks** wat jou maklik 'n groot wen kan gee.
9. **Pentesting** al die webs wat jy gevind het

## Volledige Recon Outomatiese Tools

Daar is verskeie tools daar buite wat 'n deel van die voorgestelde aksies teen 'n gegewe scope sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 'n bietjie oud en nie opgedateer nie

## **Verwysings**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
