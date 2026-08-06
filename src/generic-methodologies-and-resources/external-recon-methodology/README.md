# Eksterne Recon-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Bate-ontdekkings

> Daar is dus aan jou gesê dat alles wat aan een of ander maatskappy behoort binne die scope is, en jy wil uitvind wat hierdie maatskappy werklik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te verkry, en daarna al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:

1. Die verkrygings van die hoofmaatskappy vind; dit sal ons die maatskappye binne die scope gee.
2. Die ASN (indien enige) van elke maatskappy vind; dit sal ons die IP-reekse wat deur elke maatskappy besit word gee
3. Reverse whois lookups gebruik om na ander inskrywings (organisasiename, domeine...) te soek wat met die eerste een verband hou (dit kan rekursief gedoen word)
4. Ander tegnieke gebruik, soos Shodan se `org`- en `ssl`-filters, om na ander bates te soek (die `ssl`-truuk kan rekursief gedoen word).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, vir die **hoofmaatskappy** te **soek**, en op "**acquisitions**" te **klik**. Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
Nog ’n opsie is om die **Wikipedia**-bladsy van die hoofmaatskappy te besoek en na **acquisitions** te soek.\
Vir publieke maatskappye, gaan **SEC/EDGAR filings**, **investor relations**-bladsye, of plaaslike korporatiewe registers (bv. **Companies House** in die VK) na.\
Vir globale korporatiewe strukture en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI**-databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Goed, op hierdie stadium behoort jy al die maatskappye binne die scope te ken. Kom ons vind uit hoe om hul bates te vind.

### **ASNs**

’n Autonomous System Number (**ASN**) is ’n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan ’n **autonome stelsel** (AS) toegeken word.\
’n **AS** bestaan uit **blokke** **IP-adresse** wat ’n duidelik gedefinieerde beleid het vir toegang tot eksterne netwerke en deur ’n enkele organisasie geadministreer word, maar uit verskeie operateurs kan bestaan.

Dit is interessant om vas te stel of die **maatskappy enige ASN toegeken is**, om sy **IP-reekse** te vind. Dit sal interessant wees om ’n **kwesbaarheidstoets** teen al die **hosts** binne die **scope** uit te voer en na **domeine** binne hierdie IP’s te soek.\
Jy kan volgens maatskappy**naam**, **IP** of **domein** soek op [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangende van die streek waarin die maatskappy is, kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In elk geval verskyn waarskynlik al die** nuttige inligting **(IP-reekse en Whois)** reeds in die eerste skakel.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ook versamel en som [**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** enumerasie outomaties ASNs aan die einde van die scan op.
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
Jy kan die IP en ASN van ’n domain met [http://ipv4info.com/](http://ipv4info.com) vind.

### **Soek na vulnerabilities**

Op hierdie punt ken ons **al die bates binne die scope**, dus, indien jy toegelaat word, kan jy ’n **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) oor al die hosts uitvoer.\
Jy kan ook [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) uitvoer **of dienste soos** Shodan, Censys of ZoomEye **gebruik om** oop poorte **te vind, en afhangend van wat jy vind, moet jy** in hierdie boek kyk hoe om verskeie moontlike dienste wat loop, te pentest.\
**Dit kan ook die moeite werd wees om te noem dat jy sommige** verstek-username **en** passwords **lyste kan voorberei en probeer om dienste te** bruteforce met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Ons ken al die maatskappye binne die scope en hul bates; dit is tyd om die domains binne die scope te vind.

_Let daarop dat jy met die volgende voorgestelde tegnieke ook subdomains kan vind en dat daardie inligting nie onderskat moet word nie._

Eerstens moet jy die **hoofdomain**(s) van elke maatskappy soek. Byvoorbeeld, vir _Tesla Inc._ is dit _tesla.com_.

### **Reverse DNS**

Aangesien jy al die IP-reekse van die domains gevind het, kan jy probeer om **reverse dns lookups** op daardie **IPs uit te voer om meer domains binne die scope te vind**. Probeer om ’n dns server van die slagoffer of ’n bekende dns server (1.1.1.1, 8.8.8.8) te gebruik.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Om dit te laat werk, moet die administrateur die PTR handmatig aktiveer.\
Jy kan ook ’n aanlyn hulpmiddel vir hierdie inligting gebruik: [http://ptrarchive.com/](http://ptrarchive.com).\
Vir groot reekse is hulpmiddels soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en verryking te outomatiseer.

### **Reverse Whois (lus)**

Binne ’n **whois** kan jy baie interessante **inligting** vind, soos **organisasienaam**, **adres**, **e-posadresse**, telefoonnommers... Wat egter selfs interessanter is, is dat jy **meer bates wat met die maatskappy verband hou** kan vind as jy **reverse whois lookups volgens enige van daardie velde** uitvoer (byvoorbeeld ander whois-registrasies waar dieselfde e-posadres voorkom).\
Jy kan aanlyn hulpmiddels soos die volgende gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web en API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** web, nie-gratis API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie gratis nie
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis nie (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis nie
- [https://securitytrails.com/](https://securitytrails.com/) - Nie gratis nie (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nie gratis nie (API)

Jy kan hierdie taak outomatiseer deur [**DomLink** ](https://github.com/vysecurity/DomLink) te gebruik (vereis ’n whoxy API-sleutel).\
Jy kan ook outomatiese reverse whois-ontdekking met [amass](https://github.com/OWASP/Amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om elke keer wanneer jy ’n nuwe domeinnaam vind, meer domeinname te ontdek.**

### **Trackers**

As jy die **selfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy aanvaar dat **beide bladsye** deur **dieselfde span** bestuur word.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is sommige bladsye en hulpmiddels waarmee jy volgens hierdie trackers en meer kan soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (vind verwante webwerwe volgens gedeelde analytics/trackers)

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine vir ons teiken kan vind deur te soek na dieselfde favicon-ikoonhash? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)-tool, wat deur [@m4ll0k2](https://twitter.com/m4ll0k2) gemaak is, doen. Hier is hoe om dit te gebruik:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ontdek domeine met dieselfde favicon-ikoon-hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, sal favihash ons in staat stel om domeine te ontdek wat dieselfde favicon-ikoon-hash as ons teiken het.

Boonop kan jy ook na tegnologieë soek deur die favicon-hash te gebruik, soos in [**hierdie blogplasing**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) verduidelik word. Dit beteken dat indien jy die **hash van die favicon van ’n kwesbare weergawe van ’n webtegnologie** ken, jy in Shodan kan soek en **meer kwesbare plekke kan vind**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Dit is hoe jy die **favicon hash** van ’n webwerf kan **bereken** (MMH3 oor die **base64-encoded** favicon bytes):
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

Nuttige dinge om te onthou wanneer favicon-fingerprints gebruik word:<sup>[[3]](#references)[[4]](#references)</sup>

- **Behandel die hash as ’n aanduiding, nie as bewys nie**: MMH3 is kompak en collisions is moontlik; operateurs kan ook favicons vervang of doelbewus ’n misleidende ikoon hergebruik.
- **Probeer meer as** `/favicon.ico`: baie produkte stel ikone bloot in framework/build-paaie of via `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:`-URLs of HTML-`<link rel="icon">`-tags. Die pad self kan ’n produkfamilie fingerprint.
- **Static files is dikwels bereikbaar wanneer die app nie is nie**: WAF/SSO/IdP-kontroles kan dinamiese roetes beskerm, maar steeds static icons blootstel. Versoek altyd die favicon direk en hersien `ETag`, `Last-Modified`, redirects en cache headers vir swak weergawe-/build-aanwysings.
- **Valideer matches met omliggende seine**: vergelyk titel, HTML/body-hash, headers, TLS-sertifikaat-subjects/SANs, Shodan/Censys-komponente en blootgestelde poorte voordat jy aflei dat ’n favicon ’n produk identifiseer.
- **Cluster volgens HTML/body-hash wanneer jy op skaal pivot**: indien die meeste hosts wat ’n favicon deel in een bladsy-template saamval, is die fingerprint sterker; indien dieselfde hash in baie onverwante templates verdeel, verkies `"generic/shared/honeypot"` bo ’n produketiket.
- **Honeypot-heuristiek**: indien dieselfde favicon-hash oor baie onverwante HTML-signatures, random poorte en botsende produkte verskyn, behandel dit as ’n waarskynlike honeypot of generiese placeholder eerder as ’n werklike produk-fingerprint.
- **Gebruik ’n 404-probe op dubbelsinnige teikens**: haal ’n werklike bladsy en ’n niebestaande pad soos `/_favicon_probe_<8-hex>` in ’n browser op. Ooreenstemmende hosting-provider-/parking-antwoorde verklaar gedeelde favicons dikwels beter as werklike produk-oorvleueling.
- **Bootstrap mappings vanaf detection rules**: Nuclei-templates en publieke favicon-datasets kan bekende `favicon` ↔ `product` ↔ `CPE`-mappings verskaf wat nuttig is vir vinnige triage ná CVE-openbaarmakings.
- **Dekkingsvoorbehoud**: Shodan-styl-datasets is IP-gesentreerd. CDN-fronted, SNI-gerouteerde, anycast- en domein-alleen-oppervlakke kan ondergetel word, dus beteken ’n lae treftelling **nie** lae werklike implementering nie.

### **Kopiereg / Uniq string**

Soek binne die webblaaie **strings wat oor verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **copyright string** kan ’n goeie voorbeeld wees. Soek dan vir daardie string in **google**, in ander **browsers** of selfs in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Dit is algemeen om ’n cron job soos ’n
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
om al die domain certificates op die server te hernu. Dit beteken dat selfs al stel die CA wat hiervoor gebruik word nie die tyd waarop dit gegenereer is in die Validity time nie, dit steeds moontlik is om **domains te vind wat aan dieselfde maatskappy behoort in die certificate transparency logs**.\
Kyk na hierdie [**writeup vir meer inligting**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Gebruik ook **certificate transparency** logs direk:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-inligting

Jy kan ’n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of ’n tool soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domains en subdomains te vind wat dieselfde dmarc-inligting deel**.\
Ander nuttige tools is [**spoofcheck**](https://github.com/BishopFox/spoofcheck) en [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Dit is blykbaar algemeen dat mense subdomains toewys aan IPs wat aan cloud providers behoort en op ’n stadium **daardie IP-adres verloor, maar vergeet om die DNS record te verwyder**. Daarom sal jy, deur eenvoudig ’n **VM** in ’n cloud (soos Digital Ocean) te **spawn**, in werklikheid **sommige subdomains oorneem**.

[**Hierdie post**](https://kmsec.uk/blog/passive-takeover/) verduidelik ’n storie daaroor en stel ’n script voor wat ’n **VM in DigitalOcean spawn**, die **IPv4** van die nuwe machine **verkry**, en in Virustotal **soek vir subdomain records** wat daarheen wys.

### **Ander maniere**

**Let daarop dat jy hierdie technique kan gebruik om elke keer meer domain names te ontdek wanneer jy ’n nuwe domain vind.**

**Shodan**

Soos jy reeds die naam van die organisasie ken wat die IP-space besit, kan jy volgens daardie data in shodan soek deur die volgende te gebruik: `org:"Tesla, Inc."` Kontroleer die gevonde hosts vir nuwe onverwagte domains in die TLS certificate.

Jy kan toegang verkry tot die **TLS certificate** van die hoofwebblad, die **Organisation name** verkry en dan binne die **TLS certificates** van al die webblaaie wat aan **shodan** bekend is vir daardie naam soek met die filter: `ssl:"Tesla Motors"` of ’n tool soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ’n tool wat soek na **domains wat verband hou** met ’n hoofdomain en die **subdomains** daarvan; dit is nogal indrukwekkend.

**Passive DNS / Historiese DNS**

Passive DNS-data is uitstekend om **ou en vergete records te vind** wat steeds resolve of wat oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Soek na vulnerabilities**

Kyk vir ’n moontlike [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien **gebruik ’n maatskappy ’n domain**, maar het hulle **eienaarskap verloor**. Registreer dit eenvoudig (indien dit goedkoop genoeg is) en laat weet die maatskappy.

As jy enige **domain met ’n ander IP** vind as dié wat jy reeds tydens die assets discovery gevind het, moet jy ’n **basic vulnerability scan** uitvoer (met Nessus of OpenVAS) en ’n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** doen. Afhangend van watter services loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "attack"**.\
_Let daarop dat die domain soms binne ’n IP gehuisves word wat nie deur die client beheer word nie, dus is dit nie binne die scope nie; wees versigtig._

## Subdomains

> Ons ken al die maatskappye binne die scope, al die assets van elke maatskappy en al die domains wat met die maatskappye verband hou.

Dit is tyd om al die moontlike subdomains van elke gevonde domain te vind.

> [!TIP]
> Let daarop dat sommige van die tools en techniques om domains te vind ook kan help om subdomains te vind

### **DNS**

Kom ons probeer om **subdomains** uit die **DNS** records te verkry. Ons moet ook **Zone Transfer** probeer (As dit vulnerable is, moet jy dit report).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die vinnigste manier om baie subdomains te verkry, is om in eksterne bronne te soek. Die mees gebruikte **tools** is die volgende (vir beter resultate, stel die API-sleutels op):

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
Daar is **ander interessante tools/API's** wat, selfs al is hulle nie direk daarin gespesialiseer om subdomeine te vind nie, nuttig kan wees om subdomeine te vind, soos:

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
- [**gau**](https://github.com/lc/gau)**:** haal bekende URL's van AlienVault se Open Threat Exchange, die Wayback Machine en Common Crawl vir enige gegewe domein op.
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
- [**securitytrails.com**](https://securitytrails.com/) het 'n gratis API om na subdomeine en IP-geskiedenis te soek
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Hierdie projek bied **gratis al die subdomeine wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data verkry deur [chaospy](https://github.com/dr-0x0x/chaospy), of selfs toegang verkry tot die scope wat deur hierdie projek gebruik word: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan 'n **vergelyking** van baie van hierdie tools hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomeine** te vind deur DNS-bedieners te brute-force met behulp van moontlike subdomeinname.

Vir hierdie aksie benodig jy 'n paar **algemene subdomein-wordlists soos**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP's van goeie DNS-resolvers. Om 'n lys van betroubare DNS-resolvers te genereer, kan jy die resolvers vanaf [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) aflaai en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole tools vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat 'n effektiewe DNS brute-force uitgevoer het. Dit is baie vinnig, maar dit is geneig tot false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik, dink ek, net 1 resolver.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is ’n wrapper rondom `massdns`, geskryf in Go, wat jou toelaat om geldige subdomeine met active bruteforce te enumereer, asook om subdomeine met wildcard-hantering en maklike invoer-uitvoerondersteuning op te los.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinname asinkroon te brute-force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Tweede DNS Brute-Force-rondte

Nadat subdomeine met behulp van oop bronne en brute-forcing gevind is, kan jy variasies van die gevonde subdomeine genereer om moontlik nog meer te vind. Verskeie tools is nuttig vir hierdie doel:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Genereer permutasies gegrond op die domeine en subdomeine.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Gegewe die domains en subdomains, genereer permutations.
- Jy kan goaltdns se permutations-**wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegewe die domeine en subdomeine, genereer permutasies. Indien geen permutasieslêer aangedui word nie, sal gotator sy eie een gebruik.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Benewens die generering van subdomein-permutasies, kan dit ook probeer om hulle op te los (maar dit is beter om die voorafgaande genoemde nutsmiddels te gebruik).
- Jy kan altdns se permutasie-**wordlist** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Nog 'n instrument om permutasies, mutasies en wysigings van subdomains uit te voer. Hierdie instrument sal die resultaat brute force (dit ondersteun nie DNS-wildcards nie).
- Jy kan dmut se permutations-wordlist [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Gebaseer op ’n domain **genereer dit nuwe potensiële subdomeinname** volgens aangeduide patrone om meer subdomeine te probeer ontdek.

#### Slim permutasie-generering

- [**regulator**](https://github.com/cramppet/regulator): Lees hierdie [**plasing**](https://cramppet.github.io/regulator/index.html) vir meer inligting, maar dit sal basies die **hoofdele** uit die **ontdekte subdomeine** neem en dit kombineer om meer subdomeine te vind.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is 'n subdomein-brute-force-fuzzer, gekoppel aan 'n uiters eenvoudige maar effektiewe DNS-responsgeleide algoritme. Dit gebruik 'n verskafde stel invoerdata, soos 'n doelgemaakte wordlist of historiese DNS/TLS-rekords, om akkuraat meer ooreenstemmende domeinname te genereer en dit verder in 'n lus uit te brei op grond van inligting wat tydens die DNS-scan ingewin is.
```
echo www | subzuf facebook.com
```
### **Subdomein-ontdekkingswerkvloei**

Kyk na hierdie blogplasing wat ek geskryf het oor hoe om **die ontdekking van subdomeine te outomatiseer** vanaf ’n domein met behulp van **Trickest workflows**, sodat ek nie handmatig ’n klomp tools op my rekenaar hoef te begin nie:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

As jy ’n IP-adres gevind het wat **een of verskeie webbladsye** bevat wat aan subdomeine behoort, kan jy probeer om **ander subdomeine met webwerwe op daardie IP te vind** deur in **OSINT-bronne** na domeine op ’n IP te soek of deur **VHost-domeinname op daardie IP te brute-force**.

#### OSINT

Jy kan sommige **VHosts in IP’s vind deur** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander APIs te gebruik**.

**Brute Force**

As jy vermoed dat ’n subdomein in ’n webbediener versteek kan wees, kan jy probeer om dit te brute-force:

Wanneer die **IP na ’n hostname herlei** (name-based vhosts), fuzz die `Host`-header direk en laat ffuf **outomaties kalibreer** om response uit te lig wat van die verstek-vhost verskil:<sup>[[2]](#references)</sup>
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
> Met hierdie tegniek kan jy selfs toegang tot interne/verborge endpoints verkry.

### **CORS Brute Force**

Soms sal jy bladsye vind wat slegs die _**Access-Control-Allow-Origin**_-header terugstuur wanneer ’n geldige domein/subdomein in die _**Origin**_-header gestel word. In hierdie scenario’s kan jy hierdie gedrag misbruik om nuwe **subdomeine** te **ontdek**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Terwyl jy na **subdomains** soek, let daarop of enigeen **wys** na enige tipe **bucket**, en in daardie geval [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Aangesien jy op hierdie stadium al die domains binne die scope sal ken, probeer ook om [**moontlike bucket name te brute force en die permissions te check**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitering**

Jy kan **monitor** of **nuwe subdomains** van ’n domain geskep word deur die **Certificate Transparency** Logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Soek na vulnerabilities**

Check vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na ’n **S3 bucket** wys, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomain met ’n IP wat verskil** van dié wat jy reeds tydens die assets discovery gevind het, vind, moet jy ’n **basic vulnerability scan** uitvoer (met Nessus of OpenVAS) en ’n paar [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** doen. Afhangende van watter services loop, kan jy in **hierdie boek ’n paar tricks vind om hulle te "attack"**.\
_Let daarop dat die subdomain soms binne ’n IP gehuisves word wat nie deur die client beheer word nie, en dit dus nie binne die scope is nie; wees versigtig._

## IPs

In die aanvanklike stappe het jy dalk **’n paar IP ranges, domains en subdomains gevind**.\
Dit is tyd om **al die IPs uit daardie ranges te versamel** en dieselfde vir die **domains/subdomains (DNS queries)** te doen.

Deur services van die volgende **free apis** te gebruik, kan jy ook **vorige IPs vind wat deur domains en subdomains gebruik is**. Hierdie IPs kan steeds deur die client besit word (en kan jou moontlik help om [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook check vir domains wat na ’n spesifieke IP address wys deur die tool [**hakip2host**](https://github.com/hakluke/hakip2host) te gebruik.

### **Soek na vulnerabilities**

**Doen ’n port scan van al die IPs wat nie aan CDNs behoort nie** (aangesien jy hoogs waarskynlik niks interessants daar sal vind nie). In die services wat loop en ontdek is, kan jy moontlik **vulnerabilities vind**.

**Vind ’n** [**guide**](../pentesting-network/index.html) **oor hoe om hosts te scan.**

## Soektog na webbedieners

> Ons het al die companies en hulle assets gevind, en ons ken die IP ranges, domains en subdomains binne die scope. Dit is tyd om na webbedieners te soek.

In die vorige stappe het jy waarskynlik reeds ’n mate van **recon van die ontdekte IPs en domains** gedoen, en dus moontlik reeds **al die moontlike webbedieners gevind**. Indien nie, gaan ons nou ’n paar **vinnige tricks sien om na webbedieners** binne die scope te soek.

Let daarop dat dit **op web apps discovery gefokus** sal wees, dus moet jy ook **vulnerability**- en **port scanning** uitvoer (**indien dit** deur die scope **toegelaat word**).

’n **Vinnige metode** om **oop ports** wat met **web** servers verband hou, te ontdek deur [**masscan** kan hier gevind word](../pentesting-network/index.html#http-port-discovery).\
Nog ’n gebruikersvriendelike tool om na webbedieners te soek, is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy gee bloot ’n lys van domains, waarna dit sal probeer om aan port 80 (http) en 443 (https) te koppel. Daarbenewens kan jy aandui dat dit ander ports moet probeer:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Skermkiekies**

Noudat jy **al die webbedieners** binne die omvang ontdek het (onder die **IP's** van die maatskappy en al die **domeine** en **subdomeine**), weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit dus eenvoudig en begin deur net skermkiekies van almal te neem. Deur net na die **hoofblad** te **kyk**, kan jy **vreemde** eindpunte vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** gebruik.**

Daarbenewens kan jy [**eyeballer**](https://github.com/BishopFox/eyeballer) daarna oor al die **skermkiekies** laat loop om vir jou te sê **wat waarskynlik kwesbaarhede sal bevat**, en wat nie.

## Publieke Cloud-bates

Om potensiële cloud-bates te vind wat aan ’n maatskappy behoort, moet jy **begin met ’n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir ’n crypto-maatskappy kan jy woorde soos die volgende gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordlyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Daarna moet jy met daardie woorde **permutasies** genereer (kyk na die [**Tweede DNS Brute-Force-ronde**](#second-dns-bruteforce-round) vir meer inligting).

Met die gevolglike woordlyste kan jy tools soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat jy, wanneer jy na Cloud-bates soek, **na meer as net buckets in AWS** moet **soek**.

### **Soek na kwesbaarhede**

As jy dinge soos **oop buckets of cloud-funksies wat blootgestel is** vind, moet jy **toegang daartoe verkry** en probeer vasstel wat hulle jou bied en of jy dit kan misbruik.

## E-posse

Met die **domeine** en **subdomeine** binne die omvang het jy basies alles wat jy **nodig het om na e-posse te begin soek**. Dit is die **API's** en **tools** wat die beste vir my gewerk het om e-posse van ’n maatskappy te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met API's
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Soek na kwesbaarhede**

E-posse sal later handig te pas kom om **web-aanmeldings en auth-dienste te brute-force** (soos SSH). Hulle is ook nodig vir **phishings**. Verder sal hierdie API's jou selfs meer **inligting oor die persoon** agter die e-pos gee, wat nuttig is vir die phishing-veldtog.

## Credential Leaks

Met die **domeine,** **subdomeine** en **e-posse** kan jy begin soek na credentials wat in die verlede geleak is en aan daardie e-posse behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Soek na kwesbaarhede**

As jy **geldige geleakte** credentials vind, is dit ’n baie maklike oorwinning.

## Secrets Leaks

Credential leaks hou verband met hacks van maatskappye waar **sensitiewe inligting geleak en verkoop is**. Maatskappye kan egter deur **ander leaks** geraak word waarvan die inligting nie in daardie databasisse is nie:

### Github Leaks

Credentials en API's kan in die **publieke repositories** van die **maatskappy** of van die **gebruikers** wat vir daardie github-maatskappy werk, geleak wees.\
Jy kan die **tool** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **publieke repos** van ’n **organisasie** en sy **ontwikkelaars** af te laai en [**gitleaks**](https://github.com/zricethezav/gitleaks) outomaties daaroor te laat loop.

**Leakos** kan ook gebruik word om **gitleaks** teen al die **teks** van **URL's wat daaraan verskaf** word, te laat loop, aangesien **webbladsye** soms ook secrets bevat.

#### Github Dorks

Kyk ook na hierdie **bladsy** vir potensiële **github dorks** waarna jy ook in die organisasie wat jy aanval kan soek:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Soms sal aanvallers of bloot werknemers maatskappy-inhoud op ’n paste-werf **publiseer**. Dit mag dalk **sensitiewe inligting** bevat of nie, maar dit is baie interessant om daarna te soek.\
Jy kan die tool [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om gelyktydig in meer as 80 paste-webwerwe te soek.

### Google Dorks

Ou maar kosbare google dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar behoort te wees nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) etlike **duisende** moontlike navrae bevat wat jy nie handmatig kan uitvoer nie. Jy kan dus jou gunsteling 10 kies, of jy kan ’n **tool soos** [**Gorks**](https://github.com/carlospolop/Gorks) gebruik **om hulle almal uit te voer**.

_Let daarop dat die tools wat verwag om die hele databasis met die gewone Google-blaaier uit te voer, nooit sal klaarmaak nie, aangesien google jou baie, baie gou sal blokkeer._

### **Soek na kwesbaarhede**

As jy **geldige geleakte** credentials of API-tokens vind, is dit ’n baie maklike oorwinning.

## Kwesbaarhede in Publieke Kode

As jy vind dat die maatskappy **open-source-kode** het, kan jy dit **ontleed** en na **kwesbaarhede** daarin soek.

**Afhangend van die taal** is daar verskillende **tools** wat jy kan gebruik:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Daar is ook gratis dienste wat jou toelaat om **publieke repositories** te **skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **meerderheid van die kwesbaarhede** wat bug hunters vind, is binne **webtoepassings**, dus wil ek op hierdie punt oor ’n **webtoepassingstoetsmetodologie** praat, en jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook spesiale vermelding maak van die afdeling [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede vir jou sal vind nie, is hulle handig om dit in **workflows te implementeer om aanvanklike webinligting te verkry.**

## Herhaling

> Baie geluk! Op hierdie punt het jy reeds **al die basiese enumerasie** uitgevoer. Ja, dit is basies, want baie meer enumerasie kan gedoen word (ons sal later meer truuks sien).

Jy het dus reeds:

1. Al die **maatskappye** binne die omvang gevind
2. Al die **bates** wat aan die maatskappye behoort, gevind (en ’n vuln scan uitgevoer indien dit binne die omvang is)
3. Al die **domeine** wat aan die maatskappye behoort, gevind
4. Al die **subdomeine** van die domeine gevind (enige subdomein takeover?)
5. Al die **IP's** (van en **nie van CDN's nie**) binne die omvang gevind.
6. Al die **webbedieners** gevind en ’n **skermkiekie** van hulle geneem (is daar enigiets vreemds wat ’n dieper ondersoek werd is?)
7. Al die **potensiële publieke cloud-bates** wat aan die maatskappy behoort, gevind.
8. **E-posse**, **credential leaks** en **secret leaks** gevind wat jou **baie maklik ’n groot oorwinning** kan gee.
9. **Pentesting uitgevoer op al die webwerwe wat jy gevind het**

## **Volledige Outomatiese Recon-tools**

Daar is verskeie tools beskikbaar wat ’n deel van die voorgestelde aksies teen ’n gegewe omvang sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - ’n Bietjie oud en nie opgedateer nie

## Verwysings

- [1] Alle gratis kursusse van [**@Jhaddix**](https://twitter.com/Jhaddix) soos [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
