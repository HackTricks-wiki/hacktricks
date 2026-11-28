# Eksterne Verkenningsmetodologie

{{#include ../../banners/hacktricks-training.md}}

## Bate-ontdekkings

Vir ’n gekategoriseerde lys van bykomende OSINT- en webontdekkingsprojekte, sien [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint).

> Daar is vir jou gesê dat alles wat aan ’n maatskappy behoort binne die scope val, en jy wil vasstel wat hierdie maatskappy werklik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te vind, en daarna al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:<sup>[[1]](#references)</sup>

1. Vind die verkrygings van die hoofmaatskappy; dit sal ons die maatskappye binne die scope gee.
2. Vind die ASN (indien enige) van elke maatskappy; dit sal ons die IP-reekse gee wat elke maatskappy besit.
3. Gebruik reverse whois-opsoeke om na ander inskrywings (organisasiename, domeine...) te soek wat met die eerste een verband hou (dit kan rekursief gedoen word).
4. Gebruik ander tegnieke, soos shodan `org`and `ssl`filters, om na ander bates te soek (die `ssl`-truuk kan rekursief gedoen word).

Vir die gefaseerde oorhandiging van opgeloste subdomeine na HTTP-crawling en poortontdekking, sien die [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, na die **hoofmaatskappy te soek** en op "**acquisitions**" te **klik**. Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
’n Ander opsie is om die **Wikipedia**-bladsy van die hoofmaatskappy te besoek en na **acquisitions** te soek.\
Vir openbare maatskappye, gaan **SEC/EDGAR-lêers**, **investor relations**-bladsye of plaaslike maatskappyregisters na (bv. **Companies House** in die VK).\
Vir wêreldwye korporatiewe strukture en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI**-databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Goed, op hierdie punt behoort jy al die maatskappye binne die scope te ken. Kom ons kyk hoe om hul bates te vind.

### **ASNs**

’n Outonome stelselnommer (**ASN**) is ’n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan ’n **outonome stelsel** (AS) toegeken word.\
’n **AS** bestaan uit **blokke** **IP-adresse** met ’n duidelik omskrewe beleid vir toegang tot eksterne netwerke. Dit word deur ’n enkele organisasie geadministreer, maar kan uit verskeie operateurs bestaan.

Dit is nuttig om uit te vind of die **maatskappy enige ASN toegeken is**, sodat ons sy **IP-reekse** kan vind. Dit kan nuttig wees om ’n **kwesbaarheidstoets** uit te voer teen al die **gashere** binne die **scope** en **na domeine te soek** wat binne hierdie IP’s val.\
Jy kan op **maatskappynaam**, **IP** of **domein** soek by [**https://bgp.he.net/**](https://bgp.he.net) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die maatskappy se streek, kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). In elk geval verskyn waarskynlik al die** nuttige inligting **(IP ranges and Whois)** reeds in die eerste skakel.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** enumeration versamel en som ASNs outomaties op aan die einde van die scan.

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

Jy kan ook ’n organisasie se IP-reekse vind met [ASNLookup](https://asnlookup.com/), wat ’n beperkte gratis API-vlak het.

### **Soek na kwesbaarhede**

Op hierdie stadium ken ons **al die bates binne die omvang**, so as jy toegelaat word, kan jy ’n **kwesbaarheidskandeerder** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) op al die gashere laat loop.\
Jy kan ook [**poortskanderings**](../pentesting-network/index.html#discovering-hosts-from-the-outside) laat loop **of dienste soos** Shodan, Censys of ZoomEye gebruik **om** oop poorte **te vind, en afhangend van wat jy vind, moet jy** in hierdie boek kyk hoe om verskeie moontlike dienste wat loop, te pentest.\
**Dit kan ook die moeite werd wees om te noem dat jy** verstekgebruikersnaam- **en** wagwoordlyste **kan voorberei en probeer om dienste met** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **te brute force.**

## Domains

> Ons ken al die maatskappye binne die omvang en hul bates; dit is tyd om die domeine binne die omvang te vind.

_Neem asseblief kennis dat jy met die voorgestelde tegnieke hieronder ook subdomeine kan vind en dat dié inligting nie onderskat moet word nie._

Eerstens moet jy die **hoofdomein**(e) van elke maatskappy soek. Byvoorbeeld, vir _Tesla Inc._ sal dit _tesla.com_ wees.

### **Reverse DNS**

Noudat jy al die IP-reekse van die domeine gevind het, kan jy probeer om **reverse DNS-lookups** op daardie **IP’s uit te voer om meer domeine binne die omvang te vind**. Probeer ’n DNS-bediener van die slagoffer of ’n bekende DNS-bediener (1.1.1.1, 8.8.8.8) gebruik.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Om dit te laat werk, moet die administrateur PTR handmatig aktiveer.\
Jy kan ook [SecurityTrails](https://securitytrails.com/) vir hierdie inligting gebruik, hoewel historiese DNS-data ’n betaalde plan vereis.\
Vir groot reekse is nutsgoed soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en verryking te outomatiseer.

### **Reverse Whois (loop)**

In ’n **whois** kan jy baie interessante **inligting** vind, soos **organisasienaam**, **adres**, **e-posadresse**, telefoonnommers... Maar wat selfs interessanter is, is dat jy **meer bates kan vind wat met die maatskappy verband hou** deur **reverse whois lookups op enige van daardie velde uit te voer** (byvoorbeeld ander whois-registers waarin dieselfde e-posadres voorkom).\
Jy kan aanlyn nutsgoed soos die volgende gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web en API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** webkoppelvlak; betaalde API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Betaald
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis nie (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis nie
- [https://securitytrails.com/](https://securitytrails.com/) - Beperkte gratis API-toegang vir huidige DNS/subdomeine; historiese en reverse lookups vereis ’n betaalde plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 gratis API-krediete wanneer jy inteken; daarna betaal.

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(vereis ’n whoxy API-sleutel).\
Jy kan ook outomatiese reverse whois-ontdekking met [amass](https://github.com/owasp-amass/amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer as jy ’n nuwe domein vind.**

### **Trackers**

As jy **dieselfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy aanneem dat **albei bladsye** deur **dieselfde span bestuur word**.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is ’n paar bladsye en nutsgoed waarmee jy op grond van hierdie trackers en meer kan soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Betaalde** web- en API-diens ([pryse](https://www.stackscan.com/pricing)); geen gratis plan word tans geadverteer nie. Gebruik enige bediende bate as draaipunt, nie net tracker-ID’s nie: ’n script path, ’n self-hosted bundlename of die gasheer waarvan ’n bate gelaai word; dit lewer elke webwerf op wat dit bevat.

Die API gee die stack vir ’n enkele domein terug, wat nuttig is om te bevestig dat ’n kandidaatbate aan dieselfde domeingroep behoort:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gee elke opgespoorde tegnologie saam met sy kategorie terug. Asset pivoting is tans net vir web beskikbaar; die API dek opsoeke per domein.

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine van ons teiken kan vind deur na dieselfde favicon-ikoonhash te soek? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py)-tool, gemaak deur [@m4ll0k2](https://twitter.com/m4ll0k2), doen. So gebruik jy dit:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash-resultate wat gebruik word om domeine te ontdek wat dieselfde favicon-hash deel](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, sal favihash ons help om domeine te ontdek wat dieselfde favicon-ikoonhash as ons teiken het.

![favihash-uitset wat gebruik word om domeine met dieselfde favicon-hash te ontdek](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Gebruik ’n bekende favicon-hash as ’n Shodan- of FOFA-pivot om ander blootgestelde gevalle van dieselfde tegnologie te vind.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

So kan jy die **favicon-hash** van ’n webwerf bereken (MMH3 oor die **base64-gekodeerde** favicon-grepe):

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

Jy kan ook favicon-hashes op groot skaal kry met [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) en dan in Shodan/Censys pivot.

Beskou favicon-fingerafdrukke as leidrade en valideer dit met omliggende seine.<sup>[[3]](#references)[[4]](#references)</sup>

- **Beskou die hash as ’n aanduiding, nie as bewys nie**: MMH3 is kompak; botsings, hergebruikte ikone en doelbewuste vervalsing is moontlik.
- **Ondersoek meer as** `/favicon.ico`: kyk na framework-/build-paaie, manifest-lêers, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data-URL’s en HTML-`<link rel="icon">`-tags.
- **Statiese bates kan steeds bereikbaar wees agter WAF-/SSO-/IdP-kontroles**: vra die ikoon direk aan en hersien `ETag`, `Last-Modified`, redirects en cache-headers.
- **Valideer ooreenstemmings met omliggende seine**: vergelyk die titel, HTML-/body-hash, headers, TLS-sertifikaatonderwerpe/SAN’s, produkkomponente en blootgestelde poorte.
- **Groepeer volgens HTML-/body-hash**: ’n konsekwente template versterk die fingerafdruk; gemengde templates dui op ’n generiese of gedeelde ikoon.
- **Beskou ’n hash wat oor onverwante handtekeninge, poorte en produkte voorkom as ’n moontlike honeypot of plekhouer.**
- **Vergelyk by dubbelsinnige teikens ’n regte bladsy met ’n niebestaande pad**, soos `/_favicon_probe_<8-hex>`; ooreenstemmende hosting- of parkeerantwoorde kan die gedeelde ikoon verklaar.
- **Begin triage met Nuclei-opsporingsreëls of publieke datastelle** wat favicon-hashes aan produkte en CPE’s koppel.
- **Onthou die IP-gesentreerde dekkingsgaping**: CDN-gefrontde, SNI-gerouteerde, anycast- en slegs-domein-oppervlakke kan uit Shodan-agtige datastelle ontbreek.

### **Kopiereg / Uniq string**

Soek binne die webblaaie na **stringe wat oor verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **kopieregstring** kan ’n goeie voorbeeld wees. Soek dan na daardie string in **Google**, in ander **blaaiers** of selfs in **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT-tyd**

Dit is algemeen om ’n cron-taak soos die volgende te hê.

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

om alle sertifikate op ’n bediener gelyktydig te hernu. Deur sertifikaattydstempels of posisies in certificate-transparency-logboeke met mekaar te vergelyk, kan verwante domains onthul word.<sup>[[6]](#references)</sup>

Gebruik ook **certificate transparency**-logboeke direk:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### E-pos-DMARC-inligting

Jy kan ’n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of ’n hulpmiddel soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domains en subdomains te vind wat dieselfde DMARC-inligting deel**.\
Nog ’n nuttige diens is [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

’n Verlate A-rekord kan bereikbaar word wanneer ’n cloud-verskaffer ’n IP heraanwys. Die aangehaalde navorsing demonstreer ’n opportunistiese werkvloei wat ’n instance voorsien en die adres met passiewe DNS-data vergelyk; toets takeover-scenario’s slegs binne die gemagtigde scope.<sup>[[7]](#references)</sup>

### **Ander maniere**

Herhaal die toepaslike ontdekkingspivots wanneer jy ’n nuwe domain vind: elke resultaat kan bykomende sertifikaatname, passiewe-DNS-verhoudings, favicon-ooreenkomste en organisasie-identifiseerders onthul wat nie vanaf die oorspronklike saad sigbaar was nie.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Soos jy reeds die naam ken van die organisasie wat die IP-spasie besit, kan jy met daardie data in Shodan soek deur: `org:"Tesla, Inc."` Gaan die gevonde hosts na vir nuwe, onverwagte domains in die TLS-sertifikaat.

Jy kan toegang tot die **TLS-sertifikaat** van die hoofwebblad kry, die **organisasienaam** verkry en dan binne die **TLS-sertifikate** van al die webblaaie wat aan **Shodan** bekend is na daardie naam soek met die filter: `ssl:"Tesla Motors"` of ’n hulpmiddel soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ’n hulpmiddel wat **domains soek wat met ’n hoofdomein verband hou** en **subdomains** daarvan vind; dis nogal indrukwekkend.

**Passiewe DNS / Historiese DNS**

Passiewe DNS-data is uitstekend om **ou en vergete rekords** te vind wat steeds resolve of oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Soek na kwesbaarhede**

Kyk vir moontlike [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien **gebruik ’n maatskappy ’n domain**, maar het hulle **eienaarskap verloor**. Registreer dit bloot (as dit goedkoop genoeg is) en laat weet die maatskappy.

As jy enige **domain met ’n ander IP** as dié wat jy reeds tydens die bate-ontdekking gevind het, opspoor, moet jy ’n **basiese kwesbaarheidskandering** (met Nessus of OpenVAS) en ’n [**poortskandering**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** uitvoer. Afhangend van watter dienste loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "aanval"**.\
_Let daarop dat die domain soms op ’n IP gehuisves word wat nie deur die kliënt beheer word nie, en dus buite die scope val. Wees versigtig._

## Subdomains

> Ons ken al die maatskappye binne die scope, al die bates van elke maatskappy en al die domains wat met die maatskappye verband hou.

Dis tyd om al die moontlike subdomains van elke gevonde domain te vind.

> [!TIP]
> Let daarop dat sommige van die hulpmiddels en tegnieke om domains te vind, ook kan help om subdomains te vind

### **DNS**

Kom ons probeer om **subdomains** uit die **DNS**-rekords te kry. Ons moet ook **Zone Transfer** probeer (indien dit kwesbaar is, moet jy dit rapporteer).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Vir API's en platforms wat infrastruktuur, reputasie, datalekrekords en verryking buite subdomeinontdekking dek, sien die [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md).

Die vinnigste manier om baie subdomeine te kry, is om in eksterne bronne te soek. Die mees gebruikte **hulpmiddels** is die volgende (stel die API-sleutels op vir beter resultate):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

Daar is **ander interessante tools/API's** wat, selfs al is hulle nie direk daarop toegespits om subdomeine te vind nie, nuttig kan wees om subdomeine te vind, soos:

- [**IP.THC.ORG**](https://ip.thc.org) gratis API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB gratis API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** haal bekende URL's van AlienVault's Open Threat Exchange, die Wayback Machine en Common Crawl vir enige gegewe domein op.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hulle skandeer die web op soek na JS-lêers en haal subdomeine daaruit.

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

- [**SecurityTrails**](https://securitytrails.com/) bied beperkte gratis API-toegang vir huidige DNS- en subdomeindata; historiese DNS-/IP-data vereis ’n betaalde plan.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Hierdie projek bied **gratis alle subdomeine wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data kry met [chaospy](https://github.com/Moaaz-0x/chaospy), of selfs toegang kry tot die omvang wat hierdie projek gebruik: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Jy kan ’n **vergelyking** van baie van hierdie nutsmiddels hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomeine** te vind deur DNS-bedieners met moontlike subdomeinname te brute-force.

Vir hierdie aksie het jy ’n paar **algemene subdomeinwoordlyste nodig, soos**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP-adresse van goeie DNS-resolvers. Om ’n lys van betroubare DNS-resolvers te genereer, kan jy die resolvers aflaai vanaf [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole nutsmiddels vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste nutsmiddel wat ’n doeltreffende DNS brute-force uitgevoer het. Dit is baie vinnig, maar geneig om vals positiewe resultate te lewer.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik volgens my net 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is ’n wrapper om `massdns`, geskryf in go, waarmee jy geldige subdomeine deur middel van aktiewe bruteforce kan enumereer, asook subdomeine met wildcard-hantering kan resolve, met maklike ondersteuning vir invoer en uitvoer.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinname asynchroon met brute force te probeer.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Tweede DNS Brute-Force-rondte

Nadat jy subdomeine met behulp van oop bronne en brute-force gevind het, kan jy variasies van die gevonde subdomeine genereer om nog meer te probeer vind. Verskeie nutsmiddels is hiervoor nuttig:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Genereer permutasies op grond van die domeine en subdomeine.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Genereer permutasies gegewe die domeine en subdomeine.
  - Jy kan goaltdns se permutasie-**wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Genereer permutasies op grond van die domeine en subdomeine. As geen permutasielêer aangedui word nie, sal gotator sy eie een gebruik.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Benewens die generering van permutations van subdomains, kan dit ook probeer om hulle te resolve (maar dis beter om die tools wat hierbo genoem is, te gebruik).
  - Jy kan altdns-permutations se **wordlist** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Nog ’n hulpmiddel om permutasies, mutasies en wysigings van subdomeine uit te voer. Hierdie hulpmiddel sal die resultaat brute force (dit ondersteun nie DNS-wildcards nie).
  - Jy kan die dmut-permutasiewoordelys [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Op grond van ’n domein **genereer dit nuwe potensiële subdomeinname** volgens aangeduide patrone om meer subdomeine te probeer ontdek.

#### Slim permutasiegenerering

- [**regulator**](https://github.com/cramppet/regulator): Leer regex-agtige patrone uit ontdekte subdomeine en genereer kandidaatname om te resolveer.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is ’n subdomein-brute-force-fuzzer, gekoppel aan ’n uiters eenvoudige maar doeltreffende DNS-responsgeleide algoritme. Dit gebruik ’n verskafte stel invoerdata, soos ’n pasgemaakte woordelys of historiese DNS/TLS-rekords, om akkuraat meer ooreenstemmende domeinname te sintetiseer en hulle verder in ’n lus uit te brei op grond van inligting wat tydens ’n DNS-skandering versamel is.

```
echo www | subzuf facebook.com
```

### **Subdomein-ontdekkingswerkvloei**

Trickest-werkvloervoorbeelde kombineer OSINT, DNS-brute force en permutasiestappe vir herhaalbare subdomein-enumerasie.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

As jy ’n IP-adres gevind het wat **een of meer webblaaie** bevat wat aan subdomeine behoort, kan jy probeer om **ander subdomeine met webwerwe op daardie IP-adres te vind** deur **OSINT-bronne** vir domeine op ’n IP-adres te deursoek, of deur **VHost-domeinname op daardie IP-adres met brute force te probeer**.

#### OSINT

Jy kan **VHosts op IP-adresse vind met** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander API’s**.

**Brute Force**

As jy vermoed dat ’n subdomein dalk op ’n webbediener versteek is, kan jy probeer om dit met brute force te vind:

Vir name-based vhosts, fuzz die `Host`-header en gebruik ffuf se outomatiese kalibrasie om die verstekrespons uit te filter.<sup>[[2]](#references)</sup>

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
> Met hierdie tegniek kan jy dalk selfs toegang kry tot interne/verborge endpoints.

### **CORS Brute Force**

Soms sal jy bladsye vind wat die header _**Access-Control-Allow-Origin**_ slegs terugstuur wanneer ’n geldige domein/subdomein in die _**Origin**_-header gestel is. In hierdie scenario’s kan jy hierdie gedrag misbruik om nuwe **subdomeine** te **ontdek**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Wanneer jy na **subdomains** soek, let op of enige daarvan na ’n soort **bucket** wys, en [**kontroleer in daardie geval die permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Aangesien jy teen hierdie tyd al die domains binne die scope sal ken, kan jy ook probeer om [**moontlike bucket name met brute force te vind en die permissions na te gaan**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Monitering**

Jy kan monitor of **nuwe subdomains** van ’n domain geskep word deur die **Certificate Transparency**-logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Soek na kwesbaarhede**

Kyk vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na ’n **S3 bucket** wys, [**kontroleer die permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

As jy enige **subdomain met ’n IP-adres wat verskil** van dié wat jy reeds tydens die assets discovery gevind het, moet jy ’n **basiese kwesbaarheidsskandering** uitvoer (met Nessus of OpenVAS) en ook ’n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangend van die dienste wat loop, kan jy **in hierdie boek truuks vind om hulle te "attack"**.\
_Let daarop dat die subdomain soms op ’n IP-adres gehuisves word wat nie deur die kliënt beheer word nie, en dus buite die scope val. Wees versigtig._

## IPs

In die aanvanklike stappe het jy moontlik **IP-reekse, domains en subdomains gevind**.\
Dis tyd om **al die IPs uit daardie reekse te versamel**, asook dié vir die **domains/subdomains (DNS-navrae).**

Deur dienste soos die volgende te gebruik, kan jy ook **vorige IPs vind wat deur domains en subdomains gebruik is**. Die kliënt besit dalk steeds hierdie IPs (en hulle kan jou help om [**CloudFlare-bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind).

- [**SecurityTrails**](https://securitytrails.com/) (historiese DNS/IP-data vereis ’n betaalde plan)

Jy kan ook met die [**hakip2host**](https://github.com/hakluke/hakip2host)-tool of ’n aanlyn reverse IP-lookup soos [**NetAPI**](https://netapi.com/lookup-ip/) kyk watter domains na ’n spesifieke IP-adres wys.

### **Soek na kwesbaarhede**

**Voer ’n port scan uit op alle IPs wat nie aan CDNs behoort nie** (want jy sal waarskynlik niks interessants daar vind nie). Jy kan moontlik **kwesbaarhede vind** in die ontdekte dienste wat loop.

**Vind ’n** [**gids**](../pentesting-network/index.html) **oor hoe om hosts te skandeer.**

## Soektog na web servers

> Ons het al die maatskappye en hul assets gevind, en ons ken die IP-reekse, domains en subdomains binne die scope. Dis tyd om na web servers te soek.

In die vorige stappe het jy waarskynlik reeds ’n mate van **recon op die ontdekte IPs en domains** gedoen, en moontlik **al die moontlike web servers gevind**. Indien nie, gaan ons nou ’n paar **vinnige truuks sien om web servers binne die scope te vind**.

Let daarop dat dit **op die ontdekking van web apps gerig** sal wees. Jy moet dus ook **kwesbaarheids-** en **port scanning** uitvoer (**indien die scope dit toelaat**).

’n **Vinnige metode** om **oop ports** te ontdek wat met **web** servers verband hou, met [**masscan, kan jy hier vind**](../pentesting-network/index.html#http-port-discovery).\
Nog ’n gebruikersvriendelike tool om web servers te vind, is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy hoef net ’n lys domains te verskaf; die tool sal probeer om aan port 80 (http) en 443 (https) te koppel. Jy kan ook aandui dat dit ander ports moet probeer:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Skermskote**

Noudat jy **al die webbedieners** binne die omvang ontdek het (onder die **IP's** van die maatskappy en al die **domeine** en **subdomeine**), weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit dus eenvoudig en begin deur bloot skermskote van almal te neem. Deur net na die **hoofbladsy** te **kyk**, kan jy **vreemde** endpoints vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Daarna kan jy ook [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om al die **skermskote** te verwerk en vir jou te sê **wat waarskynlik kwesbaarhede bevat** en wat nie.

## Publieke Wolkbates

Om potensiële wolkbates te vind wat aan 'n maatskappy behoort, moet jy **begin met 'n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir 'n kripto-maatskappy kan jy woorde soos hierdie gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordlyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Vervolgens moet jy met daardie woorde **permutasies** genereer (raadpleeg die [**Tweede rondte DNS-brute-force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordlyste kan jy nutsmiddels soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Onthou dat jy, wanneer jy na Cloud Assets soek, na **meer as net buckets in AWS** moet kyk.

### **Soek na kwesbaarhede**

As jy dinge soos **oop buckets of blootgestelde cloud functions** vind, moet jy **toegang daartoe verkry** en probeer sien wat hulle bied en of jy hulle kan misbruik.

## E-posse

Met die **domeine** en **subdomeine** binne die omvang het jy basies alles wat jy **nodig het om na e-posadresse te begin soek**. Die volgende **API's** en **nutsmiddels** het vir my die beste gewerk om e-posadresse van 'n maatskappy te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met API's
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Soek na kwesbaarhede**

E-posadresse sal later handig te pas kom om **web-aanmeldings en auth-dienste** (soos SSH) met brute-force aan te val. Hulle is ook nodig vir **phishing**. Verder sal hierdie API's jou nog meer **inligting oor die persoon** agter die e-posadres gee, wat nuttig is vir die phishing-veldtog.

## Geloofsbriewe-leaks

Met die **domeine,** **subdomeine** en **e-posadresse** kan jy begin soek na geloofsbriewe wat in die verlede geleak is en aan daardie e-posadresse behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe vind wat gelek het**, is dit 'n baie maklike oorwinning.

## Secrets-leaks

Geloofsbriewe-leaks hou verband met hacks van maatskappye waar **sensitiewe inligting gelek en verkoop is**. Maatskappye kan egter deur **ander leaks** geraak word waarvan die inligting nie in daardie databasisse voorkom nie:

### Github-leaks

Geloofsbriewe en API's kan uitlek in die **publieke repositories** van die **maatskappy** of van die **gebruikers** wat by daardie maatskappy werk.\
Jy kan die **nutsmiddel** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **publieke repos** van 'n **organisasie** en sy **ontwikkelaars** af te laai en [**gitleaks**](https://github.com/gitleaks/gitleaks) outomaties daaroor te laat loop.

**Leakos** kan ook gebruik word om **gitleaks** te laat loop oor al die **teks** wat deur **URL's wat daaraan deurgegee word** verskaf word, aangesien **webbladsye soms ook secrets bevat**.

#### Github Dorks

Raadpleeg die [GitHub dorks and leaks page](github-leaked-secrets.md) vir moontlike **GitHub dorks** om in die organisasie te soek.

### Paste-leaks

Soms **publiseer aanvallers of bloot werknemers maatskappy-inhoud op 'n paste-werf**. Dit kan **sensitiewe inligting bevat** of nie, maar dit is baie nuttig om daarna te soek.\
Jy kan die nutsmiddel [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om gelyktydig op meer as 80 paste-werwe te soek.

### Google Dorks

Ou maar goudwaardige google dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar behoort te wees nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) etlike **duisende** moontlike navrae bevat wat jy nie met die hand kan uitvoer nie. Jy kan dus jou gunsteling 10 kies, of 'n **nutsmiddel soos** [**Gorks**](https://github.com/carlospolop/Gorks) gebruik **om almal uit te voer**.

_Let daarop dat nutsmiddels wat verwag om die hele databasis met die gewone Google-blaaier uit te voer, nooit klaar sal wees nie, want Google sal jou baie, baie gou blokkeer._

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe of API-tokens vind wat gelek het**, is dit 'n baie maklike oorwinning.

## Kwesbaarhede in publieke kode

As jy ontdek dat die maatskappy **oopbronkode** het, kan jy dit **ontleed** en na **kwesbaarhede** daarin soek.

**Afhangend van die taal** is daar verskillende **nutsmiddels** wat jy kan gebruik; sien die lys [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Daar is ook gratis dienste waarmee jy **publieke repositories kan skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting-webmetodologie**](../../network-services-pentesting/pentesting-web/index.html)

Die **meeste kwesbaarhede** wat bug hunters vind, is in **webtoepassings**, so op hierdie punt wil ek graag oor 'n **toetsmetodologie vir webtoepassings** praat. Jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook spesiaal melding maak van die afdeling [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede sal vind nie, is hulle handig om in **workflows te gebruik en aanvanklike webinligting te bekom.**

## Samevatting

> Baie geluk! Op hierdie punt het jy reeds **al die basiese enumerasie** uitgevoer. Ja, dit is basies, want daar is nog baie meer enumerasie wat gedoen kan word (ons sal later meer truuks sien).

Jy het dus reeds:

1. Al die **maatskappye** binne die omvang gevind
2. Al die **bates** gevind wat aan die maatskappye behoort (en 'n vuln-scan uitgevoer indien dit binne omvang is)
3. Al die **domeine** gevind wat aan die maatskappye behoort
4. Al die **subdomeine** van die domeine gevind (enige subdomain takeover?)
5. Al die **IP's** (van en **nie van CDNs nie**) binne die omvang gevind.
6. Al die **webbedieners** gevind en 'n **skermskoot** van hulle geneem (enigiets vreemds wat die moeite werd is om van nader te bekyk?)
7. Al die **moontlike publieke wolkbates** gevind wat aan die maatskappy behoort.
8. **E-posadresse**, **geloofsbriewe-leaks** en **secret-leaks** gevind wat jou **baie maklik 'n groot oorwinning** kan besorg.
9. **Pentesting op al die webwerwe wat jy gevind het** uitgevoer

## **Volledige outomatiese Recon-nutsmiddels**

Daar is verskeie nutsmiddels beskikbaar wat sommige van die voorgestelde aksies teen 'n gegewe omvang sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 'n Bietjie oud en nie opgedateer nie



## References

- [1] [Jason Haddix – Die Bug Hunter's Methodology v4.0: Recon-uitgawe](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Oor Favicons: Van blaaierikone tot intelligensie oor die aanvalsvlak](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Favicon.ico bewapen vir BugBounties, OSINT en alles moontlik](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ontdekking van domeine via 'n tydkorrelasie-aanval op Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passiewe oorneem: 'n Duur subdomein-oornameveldtog ontbloot (en naboots)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: 'n Unieke metode vir subdomein-enumerasie](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Volledige subdomein-ontdekkingsworkflow, Deel 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Volledige brute-force-ontdekking van subdomeine met 'n geoutomatiseerde Trickest-workflow, Deel 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Skermskoot van favihash-uitset](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
