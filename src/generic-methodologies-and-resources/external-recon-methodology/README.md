# Eksterne verkenningsmetodologie

{{#include ../../banners/hacktricks-training.md}}

## Bates-ontdekkings

> Daar is vir jou gesê dat alles wat aan ’n maatskappy behoort binne scope val, en jy wil uitvind wat hierdie maatskappy werklik besit.

Die doel van hierdie fase is om al die **maatskappye te vind wat deur die hoofmaatskappy besit word**, en dan al die **bates** van hierdie maatskappye. Hiervoor gaan ons:<sup>[[1]](#references)</sup>

1. Die verkrygings van die hoofmaatskappy vind; dit sal ons die maatskappye binne scope gee.
2. Die ASN (indien enige) van elke maatskappy vind; dit sal ons die IP-reekse gee wat elke maatskappy besit.
3. Omgekeerde whois-soektogte gebruik om ander inskrywings (organisasiename, domeine...) te soek wat met die eerste een verband hou (dit kan rekursief gedoen word).
4. Ander tegnieke soos shodan `org`- en `ssl`-filters gebruik om ander bates te soek (die `ssl`-truuk kan rekursief gedoen word).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, vir die **hoofmaatskappy te soek** en op "**acquisitions**" te **klik**. Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
’n Ander opsie is om die **Wikipedia**-bladsy van die hoofmaatskappy te besoek en vir **acquisitions** te soek.\
Vir openbare maatskappye, raadpleeg **SEC/EDGAR-filings**, **beleggersverhoudinge**-bladsye of plaaslike maatskappyregisters (bv. **Companies House** in die VK).\
Vir globale korporatiewe strukture en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI**-databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Goed, teen hierdie punt behoort jy al die maatskappye binne scope te ken. Kom ons kyk hoe om hul bates te vind.

### **ASNs**

’n Autonomous system number (**ASN**) is ’n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan ’n **autonomous system** (AS) toegeken word.\
’n **AS** bestaan uit **blokke** van **IP-adresse** met ’n duidelik omskrewe beleid vir toegang tot eksterne netwerke. Dit word deur ’n enkele organisasie bestuur, maar kan uit verskeie operateurs bestaan.

Dit is nuttig om uit te vind of die **maatskappy enige ASN toegeken gekry het**, sodat sy **IP-reekse** gevind kan word. Dit sal nuttig wees om ’n **kwesbaarheidstoets** uit te voer teen alle **hosts** binne **scope** en **na domeine** binne hierdie IP’s te soek.\
Jy kan volgens maatskappy**naam**, **IP** of **domein** soek by [**https://bgp.he.net/**](https://bgp.he.net) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die streek waar die maatskappy geleë is, kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In elk geval verskyn waarskynlik al die** nuttige inligting **(IP-reekse en Whois)** reeds in die eerste skakel.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

[**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** enumerering versamel en som ASNs outomaties op aan die einde van die scan.

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

Jy kan ook ’n organisasie se IP-reekse vind deur [ASNLookup](https://asnlookup.com/) te gebruik, wat ’n beperkte gratis API-vlak het.

### **Soek na kwesbaarhede**

Op hierdie stadium ken ons **al die bates binne die omvang**, dus kan jy, indien jy toestemming het, ’n **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) op al die gashere laat loop.\
Jy kan ook [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) uitvoer **of dienste soos** Shodan, Censys of ZoomEye **gebruik om** oop poorte **te vind, en afhangend van wat jy vind, moet jy** in hierdie boek kyk hoe om verskeie moontlike dienste wat loop, te pentest.\
**Dit kan ook die moeite werd wees om te noem dat jy ook** lyste met verstekgebruikersname **en** wagwoorde **kan voorberei en probeer om dienste met** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) te **bruteforce**.

## Domeine

> Ons ken al die maatskappye binne die omvang en hul bates; dis tyd om die domeine binne die omvang te vind.

_Let asseblief daarop dat jy met die tegnieke wat hierna voorgestel word ook subdomeine kan vind, en dat jy daardie inligting nie moet onderskat nie._

Eerstens moet jy die **hoofdomein**(e) van elke maatskappy soek. Byvoorbeeld, vir _Tesla Inc._ sal dit _tesla.com_ wees.

### **Reverse DNS**

Aangesien jy al die IP-reekse van die domeine gevind het, kan jy probeer om **reverse dns lookups** op daardie **IP’s uit te voer om meer domeine binne die omvang te vind**. Probeer om ’n DNS-bediener van die slagoffer of ’n bekende DNS-bediener (1.1.1.1, 8.8.8.8) te gebruik.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Om dit te laat werk, moet die administrateur PTR handmatig aktiveer.\
Jy kan ook [SecurityTrails](https://securitytrails.com/) vir hierdie inligting gebruik, hoewel historiese DNS-data ’n betaalde plan vereis.\
Vir groot reekse is nutsmiddels soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en verryking te outomatiseer.

### **Reverse Whois (loop)**

In ’n **whois** kan jy baie interessante **inligting** vind, soos **organisasienaam**, **adres**, **e-posadresse**, telefoonnommers... Maar wat nog interessanter is, is dat jy **meer bates kan vind wat met die maatskappy verband hou** as jy **reverse whois-lookups op enige van daardie velde uitvoer** (byvoorbeeld ander whois-registers waar dieselfde e-posadres voorkom).\
Jy kan aanlyn nutsmiddels soos die volgende gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (web en API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** webkoppelvlak; betaalde API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Betaald
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis nie (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis nie
- [https://securitytrails.com/](https://securitytrails.com/) - Beperkte gratis API-toegang vir huidige DNS/subdomeine; historiese en reverse lookups vereis ’n betaalde plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 gratis API-krediete wanneer jy registreer; daarna betaal.

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(vereis ’n whoxy API-sleutel).\
Jy kan ook outomatiese reverse whois-ontdekking met [amass](https://github.com/owasp-amass/amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer as jy ’n nuwe domein vind.**

### **Trackers**

As jy **dieselfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy aanvaar dat **albei bladsye** deur **dieselfde span bestuur word**.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is ’n paar bladsye en nutsmiddels waarmee jy volgens hierdie en ander trackers kan soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Betaalde** web- en API-diens ([pryse](https://www.stackscan.com/pricing)); geen gratis plan word tans geadverteer nie. Pivot op enige bediende bate, nie net tracker-ID’s nie: ’n script-pad, ’n selfgehoste bundelnaam of die host waarvan ’n bate gelaai word; dit gee elke webwerf terug wat dit bevat.

Die API gee die stack vir ’n enkele domein terug, wat nuttig is om te bevestig dat ’n kandidaatbate aan dieselfde omgewing behoort:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gee elke bespeurde tegnologie saam met sy kategorie terug. Asset pivoting is tans net vir web beskikbaar; die API bied opsoeke per domein.

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine van ons teiken kan vind deur na dieselfde favicon-ikoonhash te soek? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py)-nutsding, gemaak deur [@m4ll0k2](https://twitter.com/m4ll0k2), doen. So gebruik jy dit:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash-resultate wat gebruik word om domeine te ontdek wat dieselfde favicon-hash deel](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, stel favihash ons in staat om domeine te ontdek wat dieselfde favicon-hash as ons teiken het.

![favihash-uitvoer wat gebruik word om domeine met dieselfde favicon-hash te ontdek](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Gebruik ’n bekende favicon-hash as ’n Shodan- of FOFA-pivot om ander blootgestelde instansies van dieselfde tegnologie te vind.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

So kan jy die **favicon-hash bereken** van ’n webwerf (MMH3 oor die **base64-geënkodeerde** favicon-grepe):

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

Beskou favicon-vingerafdrukke as leidrade en valideer dit met omliggende seine.<sup>[[3]](#references)[[4]](#references)</sup>

- **Beskou die hash as ’n aanwyser, nie as bewys nie**: MMH3 is kompak; botsings, hergebruikte ikone en doelbewuste spoofing is moontlik.
- **Ondersoek meer as** `/favicon.ico`: inspekteer raamwerk-/bou-paaie, manifeslêers, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, ingebedde data-URL’s en HTML-`<link rel="icon">`-etikette.
- **Statiese bates kan steeds bereikbaar wees agter WAF-/SSO-/IdP-kontroles**: versoek die ikoon direk en ondersoek `ETag`, `Last-Modified`, herleidings en kasopskrifte.
- **Valideer ooreenstemmings met omliggende seine**: vergelyk die titel, HTML-/liggaam-hash, opskrifte, TLS-sertifikaatonderwerpe/SAN’s, produkkomponente en blootgestelde poorte.
- **Groepeer volgens HTML-/liggaam-hash**: ’n konsekwente sjabloon versterk die vingerafdruk; gemengde sjablone dui op ’n generiese of gedeelde ikoon.
- **Beskou ’n hash wat oor onverwante handtekeninge, poorte en produkte voorkom as ’n moontlike honeypot of plekhouer.**
- **Vergelyk op dubbelsinnige teikens ’n regte bladsy met ’n niebestaande pad**, soos `/_favicon_probe_<8-hex>`; ooreenstemmende hosting- of parkeerantwoorde kan die gedeelde ikoon verklaar.
- **Begin triage met Nuclei-opsporingsreëls of publieke datastelle** wat favicon-hashes aan produkte en CPE’s koppel.
- **Onthou die IP-gesentreerde dekkingsgaping**: CDN-voorgestelde, SNI-gerouteerde, anycast- en domein-alleen-oppervlakke kan in Shodan-agtige datastelle ontbreek.

### **Kopiereg / Unieke string**

Soek binne die webblaaie na **stringe wat oor verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **kopieregstring** kan ’n goeie voorbeeld wees. Soek dan na daardie string in **Google**, ander **blaaiers** of selfs in **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT-tyd**

Dit is algemeen om ’n cron-taak te hê soos ’n bewerking wat

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

om alle sertifikate op ’n bediener gelyktydig te hernu. Deur sertifikaattydstempels of posisies in certificate transparency-logboeke te korreleer, kan verwante domeine onthul word.<sup>[[6]](#references)</sup>

Gebruik ook **certificate transparency**-logboeke direk:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### E-pos-DMARC-inligting

Jy kan ’n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of ’n nutsmiddel soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domeine en subdomeine te vind wat dieselfde DMARC-inligting deel**.\
Nog ’n nuttige diens is [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

’n Verlate A-rekord kan bereikbaar word wanneer ’n wolkverskaffer ’n IP-adres hertoewys. Die aangehaalde navorsing demonstreer ’n opportunistiese werkvloei wat ’n instansie voorsien en sy adres met passiewe DNS-data korreleer; toets takeover-scenario’s slegs binne die gemagtigde omvang.<sup>[[7]](#references)</sup>

### **Ander maniere**

Herhaal die toepaslike ontdekkingsmetodes elke keer wanneer jy ’n nuwe domein vind: elke resultaat kan bykomende sertifikaatname, passiewe DNS-verwantskappe, favicon-ooreenkomste en organisasie-identifiseerders blootlê wat nie uit die oorspronklike beginpunt sigbaar was nie.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Aangesien jy reeds die naam ken van die organisasie wat die IP-adresruimte besit, kan jy met daardie data in shodan soek deur: `org:"Tesla, Inc."` Gaan die gevonde gashere na vir nuwe, onverwagte domeine in die TLS-sertifikaat.

Jy kan toegang tot die **TLS-sertifikaat** van die hoofwebblad verkry, die **Organisasienaam** kry en dan binne die **TLS-sertifikate** van al die webblaaie wat aan **shodan** bekend is vir daardie naam soek met die filter: `ssl:"Tesla Motors"` of ’n nutsmiddel soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ’n nutsmiddel wat soek na **domeine wat met ’n hoofdomein verband hou** en **subdomeine** daarvan; dit is nogal indrukwekkend.

**Passiewe DNS / Historiese DNS**

Passiewe DNS-data is uitstekend om **ou en vergete rekords** te vind wat steeds resolve of oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Soek na kwesbaarhede**

Kyk vir moontlike [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Miskien **gebruik ’n maatskappy ’n domein** maar het hulle **eienaarskap verloor**. Registreer dit eenvoudig (as dit goedkoop genoeg is) en laat weet die maatskappy.

As jy enige **domein met ’n ander IP-adres** vind as dié wat jy reeds tydens die bate-ontdekking gevind het, moet jy ’n **basiese kwesbaarheidskandering** (met Nessus of OpenVAS) en ’n [**poortskandering**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** uitvoer. Afhangend van watter dienste loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "aanval"**.\
_Let daarop dat die domein soms gehuisves word op ’n IP-adres wat nie deur die kliënt beheer word nie en dus buite die omvang val; wees versigtig._

## Subdomeine

> Ons ken al die maatskappye binne die omvang, al die bates van elke maatskappy en al die domeine wat met die maatskappye verband hou.

Dit is tyd om al die moontlike subdomeine van elke gevonde domein te vind.

> [!TIP]
> Let daarop dat sommige van die nutsmiddels en tegnieke om domeine te vind ook kan help om subdomeine te vind

### **DNS**

Kom ons probeer om **subdomeine** uit die **DNS**-rekords te kry. Ons moet ook **Zone Transfer** probeer (As dit kwesbaar is, moet jy dit rapporteer).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Vir APIs en platforms wat infrastruktuur, reputasie, breach records en verryking buite subdomain discovery dek, sien die [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md).

Die vinnigste manier om baie subdomains te verkry, is om in eksterne bronne te soek. Die gereedskap wat die meeste gebruik word, is die volgende (stel die API keys in vir beter resultate):


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

Daar is **ander interessante tools/API's** wat, hoewel hulle nie spesifiek daarop gerig is om subdomeine te vind nie, nuttig kan wees om subdomeine te vind, soos:

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

- [**gau**](https://github.com/lc/gau)**:** haal bekende URL's op vanaf AlienVault se Open Threat Exchange, die Wayback Machine en Common Crawl vir enige domein.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hulle deurkruis die web op soek na JS-lêers en haal subdomeine daaruit.

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

- [**Censys subdomain-soeker**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) bied beperkte gratis API-toegang tot huidige DNS- en subdomaindata; historiese DNS-/IP-data vereis ’n betaalde plan.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Hierdie projek bied **gratis al die subdomeine wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data kry met [chaospy](https://github.com/Moaaz-0x/chaospy), of selfs toegang kry tot die scope wat deur hierdie projek gebruik word: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Jy kan ’n **vergelyking** van baie van hierdie tools hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomeine** te vind deur DNS-bedieners met moontlike subdomeinname te brute-force.

Vir hierdie aksie het jy ’n paar **algemene woordlyste vir subdomeine nodig, soos**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP-adresse van goeie DNS-resolvers. Om ’n lys van betroubare DNS-resolvers te skep, kan jy die resolvers aflaai vanaf [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filter. Of jy kan die volgende gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole tools vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat ’n doeltreffende DNS brute-force uitgevoer het. Dit is baie vinnig, maar is geneig om vals positiewe te lewer.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Ek dink hierdie een gebruik net 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is ’n wrapper om `massdns`, geskryf in Go, waarmee jy geldige subdomeine deur aktiewe bruteforce kan enumereer, asook subdomeine kan resolve met wildcard-hantering en maklike invoer-uitvoerondersteuning.

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

### Tweede DNS Brute-Force-rondte

Nadat jy subdomeine met behulp van oop bronne en brute-forcing gevind het, kan jy variasies van die gevonde subdomeine genereer om nog meer te probeer vind. Verskeie nutsmiddels is hiervoor nuttig:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Genereer permutasies op grond van die domeine en subdomeine.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Genereer permutasies op grond van die gegewe domeine en subdomeine.
  - Jy kan goaltdns se permutasie-**wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Genereer permutations gegewe die domeine en subdomeine. Indien geen permutations-lêer aangedui word nie, gebruik gotator sy eie een.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Behalwe om subdomein-permutasies te genereer, kan dit ook probeer om hulle op te los (maar dit is beter om die nutsgoed te gebruik wat vroeër bespreek is).
  - Jy kan die altdns-permutasies-**wordlist** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Nog ’n hulpmiddel om permutasies, mutasies en wysigings van subdomeine uit te voer. Hierdie hulpmiddel sal die resultaat brute force-aanval (dit ondersteun nie DNS-wildcards nie).
  - Jy kan die dmut-permutasiewoordelys [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Op grond van ’n domein **genereer dit nuwe moontlike subdomain-name** volgens aangeduide patrone om nog subdomains te probeer ontdek.

#### Slim permutasiegenerering

- [**regulator**](https://github.com/cramppet/regulator): Leer regex-agtige patrone uit ontdekte subdomains en genereer kandidaatname om te resolve.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is ’n subdomain-brute-force-fuzzer wat gekombineer word met ’n ongelooflik eenvoudige maar doeltreffende DNS-reaksiegeleide algoritme. Dit gebruik ’n verskafte stel invoerdata, soos ’n pasgemaakte woordelys of historiese DNS/TLS-rekords, om meer ooreenstemmende domeinname akkuraat te sintetiseer en dit verder uit te brei in ’n lus, gebaseer op inligting wat tydens die DNS-skandering ingesamel is.

```
echo www | subzuf facebook.com
```

### **Subdomain-ontdekkingswerkvloei**

Trickest-werkvloervoorbeelde kombineer OSINT, DNS-brute force en permutasiefases vir herhaalbare subdomain-enumerasie.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

As jy ’n IP-adres gevind het wat **een of meer webblaaie** bevat wat aan subdomains behoort, kan jy probeer om **ander subdomains met webwerwe op daardie IP** te vind deur in **OSINT-bronne** na domeine op ’n IP te soek, of deur **VHost-domeinname op daardie IP te brute-force**.

#### OSINT

Jy kan sommige **VHosts op IP-adresse vind met** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander API’s**.

**Brute Force**

As jy vermoed dat ’n subdomain op ’n webbediener versteek kan wees, kan jy probeer om dit te brute-force:

Vir naamgebaseerde vhosts, fuzz die `Host`-header en gebruik ffuf se outomatiese kalibrasie om die verstekrespons uit te filter.<sup>[[2]](#references)</sup>

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
> Met hierdie tegniek kan jy dalk selfs toegang tot interne/versteekte endpoints kry.

### **CORS Brute Force**

Soms sal jy bladsye vind wat slegs die _**Access-Control-Allow-Origin**_-header terugstuur wanneer ’n geldige domein/subdomein in die _**Origin**_-header gestel is. In hierdie scenario’s kan jy hierdie gedrag misbruik om nuwe **subdomeine** te **ontdek**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Terwyl jy na **subdomeine** soek, let op of hulle na enige soort **bucket** **wys**; indien wel, [**kyk na die toestemmings**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Aangesien jy op hierdie punt al die domeine binne die omvang sal ken, probeer ook om [**moontlike bucket-name met brute force te raai en die toestemmings na te gaan**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitering**

Jy kan **monitor** of **nuwe subdomeine** van ’n domein geskep word deur die **Certificate Transparency**-logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Soek na kwesbaarhede**

Kyk vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomein** na ’n **S3 bucket** wys, [**kyk na die toestemmings**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomein met ’n IP-adres vind wat verskil** van dié wat jy reeds tydens bates-ontdekking gevind het, moet jy ’n **basiese kwesbaarheidskandering** uitvoer (met Nessus of OpenVAS) en ’n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** doen. Afhangend van watter dienste loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "attack"**.\
_Let daarop dat die subdomein soms op ’n IP-adres gehuisves word wat nie deur die kliënt beheer word nie en dus buite die omvang val. Wees versigtig._

## IPs

In die aanvanklike stappe het jy moontlik **IP-reekse, domeine en subdomeine gevind**.\
Dis tyd om **al die IP-adresse uit daardie reekse te versamel**, asook dié vir die **domeine/subdomeine (DNS-navrae).**

Met dienste soos die volgende kan jy ook **vorige IP-adresse vind wat deur domeine en subdomeine gebruik is**. Die kliënt besit moontlik steeds hierdie IP-adresse (en dit kan jou help om [**CloudFlare-bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind).

- [**SecurityTrails**](https://securitytrails.com/) (historiese DNS-/IP-data vereis ’n betaalde plan)

Jy kan ook met die hulpmiddel [**hakip2host**](https://github.com/hakluke/hakip2host) kyk watter domeine na ’n spesifieke IP-adres wys.

### **Soek na kwesbaarhede**

Voer ’n **port scan uit op alle IP-adresse wat nie aan CDNs behoort nie** (want jy sal waarskynlik niks interessants daar vind nie). Jy kan moontlik **kwesbaarhede vind** in die dienste wat loop.

**Vind ’n** [**gids**](../pentesting-network/index.html) **oor hoe om hosts te scan.**

## Soek na webbedieners

> Ons het al die maatskappye en hul bates gevind en ken die IP-reekse, domeine en subdomeine binne die omvang. Dis tyd om na webbedieners te soek.

In die vorige stappe het jy waarskynlik reeds ’n bietjie **recon van die ontdekte IP-adresse en domeine gedoen**, so jy het dalk **al die moontlike webbedieners gevind**. Indien nie, gaan ons nou ’n paar **vinnige truuks sien om webbedieners binne die omvang te vind**.

Let daarop dat dit **op die ontdekking van webtoepassings gerig** sal wees. Daarom moet jy ook **kwesbaarheidskanderings** en **port scanning** uitvoer (**indien die omvang dit toelaat**).

’n [**Vinnige metode** om **oop poorte** te ontdek wat met **web**bedieners verband hou, met behulp van **masscan**, is hier beskikbaar](../pentesting-network/index.html#http-port-discovery).\
Nog ’n handige hulpmiddel om webbedieners te vind, is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Gee hulle bloot ’n lys domeine, en hulle sal probeer om aan poort 80 (http) en 443 (https) te koppel. Jy kan ook aandui dat hulle ander poorte moet probeer:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Noudat jy **al die web servers** binne die scope ontdek het (onder die maatskappy se **IPs** en al sy **domains** en **subdomains**), weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit dus eenvoudig en begin deur net screenshots van almal te neem. Deur net na die **hoofbladsy** te **kyk**, kan jy **vreemde** endpoints vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Daarna kan jy ook [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om al die **screenshots** te verwerk en vir jou te vertel **watter waarskynlik kwesbaarhede bevat** en watter nie.

## Public Cloud Assets

Om potensiële cloud assets te vind wat aan ’n maatskappy behoort, moet jy **begin met ’n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir ’n kriptomaatskappy kan jy woorde soos dié gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordelyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Gebruik dan daardie woorde om **permutasies** te genereer (raadpleeg die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordelyste kan jy tools soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat jy, wanneer jy na Cloud Assets soek, n**a meer as net buckets in AWS moet kyk**.

### **Op soek na kwesbaarhede**

As jy dinge soos **oop buckets of blootgestelde cloud functions** vind, moet jy **toegang daartoe kry** en probeer vasstel wat hulle bied en of jy hulle kan misbruik.

## Emails

Met die **domains** en **subdomains** binne die scope het jy basies alles wat jy **nodig het om na emails te begin soek**. Dit is die **APIs** en **tools** wat vir my die beste gewerk het om ’n maatskappy se emails te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met APIs
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Op soek na kwesbaarhede**

Emails sal later handig te pas kom om **web logins en auth services** (soos SSH) te **brute-force**. Hulle is ook nodig vir **phishing**. Boonop gee hierdie APIs jou nog meer **inligting oor die persoon** agter die email, wat nuttig is vir die phishing-veldtog.

## Credential Leaks

Met die **domains,** **subdomains** en **emails** kan jy begin soek na credentials wat in die verlede geleak het en aan daardie emails behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Op soek na kwesbaarhede**

As jy **geldige geleakte** credentials vind, is dit ’n baie maklike wins.

## Secrets Leaks

Credential leaks hou verband met hacks van maatskappye waar **sensitiewe inligting gelek en verkoop is**. Maatskappye kan egter deur **ander leaks** geraak word waarvan die inligting nie in daardie databasisse voorkom nie:

### Github Leaks

Credentials en APIs kan in die **publieke repositories** van die **maatskappy** of van die **gebruikers** wat vir daardie Github-maatskappy werk, gelek word.\
Jy kan die **tool** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **publieke repos** van ’n **organisasie** en sy **ontwikkelaars** af te laai en [**gitleaks**](https://github.com/gitleaks/gitleaks) outomaties daarop uit te voer.

**Leakos** kan ook gebruik word om **gitleaks** uit te voer op al die **teks** van die **URLs wat daaraan verskaf word**, aangesien **webblaaie soms ook secrets bevat**.

#### Github Dorks

Raadpleeg die [GitHub dorks and leaks page](github-leaked-secrets.md) vir moontlike **GitHub dorks** om in die organisasie te soek.

### Pastes Leaks

Soms **publiseer aanvallers of bloot werknemers maatskappy-inhoud op ’n paste-werf**. Dit bevat dalk **sensitiewe inligting**, of dalk nie, maar dit is baie interessant om daarna te soek.\
Jy kan die tool [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om tegelyk op meer as 80 paste-werwe te soek.

### Google Dorks

Ou maar goudwaardige Google dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar hoort nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) etlike **duisende** moontlike navrae bevat wat jy nie met die hand kan uitvoer nie. Jy kan dus jou gunsteling 10 kies, of ’n **tool soos** [**Gorks**](https://github.com/carlospolop/Gorks) gebruik **om hulle almal uit te voer**.

_Let daarop dat tools wat verwag om die hele databasis met die gewone Google-blaaier uit te voer, nooit sal klaarmaak nie, aangesien Google jou baie, baie gou sal blokkeer._

### **Op soek na kwesbaarhede**

As jy **geldige geleakte** credentials of API tokens vind, is dit ’n baie maklike wins.

## Public Code Vulnerabilities

As jy vind dat die maatskappy **oopbronkode** het, kan jy dit **ontleed** en na **kwesbaarhede** daarin soek.

**Afhangend van die taal** is daar verskillende **tools** wat jy kan gebruik; sien die lys [tools vir bronkode-oorsig](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Daar is ook gratis dienste waarmee jy **publieke repositories kan skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **meerderheid kwesbaarhede** wat bug hunters vind, is in **webtoepassings**, daarom wil ek op hierdie punt praat oor ’n **toetsmetodologie vir webtoepassings**; jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook spesiaal melding maak van die afdeling [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede sal vind nie, is hulle handig om in **workflows te implementeer sodat jy aanvanklike webinligting kry.**

## Recapitulation

> Baie geluk! Op hierdie punt het jy reeds **al die basiese enumerasie** uitgevoer. Ja, dis basies, want daar is nog baie meer enumerasie wat gedoen kan word (ons sal later nog truuks sien).

Jy het dus reeds:

1. Al die **maatskappye** binne die scope gevind
2. Al die **assets** gevind wat aan die maatskappye behoort (en ’n vuln scan uitgevoer as dit binne scope val)
3. Al die **domains** gevind wat aan die maatskappye behoort
4. Al die **subdomains** van die domains gevind (enige subdomain takeover?)
5. Al die **IPs** binne die scope gevind (van **CDNs** en **nie van CDNs nie**).
6. Al die **web servers** gevind en ’n **screenshot** daarvan geneem (is daar enigiets vreemds wat ’n dieper ondersoek verdien?)
7. Al die **potensiële publieke cloud assets** gevind wat aan die maatskappy behoort.
8. **Emails**, **credential leaks** en **secret leaks** wat jou maklik ’n **groot wins** kan besorg.
9. **Pentesting van al die webwerwe wat jy gevind het**

## **Full Recon Automatic Tools**

Daar is verskeie tools wat ’n deel van die voorgestelde aksies teen ’n gegewe scope sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - ’n Bietjie oud en nie opgedateer nie

## References

- [1] [Jason Haddix – Die Bug Hunter se Metodologie v4.0: Recon-uitgawe](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Oor Favicons: Van blaaierikone tot intelligensie oor aanvalsvlakke](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico vir BugBounties, OSINT en nog wat](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ontdekking van domains via ’n tydkorrelasie-aanval op Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passiewe oorname: ’n Duur subdomain takeover-veldtog ontbloot (en nageboots)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: ’n Unieke metode vir subdomain-enumerasie](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Volledige subdomain-ontdekkingswerkvloei, Deel 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Volledige brute-force-ontdekking van subdomains met ’n geoutomatiseerde Trickest-werkvloei, Deel 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash-uitset-screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
