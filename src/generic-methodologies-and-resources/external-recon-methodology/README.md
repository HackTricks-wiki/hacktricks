# Eksterne Verkenningsmetodologie

{{#include ../../banners/hacktricks-training.md}}

## Bates-ontdekkings

> Jy is dus meegedeel dat alles wat aan ’n maatskappy behoort binne die scope val, en jy wil vasstel wat hierdie maatskappy werklik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te identifiseer, en dan al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:<sup>[[1]](#references)</sup>

1. Vind die hoofmaatskappy se verkrygings. Dit gee ons die maatskappye binne die scope.
2. Vind die ASN (indien enige) van elke maatskappy. Dit gee ons die IP-reekse wat elke maatskappy besit.
3. Gebruik reverse whois-opsoeke om na ander inskrywings (organisasiename, domeine...) te soek wat met die eerste een verband hou (dit kan rekursief gedoen word).
4. Gebruik ander tegnieke, soos shodan se `org`- en `ssl`-filters, om na ander bates te soek (die `ssl`-truuk kan rekursief gedoen word).

Sien die [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline) vir die gefaseerde oorhandiging van opgeloste subdomeine aan HTTP-crawling en poortontdekking.

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, na die **hoofmaatskappy te soek** en op "**acquisitions**" te **klik**. Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
’n Ander opsie is om die hoofmaatskappy se **Wikipedia**-bladsy te besoek en na **acquisitions** te soek.\
Vir openbare maatskappye, kyk na **SEC/EDGAR-filings**, **investor relations**-bladsye of plaaslike korporatiewe registers (bv. **Companies House** in die VK).\
Vir wêreldwye korporatiewe strukture en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI**-databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Goed, teen hierdie tyd behoort jy al die maatskappye binne die scope te ken. Kom ons kyk hoe om hul bates te vind.

### **ASNs**

’n Outonome stelselnommer (**ASN**) is ’n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan ’n **outonome stelsel** (AS) toegeken word.\
’n **AS** bestaan uit **blokke** **IP-adresse** met ’n duidelik omskrewe beleid vir toegang tot eksterne netwerke. Dit word deur ’n enkele organisasie geadministreer, maar kan uit verskeie operateurs bestaan.

Dit is nuttig om vas te stel of ’n **ASN aan die maatskappy toegeken is**, sodat sy **IP-reekse** gevind kan word. Dit is nuttig om ’n **kwesbaarheidstoets** uit te voer teen al die **gashere** binne die **scope** en na **domeine** binne hierdie IP’s te soek.\
Jy kan op **maatskappynaam**, **IP** of **domein** soek by [**https://bgp.he.net/**](https://bgp.he.net) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die streek waarin die maatskappy geleë is, kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In elk geval verskyn al die** nuttige inligting **(IP-reekse en Whois)** waarskynlik reeds in die eerste skakel.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** enumeration voeg ASNs outomaties saam en som dit aan die einde van die scan op.

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

Jy kan ook ’n organisasie se IP-reekse vind met [ASNLookup](https://asnlookup.com/), wat ’n beperkte gratis API-vlak bied.

### **Soek na kwesbaarhede**

Op hierdie stadium ken ons **al die bates binne die scope**, so as jy toegelaat word, kan jy ’n **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) op al die gashere laat loop.\
Jy kan ook [**poortskanderings**](../pentesting-network/index.html#discovering-hosts-from-the-outside) uitvoer **of dienste soos** Shodan, Censys of ZoomEye gebruik **om** oop poorte **te vind, en na gelang van wat jy vind, moet jy** in hierdie boek kyk hoe om verskeie moontlike dienste wat loop, te pentest.\
**Dit kan ook die moeite werd wees om te noem dat jy verstekgebruikersnaam- en wagwoordlyste kan voorberei en probeer om dienste te** bruteforce met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeine

> Ons ken al die maatskappye binne die scope en hul bates; dit is tyd om die domeine binne die scope te vind.

_Let asseblief daarop dat jy met die tegnieke hieronder ook subdomeine kan vind, en dat daardie inligting nie onderskat moet word nie._

Eerstens moet jy die **hoof-domein**(e) van elke maatskappy soek. Byvoorbeeld, vir _Tesla Inc._ sal dit _tesla.com_ wees.

### **Omgekeerde DNS**

Noudat jy al die IP-reekse van die domeine gevind het, kan jy probeer om **omgekeerde DNS-opsoeke** op daardie **IP’s uit te voer om meer domeine binne die scope te vind**. Probeer ’n DNS-bediener van die slagoffer of ’n bekende DNS-bediener gebruik (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

For this om te werk, moet die administrateur PTR handmatig aktiveer.\
Jy kan ook [SecurityTrails](https://securitytrails.com/) vir hierdie inligting gebruik, hoewel historiese DNS-data ’n betaalde plan vereis.\
Vir groot reekse is nutsmiddels soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en verryking te outomatiseer.

### **Reverse Whois (loop)**

In ’n **whois** kan jy baie interessante **inligting** vind, soos **organisasienaam**, **adres**, **e-posse**, telefoonnommers... Maar wat nog interessanter is, is dat jy **meer bates kan vind wat met die maatskappy verband hou** as jy **reverse whois lookups op enige van daardie velde uitvoer** (byvoorbeeld ander whois-registers waar dieselfde e-pos voorkom).\
Jy kan aanlyn nutsmiddels soos die volgende gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web en API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** webkoppelvlak; betaalde API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Betaald
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis nie (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis nie
- [https://securitytrails.com/](https://securitytrails.com/) - Beperkte gratis API-toegang vir huidige DNS/subdomeine; historiese en reverse lookups vereis ’n betaalde plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 gratis API-krediete met registrasie; daarna betaal.

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(vereis ’n whoxy API-sleutel).\
Jy kan ook outomatiese reverse whois-ontdekking met [amass](https://github.com/owasp-amass/amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer as jy ’n nuwe domein vind.**

### **Trackers**

As jy **dieselfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy aanvaar dat **albei bladsye** deur **dieselfde span bestuur word**.\
Byvoorbeeld, as jy dieselfde **Google Analytics-ID** of dieselfde **Adsense-ID** op verskeie bladsye sien.

Daar is ’n paar bladsye en nutsmiddels waarmee jy volgens hierdie trackers en meer kan soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Betaalde** web- en API-diens ([pryse](https://www.stackscan.com/pricing)); geen gratis plan word tans geadverteer nie. Soek op enige bediende bate, nie net tracker-ID’s nie: ’n skrippad, ’n selfgehoste bundelnaam of die gasheer waarvandaan ’n bate gelaai word; die resultaat wys elke webwerf wat dit bevat.

Die API gee die stack vir ’n enkele domein terug, wat nuttig is om te bevestig dat ’n kandidaatbate aan dieselfde boedel behoort:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gee elke bespeurde tegnologie saam met sy kategorie terug. Asset pivoting is tans net vir web beskikbaar; die API dek opsoeke per domein.

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine van ons teiken kan vind deur na dieselfde favicon-ikoonhash te soek? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py)-tool, geskep deur [@m4ll0k2](https://twitter.com/m4ll0k2), doen. Hier is hoe om dit te gebruik:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash-resultate wat gebruik word om domeine te ontdek wat 'n favicon-hash deel](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, sal favihash ons help om domeine te ontdek wat dieselfde favicon-ikoonhash as ons teiken het.

![favihash-uitset wat gebruik word om domeine met dieselfde favicon-hash te ontdek](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Gebruik 'n bekende favicon-hash as 'n Shodan- of FOFA-pivot om ander blootgestelde instansies van dieselfde tegnologie te vind.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Dit is hoe jy die **favicon-hash** van ’n webwerf kan **bereken** (MMH3 oor die **base64-gekodeerde** favicon-grepe):

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

Beskou favicon-fingerprints as leidrade en valideer hulle met omliggende seine.<sup>[[3]](#references)[[4]](#references)</sup>

- **Beskou die hash as ’n aanduiding, nie as bewys nie**: MMH3 is kompak; botsings, hergebruikte ikone en doelbewuste vervalsing is moontlik.
- **Ondersoek meer as** `/favicon.ico`: inspekteer raamwerk-/bou-paaie, manifest-lêers, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, ingebedde data-URL’s en HTML-etikette `<link rel="icon">`.
- **Statiese bates kan steeds bereikbaar wees agter WAF-/SSO-/IdP-kontroles**: vra die ikoon direk aan en kontroleer `ETag`, `Last-Modified`, herleidings en kasopskrifte.
- **Valideer ooreenkomste met omliggende seine**: vergelyk die titel, HTML-/liggaam-hash, opskrifte, TLS-sertifikaatonderwerpe/SAN’s, produkkomponente en blootgestelde poorte.
- **Groepeer volgens HTML-/liggaam-hash**: ’n konsekwente sjabloon versterk die fingerprint; gemengde sjablone dui op ’n generiese of gedeelde ikoon.
- **Beskou ’n hash wat oor onverwante handtekeninge, poorte en produkte voorkom as ’n moontlike honeypot of plekhouer.**
- **Vergelyk op dubbelsinnige teikens ’n werklike bladsy met ’n niebestaande pad**, soos `/_favicon_probe_<8-hex>`; ooreenstemmende hosting- of geparkeerde-domein-antwoorde kan die gedeelde ikoon verklaar.
- **Begin triage met Nuclei-opsporingsreëls of publieke datastelle** wat favicon-hashes aan produkte en CPE’s koppel.
- **Onthou die gaping in IP-gesentreerde dekking**: CDN-voorkante, SNI-gerigte, anycast- en domein-alleen-oppervlakke kan ontbreek in Shodan-agtige datastelle.

### **Kopiereg / Uniq string**

Soek binne die webblaaie na **stringe wat oor verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **kopieregstring** kan ’n goeie voorbeeld wees. Soek dan vir daardie string in **google**, in ander **blaaiers** of selfs in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT-tyd**

Dit is algemeen om ’n cron job soos volg te hê】【。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

om al die sertifikate op ’n bediener terselfdertyd te hernu. Deur sertifikaattydstempels of posisies in sertifikaattransparansielogboeke te korreleer, kan verwante domeine onthul word.<sup>[[6]](#references)</sup>

Gebruik ook **certificate transparency**-logboeke direk:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### E-pos DMARC-inligting

Jy kan ’n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of ’n hulpmiddel soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domeine en subdomeine te vind wat dieselfde DMARC-inligting deel**.\
Nog ’n nuttige diens is [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

’n Verlate A-rekord kan bereikbaar word wanneer ’n wolkverskaffer ’n IP-adres heraanwys. Die aangehaalde navorsing demonstreer ’n opportunistiese werkvloei wat ’n instansie voorsien en die adres daarvan met passiewe DNS-data korreleer; toets takeover-scenario’s slegs binne die gemagtigde omvang.<sup>[[7]](#references)</sup>

### **Ander maniere**

Herhaal die toepaslike ontdekkingsmetodes elke keer wanneer jy ’n nuwe domein vind: elke resultaat kan bykomende sertifikaatname, passiewe DNS-verwantskappe, favicon-ooreenkomste en organisasie-identifiseerders blootlê wat nie uit die oorspronklike saad sigbaar was nie.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Omdat jy reeds die naam ken van die organisasie wat die IP-ruimte besit, kan jy met daardie data in Shodan soek deur: `org:"Tesla, Inc."` Gaan die gevonde gashere na vir nuwe, onverwagte domeine in die TLS-sertifikaat.

Jy kan toegang tot die **TLS-sertifikaat** van die hoofwebblad kry, die **Organisasienaam** verkry en dan binne die **TLS-sertifikate** van al die webblaaie wat aan **Shodan** bekend is na daardie naam soek met die filter: `ssl:"Tesla Motors"` of ’n hulpmiddel soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ’n hulpmiddel wat soek na **domeine wat verband hou** met ’n hoofdomein en hul **subdomeine**; dit is nogal indrukwekkend.

**Passiewe DNS / Historiese DNS**

Passiewe DNS-data is uitstekend om **ou en vergete rekords** te vind wat steeds oplos of oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Soek na kwesbaarhede**

Kyk of daar ’n [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) is. Miskien **gebruik ’n maatskappy ’n domein**, maar het hulle **die eienaarskap verloor**. Registreer dit net (as dit goedkoop genoeg is) en stel die maatskappy in kennis.

As jy enige **domein met ’n ander IP-adres** vind as dié wat jy reeds tydens die bate-ontdekking gevind het, moet jy ’n **basiese kwesbaarheidskandering** (met Nessus of OpenVAS) en ’n [**poortskandering**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** uitvoer. Afhangend van watter dienste loop, kan jy in **hierdie boek ’n paar truuks vind om hulle aan te val**.\
_Neem kennis dat die domein soms op ’n IP-adres gehuisves word wat nie deur die kliënt beheer word nie en dus buite die omvang val; wees versigtig._

## Subdomeine

> Ons ken al die maatskappye binne die omvang, al die bates van elke maatskappy en al die domeine wat met die maatskappye verband hou.

Dit is tyd om al die moontlike subdomeine van elke gevonde domein te vind.

> [!TIP]
> Neem kennis dat sommige van die hulpmiddels en tegnieke om domeine te vind ook kan help om subdomeine te vind

### **DNS**

Kom ons probeer om **subdomeine** uit die **DNS**-rekords te kry. Ons moet ook **Zone Transfer** probeer (As dit kwesbaar is, moet jy dit rapporteer).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Vir APIs en platforms wat infrastruktuur, reputasie, rekords van sekuriteitsbreuke en verryking buite subdomein-ontdekking dek, sien die [katalogus van Reconnaissance- en Threat-Intelligence-APIs](reconnaissance-and-threat-intelligence-apis.md).

Die vinnigste manier om baie subdomeine te kry, is om in eksterne bronne te soek. Die mees gebruikte **tools** is die volgende (stel die API keys op vir beter resultate):


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

Daar is **ander interessante tools/API's** wat nuttig kan wees om subdomeine te vind, selfs al is hulle nie direk daarin gespesialiseer nie, soos:

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

- [**SecurityTrails**](https://securitytrails.com/) bied beperkte gratis API-toegang vir huidige DNS- en subdomeindata; historiese DNS-/IP-data vereis ’n betaalde plan.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Hierdie projek bied **gratis al die subdomeine wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data kry deur [chaospy](https://github.com/Moaaz-0x/chaospy) te gebruik, of selfs toegang kry tot die scope wat deur hierdie projek gebruik word: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Jy kan ’n **vergelyking** van baie van hierdie tools hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer nuwe **subdomains** vind deur DNS-bedieners met moontlike subdomeinname te brute-force.

Vir hierdie aksie het jy ’n paar **algemene subdomain-wordlists soos** nodig:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP’s van goeie DNS-resolvers. Om ’n lys van betroubare DNS-resolvers te genereer, kan jy die resolvers van [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) aflaai en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filtreer. Of jy kan gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole tools vir DNS-brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat effektiewe DNS-brute-force uitgevoer het. Dit is baie vinnig, maar is geneig om vals positiewe resultate te lewer.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik volgens my net 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is 'n wrapper om `massdns`, geskryf in go, waarmee jy geldige subdomains met aktiewe bruteforce kan enumereer, asook subdomains kan resolve met wildcard-hantering en maklike input-output-ondersteuning.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinname asinchronies te brute force.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Tweede DNS-brute-force-rondte

Nadat jy subdomains met behulp van openbare bronne en brute-forcing gevind het, kan jy variasies van die gevonde subdomains genereer om nog meer te probeer vind. Verskeie nutsmiddels is hiervoor nuttig:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Genereer permutasies gegewe die domains en subdomains.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Genereer permutasies gegrond op die domeine en subdomeine.
  - Jy kan goaltdns se permutasies-**wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Genereer permutasies gegrond op die domeine en subdomeine. As geen permutasielêer aangedui word nie, sal gotator sy eie lêer gebruik.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Behalwe dat dit subdomain-permutasies genereer, kan dit ook probeer om hulle op te los (maar dit is beter om die voorheen genoemde tools te gebruik).
  - Jy kan altdns-permutasies se **wordlist** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Nog ’n hulpmiddel om permutasies, mutasies en wysigings van subdomeine uit te voer. Hierdie hulpmiddel sal die resultaat met brute force vind (dit ondersteun nie DNS-wildcards nie).
  - Jy kan die dmut-permutasiewoordelys [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Gebaseer op ’n domain **genereer dit nuwe potensiële subdomain-name** volgens aangeduide patrone om meer subdomains te probeer ontdek.

#### Slim permutation-generering

- [**regulator**](https://github.com/cramppet/regulator): Leer regex-agtige patrone uit ontdekte subdomains en genereer kandidaatname om op te los.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is 'n subdomain brute-force fuzzer wat gepaard gaan met 'n uiters eenvoudige maar doeltreffende DNS-responsgeleide algoritme. Dit gebruik 'n verskafte stel invoerdata, soos 'n pasgemaakte wordlist of historiese DNS/TLS-rekords, om akkuraat meer ooreenstemmende domeinname saam te stel en hulle verder in 'n lus uit te brei op grond van inligting wat tydens 'n DNS-scan ingesamel is.

```
echo www | subzuf facebook.com
```

### **Subdomein-ontdekkingswerkvloei**

Trickest-werkvloei-voorbeelde kombineer OSINT, DNS-brute force en permutasiestappe vir herhaalbare subdomein-enumerasie.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtuele gashere**

As jy ’n IP-adres gevind het met **een of meer webblaaie** wat aan subdomeine behoort, kan jy probeer om **ander subdomeine met webwerwe op daardie IP** te **vind** deur in **OSINT-bronne** na domeine op ’n IP te soek, of deur **VHost-domeinname op daardie IP met brute force te probeer**.

#### OSINT

Jy kan sommige **VHosts op IP’s vind met** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander API’s**.

**Brute Force**

As jy vermoed dat ’n subdomein op ’n webbediener versteek kan wees, kan jy brute force probeer:

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
> Met hierdie tegniek kan jy dalk selfs toegang tot interne/verborge endpoints kry.

### **CORS Brute Force**

Soms sal jy bladsye vind wat die kop _**Access-Control-Allow-Origin**_ slegs terugstuur wanneer ’n geldige domein/subdomein in die _**Origin**_-kop gestel is. In hierdie scenario’s kan jy hierdie gedrag misbruik om nuwe **subdomeine** te **ontdek**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Terwyl jy na **subdomains** soek, let op of dit na enige soort **bucket** **wys**, en [**kontroleer in daardie geval die permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Aangesien jy teen hierdie tyd al die domeine binne die scope sal ken, kan jy ook probeer om [**moontlike bucket name met brute force te vind en die permissions te kontroleer**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitering**

Jy kan **monitor** of **nuwe subdomains** van ’n domein geskep word deur die **Certificate Transparency**-logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Soek na vulnerabilities**

Kontroleer vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na ’n **S3 bucket** **wys**, [**kontroleer die permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomain met ’n IP-adres vind wat verskil** van dié wat jy reeds tydens die batesontdekking gevind het, moet jy ’n **basiese vulnerability scan** uitvoer (met Nessus of OpenVAS), asook ’n [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangend van watter dienste loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "attack"**.\
_Noteer dat die subdomain soms op ’n IP-adres gehuisves word wat nie deur die kliënt beheer word nie, en dus buite die scope val. Wees versigtig._

## IPs

In die aanvanklike stappe het jy moontlik **IP-reekse, domeine en subdomains gevind**.\
Dis tyd om **al die IPs uit daardie reekse bymekaar te maak**, asook die IPs vir die **domeine/subdomains (DNS queries).**

Deur dienste soos die volgende te gebruik, kan jy ook **vorige IPs vind wat deur domeine en subdomains gebruik is**. Die kliënt besit moontlik steeds hierdie IPs (en dit kan jou help om [**CloudFlare-bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind).

- [**SecurityTrails**](https://securitytrails.com/) (historiese DNS/IP-data vereis ’n betaalde plan)

Jy kan ook met die [**hakip2host**](https://github.com/hakluke/hakip2host)-tool kyk vir domeine wat na ’n spesifieke IP-adres wys.

### **Soek na vulnerabilities**

**Doen ’n port scan van al die IPs wat nie aan CDNs behoort nie** (want jy sal hoogs waarskynlik niks interessants daar vind nie). Jy kan moontlik **vulnerabilities vind** in die dienste wat loop.

**Vind ’n** [**gids**](../pentesting-network/index.html) **oor hoe om hosts te scan.**

## Soektog na webservers

> Ons het al die maatskappye en hul bates gevind, en ons ken die IP-reekse, domeine en subdomains binne die scope. Dis tyd om na webservers te soek.

In die vorige stappe het jy waarskynlik reeds ’n bietjie **recon op die ontdekte IPs en domeine** gedoen, so jy het dalk **al die moontlike webservers gevind**. Indien nie, gaan ons nou ’n paar **vinnige truuks bespreek om webservers** binne die scope te soek.

Let daarop dat dit **op die ontdekking van webapps gerig** sal wees, so jy moet ook **vulnerability-** en **port scanning** uitvoer (**indien dit deur die scope toegelaat word**).

’n **Vinnige metode** om met [**masscan**](../pentesting-network/index.html#http-port-discovery) **oop poorte** te ontdek wat met **web**servers verband hou, is hier beskikbaar.\
Nog ’n gebruikersvriendelike tool om webservers te soek, is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Gee net ’n lys domeine, en die tool sal probeer om aan poort 80 (http) en 443 (https) te koppel. Jy kan ook aandui dat dit ander poorte moet probeer:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Skermkiekies**

Noudat jy **al die web servers** binne die omvang ontdek het (onder die maatskappy se **IP's** en al sy **domains** en **subdomains**), weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit dus eenvoudig en begin deur net skermkiekies van almal te neem. Deur net na die **hoofblad** te **kyk**, kan jy **vreemde** endpoints vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** gebruik.**

Daarna kan jy ook [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om deur al die **skermkiekies** te gaan en jou te vertel **wat waarskynlik kwesbaarhede bevat** en wat nie.

## Publieke Cloud-bates

Om potensiële cloud-bates te vind wat aan 'n maatskappy behoort, moet jy **begin met 'n lys sleutelwoorde wat die maatskappy identifiseer**. Byvoorbeeld, vir 'n kriptomaatskappy kan jy woorde soos die volgende gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordelyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Met daardie woorde moet jy dan **permutasies** genereer (kyk na die [**Tweede DNS-bruteforce-ronde**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordelyste kan jy nutsmiddels soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gebruik.**

Onthou dat wanneer jy na Cloud Assets soek, jy m**eer as net buckets in AWS moet soek**.

### **Soek na kwesbaarhede**

As jy dinge soos **oop buckets of blootgestelde cloud functions** vind, moet jy **toegang daartoe kry** en probeer vasstel wat hulle bied en of jy dit kan misbruik.

## E-posse

Met die **domains** en **subdomains** binne die omvang het jy basies alles wat jy **nodig het om na e-posadresse te begin soek**. Dit is die **APIs** en **nutsmiddels** wat vir my die beste gewerk het om 'n maatskappy se e-posadresse te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met APIs
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Soek na kwesbaarhede**

E-posse sal later handig te pas kom om **webaanmeldings en auth-dienste te brute-force** (soos SSH). Hulle is ook nodig vir **phishing**. Boonop sal hierdie APIs jou nog meer **inligting oor die persoon** agter die e-posadres gee, wat nuttig is vir die phishing-veldtog.

## Geloofsbriewe-leaks

Met die **domains,** **subdomains** en **e-posadresse** kan jy begin soek na geloofsbriewe wat voorheen geleak is en aan daardie e-posadresse behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe vind wat geleak is**, is dit 'n baie maklike wins.

## Secrets-leaks

Geloofsbriewe-leaks hou verband met hacks van maatskappye waar **sensitiewe inligting geleak en verkoop is**. Maatskappye kan egter deur **ander leaks** geraak word waarvan die inligting nie in daardie databasisse voorkom nie:

### Github-leaks

Geloofsbriewe en APIs kan in die **publieke repositories** van die **maatskappy** of van die **gebruikers** wat vir daardie Github-maatskappy werk, geleak word.\
Jy kan die **nutsmiddel** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **publieke repos** van 'n **organisasie** en sy **ontwikkelaars** af te laai en [**gitleaks**](https://github.com/gitleaks/gitleaks) outomaties daarop uit te voer.

**Leakos** kan ook gebruik word om **gitleaks** uit te voer op al die **teks** van **URL's wat daaraan gegee word**, aangesien **webbladsye soms ook secrets bevat**.

#### Github Dorks

Kyk na die [GitHub dorks and leaks page](github-leaked-secrets.md) vir moontlike **GitHub dorks** om in die organisasie te soek.

### Paste-leaks

Soms sal aanvallers of bloot werknemers **maatskappy-inhoud op 'n paste-werf publiseer**. Dit bevat dalk **sensitiewe inligting**, of dalk nie, maar dit is beslis die moeite werd om daarna te soek.\
Jy kan die nutsmiddel [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om gelyktydig op meer as 80 paste-webwerwe te soek.

### Google Dorks

Ou maar goudwaardige Google dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar behoort te wees nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) etlike **duisende** moontlike navrae bevat wat jy nie met die hand kan uitvoer nie. Jy kan dus jou gunsteling 10 kies, of 'n **nutsmiddel soos** [**Gorks**](https://github.com/carlospolop/Gorks) **gebruik om hulle almal uit te voer**.

_Let daarop dat die nutsmiddels wat verwag om die hele databasis met die gewone Google-blaaier uit te voer, nooit klaar sal wees nie, aangesien Google jou baie, baie gou sal blokkeer._

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe of API-tokens vind wat geleak is**, is dit 'n baie maklike wins.

## Kwesbaarhede in publieke kode

As jy ontdek dat die maatskappy **oopbronkode** het, kan jy dit **ontleed** en daarin na **kwesbaarhede** soek.

**Afhangend van die taal** is daar verskillende **nutsmiddels** wat jy kan gebruik; sien die lys [nutsmiddels vir bronkode-oorsig](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Daar is ook gratis dienste waarmee jy **publieke repositories kan skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting-webmetodologie**](../../network-services-pentesting/pentesting-web/index.html)

Die **meeste kwesbaarhede** wat bug hunters vind, is in **webtoepassings**. Daarom wil ek op hierdie punt 'n **toetsmetodologie vir webtoepassings** bespreek; jy kan [**die inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook spesiaal melding maak van die afdeling [**Oopbron-nutsmiddels vir geoutomatiseerde webskandeerders**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede sal vind nie, is hulle handig om in **workflows te gebruik om aanvanklike webinligting te kry.**

## Samevatting

> Baie geluk! Op hierdie punt het jy reeds **al die basiese enumerasie** uitgevoer. Ja, dit is basies, want daar is nog baie meer enumerasie moontlik (ons sal later meer truuks sien).

Jy het dus reeds:

1. Al die **maatskappye** binne die omvang gevind
2. Al die **bates** wat aan die maatskappye behoort, gevind (en 'n vuln scan uitgevoer indien dit binne die omvang val)
3. Al die **domains** gevind wat aan die maatskappye behoort
4. Al die **subdomains** van die domains gevind (is daar enige subdomain takeover?)
5. Al die **IP's** (van en **nie van CDNs nie**) binne die omvang gevind.
6. Al die **web servers** gevind en 'n **skermkiekie** daarvan geneem (is daar enigiets vreemds wat die moeite werd is om van nader te ondersoek?)
7. Al die **moontlike publieke cloud-bates** gevind wat aan die maatskappy behoort.
8. **E-posse**, **geloofsbriewe-leaks** en **secret-leaks** wat jou maklik 'n **groot wins** kan oplewer.
9. **Pentesting uitgevoer op al die webwerwe wat jy gevind het**

## **Volledige outomatiese recon-nutsmiddels**

Daar is verskeie nutsmiddels beskikbaar wat sommige van die voorgestelde aksies op 'n gegewe omvang uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Effens verouderd en nie opgedateer nie



## References

- [1] [Jason Haddix – Die Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Oor Favicons: Van blaaierikone tot intelligensie oor die aanvalsoppervlak](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Favicon.ico as wapen gebruik vir BugBounties, OSINT en wat ook al](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ontdekking van domains via 'n tydskorrelasie-aanval op Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passiewe takeover: Die ontdekking (en nabootsing) van 'n duur subdomain-takeover-veldtog](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: 'n Unieke metode vir subdomain-enumerasie](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Volledige subdomain-ontdekkingsworkflow, Deel 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Volledige geoutomatiseerde workflow vir subdomain-bruteforce-ontdekking met Trickest, Deel 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Skermkiekie van favihash-uitset](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
