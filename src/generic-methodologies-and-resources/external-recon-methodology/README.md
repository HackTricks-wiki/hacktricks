# Eksterne Recon-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Ontdekking van bates

> Daar is dus vir jou gesê dat alles wat aan ’n maatskappy behoort binne die omvang val, en jy wil uitvind wat hierdie maatskappy werklik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te identifiseer, en dan al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:<sup>[[1]](#references)</sup>

1. Vind die hoofmaatskappy se verkrygings; dit sal ons die maatskappye binne die omvang gee.
2. Vind elke maatskappy se ASN (indien enige); dit sal ons die IP-reekse gee wat elke maatskappy besit.
3. Gebruik reverse whois-opsoeke om na ander inskrywings (organisasiename, domeine...) te soek wat met die eerste een verband hou (dit kan rekursief gedoen word).
4. Gebruik ander tegnieke, soos shodan se `org`- en `ssl`-filters, om na ander bates te soek (die `ssl`-truuk kan rekursief gedoen word).

Vir die gefaseerde oorhandiging van opgeloste subdomeine aan HTTP-crawling en poortontdekking, sien die [Pentesting-metodologie](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Verkrygings**

Eerstens moet ons weet **watter ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, vir die **hoofmaatskappy te soek** en op "**acquisitions**" te **klik**. Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
’n Ander opsie is om die hoofmaatskappy se **Wikipedia**-bladsy te besoek en na **acquisitions** te soek.\
Gaan vir openbare maatskappye **SEC/EDGAR-filings**, **investor relations**-bladsye of plaaslike maatskappyregisters na (bv. **Companies House** in die VK).\
Probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI**-databasis ([https://www.gleif.org/](https://www.gleif.org/)) vir wêreldwye korporatiewe strukture en filiale.

> Goed, teen hierdie tyd behoort jy al die maatskappye binne die omvang te ken. Kom ons kyk hoe om hul bates te vind.

### **ASNs**

’n Outonome stelselnommer (**ASN**) is ’n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan ’n **outonome stelsel** (AS) toegeken word.\
’n **AS** bestaan uit **blokke** **IP-adresse** met ’n duidelik omskrewe beleid vir toegang tot eksterne netwerke. Dit word deur ’n enkele organisasie bestuur, maar kan uit verskeie operateurs bestaan.

Dit is nuttig om uit te vind of die **maatskappy ’n ASN toegewys is**, sodat jy sy **IP-reekse** kan vind. Dit kan nuttig wees om ’n **kwesbaarheidstoets** uit te voer teen al die **gashere** binne die **omvang** en na **domeine** binne hierdie IP’s te **soek**.\
Jy kan volgens maatskappy**naam**, **IP** of **domein** in [**https://bgp.he.net/**](https://bgp.he.net) **of** [**https://ipinfo.io/**](https://ipinfo.io/) **soek**.\
**Afhangend van die streek waarin die maatskappy geleë is, kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Hoe dit ook al sy, waarskynlik verskyn al die** nuttige inligting **(IP-reekse en Whois)** reeds in die eerste skakel.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** enumeration versamel en som ASNs outomaties op aan die einde van die skandering.

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

Jy kan ook ’n organisasie se IP-reekse met [ASNLookup](https://asnlookup.com/) vind, wat ’n beperkte gratis API-vlak het.

### **Soek na kwesbaarhede**

Op hierdie punt ken ons **al die bates binne die scope**, so as jy toestemming het, kan jy ’n **kwesbaarheidskandeerder** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) op al die hosts laat loop.\
Jy kan ook [**poortskanderings**](../pentesting-network/index.html#discovering-hosts-from-the-outside) uitvoer **of dienste soos** Shodan, Censys of ZoomEye gebruik **om** oop poorte **te vind, en afhangend van wat jy vind, moet jy** in hierdie boek kyk hoe om verskeie moontlike dienste wat loop, te pentest.\
**Dit kan ook die moeite werd wees om te noem dat jy ook** lyste met verstekgebruikersname **en** wagwoorde **kan voorberei en probeer om dienste met** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **te bruteforce**.

## Domeine

> Ons ken al die maatskappye binne die scope en hul bates; dit is tyd om die domeine binne die scope te vind.

_Let daarop dat jy met die voorgestelde tegnieke hieronder ook subdomeine kan vind, en dat dié inligting nie onderskat moet word nie._

Eerstens moet jy die **hoofdomein(e)** van elke maatskappy soek. Byvoorbeeld, vir _Tesla Inc._ is dit _tesla.com_.

### **Reverse DNS**

Noudat jy al die IP-reekse van die domeine gevind het, kan jy probeer om **reverse DNS-lookups** op daardie **IP’s uit te voer om meer domeine binne die scope te vind**. Probeer ’n DNS-bediener van die slagoffer of ’n bekende DNS-bediener (1.1.1.1, 8.8.8.8) gebruik.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Vir dit om te werk, moet die administrateur PTR handmatig aktiveer.\
Jy kan ook [SecurityTrails](https://securitytrails.com/) vir hierdie inligting gebruik, hoewel historiese DNS-data ’n betaalde plan vereis.\
Vir groot reekse is tools soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en verryking te outomatiseer.

### **Reverse Whois (loop)**

In ’n **whois** kan jy baie interessante **inligting** vind, soos **organisasienaam**, **adres**, **e-posadresse**, telefoonnommers... Maar wat selfs interessanter is, is dat jy **meer bates wat met die maatskappy verband hou** kan vind deur **reverse whois lookups op enige van daardie velde uit te voer** (byvoorbeeld ander whois-registers waar dieselfde e-posadres voorkom).\
Jy kan aanlynnutsgoed soos die volgende gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web en API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** webkoppelvlak; betaalde API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Betaald
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis nie (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis nie
- [https://securitytrails.com/](https://securitytrails.com/) - Beperkte gratis API-toegang vir huidige DNS/subdomeine; historiese en reverse lookups vereis ’n betaalde plan.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 gratis API-krediete wanneer jy inteken; daarna betaalbaar.

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(vereis ’n whoxy API-sleutel).\
Jy kan ook outomatiese reverse whois-ontdekking met [amass](https://github.com/owasp-amass/amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om elke keer as jy ’n nuwe domein vind, meer domeinname te ontdek.**

### **Trackers**

As jy **dieselfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy aanneem dat **albei bladsye** deur **dieselfde span bestuur word**.\
Byvoorbeeld, as jy dieselfde **Google Analytics-ID** of dieselfde **Adsense-ID** op verskeie bladsye sien.

Daar is ’n paar bladsye en tools waarmee jy op grond van hierdie en ander trackers kan soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Betaalde** web- en API-diens ([pryse](https://www.stackscan.com/pricing)); daar word tans geen gratis plan aangebied nie. Gebruik enige bediende bate as beginpunt, nie net tracker-ID’s nie: ’n script-pad, ’n selfgehoste bundelnaam of die host waarvandaan ’n bate gelaai word. Dit gee elke webwerf terug waarop dit voorkom.

Die API gee die stack vir ’n enkele domein terug, wat nuttig is om te bevestig dat ’n kandidaatbate aan dieselfde omgewing behoort:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gee elke opgespoorde tegnologie saam met sy kategorie terug. Asset pivoting is tans net vir web; die API dek opsoeke per domein.

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine van ons teiken kan vind deur na dieselfde favicon-hash te soek? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py)-tool, geskep deur [@m4ll0k2](https://twitter.com/m4ll0k2), doen. Hier is hoe om dit te gebruik:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash-resultate wat gebruik word om domeine te ontdek wat 'n favicon-hash deel](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, stel favihash ons in staat om domeine te ontdek wat dieselfde favicon-ikoonhash as ons teiken het.

![favihash-afvoer wat gebruik word om domeine met dieselfde favicon-hash te ontdek](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Gebruik 'n bekende favicon-hash as 'n Shodan- of FOFA-pivot om ander blootgestelde gevalle van dieselfde tegnologie te vind.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Dit is hoe jy die **favicon-hash kan bereken** van ’n webwerf (MMH3 oor die **base64-encoded** favicon-bytes):

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

Jy kan ook favicon-hashes op skaal verkry met [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) en dan in Shodan/Censys soek.

Behandel favicon-vingerafdrukke as leidrade en bevestig dit met omliggende seine.<sup>[[3]](#references)[[4]](#references)</sup>

- **Behandel die hash as ’n aanduiding, nie as bewys nie**: MMH3 is kompak; botsings, hergebruikte ikone en doelbewuste vervalsing is moontlik.
- **Ondersoek meer as** `/favicon.ico`: kyk na framework-/build-paaie, manifest-lêers, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data-URL’s en HTML-etikette soos `<link rel="icon">`.
- **Statiese bates kan steeds bereikbaar wees agter WAF/SSO/IdP-beheermaatreëls**: versoek die ikoon direk en ondersoek `ETag`, `Last-Modified`, redirects en kasopskrifte.
- **Bevestig ooreenkomste met omliggende seine**: vergelyk die titel, HTML-/body-hash, opskrifte, TLS-sertifikaat-onderwerpe/SAN’s, produkkomponente en blootgestelde poorte.
- **Groepeer volgens HTML-/body-hash**: ’n konsekwente template versterk die vingerafdruk; gemengde templates dui op ’n generiese of gedeelde ikoon.
- **Behandel ’n hash wat oor onverwante handtekeninge, poorte en produkte voorkom as ’n moontlike honeypot of plekhouer.**
- **Vergelyk op dubbelsinnige teikens ’n regte bladsy met ’n niebestaande pad**, soos `/_favicon_probe_<8-hex>`; ooreenstemmende hosting- of parkeerantwoorde kan die gedeelde ikoon verklaar.
- **Begin triage met Nuclei-opsporingsreëls of openbare datastelle** wat favicon-hashes aan produkte en CPE’s koppel.
- **Onthou die IP-gesentreerde dekkingsgaping**: CDN-gefrontde, SNI-gerouteerde, anycast- en domein-alleen-oppervlakke kan ontbreek in Shodan-agtige datastelle.

### **Kopiereg / Unieke string**

Soek in die webblaaie na **stringe wat op verskillende webwerwe in dieselfde organisasie kan voorkom**. Die **kopieregstring** kan ’n goeie voorbeeld wees. Soek dan na daardie string in **Google**, ander **blaaiers** of selfs in **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT-tyd**

Dit is algemeen om ’n cron job te hê soosalakkersuis

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

om alle sertifikate op ’n bediener terselfdertyd te hernu. Deur sertifikaattydstempels of posisies in certificate-transparency-logs met mekaar te vergelyk, kan verwante domains onthul word.<sup>[[6]](#references)</sup>

Gebruik ook **certificate transparency**-logs direk:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-inligting

Jy kan ’n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of ’n tool soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domains en subdomains te vind wat dieselfde DMARC-inligting deel**.\
Nog ’n nuttige diens is [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

’n Verlate A-record kan weer bereikbaar word wanneer ’n cloud provider ’n IP heraanwys. Die aangehaalde navorsing demonstreer ’n opportunistiese werksvloei wat ’n instance voorsien en sy adres met passive DNS-data vergelyk; toets takeover-scenario’s slegs binne die gemagtigde omvang.<sup>[[7]](#references)</sup>

### **Ander maniere**

Herhaal die toepaslike ontdekkingstegnieke elke keer wanneer jy ’n nuwe domain vind: elke resultaat kan bykomende sertifikaatname, passive-DNS-verhoudings, favicon-ooreenkomste en organisasie-identifiseerders blootlê wat nie vanaf die oorspronklike saad sigbaar was nie.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Aangesien jy reeds die naam ken van die organisasie wat die IP-spasie besit, kan jy met daardie data in shodan soek deur: `org:"Tesla, Inc."` Gaan die gevonde hosts na vir nuwe, onverwagte domains in die TLS-sertifikaat.

Jy kan die **TLS-sertifikaat** van die hoofwebblad bekyk, die **Organisation name** kry en dan binne die **TLS-sertifikate** van al die webblaaie wat aan **shodan** bekend is na daardie naam soek met die filter: `ssl:"Tesla Motors"` of ’n tool soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ’n tool wat **domains soek wat verband hou** met ’n hoofdomein en **subdomains** daarvan; dit is ongelooflik handig.

**Passive DNS / Historiese DNS**

Passive DNS-data is uitstekend om **ou en vergete records** te vind wat steeds resolve of oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Soek na kwesbaarhede**

Kyk of daar ’n [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) is. Dalk **gebruik ’n maatskappy ’n domain**, maar het hulle **eienaarskap verloor**. Registreer dit net (as dit goedkoop genoeg is) en stel die maatskappy in kennis.

As jy enige **domain met ’n ander IP** vind as dié wat jy reeds tydens bate-ontdekking gevind het, moet jy ’n **basiese kwesbaarheidskandering** uitvoer (met Nessus of OpenVAS) en ook ’n [**poortskandering**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** doen. Afhangend van die dienste wat loop, kan jy in **hierdie boek truuks vind om hulle te “attack”**.\
_Neem kennis dat die domain soms op ’n IP gehuisves word wat nie deur die kliënt beheer word nie, en dus buite die omvang val; wees versigtig._

## Subdomains

> Ons ken al die maatskappye binne die omvang, al die bates van elke maatskappy en al die domains wat met die maatskappye verband hou.

Dit is tyd om al die moontlike subdomains van elke gevonde domain te vind.

> [!TIP]
> Let daarop dat sommige van die tools en tegnieke om domains te vind ook kan help om subdomains te vind

### **DNS**

Kom ons probeer om **subdomains** uit die **DNS**-records te kry. Ons moet ook **Zone Transfer** probeer (As dit kwesbaar is, moet jy dit rapporteer).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Vir API's en platforms wat infrastruktuur, reputasie, breukrekords en verryking buite subdomein-ontdekking dek, sien die [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md).

Die vinnigste manier om baie subdomeine te verkry, is om in eksterne bronne te soek. Die mees gebruikte **hulpmiddels** is die volgende (konfigureer die API-sleutels vir beter resultate):


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

Daar is **ander interessante tools/API's** wat, hoewel hulle nie direk gespesialiseerd is in die vind van subdomeine nie, nuttig kan wees om subdomeine te vind, soos:

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

- [**gau**](https://github.com/lc/gau)**:** haal bekende URL's vir enige gegewe domein by AlienVault se Open Threat Exchange, die Wayback Machine en Common Crawl op.

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

- [**SecurityTrails**](https://securitytrails.com/) bied beperkte gratis API-toegang vir huidige DNS- en subdomain-data; historiese DNS/IP-data vereis ’n betaalde plan.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Hierdie projek bied **gratis alle subdomains wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data kry met [chaospy](https://github.com/Moaaz-0x/chaospy), of selfs toegang kry tot die scope wat hierdie projek gebruik: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Jy kan hier ’n **vergelyking** van baie van hierdie tools vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomains** te vind deur DNS-servers met moontlike subdomain-name te brute-force.

Vir hierdie aksie het jy ’n paar **algemene subdomain-wordlists nodig, soos**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Jy het ook IP-adresse van goeie DNS-resolvers nodig. Om ’n lys van betroubare DNS-resolvers saam te stel, kan jy die resolvers aflaai vanaf [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filtreer. Of jy kan hierdie lys gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole tools vir DNS brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste tool wat ’n doeltreffende DNS brute-force uitgevoer het. Dit is baie vinnig, maar is geneig om vals positiewe resultate te lewer.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik, dink ek, net 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is ’n wrapper om `massdns`, geskryf in go, waarmee jy geldige subdomeine met aktiewe bruteforce kan enumerate, asook subdomeine kan resolve met wildcard-hantering en maklike invoer-uitvoerondersteuning.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Dit gebruik ook `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) gebruik asyncio om domeinname asynchroon te brute-force.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Tweede DNS Brute-Force-rondte

Nadat jy subdomeine met behulp van oop bronne en brute-forcing gevind het, kan jy wysigings van die gevonde subdomeine genereer om nog meer te probeer vind. Verskeie nutsgoed is hiervoor nuttig:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Gegewe die domeine en subdomeine, genereer dit permutasies.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Genereer permutasies op grond van die domeine en subdomeine.
  - Jy kan die goaltdns-permutasies-**wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Gegewe die domeine en subdomeine, genereer permutasies. As geen permutasielêer aangedui word nie, sal gotator sy eie een gebruik.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Behalwe om subdomein-permutasies te genereer, kan dit ook probeer om hulle op te los (maar dit is beter om die tools wat vroeër genoem is, te gebruik).
  - Jy kan altdns-permutasies se **wordlist** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Nog ’n hulpmiddel om permutasies, mutasies en wysigings van subdomeine uit te voer. Hierdie hulpmiddel sal die resultaat brute force (dit ondersteun nie DNS-wildcards nie).
  - Jy kan die dmut-permutasiewoordelys [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Op grond van 'n domein **genereer dit nuwe moontlike subdomeinname** volgens aangeduide patrone om meer subdomeine te probeer ontdek.

#### Slim permutasie-generering

- [**regulator**](https://github.com/cramppet/regulator): Leer regex-agtige patrone uit ontdekte subdomeine en genereer kandidaatname om op te los.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is ’n subdomein-brute-force-fuzzer wat gekoppel is aan ’n ongelooflik eenvoudige maar doeltreffende DNS-antwoordgestuurde algoritme. Dit gebruik ’n verskafte stel invoerdata, soos ’n doelgemaakte woordelys of historiese DNS/TLS-rekords, om meer ooreenstemmende domeinname akkuraat te sintetiseer en dit verder uit te brei in ’n lus op grond van inligting wat tydens DNS-skandering ingesamel is.

```
echo www | subzuf facebook.com
```

### **Subdomein-ontdekkingswerkvloei**

Trickest-werkvloei-voorbeelde kombineer OSINT, DNS-brute force en permutasiestappe vir herhaalbare subdomein-enumerasie.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

As jy ’n IP-adres gevind het wat **een of meer webblaaie** bevat wat aan subdomeine behoort, kan jy probeer om **ander subdomeine met webwerwe op daardie IP** te **vind** deur in **OSINT-bronne** na domeine op ’n IP te soek of deur VHost-domeinname op daardie IP met brute force te probeer.

#### OSINT

Jy kan **VHosts op IP’s vind met** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander API’s**.

**Brute Force**

As jy vermoed dat ’n subdomein in ’n webbediener versteek kan wees, kan jy probeer om dit met brute force te vind:

Vir naamgebaseerde vhosts, fuzz die `Host`-header en gebruik ffuf se outomatiese kalibrering om die verstekantwoord uit te filter.<sup>[[2]](#references)</sup>

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
> Met hierdie tegniek kan jy dalk selfs toegang tot interne/verborge eindpunte kry.

### **CORS Brute Force**

Soms vind jy bladsye wat die kop _**Access-Control-Allow-Origin**_ slegs terugstuur wanneer ’n geldige domein/subdomein in die _**Origin**_-kop gestel is. In hierdie situasies kan jy hierdie gedrag misbruik om nuwe **subdomeine** te **ontdek**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Hou tydens jou soektog na **subdomeine** dop of hulle na enige tipe **bucket** **wys**, en [**kontroleer in daardie geval die toestemmings**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Aangesien jy teen hierdie tyd al die domeine binne die bestek sal ken, kan jy ook probeer om [**moontlike bucket-name te brute force en die toestemmings te kontroleer**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Monitering**

Jy kan monitor of **nuwe subdomeine** van ’n domein geskep word deur die **Certificate Transparency**-logs te monitor, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Soek na kwesbaarhede**

Kyk vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomein** na ’n **S3 bucket** wys, [**kontroleer die toestemmings**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

As jy enige **subdomein met ’n IP-adres anders** as dié wat jy reeds tydens die batesontdekking gevind het, opspoor, moet jy ’n **basiese kwesbaarheidskandering** (met Nessus of OpenVAS) en ’n [**poortskandering**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** uitvoer. Afhangend van watter dienste loop, kan jy in **hierdie boek truuks vind om hulle te "attack"**.\
_Let daarop dat die subdomein soms op ’n IP-adres gehuisves word wat nie deur die kliënt beheer word nie, en dus buite die bestek val. Wees versigtig._

## IPs

In die aanvanklike stappe het jy dalk **enkele IP-reekse, domeine en subdomeine gevind**.\
Dis tyd om **al die IP-adresse uit daardie reekse te versamel**, asook dié vir die **domeine/subdomeine (DNS-navrae).**

Deur dienste soos die volgende te gebruik, kan jy ook **vorige IP-adresse vind wat deur domeine en subdomeine gebruik is**. Die kliënt besit dalk steeds hierdie IP-adresse (en hulle kan jou dalk help om [**CloudFlare-bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind).

- [**SecurityTrails**](https://securitytrails.com/) (toegang tot historiese DNS/IP-data vereis ’n betaalde plan)

Jy kan ook met die [**hakip2host**](https://github.com/hakluke/hakip2host)-tool kyk vir domeine wat na ’n spesifieke IP-adres wys.

### **Soek na kwesbaarhede**

**Voer ’n poortskandering uit op alle IP-adresse wat nie aan CDN’s behoort nie** (want jy sal heel waarskynlik niks interessants daar vind nie). Jy kan moontlik **kwesbaarhede vind** in die dienste wat loop.

**Vind ’n** [**gids**](../pentesting-network/index.html) **oor hoe om hosts te skandeer.**

## Webbedieners opspoor

> Ons het al die maatskappye en hul bates gevind, en ons ken die IP-reekse, domeine en subdomeine binne die bestek. Dis tyd om na webbedieners te soek.

In die vorige stappe het jy waarskynlik reeds ’n mate van **recon op die ontdekte IP-adresse en domeine** uitgevoer, en dalk **al die moontlike webbedieners gevind**. Indien nie, gaan ons nou ’n paar **vinnige truuks bespreek om binne die bestek na webbedieners te soek**.

Let daarop dat dit **op die ontdekking van webtoepassings gerig** sal wees, dus moet jy ook die **kwesbaarheidskandering** en **poortskandering** uitvoer (**indien die bestek dit toelaat**).

’n **Vinnige metode** om **oop poorte** op te spoor wat met **web**-bedieners verband hou, deur [**masscan** te gebruik, is hier beskikbaar](../pentesting-network/index.html#http-port-discovery).\
Nog ’n handige tool om webbedieners op te spoor, is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Gee hulle ’n lys domeine, en hulle sal probeer om aan poort 80 (http) en 443 (https) te koppel. Jy kan ook aandui dat hulle ander poorte moet probeer:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Skermskote**

Noudat jy **al die webbedieners** in die omvang ontdek het (tussen die maatskappy se **IP's** en al die **domeine** en **subdomeine**), weet jy waarskynlik **nie waar om te begin nie**. Kom ons maak dit dus eenvoudig en begin deur net skermskote van almal te neem. Deur net na die **hoofbladsy** te **kyk**, kan jy **vreemde** eindpunte vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Daarna kan jy ook [**eyeballer**](https://github.com/BishopFox/eyeballer) gebruik om al die **skermskote** te verwerk en aan te dui **wat waarskynlik kwesbaarhede bevat**, en wat nie.

## Publieke wolkbates

Om potensiële wolkbates te vind wat aan ’n maatskappy behoort, moet jy **begin met ’n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir ’n kriptomaatskappy kan jy woorde soos die volgende gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordelyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Gebruik dan daardie woorde om **permutasies** te genereer (kyk na [**Tweede rondte DNS-brute force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordelyste kan jy nutsmiddels soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Onthou dat jy, wanneer jy na wolkbates soek, na meer as net buckets in AWS moet **soek**.

### **Soek na kwesbaarhede**

As jy dinge soos **oop buckets of blootgestelde cloud functions** vind, moet jy **toegang daartoe verkry** en probeer vasstel wat hulle bied en of jy hulle kan misbruik.

## E-posadresse

Met die **domeine** en **subdomeine** binne die omvang het jy basies alles wat jy **nodig het om na e-posadresse te begin soek**. Die volgende **API's** en **nutsmiddels** het vir my die beste gewerk om ’n maatskappy se e-posadresse te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met API's
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Soek na kwesbaarhede**

E-posadresse sal later handig te pas kom om **webaanmeldings en auth-dienste** (soos SSH) met brute force aan te val. Hulle is ook nodig vir **phishing**. Boonop gee hierdie API's jou nog meer **inligting oor die persoon** agter die e-posadres, wat nuttig is vir die phishing-veldtog.

## Geloofsbriefleaks

Met die **domeine,** **subdomeine** en **e-posadresse** kan jy begin soek na geloofsbriewe wat in die verlede uitgelek het en met daardie e-posadresse verband hou:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe vind wat uitgelek het**, is dit ’n baie maklike oorwinning.

## Geheimleaks

Geloofsbriefleaks hou verband met hacks van maatskappye waar **sensitiewe inligting uitgelek en verkoop is**. Maatskappye kan egter ook deur **ander leaks** geraak word waarvan die inligting nie in daardie databasisse voorkom nie:

### Github-leaks

Geloofsbriewe en API's kan uitlek in die **publieke repos** van die **maatskappy** of van die **gebruikers** wat vir daardie Github-maatskappy werk.\
Jy kan die **nutsmiddel** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **publieke repos** van ’n **organisasie** en sy **ontwikkelaars** af te laai, en [**gitleaks**](https://github.com/gitleaks/gitleaks) outomaties daarop uit te voer.

**Leakos** kan ook gebruik word om **gitleaks** uit te voer op al die **teks** wat verskaf word deur **URL's wat daaraan deurgegee word**, aangesien **webbladsye soms ook geheime bevat**.

#### Github Dorks

Kyk na die [GitHub dorks and leaks page](github-leaked-secrets.md) vir moontlike **GitHub dorks** om in die organisasie te soek.

### Paste-leaks

Soms **publiseer aanvallers of bloot werknemers maatskappyinhoud op ’n paste-werf**. Dit kan dalk **sensitiewe inligting** bevat of nie, maar dit is baie interessant om daarna te soek.\
Jy kan die nutsmiddel [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om gelyktydig op meer as 80 paste-werwe te soek.

### Google Dorks

Ou maar goudwaardige Google dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar behoort te wees nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) etlike **duisende** moontlike navrae bevat wat jy nie met die hand kan uitvoer nie. Jy kan dus jou gunsteling 10 kies, of ’n **nutsmiddel soos** [**Gorks**](https://github.com/carlospolop/Gorks) gebruik **om hulle almal uit te voer**.

_Let daarop dat nutsmiddels wat verwag om die hele databasis met die gewone Google-blaaier uit te voer, nooit klaar sal maak nie, aangesien Google jou baie gou sal blokkeer._

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe of API-tokens vind wat uitgelek het**, is dit ’n baie maklike oorwinning.

## Kwesbaarhede in publieke kode

As jy vind dat die maatskappy **oopbronkode** het, kan jy dit **ontleed** en daarin na **kwesbaarhede** soek.

**Afhangend van die taal** is daar verskillende **nutsmiddels** wat jy kan gebruik; sien die lys [nutsmiddels vir bronkodehersiening](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Daar is ook gratis dienste waarmee jy **publieke repos kan skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting-webmetodologie**](../../network-services-pentesting/pentesting-web/index.html)

Die **meeste kwesbaarhede** wat bug hunters vind, is in **webtoepassings**, daarom wil ek op hierdie punt ’n **toetsmetodologie vir webtoepassings** bespreek. Jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook die afdeling [**Oopbron-nutsmiddels vir outomatiese webskandeerders**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) spesiaal noem, want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede sal vind nie, is hulle handig om in **werkvloeie te implementeer en aanvanklike webinligting te kry.**

## Samevatting

> Baie geluk! Op hierdie punt het jy reeds **al die basiese enumerasie** gedoen. Ja, dis basies, want daar is nog baie meer enumerasie wat gedoen kan word (ons sal later meer truuks sien).

Jy het dus reeds:

1. Al die **maatskappye** binne die omvang gevind
2. Al die **bates** gevind wat aan die maatskappye behoort (en ’n kwesbaarheidskandering gedoen indien dit binne die omvang val)
3. Al die **domeine** gevind wat aan die maatskappye behoort
4. Al die **subdomeine** van die domeine gevind (is daar enige subdomain takeover?)
5. Al die **IP's** binne die omvang gevind (van **CDN's** en **nie van CDN's**).
6. Al die **webbedieners** gevind en ’n **skermskoot** van hulle geneem (is daar enigiets vreemds wat ’n dieper ondersoek werd is?)
7. Al die **potensiële publieke wolkbates** gevind wat aan die maatskappy behoort.
8. **E-posadresse**, **geloofsbriefleaks** en **geheimleaks** gevind wat jou **maklik ’n groot oorwinning** kan besorg.
9. **Al die webwerwe wat jy gevind het gepentesten**

## **Volledige outomatiese recon-nutsmiddels**

Daar is verskeie nutsmiddels wat ’n deel van die voorgestelde aksies op ’n gegewe omvang sal uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - ’n Bietjie oud en nie opgedateer nie



## References

- [1] [Jason Haddix – Die bug hunter se metodologie v4.0: Recon-uitgawe](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Oor favicons: Van blaaierikone tot aanvalsvlakinligting](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Favicons.ico bewapen vir BugBounties, OSINT en nog wat](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ontdek domeine deur ’n tydkorrelasie-aanval op Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passiewe takeover: ’n Duur subdomain takeover-veldtog ontbloot (en nageboots)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: ’n Unieke metode vir subdomein-enumerasie](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Volledige subdomein-ontdekkingswerkvloei, deel 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Volledige subdomein-brute-force-ontdekking met ’n outomatiese Trickest-werkvloei, deel 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Skermskoot van favihash-uitvoer](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
