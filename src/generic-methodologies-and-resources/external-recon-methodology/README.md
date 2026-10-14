# Eksterne verkenningsmetodologie

{{#include ../../banners/hacktricks-training.md}}

## Ontdekking van bates

> Daar is dus vir jou gesê dat alles wat aan ’n maatskappy behoort binne die scope val, en jy wil uitvind wat hierdie maatskappy werklik besit.

Die doel van hierdie fase is om al die **maatskappye wat deur die hoofmaatskappy besit word** te identifiseer, en dan al die **bates** van hierdie maatskappye. Om dit te doen, gaan ons:<sup>[[1]](#references)</sup>

1. Die verkrygings van die hoofmaatskappy vind; dit sal ons die maatskappye binne die scope gee.
2. Die ASN (indien enige) van elke maatskappy vind; dit sal ons die IP-reekse gee wat elke maatskappy besit.
3. Reverse whois-opsoeke gebruik om ander inskrywings (organisasiename, domeine...) te soek wat met die eerste een verband hou (dit kan rekursief gedoen word).
4. Ander tegnieke gebruik, soos shodan se `org`- en `ssl`-filters, om na ander bates te soek (die `ssl`-truuk kan rekursief gedoen word).

### **Verkrygings**

Eerstens moet ons weet watter **ander maatskappye deur die hoofmaatskappy besit word**.\
Een opsie is om [https://www.crunchbase.com/](https://www.crunchbase.com) te besoek, na die **hoofmaatskappy te soek** en op "**acquisitions**" te **klik**. Daar sal jy ander maatskappye sien wat deur die hoofmaatskappy verkry is.\
Nog ’n opsie is om die **Wikipedia**-bladsy van die hoofmaatskappy te besoek en na **acquisitions** te soek.\
Vir openbare maatskappye, kyk na **SEC/EDGAR-lêers**, **beleggersverhoudinge**-bladsye of plaaslike maatskappyregisters (bv. **Companies House** in die VK).\
Vir globale korporatiewe strukture en filiale, probeer **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) en die **GLEIF LEI**-databasis ([https://www.gleif.org/](https://www.gleif.org/)).

> Goed, teen hierdie punt behoort jy al die maatskappye binne die scope te ken. Kom ons kyk hoe om hul bates te vind.

### **ASN’s**

’n Outonome stelselnommer (**ASN**) is ’n **unieke nommer** wat deur die **Internet Assigned Numbers Authority (IANA)** aan ’n **outonome stelsel** (AS) toegeken word.\
’n **AS** bestaan uit **blokke** **IP-adresse** met ’n duidelik omskrewe beleid vir toegang tot eksterne netwerke. Dit word deur ’n enkele organisasie geadministreer, maar kan uit verskeie operateurs bestaan.

Dit is nuttig om uit te vind of die **maatskappy enige ASN toegeken is**, sodat jy sy **IP-reekse** kan vind. Dit sal nuttig wees om ’n **kwesbaarheidstoets** uit te voer teen al die **hosts** binne die **scope** en na **domeine** binne hierdie IP’s te soek.\
Jy kan op maatskappynaam, **IP** of **domein** soek by [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **of** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Afhangend van die streek waarin die maatskappy geleë is, kan hierdie skakels nuttig wees om meer data in te samel:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Noord-Amerika),** [**APNIC**](https://www.apnic.net) **(Asië),** [**LACNIC**](https://www.lacnic.net) **(Latyns-Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In elk geval verskyn waarskynlik al die** nuttige inligting **(IP-reekse en Whois)** reeds in die eerste skakel.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ook, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** se** enumerasie versamel en som ASNs outomaties aan die einde van die skandering op.

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

Jy kan die IP-reekse van ’n organisasie ook vind met [http://asnlookup.com/](http://asnlookup.com) (dit het ’n gratis API).\
Jy kan die IP en ASN van ’n domain vind met [http://ipv4info.com/](http://ipv4info.com).

### **Soek na kwesbaarhede**

Op hierdie punt ken ons **al die assets binne scope**, dus, as jy toestemming het, kan jy ’n **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) op al die hosts laat loop.\
Jy kan ook [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) uitvoer **of dienste soos** Shodan, Censys of ZoomEye gebruik **om** oop poorte **te vind, en afhangend van wat jy vind, moet jy** in hierdie boek kyk hoe om verskeie moontlike dienste wat loop te pentest.\
**Dit kan ook die moeite werd wees om te noem dat jy ook ’n paar** verstekgebruikersname **en** wagwoord **lyste kan voorberei en probeer om** dienste te bruteforce met [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Ons ken al die maatskappye binne scope en hul assets; dit is tyd om die domains binne scope te vind.

_Let daarop dat jy met die volgende voorgestelde tegnieke ook subdomains kan vind, en dat daardie inligting nie onderskat moet word nie._

Eerstens moet jy die **main domain**(s) van elke maatskappy vind. Byvoorbeeld, vir _Tesla Inc._ is dit _tesla.com_.

### **Reverse DNS**

Noudat jy al die IP-reekse van die domains gevind het, kan jy probeer om **reverse DNS-lookups** op daardie **IPs uit te voer om meer domains binne scope te vind**. Probeer ’n DNS-server van die slagoffer of ’n bekende DNS-server gebruik (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Om dit te laat werk, moet die administrateur PTR handmatig aktiveer.\
Jy kan ook ’n aanlyn hulpmiddel vir hierdie inligting gebruik: [http://ptrarchive.com/](http://ptrarchive.com).\
Vir groot reekse is hulpmiddels soos [**massdns**](https://github.com/blechschmidt/massdns) en [**dnsx**](https://github.com/projectdiscovery/dnsx) nuttig om reverse lookups en verryking te outomatiseer.

### **Reverse Whois (loop)**

In ’n **whois** kan jy baie interessante **inligting** vind, soos **organisasienaam**, **adres**, **e-posadresse**, telefoonnommers... Maar wat nog interessanter is, is dat jy **meer bates wat met die maatskappy verband hou** kan vind as jy **reverse whois lookups op enige van daardie velde uitvoer** (byvoorbeeld ander whois-registers waar dieselfde e-posadres voorkom).\
Jy kan aanlyn hulpmiddels soos hierdie gebruik:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (web en API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - Gratis op die web, API nie gratis nie.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie gratis nie
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie gratis nie (slegs **100 gratis** soektogte)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie gratis nie
- [https://securitytrails.com/](https://securitytrails.com/) - Nie gratis nie (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nie gratis nie (API)

Jy kan hierdie taak outomatiseer met [**DomLink** ](https://github.com/vysecurity/DomLink)(vereis ’n whoxy API-sleutel).\
Jy kan ook outomatiese reverse whois-ontdekking met [amass](https://github.com/OWASP/Amass) uitvoer: `amass intel -d tesla.com -whois`

**Let daarop dat jy hierdie tegniek kan gebruik om meer domeinname te ontdek elke keer wanneer jy ’n nuwe domein vind.**

### **Trackers**

As jy die **selfde ID van dieselfde tracker** op 2 verskillende bladsye vind, kan jy aanvaar dat **albei bladsye** deur **dieselfde span bestuur word**.\
Byvoorbeeld, as jy dieselfde **Google Analytics ID** of dieselfde **Adsense ID** op verskeie bladsye sien.

Daar is ’n paar bladsye en hulpmiddels waarmee jy op hierdie en ander trackers kan soek:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (vind verwante webwerwe deur gedeelde analytics/trackers)
- [**StackScan**](https://www.stackscan.com) - **Gratis vlak** (web en API). Pivot op enige bediende bate, nie net tracker-ID’s nie: ’n script-pad, ’n selfgehoste bundelnaam of die host waarvandaan ’n bate gelaai word; dit gee elke webwerf terug wat dit bevat

Die API gee die stack vir ’n enkele domein terug, wat nuttig is om te bevestig dat ’n kandidaatbate deel van dieselfde omgewing is:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gee elke bespeurde tegnologie saam met sy kategorie terug. Asset pivoting is tans net vir web beskikbaar; die API dek opsoeke per domein.

### **Favicon**

Het jy geweet dat ons verwante domeine en subdomeine vir ons teiken kan vind deur na dieselfde favicon-ikoon-hash te soek? Dit is presies wat die [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)-nutsmiddel, geskep deur [@m4ll0k2](https://twitter.com/m4ll0k2), doen. Hier is hoe om dit te gebruik:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash-resultate wat gebruik word om domeine te ontdek wat ’n favicon-hash deel](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Eenvoudig gestel, favihash stel ons in staat om domeine te ontdek wat dieselfde favicon-ikoonhash as ons teiken het.

![favihash-afvoer wat gebruik word om domeine met dieselfde favicon-hash te ontdek](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Gebruik ’n bekende favicon-hash as ’n Shodan- of FOFA-pivot om ander blootgestelde instansies van dieselfde tegnologie te vind.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Só kan jy die **favicon-hash** van ’n webwerf bereken (MMH3 oor die **base64-encoded** favicon-grepe):

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

- **Beskou die hash as ’n aanduiding, nie as bewys nie**: MMH3 is kompak; botsings, hergebruikte ikone en doelbewuste vervalsing is moontlik.
- **Ondersoek meer as** `/favicon.ico`: kyk na raamwerk-/boupaadjies, manifest-lêers, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, ingebedde data-URL’s en HTML-`<link rel="icon">`-etikette.
- **Statiese bates kan steeds bereikbaar wees agter WAF/SSO/IdP-kontroles**: versoek die ikoon direk en ondersoek `ETag`, `Last-Modified`, herleidings en kasopskrifte.
- **Valideer ooreenstemmings met omliggende seine**: vergelyk die titel, HTML-/liggaam-hash, opskrifte, TLS-sertifikaatonderwerpe/SAN’s, produkkomponente en blootgestelde poorte.
- **Groepeer volgens HTML-/liggaam-hash**: ’n konsekwente sjabloon versterk die vingerafdruk; gemengde sjablone dui op ’n generiese of gedeelde ikoon.
- **Beskou ’n hash wat oor onverwante handtekeninge, poorte en produkte voorkom as ’n moontlike honeypot of plekhouer.**
- **Vergelyk op dubbelsinnige teikens ’n werklike bladsy met ’n niebestaande pad**, soos `/_favicon_probe_<8-hex>`; ooreenstemmende gasheer- of parkeerantwoorde kan die gedeelde ikoon verklaar.
- **Begin triage met Nuclei-opsporingsreëls of openbare datastelle** wat favicon-hashes aan produkte en CPE’s koppel.
- **Onthou die IP-sentriese dekkingsgaping**: CDN-voorkant-, SNI-gerouteerde, anycast- en slegs-domeinoppervlakke ontbreek moontlik in Shodan-agtige datastelle.

### **Kopiereg / Unieke string**

Soek binne die webblaaie na **stringe wat deur verskillende webwerwe in dieselfde organisasie gedeel kan word**. Die **kopieregstring** kan ’n goeie voorbeeld wees. Soek dan na daardie string in **google**, in ander **blaaiers** of selfs in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT-tyd**

Dit is algemeen om ’n cron-taak soos hierdie te hê:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

om alle sertifikate op ’n bediener terselfdertyd te hernu. Deur sertifikaattydstempels of posisies in certificate-transparency-logboeke te korreleer, kan verwante domains onthul word.<sup>[[6]](#references)</sup>

Gebruik ook **certificate transparency**-logboeke direk:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### E-pos-DMARC-inligting

Jy kan ’n webwerf soos [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) of ’n nutsmiddel soos [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gebruik om **domains en subdomains te vind wat dieselfde DMARC-inligting deel**.\
Ander nuttige nutsmiddels is [**spoofcheck**](https://github.com/BishopFox/spoofcheck) en [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

’n Verlate A-rekord kan bereikbaar word wanneer ’n wolkverskaffer ’n IP-adres hertoewys. Die aangehaalde navorsing demonstreer ’n opportunistiese werkvloei wat ’n instansie opstel en die adres daarvan met passiewe DNS-data korreleer; toets takeover-scenario’s slegs binne die gemagtigde omvang.<sup>[[7]](#references)</sup>

### **Ander maniere**

Herhaal die toepaslike ontdekkingspivots wanneer jy ’n nuwe domain vind: elke resultaat kan bykomende sertifikaatname, passiewe-DNS-verhoudings, favicon-ooreenkomste en organisasie-identifiseerders blootlê wat nie vanaf die oorspronklike beginpunt sigbaar was nie.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Soos jy reeds weet watter organisasie die IP-spasie besit, kan jy in Shodan na dié data soek met: `org:"Tesla, Inc."` Gaan die gevindde gashere na vir nuwe, onverwagte domains in die TLS-sertifikaat.

Jy kan toegang verkry tot die **TLS-sertifikaat** van die hoofwebblad, die **organisasienaam** verkry en dan met die filter `ssl:"Tesla Motors"` na daardie naam in die **TLS-sertifikate** van al die webblaaie wat aan **Shodan** bekend is, soek; of ’n nutsmiddel soos [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gebruik.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ’n nutsmiddel wat na **domains soek wat met ’n hoofdomain verband hou** en na hul **subdomains**; nogal indrukwekkend.

**Passiewe DNS / Historiese DNS**

Passiewe DNS-data is uitstekend om **ou en vergete rekords** te vind wat steeds resolve of oorgeneem kan word. Kyk na:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Soek na kwesbaarhede**

Kyk of daar ’n [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) is. Dalk **gebruik ’n maatskappy ’n domain**, maar het hulle **eienaarskap verloor**. Registreer dit net (as dit goedkoop genoeg is) en laat weet die maatskappy.

As jy enige **domain met ’n IP-adres anders** as dié wat jy reeds tydens die bate-ontdekking gevind het, kry, moet jy ’n **basiese kwesbaarheidskandering** uitvoer (met Nessus of OpenVAS) en ’n [**poortskandering**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan** doen. Na gelang van die dienste wat loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te “aanval”**.\
_Neem kennis dat die domain soms op ’n IP-adres gehuisves word wat nie deur die kliënt beheer word nie, en dus buite die omvang val; wees versigtig._

## Subdomains

> Ons ken al die maatskappye binne die omvang, al die bates van elke maatskappy en al die domains wat met die maatskappye verband hou.

Dit is tyd om al die moontlike subdomains van elke gevonde domain te vind.

> [!TIP]
> Let daarop dat sommige van die nutsmiddels en tegnieke om domains te vind, ook kan help om subdomains te vind

### **DNS**

Kom ons probeer om **subdomains** uit die **DNS**-rekords te kry. Ons moet ook **Zone Transfer** probeer (As dit kwesbaar is, moet jy dit rapporteer).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Vir APIs en platforms wat infrastruktuur, reputasie, lekrekords en verryking buite subdomeinontdekking dek, sien die [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md).

Die vinnigste manier om baie subdomeine te kry, is om eksterne bronne te deursoek. Die mees gebruikte **tools** is die volgende (stel die API-sleutels op vir beter resultate):


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

Daar is **ander interessante tools/API's** wat, al spesialiseer hulle nie direk daarin om subdomeine te vind nie, nuttig kan wees om subdomeine te vind, soos:

- [**IP.THC.ORG**](https://ip.thc.org) gratis API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Gebruik die API [https://sonar.omnisint.io](https://sonar.omnisint.io) om subdomeine te verkry.

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
- [**activedns.net**](https://activedns.net/)

Hierdie projek bied **gratis al die subdomeine wat met bug-bounty-programme verband hou**. Jy kan ook toegang tot hierdie data kry met [chaospy](https://github.com/dr-0x0x/chaospy), of selfs toegang kry tot die scope wat hierdie projek gebruik: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Jy kan ’n **vergelyking** van baie van hierdie nutsmiddels hier vind: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Kom ons probeer om nuwe **subdomeine** te vind deur DNS-bedieners met moontlike subdomeinname te brute-force.

Vir hierdie aksie het jy ’n paar **algemene subdomein-wordlists nodig, soos**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

En ook IP’s van goeie DNS-resolvers. Om ’n lys van betroubare DNS-resolvers saam te stel, kan jy die resolvers van [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) aflaai en [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) gebruik om hulle te filtreer. Of jy kan hierdie lys gebruik: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die mees aanbevole nutsmiddels vir DNS-brute-force is:

- [**massdns**](https://github.com/blechschmidt/massdns): Dit was die eerste nutsmiddel wat ’n doeltreffende DNS-brute-force uitgevoer het. Dit is baie vinnig, maar is geneig om vals positiewe resultate te lewer.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Hierdie een gebruik, dink ek, net 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is ’n wrapper om `massdns`, geskryf in Go, waarmee jy geldige subdomeine met aktiewe bruteforce kan enumereer, asook subdomeine kan resolve met wildcard-hantering en maklike invoer-uitvoer-ondersteuning.

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

Nadat jy subdomeine met behulp van oop bronne en brute-forcing gevind het, kan jy wysigings van die gevonde subdomeine genereer om nog meer te probeer vind. Verskeie nutsmiddels is hiervoor nuttig:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Genereer permutasies op grond van die domeine en subdomeine.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Genereer permutasies op grond van domeine en subdomeine.
  - Jy kan die goaltdns-permutasies se **wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) kry.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Gegewe die domeine en subdomeine, genereer permutasies. As geen permutasielêer aangedui word nie, sal gotator sy eie een gebruik.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Benewens die generering van subdomeinpermutasies, kan dit ook probeer om hulle te resolve (maar dit is beter om die vorige tools te gebruik wat in kommentaar genoem is).
  - Jy kan die **woordlys** vir altdns-permutasies [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) kry.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Nog ’n hulpmiddel om permutasies, mutasies en veranderinge aan subdomeine uit te voer. Hierdie hulpmiddel sal die resultate brute force (dit ondersteun nie DNS-wildcards nie).
  - Jy kan die dmut-permutasiewoordelys [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) kry.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Op grond van ’n domein **genereer dit nuwe moontlike subdomeinname** volgens aangeduide patrone om meer subdomeine te probeer ontdek.

#### Slim permutasiegenerering

- [**regulator**](https://github.com/cramppet/regulator): Leer regex-agtige patrone uit ontdekte subdomeine en genereer kandidaatname om te resolve.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is ’n subdomein-brute-force-fuzzer wat gekoppel is aan ’n ongelooflik eenvoudige maar doeltreffende DNS-responsgeleide algoritme. Dit gebruik ’n verskafte stel invoerdata, soos ’n pasgemaakte woordelys of historiese DNS/TLS-rekords, om meer ooreenstemmende domeinname akkuraat te genereer en dit verder uit te brei in ’n lus op grond van inligting wat tydens die DNS-skandering ingesamel word.

```
echo www | subzuf facebook.com
```

### **Subdomein-ontdekkingswerkvloei**

Trickest-werkvloei-voorbeelde kombineer OSINT, DNS-brute force en permutasiestappe vir herhaalbare subdomein-enumerasie.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

As jy ’n IP-adres gevind het wat **een of meer webblaaie** bevat wat aan subdomeine behoort, kan jy probeer om **ander subdomeine met webblaaie op daardie IP te vind** deur in **OSINT-bronne** na domeine op ’n IP te soek, of deur **VHost-domeinname op daardie IP met brute force te raai**.

#### OSINT

Jy kan sommige **VHosts in IP’s vind met** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **of ander API’s**.

**Brute Force**

As jy vermoed dat ’n subdomein op ’n webbediener versteek kan wees, kan jy probeer om dit met brute force te vind:

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

Soms sal jy bladsye vind wat die _**Access-Control-Allow-Origin**_-header slegs terugstuur wanneer ’n geldige domain/subdomain in die _**Origin**_-header gestel is. In hierdie scenario’s kan jy hierdie gedrag misbruik om nuwe **subdomains** te **ontdek**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Terwyl jy na **subdomains** soek, hou dop of enige daarvan na ’n soort **bucket** **wys**. Indien wel, [**kontroleer die toestemmings**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Aangesien jy teen hierdie tyd al die domeine binne die scope sal ken, probeer ook om [**moontlike bucket name met brute force te vind en die toestemmings te kontroleer**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitering**

Jy kan monitor of **nuwe subdomains** van ’n domein geskep word deur die **Certificate Transparency**-logs dop te hou, soos [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)doen.

### **Soek na kwesbaarhede**

Kontroleer vir moontlike [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
As die **subdomain** na ’n **S3 bucket** wys, [**kontroleer die toestemmings**](../../network-services-pentesting/pentesting-web/buckets/index.html).

As jy enige **subdomain vind met ’n IP wat verskil** van dié wat jy reeds tydens asset discovery gevind het, moet jy ’n **basiese kwesbaarheidskandering** uitvoer (met Nessus of OpenVAS), asook ’n [**poortskandering**](../pentesting-network/index.html#discovering-hosts-from-the-outside) met **nmap/masscan/shodan**. Afhangend van die dienste wat loop, kan jy in **hierdie boek ’n paar truuks vind om hulle te "attack"**.\
_Neem kennis dat die subdomain soms op ’n IP gehuisves word wat nie deur die kliënt beheer word nie, en dus buite die scope val. Wees versigtig._

## IPs

In die aanvanklike stappe het jy dalk **’n paar IP-reekse, domeine en subdomains gevind**.\
Dis tyd om **al die IPs uit daardie reekse te versamel**, asook dié vir die **domeine/subdomains (DNS-navrae).**

Deur dienste van die volgende **gratis APIs** te gebruik, kan jy ook **vorige IPs vind wat deur domeine en subdomains gebruik is**. Hierdie IPs kan steeds aan die kliënt behoort (en jou dalk help om [**CloudFlare-bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) te vind).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Jy kan ook met die [**hakip2host**](https://github.com/hakluke/hakip2host)-tool kyk watter domeine na ’n spesifieke IP-adres wys.

### **Soek na kwesbaarhede**

**Voer ’n poortskandering uit op al die IPs wat nie aan CDNs behoort nie** (want jy sal waarskynlik niks interessants daar vind nie). Jy kan dalk **kwesbaarhede vind** in die dienste wat loop.

**Vind ’n** [**gids**](../pentesting-network/index.html) **oor hoe om hosts te skandeer.**

## Soek na webbedieners

> Ons het al die maatskappye en hul bates gevind, en ons ken die IP-reekse, domeine en subdomains binne die scope. Dis tyd om na webbedieners te soek.

In die vorige stappe het jy waarskynlik reeds ’n bietjie **recon gedoen van die IPs en domeine wat ontdek is**, so jy het dalk **reeds al die moontlike webbedieners gevind**. Indien nie, gaan ons nou ’n paar **vinnige truuks bespreek om webbedieners binne die scope te vind**.

Let asseblief daarop dat dit **op die ontdekking van webapps gerig** sal wees. Jy moet dus ook **kwesbaarheidskanderings** en **poortskanderings** uitvoer (**indien die scope dit toelaat**).

’n **Vinnige metode** om **oop poorte** te ontdek wat met **web**bedieners verband hou, met behulp van [**masscan**, kan jy hier vind](../pentesting-network/index.html#http-port-discovery).\
Nog ’n gebruikersvriendelike tool om webbedieners te soek, is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) en [**httpx**](https://github.com/projectdiscovery/httpx). Jy gee dit net ’n lys domeine, en dit sal probeer om aan poort 80 (http) en 443 (https) te koppel. Jy kan ook aandui dat dit ander poorte moet probeer:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Noudat jy **al die webbedieners** binne die omvang ontdek het (onder die maatskappy se **IP’s** en al sy **domeine** en **subdomeine**), weet jy waarskynlik **nie waar om te begin nie**. Kom ons hou dit dus eenvoudig en begin deur bloot skermkiekies van almal te neem. Deur net na die **hoofbladsy** te **kyk**, kan jy **vreemde** eindpunte vind wat meer **geneig** is om **kwesbaar** te wees.

Om die voorgestelde idee uit te voer, kan jy [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) of [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Daarna kan jy ook [**eyeballer**](https://github.com/BishopFox/eyeballer) oor al die **skermkiekies** laat loop sodat dit jou kan vertel **wat waarskynlik kwesbaarhede bevat** en wat nie.

## Bate in die publieke wolk

Om moontlike wolkbates te vind wat aan ’n maatskappy behoort, moet jy **begin met ’n lys sleutelwoorde wat daardie maatskappy identifiseer**. Byvoorbeeld, vir ’n crypto-maatskappy kan jy woorde soos dié gebruik: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Jy sal ook woordelyste nodig hê van **algemene woorde wat in buckets gebruik word**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Met hierdie woorde moet jy dan **permutasies** genereer (kyk na die [**Tweede rondte DNS-brute-force**](#second-dns-bruteforce-round) vir meer inligting).

Met die resulterende woordelyste kan jy nutsmiddels soos [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **of** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Onthou dat jy, wanneer jy na wolkbates soek, na meer as net buckets in AWS moet so**ek.**

### **Soek na kwesbaarhede**

As jy dinge soos **oop buckets of blootgestelde wolkfunksies** vind, moet jy **toegang daartoe kry** en probeer kyk wat dit bied en of jy dit kan misbruik.

## E-posse

Met die **domeine** en **subdomeine** binne die omvang het jy basies alles wat jy **nodig het om na e-posadresse te begin soek**. Hierdie **API’s** en **nutsmiddels** het vir my die beste gewerk om ’n maatskappy se e-posadresse te vind:

- [**theHarvester**](https://github.com/laramies/theHarvester) - met API’s
- API van [**https://hunter.io/**](https://hunter.io/) (gratis weergawe)
- API van [**https://app.snov.io/**](https://app.snov.io/) (gratis weergawe)
- API van [**https://minelead.io/**](https://minelead.io/) (gratis weergawe)

### **Soek na kwesbaarhede**

E-posadresse sal later handig te pas kom om **webaanmeldings en auth-dienste** (soos SSH) met brute-force aan te val. Dit is ook nodig vir **phishing**. Boonop gee hierdie API’s jou nog meer **inligting oor die persoon** agter die e-posadres, wat nuttig is vir die phishing-veldtog.

## Lekke van geloofsbriewe

Met die **domeine,** **subdomeine** en **e-posadresse** kan jy begin soek na geloofsbriewe wat in die verlede uitgelek het en aan dié e-posadresse behoort:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe vind wat uitgelek het**, is dit ’n baie maklike oorwinning.

## Lekke van geheime

Lekke van geloofsbriewe hou verband met hacks van maatskappye waar **sensitiewe inligting uitgelek en verkoop is**. Maatskappye kan egter deur **ander lekke** geraak word waarvan die inligting nie in daardie databasisse voorkom nie:

### Github-lekke

Geloofsbriewe en API’s kan in die **publieke repositories** van die **maatskappy** of van die **gebruikers** wat by daardie Github-maatskappy werk, uitlek.\
Jy kan die **nutsmiddel** [**Leakos**](https://github.com/carlospolop/Leakos) gebruik om al die **publieke repositories** van ’n **organisasie** en sy **ontwikkelaars** af te laai en [**gitleaks**](https://github.com/zricethezav/gitleaks) outomaties daaroor te laat loop.

**Leakos** kan ook gebruik word om **gitleaks** te laat loop oor al die **teks-URL’s** wat daaraan verskaf word, want soms bevat **webbladsye ook geheime**.

#### Github-dorks

Kyk na die [GitHub dorks en lekke-bladsy](github-leaked-secrets.md) vir moontlike **GitHub-dorks** om in die organisasie te soek.

### Paste-lekke

Soms **publiseer aanvallers of bloot werknemers maatskappyinhoud op ’n paste-werf**. Dit bevat dalk **sensitiewe inligting**, of dalk nie, maar dit is baie interessant om daarna te soek.\
Jy kan die nutsmiddel [**Pastos**](https://github.com/carlospolop/Pastos) gebruik om gelyktydig op meer as 80 paste-werwe te soek.

### Google-dorks

Ou maar goeie Google-dorks is altyd nuttig om **blootgestelde inligting te vind wat nie daar behoort te wees nie**. Die enigste probleem is dat die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) etlike **duisende** moontlike navrae bevat wat jy nie handmatig kan uitvoer nie. Jy kan dus jou gunsteling 10 kies, of ’n **nutsmiddel soos** [**Gorks**](https://github.com/carlospolop/Gorks) gebruik **om hulle almal uit te voer**.

_Let daarop dat nutsmiddels wat verwag om die hele databasis met die gewone Google-blaaier te deurloop, nooit klaar sal wees nie, want Google sal jou baie, baie gou blokkeer._

### **Soek na kwesbaarhede**

As jy **geldige geloofsbriewe of API-tokens vind wat uitgelek het**, is dit ’n baie maklike oorwinning.

## Kwesbaarhede in publieke kode

As jy vasgestel het dat die maatskappy **oopbronkode** het, kan jy dit **ontleed** en daarin na **kwesbaarhede** soek.

Daar is verskillende **nutsmiddels** wat jy kan gebruik, **afhangend van die taal**; sien die lys [nutsmiddels vir bronkodehersiening](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Daar is ook gratis dienste waarmee jy **publieke repositories kan skandeer**, soos:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting-webmetodologie**](../../network-services-pentesting/pentesting-web/index.html)

Die **meeste kwesbaarhede** wat deur bug hunters gevind word, is in **webtoepassings**. Daarom wil ek op hierdie punt praat oor ’n **toetsmetodologie vir webtoepassings**; jy kan [**hierdie inligting hier vind**](../../network-services-pentesting/pentesting-web/index.html).

Ek wil ook spesiale melding maak van die afdeling [**Oopbron-nutsmiddels vir outomatiese webskandeerders**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), want hoewel jy nie moet verwag dat hulle baie sensitiewe kwesbaarhede sal vind nie, is hulle handig om in **werkvloeie te gebruik en aanvanklike webinligting te bekom.**

## Samevatting

> Baie geluk! Teen hierdie tyd het jy reeds **al die basiese enumerasie** uitgevoer. Ja, dit is basies, want daar is nog baie meer enumerasie wat gedoen kan word (ons sal later meer truuks sien).

Jy het dus reeds:

1. Al die **maatskappye** binne die omvang gevind
2. Al die **bates** gevind wat aan die maatskappye behoort (en ’n kwesbaarheidskandering uitgevoer as dit binne die omvang val)
3. Al die **domeine** gevind wat aan die maatskappye behoort
4. Al die **subdomeine** van die domeine gevind (enige subdomein-oorname?)
5. Al die **IP’s** gevind (van en **nie van CDNs nie**) binne die omvang.
6. Al die **webbedieners** gevind en ’n **skermkiekie** van hulle geneem (is daar enigiets vreemds wat dieper ondersoek werd is?)
7. Al die **moontlike publieke wolkbates** gevind wat aan die maatskappy behoort.
8. **E-posadresse**, **lekke van geloofsbriewe** en **lekke van geheime** wat jou **baie maklik ’n groot oorwinning** kan besorg.
9. **Pentesting van al die webwerwe wat jy gevind het**

## **Volledige outomatiese Recon-nutsmiddels**

Daar is verskeie nutsmiddels beskikbaar wat sommige van die voorgestelde aksies op ’n gegewe omvang kan uitvoer.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - ’n Bietjie oud en nie opgedateer nie

## References

- [1] [Jason Haddix – Die Bug Hunter se metodologie v4.0: Recon-uitgawe](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Oor favicons: Van blaaierikone tot intelligensie oor die aanvalsvlak](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ontdekking van domeine via ’n tydkorrelasie-aanval op Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passiewe oorname: Die blootlegging (en nabootsing) van ’n duur subdomein-oornameveldtog](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: ’n Unieke metode vir subdomein-enumerasie](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Volledige werkvloei vir subdomein-ontdekking, deel 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Volledige brute-force-ontdekking van subdomeine met ’n outomatiese Trickest-werkvloei, deel 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Skermkiekie van favihash-uitvoer](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
