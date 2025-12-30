# Mbinu za Utafiti wa Nje

{{#include ../../banners/hacktricks-training.md}}

## Ugunduzi wa Mali

> Kwa hivyo ulisemwa kuwa kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya upeo, na unataka kubaini kampuni hiyo inamiliki nini kwa kweli.

Lengo la hatua hii ni kupata kampuni zote **zinazomilikiwa na kampuni kuu** na kisha **mali** zote za kampuni hizo. Ili kufanya hivyo, tutafanya:

1. Tafuta acquisitions za kampuni kuu; hii itatupa kampuni zilizo ndani ya upeo.
2. Tafuta ASN (ikiwa ipo) ya kila kampuni; hii itatupa anuwai za IP zinazomilikiwa na kila kampuni.
3. Tumia reverse whois lookups kutafuta vifungu vingine (majina ya mashirika, domains...) vinavyohusiana na ya kwanza (hii inaweza kufanywa kwa urudia).
4. Tumia mbinu nyingine kama shodan `org` na `ssl` filters kutafuta mali nyingine (triki ya `ssl` inaweza kufanywa kwa urudia).

### **Manunuzi**

Kwanza kabisa, tunahitaji kujua ni kampuni gani nyingine **zinazomilikiwa na kampuni kuu**.\
Njia moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **tafuta** kampuni kuu, na **bonyeza** kwenye "**acquisitions**". Huko utaona kampuni nyingine zilizopatikana na kampuni kuu.\
Njia nyingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, angalia **SEC/EDGAR filings**, kurasa za **investor relations**, au rejista za kampuni za eneo (mfano, **Companies House** nchini Uingereza).\
Kwa miti ya kimataifa ya kampuni na kampuni tanzu, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na hifadhidata ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, kwa hatua hii unapaswa kujua kampuni zote zilizo ndani ya upeo. Hebu tuweke jinsi ya kupata mali zao.

### **ASNs**

Nambari ya autonomous system (**ASN**) ni **nambari ya kipekee** inayotolewa kwa **autonomous system** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
AS inajumuisha **mikoa** ya **anwani za IP** ambazo zina sera wazi kwa ufikiaji wa mitandao ya nje na zinaendeshwa na shirika moja lakini zinaweza kuundwa na waendeshaji kadhaa.

Ni muhimu kutafuta ikiwa kampuni imepewa **ASN** ili kupata **anuwai za IP**. Inafaa kufanya **mtihani wa vulnerability** dhidi ya **hosts** zote ndani ya **upeo** na **kutafuta domains** ndani ya anwani hizi za IP.\
Unaweza **tafuta** kwa jina la kampuni, kwa **IP** au kwa **domain** kwenye [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na mkoa wa kampuni, link hizi zinaweza kuwa muhimu kupata data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Hata hivyo, pengine taarifa zote muhimu (IP ranges na Whois)** zinaonekana tayari katika kiungo cha kwanza.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration huweka pamoja kiotomatiki na hufupisha ASNs mwishoni mwa scan.
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
Unaweza kupata anuwai za IP za shirika pia ukitumia [http://asnlookup.com/](http://asnlookup.com) (ina API ya bure).\
Unaweza kupata IP na ASN ya domain ukitumia [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta udhaifu**

Katika hatua hii tunajua **all the assets inside the scope**, hivyo ikiwa umepewa ruhusa unaweza kuanzisha baadhi ya **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) juu ya hosts zote.\
Pia, unaweza kuanzisha baadhi ya [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** Shodan, Censys, au ZoomEye **kutafuta** open ports **na kulingana na kile utakachokipata unapaswa** angalia kitabu hiki kuhusu jinsi ya pentest huduma mbalimbali zinazokimbia.\
**Pia, inaweza kuwa vyema kutaja kuwa unaweza pia kuandaa** default username **na** passwords **lists na kujaribu** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua makampuni yote ndani ya scope na rasilimali zao, sasa ni wakati wa kutafuta domains ndani ya scope.

_Tafadhali, kumbuka kwamba katika mbinu zinazopendekezwa hapa chini unaweza pia kupata subdomains na taarifa hiyo haipaswi kupuuzwa._

Kwanza kabisa unapaswa kutafuta **main domain**(s) ya kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kwa kuwa umepata anuwai zote za IP za domains unaweza kujaribu kufanya **reverse dns lookups** kwa IP hizo ili kupata domains zaidi ndani ya scope. Jaribu kutumia dns server ya victim au dns server maarufu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
Unaweza pia kutumia zana ya mtandaoni kwa taarifa hii: [http://ptrarchive.com/](http://ptrarchive.com).\
Kwa maeneo makubwa, zana kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) zinasaidia kufanya reverse lookups na enrichment kiotomatiki.

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
Unaweza kutumia zana za mtandaoni kama:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **BURE**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **BURE**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **BURE**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **BURE** tovuti, API sio bure.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - **SIO BURE**
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **SIO BURE** (tu **100** utafutaji wa bure)
- [https://www.domainiq.com/](https://www.domainiq.com) - **SIO BURE**
- [https://securitytrails.com/](https://securitytrails.com/) - **SIO BURE** (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - **SIO BURE** (API)

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
Unaweza pia kufanya ugunduzi wa reverse whois kiotomatiki kwa kutumia [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
Kwa mfano, ikiwa unaona **Google Analytics ID** ile ile au **Adsense ID** ile ile kwenye kurasa kadhaa.

There are some pages and tools that let you search by these trackers and more:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Did you know that we can find related domains and subdomains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - gundua domains zilizo na favicon icon hash sawa](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa ufupi, favihash itaturuhusu kugundua domains ambazo zina favicon icon hash sawa na lengo letu.

Zaidi ya hayo, unaweza pia kutafuta teknolojia ukitumia favicon hash kama ilivyoelezwa katika [**makala hii ya blogu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hii inamaanisha kwamba ikiwa unajua **hash ya favicon ya toleo lililo na udhaifu la web tech** unaweza kuitafuta katika shodan na **kupata maeneo zaidi yaliyo na udhaifu**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Hapa ni jinsi unavyoweza **calculate the favicon hash** ya tovuti:
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
Unaweza pia kupata favicon hashes kwa wingi kwa kutumia [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) na kisha pivot katika Shodan/Censys.

### **Haki miliki / String ya kipekee**

Tafuta ndani ya kurasa za wavuti **strings ambazo zinaweza kushirikiwa baina ya tovuti mbalimbali katika shirika moja**. Mfano mzuri ni **copyright string**. Kisha tafuta string hiyo kwenye **google**, katika **vivinjari** vingine au hata kwenye **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Ni kawaida kuwa na cron job kama
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
kurejesha vyeti vyote vya vikoa kwenye server. Hii inamaanisha kwamba hata kama CA iliyotumika haitoi muda wa kuundwa katika muda wa uhalali (Validity time), inawezekana **kupata vikoa vinavyomilikiwa na kampuni hiyo hiyo kwenye certificate transparency logs**.\
Angalia [**maelezo zaidi**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Pia tumia **certificate transparency** logs moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Taarifa za DMARC za Barua

Unaweza kutumia wavuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au chombo kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) kutafuta **vikoa na subdomain zinazoshiriki taarifa za DMARC**.\
Zana nyingine muhimu ni [**spoofcheck**](https://github.com/BishopFox/spoofcheck) na [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Inaonekana ni kawaida kwa watu kupeana subdomain kwa IP zinazomilikiwa na cloud providers na wakati fulani **kupoteza anwani hiyo ya IP lakini kusahau kuondoa rekodi ya DNS**. Kwa hiyo, kwa **kuanzisha VM** katika cloud (kama Digital Ocean) utakuwa unafanya kweli **kuchukua baadhi ya subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) inaelezea tukio kuhusu hili na inapendekeza script ambayo **inaspawn VM katika DigitalOcean**, **inapata** **IPv4** ya mashine mpya, na **inatafuta katika Virustotal rekodi za subdomain** zinazoonyesha kwa hiyo.

### **Other ways**

**Kumbuka kwamba unaweza kutumia mbinu hii kugundua majina ya kikoa zaidi kila unapopata kikoa kipya.**

**Shodan**

Kama unavyojua tayari jina la shirika linalomiliki nafasi ya IP. Unaweza kutafuta kwa kutumia data hiyo katika shodan kwa kutumia: `org:"Tesla, Inc."` Angalia host zilizopatikana kwa vikoa vipya visivyotarajiwa kwenye TLS certificate.

Unaweza kufikia **TLS certificate** ya ukurasa mkuu wa wavuti, kupata jina la shirika na kisha kutafuta jina hilo ndani ya **TLS certificates** za kurasa zote za wavuti zinazojulikana na **shodan** kwa filter: `ssl:"Tesla Motors"` au tumia chombo kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ni chombo kinachotafuta **vikoa vinavyohusiana** na kikoa kuu na **subdomains** zao, ni nzuri sana.

**Passive DNS / Historical DNS**

Data ya Passive DNS ni nzuri kupata **rekodi za zamani na zilizosahaulika** ambazo bado zinatatuliwa au ambazo zinaweza kuchukuliwa. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Angalia [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Huenda kampuni fulani inatumia **kikoa fulani** lakini wamepoteza **umiliki**. Jisajili tu (ikiwa ni nafuu) na uwajulishe kampuni.

Ikiwa utapata **kikoa chochote chenye IP tofauti** kutoka kwa zile ulizopata tayari katika ugunduzi wa assets, unapaswa kufanya **skani ya msingi ya udhaifu** (ukitumia Nessus au OpenVAS) na baadhi ya [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kutegemea huduma zipi zinaendeshwa unaweza kupata katika **kitabu hiki baadhi ya mbinu za "kuwashambulia"**.\
_Nukuu: wakati mwingine kikoa kinahifadhiwa ndani ya IP ambayo haidhibitiwi na mteja, kwa hivyo haina ndani ya wigo — kuwa mwangalifu._

## Subdomains

> Tunajua makampuni yote ndani ya wigo, mali zote za kila kampuni na vikoa vyote vinavyohusiana na kampuni hizo.

> [!TIP]
> Kumbuka kwamba baadhi ya zana na mbinu za kupata vikoa pia zinaweza kusaidia kupata subdomains

### **DNS**

Hebu tujaribu kupata **subdomains** kutoka kwa rekodi za **DNS**. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa dhaifu, unapaswa kuripoti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Njia ya haraka zaidi ya kupata subdomains nyingi ni kutafuta katika vyanzo vya nje. **Tools** zinazotumika zaidi ni zifuatazo (kwa matokeo bora, sanidi API keys):

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
Kuna **other interesting tools/APIs** ambazo, hata ikiwa hazibobezi moja kwa moja katika kutafuta subdomains, zinaweza kuwa muhimu kwa kutafuta subdomains, kama:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Inatumia API [https://sonar.omnisint.io](https://sonar.omnisint.io) kupata subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC bure API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) API ya bure
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
- [**gau**](https://github.com/lc/gau)**:** inakusanya URL zinazojulikana kutoka AlienVault's Open Threat Exchange, the Wayback Machine, na Common Crawl kwa kikoa chochote.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Huwachambua wavuti wakitafuta faili za JS na kupata subdomains kutoka huko.
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
- [**securitytrails.com**](https://securitytrails.com/) ina API ya bure kutafuta subdomains na historia ya IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Mradi huu unatoa kwa **bure all the subdomains related to bug-bounty programs**. Unaweza kupata data hii pia kwa kutumia [chaospy](https://github.com/dr-0x0x/chaospy) au hata kufikia wigo ulilotumika na mradi huu [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **ulinganisho** wa zana nyingi za aina hii hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Tujaribu kutafuta subdomains mpya kwa brute-forcing DNS servers tukitumia majina yanayowezekana ya subdomain.

Kwa hatua hii utahitaji baadhi ya **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Na pia IPs za resolvers za DNS nzuri. Ili kuunda orodha ya resolvers za DNS zinazoaminika unaweza kupakua resolvers kutoka [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzi-chuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zilizopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa zana ya kwanza iliyofanya DNS brute-force yenye ufanisi. Ni haraka sana, hata hivyo inakabiliwa na false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hii, nadhani inatumia resolver moja tu
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper ya `massdns`, iliyoandikwa kwa go, inayokuwezesha kuorodhesha subdomains halali kwa kutumia active bruteforce, na pia kutatua subdomains kwa wildcard handling pamoja na msaada rahisi wa input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Inatumia pia `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) inatumia asyncio kufanya brute force majina ya kikoa kwa njia isiyo sambazwa.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Mzunguko wa Pili wa DNS Brute-Force

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na brute-forcing, unaweza kuunda marekebisho ya subdomains ulizopata ili kujaribu kupata zaidi. Zana kadhaa zinasaidia kwa madhumuni haya:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Ikipewa domains na subdomains, huunda permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Inatengeneza permutations kutokana na domains na subdomains.
- Unaweza kupata goaltdns permutations **wordlist** [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Inatengeneza permutations kutoka kwa domains na subdomains. Ikiwa hakuna permutations file iliyotajwa, gotator atatumia yake mwenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kuunda subdomains permutations, pia inaweza kujaribu ku-resolve hizo (lakini ni bora kutumia tools zilizotajwa hapo awali).
- Unaweza kupata altdns permutations **wordlist** katika [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Chombo kingine cha kufanya permutations, mutations na mabadiliko ya subdomains. Chombo hiki kitafanya brute force matokeo (hakitambui dns wild card).
- Unaweza kupata dmut permutations wordlist katika [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kwa kuzingatia domain, **inazalisha majina mapya ya subdomains yanayowezekana** kulingana na mifumo iliyotajwa ili kujaribu kugundua subdomains zaidi.

#### Uundaji mahiri wa permutations

- [**regulator**](https://github.com/cramppet/regulator): Kwa taarifa zaidi soma hii [**post**](https://cramppet.github.io/regulator/index.html) lakini kwa msingi itachukua **sehemu kuu** kutoka kwa **subdomains zilizogunduliwa** na itazichanganya ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni subdomain brute-force fuzzer iliyoshikamana na DNS reponse-guided algorithm rahisi sana lakini yenye ufanisi. Inatumia seti ya data iliyotolewayo, kama wordlist iliyobinafsishwa au DNS/TLS records za kihistoria, kutengeneza kwa usahihi majina zaidi ya domain yanayolingana na kuyaendeleza zaidi kwa mzunguko kulingana na taarifa zilizokusanywa wakati wa DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Angalia chapisho la blogu nililoandika kuhusu jinsi ya **automate the subdomain discovery** kutoka kwa domain kwa kutumia **Trickest workflows** ili nisihitaji kuendesha kwa mkono zana nyingi kwenye kompyuta yangu:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ikiwa umepata anwani ya IP yenye **one or several web pages** zinazomilikiwa na subdomains, unaweza kujaribu **find other subdomains with webs in that IP** kwa kutafuta kwenye vyanzo vya **OSINT** kwa domain ndani ya IP hiyo au kwa **brute-forcing VHost domain names in that IP**.

#### OSINT

Unaweza kupata baadhi ya VHosts kwenye IPs kwa kutumia [**HostHunter**](https://github.com/SpiderLabs/HostHunter) au APIs nyingine.

**Brute Force**

Ikiwa unashuku kuwa subdomain fulani inaweza kujificha kwenye web server unaweza kujaribu kuitafuta kwa brute force:
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
> Kwa mbinu hii unaweza hata kuweza kupata internal/hidden endpoints.

### **CORS Brute Force**

Mara nyingine utapata kurasa ambazo zinarudisha tu header _**Access-Control-Allow-Origin**_ wakati domain/subdomain halali imewekwa katika header ya _**Origin**_. Katika mazingira haya, unaweza kutumia tabia hii ili **gundua** **subdomains** mpya.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Wakati unatafuta **subdomains** angalia kama inakuwa **pointing** kwa aina yoyote ya **bucket**, na katika kesi hiyo [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa kwa sasa utakuwa unajua domain zote ndani ya scope, jaribu [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Ufuatiliaji**

Unaweza **monitor** kama **new subdomains** za domain zimetengenezwa kwa kufuatilia **Certificate Transparency** Logs; mfano [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) hufanya hivyo.

### **Looking for vulnerabilities**

Angalia uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** ina **pointing** kwa **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ukikuta **subdomain** yoyote yenye **IP different** na zile ulizogundua kwenye assets discovery, unapaswa kufanya **basic vulnerability scan** (ukitumia Nessus au OpenVAS) na baadhi ya [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa **nmap/masscan/shodan**. Kulingana na huduma zinazoendeshwa unaweza kupata ndani ya **this book some tricks to "attack" them**.\
_Kumbuka kuwa wakati mwingine subdomain imehost ndani ya IP ambayo haiendeshwi na mteja, hivyo sio ndani ya scope, kuwa mwangalifu._

## IPs

Katika hatua za awali unaweza kuwa umepata **some IP ranges, domains and subdomains**.\
Ni wakati wa **recollect all the IPs from those ranges** na kwa **domains/subdomains (DNS queries).**

Kwa kutumia huduma kutoka kwa **free apis** zifuatazo unaweza pia kupata **previous IPs used by domains and subdomains**. IP hizi zinaweza bado kumilikiwa na mteja (na zinaweza kukuruhusu kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kuangalia kwa domains zinazoonyesha kwa IP maalum kwa kutumia tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (kwa kawaida huenda hautapata chochote kinachovutia huko). Katika services zinazopatikana unaweza **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Tumegundua kampuni zote na assets zao na tunajua IP ranges, domains na subdomains ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizopita pengine tayari umefanya aina ya **recon of the IPs and domains discovered**, hivyo huenda tayari umefinda web servers zote zinazowezekana. Hata hivyo, kama hujafanya, sasa tutaona baadhi ya **fast tricks to search for web servers** ndani ya scope.

Tafadhali, kumbuka kwamba hii itakuwa **oriented for web apps discovery**, hivyo unapaswa pia **perform the vulnerability** na **port scanning** (**if allowed** by the scope).

A **fast method** ya kugundua **ports open** zinazohusiana na **web** servers kwa kutumia [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Tool nyingine rafiki ya kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unampa tu orodha ya domains na itajaribu kuungana na port 80 (http) na 443 (https). Zaidi ya hayo, unaweza kutoa maelekezo ya kujaribu port nyingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sasa baada ya kugundua **all the web servers** zilizomo ndani ya scope (katika miongoni mwa **IPs** za kampuni na **domains** zote na **subdomains**) huenda hujui **wapi wa kuanza**. Basi, tufanye iwe rahisi na tuanze kwa kupiga screenshots za zote. Kwa **kuangalia tu** kwenye **main page** unaweza kuona endpoints **zisizo za kawaida** ambazo zina uwezekano mkubwa wa kuwa **vulnerable**.

Ili kutekeleza wazo hili unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kuangalia zote **screenshots** ili kukuambia **what's likely to contain vulnerabilities**, na zile zisizokuwa.

## Mali za Cloud ya Umma

Ili kupata mali za cloud zinazowezekana zinazo milikiwa na kampuni unapaswa kuanza na orodha ya maneno (keywords) yanayomtambulisha kampuni. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Pia utahitaji wordlists za **common words used in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa maneno hayo unapaswa kuzalisha **permutations** (tazama [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa wordlists uliopata unaweza kutumia zana kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta Cloud Assets unapaswa tazama **more than just buckets in AWS**.

### **Looking for vulnerabilities**

Ukikuta vitu kama **open buckets or cloud functions exposed** unapaswa **access them** na kujaribu kuona wanakupa nini na kama unaweza kuyaabusu.

## Barua Pepe

Kwa kutumia **domains** na **subdomains** zilizo ndani ya scope kwa msingi unaweza kuwa na yote unayohitaji kuanza kutafuta barua pepe. Hizi ndio **APIs** na zana ambazo zimenisaidia kupata barua pepe za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails zitakuwezesha baadaye kufanya **brute-force web logins and auth services** (kama SSH). Pia zinahitajika kwa **phishings**. Zaidi ya hayo, hizi APIs zitakupa hata zaidi ya **info about the person** nyuma ya email, ambayo ni muhimu kwa kampeni ya phishing.

## Credential Leaks

Kwa kutumia **domains,** **subdomains**, na **emails** unaweza kuanza kutafuta credentials zilizo leak-ia zamani zinazomilikiwa na hizo emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ikiwa utapata **valid leaked** credentials, hili ni ushindi rahisi sana.

## Secrets Leaks

Credential leaks zinahusiana na hacks za kampuni ambapo **sensitive information was leaked and sold**. Hata hivyo, kampuni zinaweza kuathiriwa na **other leaks** ambazo taarifa zake haziko katika zile databases:

### Github Leaks

Credentials na APIs zinaweza kuonekana kwenye **public repositories** za **company** au za **users** wanaofanya kazi kwa kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) kupakua **public repos** zote za **organization** na za **developers** wake na kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yao kwa ajili ya uchambuzi kiotomatiki.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **text** zote za URLs zinazopitishwa kwake kwani wakati mwingine **web pages also contains secrets**.

#### Github Dorks

Tazama pia hii **page** kwa potential **github dorks** ambazo unaweza kutafuta katika organization unayoshambulia:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Baadhi ya nyakati waharibifu au hata wafanyakazi watachapisha **company content in a paste site**. Hii inaweza kuwa na au isiwemo **sensitive information**, lakini ni muhimu kutafuta.\
Unaweza kutumia zana [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta kwenye zaidi ya tovuti 80 za paste kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini zenye thamani bado ni muhimu kutafuta **exposed information that shouldn't be there**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina **thousands** za queries ambazo huwezi kuendesha kwa mkono. Basi, unaweza kuchukua 10 zako unazopenda au unaweza kutumia **tool** kama [**Gorks**](https://github.com/carlospolop/Gorks) **kuziweka zote**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

Ikiwa utapata **valid leaked** credentials au API tokens, hili ni ushindi rahisi sana.

## Public Code Vulnerabilities

Ikiwa umegundua kwamba kampuni ina **open-source code** unaweza kui**analyse** na kutafuta **vulnerabilities** ndani yake.

**Depending on the language** kuna zana tofauti unazoweza kutumia:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Kuna pia services za bure zinazoruhusu **scan public repositories**, kama:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Majority of the vulnerabilities** zinazopatikana na bug hunters ziko ndani ya **web applications**, hivyo kwa sasa ningependa kuzungumzia **web application testing methodology**, na unaweza [**kupata taarifa hizi hapa**](../../network-services-pentesting/pentesting-web/index.html).

Ningependa pia kutaja sehemu ya [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwa sababu, ingawa huwezi kutegemea zitakupata vulnerabilities nyeti sana, zinafaa kuziweka kwenye **workflows** kupata taarifa za awali za web.

## Muhtasari

> Hongera! Kwa hatua hii tayari umefanya **all the basic enumeration**. Ndiyo, ni msingi kwa sababu kuna uchunguzi zaidi unaoweza kufanywa (tutaona mbinu zaidi baadaye).

Basi tayari umefanya:

1. Kupata kampuni zote ndani ya scope
2. Kupata mali zote zinazo milikiwa na kampuni (na kufanya baadhi ya vuln scan ikiwa iko ndani ya scope)
3. Kupata domains zote zinazomilikiwa na kampuni
4. Kupata subdomains zote za domains (je, kuna subdomain takeover?)
5. Kupata IPs zote (kutoka na **not from CDNs**) ndani ya scope.
6. Kupata web servers zote na kuchukua **screenshot** zao (kuna kitu chochote kisicho cha kawaida kinachostahili kuangaliwa kwa kina?)
7. Kupata potential public cloud assets zote zinazomilikiwa na kampuni.
8. **Emails**, **credentials leaks**, na **secret leaks** ambazo zinaweza kukupa ushindi mkubwa kwa urahisi.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Kuna zana kadhaa zitakazotekeleza sehemu ya hatua zilizopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
