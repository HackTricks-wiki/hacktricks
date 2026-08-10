# External Recon Methodology

## Ugunduzi wa Assets

> Kwa hiyo umeambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kujua kampuni hiyo inamiliki nini hasa.

Lengo la awamu hii ni kupata **makampuni yote yanayomilikiwa na kampuni kuu** na kisha **assets** zote za makampuni hayo. Ili kufanya hivyo, tutafanya yafuatayo:

1. Tafuta acquisitions za kampuni kuu; hii itatupatia makampuni yaliyo ndani ya scope.
2. Tafuta ASN (ikiwa ipo) ya kila kampuni; hii itatupatia IP ranges zinazomilikiwa na kila kampuni.
3. Tumia reverse whois lookups kutafuta entries nyingine (majina ya mashirika, domains...) zinazohusiana na ya kwanza (hili linaweza kufanywa recursively).
4. Tumia techniques nyingine kama Shodan `org` na `ssl` filters kutafuta assets nyingine (mbinu ya `ssl` inaweza kufanywa recursively).

### **Acquisitions**

Kwanza kabisa, tunahitaji kujua ni **makampuni gani mengine yanayomilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **kutafuta** **kampuni kuu**, na **kubofya** "**acquisitions**". Hapo utaona makampuni mengine yaliyonunuliwa na kampuni kuu.\
Chaguo lingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa makampuni ya umma, angalia **SEC/EDGAR filings**, kurasa za **investor relations**, au rejesta za ndani za makampuni (kwa mfano, **Companies House** nchini Uingereza).\
Kwa corporate trees na subsidiaries za kimataifa, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na database ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, kwa hatua hii unapaswa kujua makampuni yote yaliyo ndani ya scope. Hebu tujue jinsi ya kupata assets zao.

### **ASNs**

An autonomous system number (**ASN**) ni **namba ya kipekee** inayotolewa kwa **autonomous system** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
**AS** inajumuisha **blocks** za **IP addresses** ambazo zina policy iliyobainishwa kwa uwazi ya kufikia networks za nje na zinasimamiwa na organisation moja, lakini zinaweza kuundwa na waendeshaji kadhaa.

Inafaa kutafuta ikiwa **kampuni imepewa ASN yoyote** ili kupata **IP ranges** zake. Itakuwa muhimu kufanya **vulnerability test** dhidi ya **hosts** zote zilizo ndani ya **scope** na **kutafuta domains** ndani ya IP hizi.\
Unaweza **kutafuta** kwa **jina** la kampuni, kwa **IP** au kwa **domain** katika [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na eneo la kampuni, links hizi zinaweza kuwa muhimu kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Hata hivyo, huenda taarifa zote** muhimu **(IP ranges na Whois)** tayari zinaonekana katika link ya kwanza.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, enumeration ya [**BBOT**](https://github.com/blacklanternsecurity/bbot)**ya** hujumuisha na kutoa muhtasari wa ASNs kiotomatiki mwishoni mwa scan.
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
Unaweza kupata safu za IP za shirika pia kwa kutumia [http://asnlookup.com/](http://asnlookup.com) (ina free API).\
Unaweza kupata IP na ASN ya domain kwa kutumia [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta vulnerabilities**

Kwa wakati huu tunajua **assets zote zilizo ndani ya scope**, kwa hivyo ikiwa umeruhusiwa unaweza kuendesha **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) kwenye hosts zote.\
Pia, unaweza kuendesha baadhi ya [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia services kama** Shodan, Censys, au ZoomEye **ili kupata** ports zilizo wazi, **na kulingana na utakachopata unapaswa** kuangalia katika kitabu hiki jinsi ya kufanya pentest kwenye services mbalimbali zinazoweza kuwa zinaendeshwa.\
**Pia, inaweza kuwa muhimu kutaja kwamba unaweza pia kuandaa** lists za default username **na** passwords **na kujaribu kufanya** bruteforce kwenye services kwa kutumia [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua kampuni zote zilizo ndani ya scope pamoja na assets zake; ni wakati wa kutafuta domains zilizo ndani ya scope.

_Tafadhali, zingatia kwamba katika techniques zilizopendekezwa hapa chini unaweza pia kupata subdomains, na taarifa hiyo haipaswi kupuuzwa._

Kwanza kabisa unapaswa kutafuta **main domain**(s) za kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kwa kuwa umepata safu zote za IP za domains, unaweza kujaribu kufanya **reverse dns lookups** kwenye hizo **IPs ili kupata domains zaidi zilizo ndani ya scope**. Jaribu kutumia dns server ya victim au dns server inayojulikana (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Ili hii ifanye kazi, administrator lazima awezeshe PTR mwenyewe.\
Unaweza pia kutumia online tool kupata taarifa hii: [http://ptrarchive.com/](http://ptrarchive.com).\
Kwa ranges kubwa, tools kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) ni muhimu kwa ku-automate reverse lookups na uboreshaji.

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata **information** nyingi za kuvutia kama **jina la shirika**, **anwani**, **barua pepe**, nambari za simu... Lakini jambo la kuvutia zaidi ni kwamba unaweza kupata **assets zaidi zinazohusiana na kampuni** ukifanya **reverse whois lookups kwa kutumia field yoyote kati ya hizo** (kwa mfano whois registries nyingine ambako email hiyo hiyo inaonekana).\
Unaweza kutumia online tools kama:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bure** (Web na API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bure**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bure**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bure**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **bure**, API si bure.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Si bure
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Si bure (utafutaji **100 wa bure** pekee)
- [https://www.domainiq.com/](https://www.domainiq.com) - Si bure
- [https://securitytrails.com/](https://securitytrails.com/) - Si bure (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Si bure (API)

Unaweza ku-automate kazi hii kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji whoxy API key).\
Unaweza pia kufanya automatic reverse whois discovery kwa kutumia [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Kumbuka kwamba unaweza kutumia technique hii kugundua domain names zaidi kila unapopata domain mpya.**

### **Trackers**

Ukipata **ID ile ile ya tracker ile ile** kwenye pages 2 tofauti, unaweza kudhani kwamba **pages zote mbili** **zinasimamiwa na team ile ile**.\
Kwa mfano, ukiona **Google Analytics ID** ile ile au **Adsense ID** ile ile kwenye pages kadhaa.

Kuna pages na tools kadhaa zinazokuwezesha kutafuta kwa kutumia trackers hawa na wengine:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (hupata related sites kwa kutumia analytics/trackers zinazoshirikiwa)

### **Favicon**

Je, ulijua kwamba tunaweza kupata related domains na subdomains za target yetu kwa kutafuta favicon icon hash ile ile? Hivi ndivyo tool ya [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), iliyoundwa na [@m4ll0k2](https://twitter.com/m4ll0k2), inavyofanya kazi. Hivi ndivyo ya kuitumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Kwa ufupi, favihash itaturuhusu kugundua domains zilizo na favicon icon hash sawa na ya target yetu.

Tumia favicon hash inayojulikana kama pivot ya Shodan au FOFA ili kupata instances nyingine zilizo exposed za technology hiyo hiyo.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Hivi ndivyo unavyoweza **kuhesabu favicon hash** ya web (MMH3 juu ya bytes za favicon zilizo **encoded kwa base64**):
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
Unaweza pia kupata favicon hashes kwa kiwango kikubwa ukitumia [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) na kisha kufanya pivot katika Shodan/Censys.

Chukulia favicon fingerprints kama leads na uzithibitishe kwa kutumia signals zinazozizunguka.<sup>[[3]](#references)[[4]](#references)</sup>

- **Chukulia hash kama kiashiria, si uthibitisho**: MMH3 ni compact; collisions, icons zilizotumiwa tena, na spoofing ya makusudi vinawezekana.
- **Fanya probe kwenye zaidi ya** `/favicon.ico`: kagua framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs, na HTML `<link rel="icon">` tags.
- **Static assets zinaweza kubaki reachable nyuma ya vidhibiti vya WAF/SSO/IdP**: request icon moja kwa moja na kagua `ETag`, `Last-Modified`, redirects, na cache headers.
- **Thibitisha matches kwa kutumia signals zinazozizunguka**: linganisha title, HTML/body hash, headers, TLS certificate subjects/SANs, product components, na exposed ports.
- **Cluster kwa kutumia HTML/body hash**: template inayolingana kwa uthabiti huimarisha fingerprint; templates mchanganyiko huashiria icon generic au shared.
- **Chukulia hash inayoonekana katika signatures, ports, na products zisizohusiana kama honeypot au placeholder inayowezekana.**
- **Kwenye targets zisizo wazi, linganisha ukurasa halisi na path isiyokuwepo** kama `/_favicon_probe_<8-hex>`; hosting au parking responses zinazolingana zinaweza kueleza icon iliyoshirikiwa.
- **Anzisha triage kutoka Nuclei detection rules au public datasets** zinazohusisha favicon hashes na products pamoja na CPEs.
- **Kumbuka IP-centric coverage gap**: surfaces zilizo nyuma ya CDN, zinazoelekezwa kwa SNI, anycast, na domain-only zinaweza kukosekana katika datasets zinazofanana na Shodan.

### **Copyright / Uniq string**

Tafuta ndani ya web pages **strings ambazo zinaweza kushirikiwa na webs tofauti ndani ya organisation moja**. **Copyright string** inaweza kuwa mfano mzuri. Kisha tafuta string hiyo katika **google**, katika **browsers** nyingine au hata katika **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Ni kawaida kuwa na cron job kama hiyo yaliyo
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
ili kufanya upya certificates zote kwenye server kwa wakati mmoja. Kulinganisha timestamps za certificates au nafasi za certificate-transparency logs kunaweza kufichua domains zinazohusiana.<sup>[[6]](#references)</sup>

Pia tumia **certificate transparency** logs moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Taarifa za Mail DMARC

Unaweza kutumia website kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au tool kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) ili kupata **domains na subdomains zinazoshiriki taarifa sawa za dmarc**.\
Tools nyingine muhimu ni [**spoofcheck**](https://github.com/BishopFox/spoofcheck) na [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

A record iliyoachwa inaweza kufikika wakati cloud provider inapogawa upya IP. Utafiti uliorejelewa unaonyesha workflow ya opportunistic inayoprovide instance na kuoanisha address yake na passive DNS data; fanya majaribio ya takeover scenarios ndani ya scope iliyoidhinishwa pekee.<sup>[[7]](#references)</sup>

### **Njia nyingine**

**Shodan**

Kwa kuwa tayari unajua jina la organisation linalomiliki IP space. Unaweza kutafuta kwa kutumia data hiyo katika shodan: `org:"Tesla, Inc."` Kagua hosts zilizopatikana ili kutafuta domains mpya zisizotarajiwa katika TLS certificate.

Unaweza kufikia **TLS certificate** ya ukurasa mkuu wa web, kupata **jina la Organisation**, kisha kutafuta jina hilo ndani ya **TLS certificates** za kurasa zote za web zinazojulikana na **shodan** kwa filter hii: `ssl:"Tesla Motors"` au kutumia tool kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ni tool inayotafuta **domains zinazohusiana** na domain kuu pamoja na **subdomains** zake; ni nzuri sana.

**Passive DNS / Historical DNS**

Passive DNS data ni nzuri kwa kutafuta **records za zamani na zilizosahaulika** ambazo bado zinatatuliwa au zinaweza kuchukuliwa. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Kutafuta vulnerabilities**

Kagua baadhi ya [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Huenda kampuni fulani **inatumia domain fulani** lakini **imepoteza umiliki wake**. Isajili tu (ikiwa ni nafuu vya kutosha) na uijulishe kampuni.

Ukipata **domain yenye IP tofauti** na zile ambazo tayari ulipata katika asset discovery, unapaswa kufanya **basic vulnerability scan** (ukitumia Nessus au OpenVAS) na baadhi ya [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na services zinazoendesha, unaweza kupata katika **kitabu hiki mbinu kadhaa za "kuzishambulia"**.\
_Note kwamba wakati mwingine domain huwa hosted ndani ya IP ambayo haidhibitiwi na client, kwa hiyo haipo kwenye scope; kuwa mwangalifu._

## Subdomains

> Tunajua kampuni zote zilizo ndani ya scope, assets zote za kila kampuni na domains zote zinazohusiana na kampuni hizo.

Ni wakati wa kutafuta subdomains zote zinazowezekana za kila domain iliyopatikana.

> [!TIP]
> Kumbuka kwamba baadhi ya tools na techniques za kutafuta domains zinaweza pia kusaidia kutafuta subdomains

### **DNS**

Hebu tujaribu kupata **subdomains** kutoka kwenye records za **DNS**. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa kuna vulnerability, unapaswa kuripoti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Njia ya haraka zaidi ya kupata subdomains nyingi ni kutafuta katika vyanzo vya nje. **Zana** zinazotumika zaidi ni zifuatazo (kwa matokeo bora, sanidi API keys):

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
Kuna **tools/API nyingine za kuvutia** ambazo hata kama hazijawezeshwa mahsusi kutafuta subdomains, zinaweza kuwa na manufaa katika kutafuta subdomains, kama vile:

- [**IP.THC.ORG**](https://ip.thc.org) API ya bure
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Hutumia API [https://sonar.omnisint.io](https://sonar.omnisint.io) kupata subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC API ya bure**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** hukusanya URL zinazojulikana kutoka AlienVault's Open Threat Exchange, Wayback Machine, na Common Crawl kwa domain yoyote.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Huvinjari web kutafuta mafaili ya JS na kutoa subdomains kutoka humo.
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
- [**securitytrails.com**](https://securitytrails.com/) ina API ya bure ya kutafuta subdomains na historia ya IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Project hii inatoa **bila malipo subdomains zote zinazohusiana na bug-bounty programs**. Unaweza kufikia data hii pia ukitumia [chaospy](https://github.com/dr-0x0x/chaospy), au hata kufikia scope inayotumiwa na project hii kupitia [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **comparison** ya tools nyingi kati ya hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu tujaribu kupata **subdomains** mpya kwa kufanya brute-force kwenye DNS servers kwa kutumia majina yanayowezekana ya subdomains.

Kwa hatua hii utahitaji baadhi ya **common subdomains wordlists kama**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Pia utahitaji IPs za DNS resolvers nzuri. Ili kutengeneza list ya DNS resolvers zinazoaminika, unaweza kupakua resolvers kutoka [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzifilter. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Tools zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa tool ya kwanza iliyofanya DNS brute-force yenye ufanisi. Ni fast sana, hata hivyo ina uwezekano wa kutoa false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hii inaonekana kutumia resolver 1 pekee.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper ya `massdns`, iliyoandikwa kwa go, inayokuruhusu kuorodhesha subdomains halali kwa kutumia active bruteforce, na pia kutatua subdomains kwa kushughulikia wildcard pamoja na msaada rahisi wa input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Pia hutumia `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) hutumia asyncio kufanya brute force ya domain names kwa njia ya asynchronous.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Mzunguko wa Pili wa DNS Brute-Force

Baada ya kupata subdomains kwa kutumia open sources na brute-forcing, unaweza kutengeneza mabadiliko ya subdomains zilizopatikana ili kujaribu kupata zaidi. Tools kadhaa zinafaa kwa madhumuni haya:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Given the domains and subdomains generate permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Kwa kupewa domains na subdomains, tengeneza permutations.
- Unaweza kupata **wordlist** ya permutations za goaltdns [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Kwa kupewa domains na subdomains, huzalisha permutations. Ikiwa permutations file haijaainishwa, gotator itatumia file yake yenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kutengeneza permutations za subdomains, inaweza pia kujaribu kuzi-resolve (lakini ni bora kutumia tools zilizotajwa awali kwenye maoni).
- Unaweza kupata **wordlist** ya permutations za altdns [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya permutations, mutations na alteration za subdomains. Zana hii itafanya brute force ya matokeo (haitumii dns wild card).
- Unaweza kupata dmut permutations wordlist [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kulingana na domain, **huzalisha majina mapya yanayowezekana ya subdomain** kwa kutumia patterns zilizoonyeshwa ili kujaribu kugundua subdomain zaidi.

#### Uzalishaji mahiri wa permutations

- [**regulator**](https://github.com/cramppet/regulator): Hujifunza patterns zinazofanana na regex kutoka kwa subdomain zilizogunduliwa na huzalisha majina ya wagombea kwa ajili ya kuyathibitisha.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni subdomain brute-force fuzzer inayoambatanishwa na algorithm rahisi sana lakini yenye ufanisi, inayoongozwa na DNS response. Inatumia seti iliyotolewa ya input data, kama wordlist iliyoundwa mahsusi au historical DNS/TLS records, ili kuunda kwa usahihi domain names zaidi zinazolingana na kuzipanua zaidi kwenye loop kwa msingi wa taarifa iliyokusanywa wakati wa DNS scan.
```
echo www | subzuf facebook.com
```
### **Workflow ya Ugunduzi wa Subdomain**

Mifano ya workflow ya Trickest inachanganya OSINT, DNS brute force, na hatua za permutation kwa ajili ya enumeration ya subdomain inayoweza kurudiwa.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ukipata anwani ya IP yenye **ukurasa mmoja au kadhaa wa wavuti** unaomilikiwa na subdomains, unaweza kujaribu **kutafuta subdomains nyingine zenye tovuti katika IP hiyo** kwa kutafuta **vyanzo vya OSINT** vya domains zilizo katika IP, au kwa **kufanya brute force ya majina ya VHost katika IP hiyo**.

#### OSINT

Unaweza kupata baadhi ya **VHosts katika IPs kwa kutumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs nyingine**.

**Brute Force**

Ikiwa unashuku kuwa subdomain fulani inaweza kuwa imefichwa kwenye web server, unaweza kujaribu kufanya brute force:

Kwa vhosts zinazotegemea jina, fuzz `Host` header na utumie auto-calibration ya ffuf kuchuja jibu chaguomsingi.<sup>[[2]](#references)</sup>
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
> Kwa mbinu hii unaweza hata kuweza kufikia endpoints za ndani/ zilizofichwa.

### **CORS Brute Force**

Wakati mwingine utapata kurasa ambazo hurejesha tu kichwa _**Access-Control-Allow-Origin**_ wakati domain/subdomain halali imewekwa kwenye kichwa _**Origin**_. Katika hali hizi, unaweza kutumia vibaya tabia hii **kugundua** **subdomains** mpya.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Unapotafuta **subdomains**, zingatia kuona ikiwa **inaelekeza** kwenye aina yoyote ya **bucket**, na katika hali hiyo [**kagua ruhusa**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa wakati huu utakuwa unajua domains zote zilizo ndani ya scope, jaribu [**kubashiri kwa nguvu majina yanayowezekana ya buckets na kukagua ruhusa**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Ufuatiliaji**

Unaweza **kufuatilia** ikiwa **subdomains mpya** za domain zinaundwa kwa kufuatilia Logs za **Certificate Transparency**, kama inavyofanywa na [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Kutafuta udhaifu**

Kagua uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inaelekeza kwenye **S3 bucket**, [**kagua ruhusa**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ukipata **subdomain yenye IP tofauti** na zile ulizopata tayari wakati wa ugunduzi wa assets, unapaswa kufanya **basic vulnerability scan** (kwa kutumia Nessus au OpenVAS) na [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na services zinazoendesha, unaweza kupata **mbinu kadhaa za "kuzishambulia" katika kitabu hiki**.\
_​​Kumbuka kuwa wakati mwingine subdomain hu-hostiwa ndani ya IP isiyodhibitiwa na client, kwa hiyo haipo kwenye scope; kuwa mwangalifu._

## IPs

Katika hatua za awali huenda **ulipata baadhi ya IP ranges, domains na subdomains**.\
Ni wakati wa **kukusanya IPs zote kutoka kwenye ranges hizo** na kwa **domains/subdomains (DNS queries).**

Kwa kutumia services kutoka kwenye **free apis** zifuatazo, unaweza pia kupata **IPs za awali zilizotumiwa na domains na subdomains**. Huenda IPs hizi bado zinamilikiwa na client (na zinaweza kukuwezesha kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kukagua domains zinazoelekeza kwenye IP address maalum kwa kutumia tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Kutafuta udhaifu**

**Fanya port scan kwenye IPs zote ambazo si za CDNs** (kwa kuwa kuna uwezekano mkubwa hutapata chochote cha kuvutia humo). Kwenye services zinazoendesha ulizogundua, huenda **ukaweza kupata udhaifu**.

**Pata** [**mwongozo**](../pentesting-network/index.html) **kuhusu jinsi ya kuscan hosts.**

## Utafutaji wa web servers

> Tumepata kampuni zote na assets zake, na tunajua IP ranges, domains na subdomains zilizo ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizotangulia huenda tayari **ulifanya recon ya IPs na domains ulizogundua**, kwa hiyo huenda **umeshapata web servers zote zinazowezekana**. Hata hivyo, ikiwa hujafanya hivyo, sasa tutaangalia baadhi ya **mbinu za haraka za kutafuta web servers** ndani ya scope.

Tafadhali, zingatia kuwa hii **inalenga ugunduzi wa web apps**, kwa hiyo unapaswa pia **kufanya vulnerability** na **port scanning** (**ikiwa imeruhusiwa** na scope).

**Njia ya haraka** ya kugundua **ports zilizo wazi** zinazohusiana na web servers kwa kutumia [**masscan** inaweza kupatikana hapa](../pentesting-network/index.html#http-port-discovery).\
Tool nyingine rafiki ya kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unapitisha orodha ya domains nayo itajaribu kuunganisha kwenye port 80 (http) na 443 (https). Pia, unaweza kuielekeza ijaribu ports nyingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Picha za skrini**

Sasa kwa kuwa umegundua **web servers zote** zilizopo kwenye scope (miongoni mwa **IPs** za kampuni na **domains** na **subdomains** zote), huenda **hujui pa kuanzia**. Kwa hiyo, tufanye iwe rahisi na tuanze kwa kupiga picha za skrini za zote. Kwa **kutazama tu** **ukurasa mkuu**, unaweza kupata endpoints **zisizo za kawaida** ambazo zina uwezekano mkubwa wa kuwa **vulnerable**.

Ili kutekeleza wazo hili unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kupitia **screenshots** zote ili kukuambia **ni zipi huenda zina vulnerabilities**, na zipi hazina.

## Public Cloud Assets

Ili kupata cloud assets zinazoweza kuwa za kampuni, unapaswa **kuanza na orodha ya maneno muhimu yanayoitambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Pia utahitaji wordlists za **maneno yanayotumika kwa kawaida kwenye buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa kutumia maneno hayo unapaswa kutengeneza **permutations** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa wordlists utakazopata unaweza kutumia tools kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta Cloud Assets unapaswa **kutafuta zaidi ya buckets za AWS pekee**.

### **Kutafuta vulnerabilities**

Ukipata vitu kama **buckets zilizo wazi au cloud functions zilizo exposed**, unapaswa **kuzifikia** na kujaribu kuona zinakupa nini na kama unaweza kuzitumia vibaya.

## Emails

Kwa **domains** na **subdomains** zilizo ndani ya scope, kimsingi una kila kitu **unachohitaji kuanza kutafuta emails**. Hizi ndizo **APIs** na **tools** zilizonifanyia kazi vizuri zaidi katika kupata emails za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - ikiwa na APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (free version)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API ya [**https://minelead.io/**](https://minelead.io/) (free version)

### **Kutafuta vulnerabilities**

Emails zitakuwa na manufaa baadaye kwa **brute-force web logins na auth services** (kama SSH). Pia zinahitajika kwa **phishings**. Zaidi ya hayo, APIs hizi zitakupa **taarifa zaidi kuhusu mtu** aliye nyuma ya email, jambo linalofaa kwa phishing campaign.

## Credential Leaks

Kwa kutumia **domains,** **subdomains**, na **emails**, unaweza kuanza kutafuta credentials zilizoleak hapo awali zinazohusiana na emails hizo:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta vulnerabilities**

Ukipata credentials **halali zilizoleak**, hii ni ushindi rahisi sana.

## Secrets Leaks

Credential leaks zinahusiana na hacks za kampuni ambapo **taarifa nyeti zilileak na kuuzwa**. Hata hivyo, kampuni zinaweza kuathiriwa na **leaks nyingine** ambazo taarifa zake hazipo kwenye databases hizo:

### Github Leaks

Credentials na APIs zinaweza kuwa zimeleak kwenye **public repositories** za **kampuni** au za **users** wanaofanya kazi katika kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) ili **kupakua** **public repos** zote za **organization** na za **developers** wake, kisha kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yake moja kwa moja.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **text** yote inayotolewa na **URLs zilizopitishwa** kwake, kwa sababu wakati mwingine **web pages pia huwa na secrets**.

#### Github Dorks

Angalia [GitHub dorks and leaks page](github-leaked-secrets.md) kwa **GitHub dorks** zinazoweza kutumika kutafuta kwenye organization.

### Pastes Leaks

Wakati mwingine attackers au workers watachapisha **maudhui ya kampuni kwenye paste site**. Hii inaweza kuwa na au isiwe na **taarifa nyeti**, lakini inafaa sana kuitafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta kwenye zaidi ya paste sites 80 kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini zenye manufaa daima husaidia kupata **taarifa iliyo exposed ambayo haikupaswa kuwa hapo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina queries **elfu kadhaa** zinazowezekana, ambazo huwezi kuziendesha mwenyewe. Kwa hiyo, unaweza kuchagua 10 unazozipenda au kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuzitekeleza zote**.

_Note kwamba tools zinazotarajiwa kuendesha database yote kwa kutumia Google browser ya kawaida hazitamaliza kamwe, kwa sababu google itakuzuia mapema sana._

### **Kutafuta vulnerabilities**

Ukipata credentials au API tokens **halali zilizoleak**, hii ni ushindi rahisi sana.

## Public Code Vulnerabilities

Ukigundua kwamba kampuni ina **open-source code**, unaweza **kuichanganua** na kutafuta **vulnerabilities** ndani yake.

**Kulingana na language**, kuna **tools** mbalimbali unazoweza kutumia; angalia orodha ya [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Pia kuna services za bure zinazokuruhusu **kuscan public repositories**, kama vile:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Vulnerabilities nyingi** zinazopatikana na bug hunters ziko ndani ya **web applications**, kwa hiyo katika hatua hii ningependa kuzungumzia **web application testing methodology**, na unaweza [**kupata taarifa hii hapa**](../../network-services-pentesting/pentesting-web/index.html).

Pia nataka kutaja kwa namna ya pekee sehemu ya [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwa sababu, ingawa hupaswi kutarajia zipate vulnerabilities nyeti sana, zinafaa kutumika kwenye **workflows ili kupata taarifa za awali za web.**

## Recapitulation

> Hongera! Katika hatua hii tayari umefanya **basic enumeration** yote. Ndiyo, ni basic kwa sababu enumeration nyingi zaidi zinaweza kufanywa (tutaona tricks zaidi baadaye).

Kwa hiyo tayari ume:

1. Kupata **companies** zote zilizo ndani ya scope
2. Kupata **assets** zote za companies (na kufanya vuln scan ikiwa iko ndani ya scope)
3. Kupata **domains** zote za companies
4. Kupata **subdomains** zote za domains (subdomain takeover yoyote?)
5. Kupata **IPs** zote (kutoka na **zisizotoka kwenye CDNs**) zilizo ndani ya scope.
6. Kupata **web servers** zote na kupiga **screenshot** zao (kuna kitu kisicho cha kawaida kinachostahili kuangaliwa kwa kina?)
7. Kupata **public cloud assets** zote zinazoweza kuwa za kampuni.
8. **Emails**, **credential leaks**, na **secret leaks** zinazoweza kukupatia **ushindi mkubwa kwa urahisi sana**.
9. **Kufanya pentesting kwenye webs zote ulizopata**

## **Full Recon Automatic Tools**

Kuna tools kadhaa zinazoweza kutekeleza baadhi ya vitendo vilivyopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ni ya zamani kidogo na haijasasishwa

## References

- [1] [Jason Haddix – Methodology ya Bug Hunter v4.0: Toleo la Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Kuhusu Favicons: Kutoka Browser Icons hadi Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Kutumia favicon.ico kama weapon kwa BugBounties, OSINT na mambo mengine](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Kugundua Domains kupitia Time-Correlation Attack kwenye Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Kugundua (na Kuiga) Campaign Ghali ya Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Mbinu ya Kipekee ya Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Sehemu ya 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Sehemu ya 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
{{#include ../../banners/hacktricks-training.md}}
