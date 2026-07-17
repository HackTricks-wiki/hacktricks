# Methodology ya External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ugunduzi wa Assets

> Kwa hiyo umeambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kubaini ni vitu gani hasa kampuni hii inamiliki.

Lengo la awamu hii ni kupata **kampuni zote zinazomilikiwa na kampuni kuu** na kisha **assets** zote za kampuni hizo. Ili kufanya hivyo, tutafanya yafuatayo:

1. Tafuta acquisitions za kampuni kuu; hii itatupatia kampuni zilizo ndani ya scope.
2. Tafuta ASN ya kila kampuni (ikiwa ipo); hii itatupatia IP ranges zinazomilikiwa na kila kampuni.
3. Tumia reverse whois lookups kutafuta entries nyingine (majina ya mashirika, domains...) zinazohusiana na ya kwanza (hili linaweza kufanywa recursively).
4. Tumia mbinu nyingine kama filters za shodan `org` na `ssl` kutafuta assets nyingine (mbinu ya `ssl` inaweza kufanywa recursively).

### **Acquisitions**

Kwanza kabisa, tunahitaji kujua ni **kampuni gani nyingine zinazomilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **tafuta** **kampuni kuu**, kisha **bofya** kwenye "**acquisitions**". Hapo utaona kampuni nyingine zilizonunuliwa na kampuni kuu.\
Chaguo jingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, kagua **SEC/EDGAR filings**, kurasa za **investor relations**, au sajili za mashirika za eneo husika (kwa mfano, **Companies House** nchini UK).\
Kwa corporate trees za kimataifa na subsidiaries, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na database ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, katika hatua hii unapaswa kuwa unajua kampuni zote zilizo ndani ya scope. Hebu tubaini jinsi ya kupata assets zao.

### **ASNs**

An autonomous system number (**ASN**) ni **namba ya kipekee** inayotolewa kwa **autonomous system** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
An **AS** inajumuisha **blocks** za **IP addresses** zilizo na sera iliyobainishwa wazi ya kufikia networks za nje, na zinazodhibitiwa na shirika moja, lakini zinaweza kuundwa na operators kadhaa.

Inafaa kubaini ikiwa **kampuni imepewa ASN** yoyote ili kupata **IP ranges zake.** Itakuwa muhimu kufanya **vulnerability test** dhidi ya **hosts** zote zilizo ndani ya **scope** na **kutafuta domains** ndani ya IP hizi.\
Unaweza **kutafuta** kwa kutumia **jina** la kampuni, **IP** au **domain** kwenye [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na eneo la kampuni, links hizi zinaweza kusaidia kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Hata hivyo, pengine taarifa zote muhimu** (IP ranges na Whois) **tayari zinaonekana katika link ya kwanza.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, enumeration ya [**BBOT**](https://github.com/blacklanternsecurity/bbot) hukusanya na kufanya muhtasari wa ASNs kiotomatiki mwishoni mwa scan.
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
Unaweza kupata safu za IP za shirika pia kwa kutumia [http://asnlookup.com/](http://asnlookup.com) (ina API ya bure).\
Unaweza kupata IP na ASN ya domain kwa kutumia [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta vulnerabilities**

Kwa hatua hii tunajua **assets zote zilizo ndani ya scope**, kwa hivyo ikiwa umeidhinishwa unaweza kuendesha **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) kwenye hosts zote.\
Pia, unaweza kuendesha baadhi ya [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia services kama** Shodan, Censys, au ZoomEye **ili kupata** ports zilizo wazi **na kulingana na utakachopata unapaswa** kuangalia katika kitabu hiki jinsi ya kufanya pentest ya services mbalimbali zinazoweza kuwa zinaendesha.\
**Pia, inaweza kuwa muhimu kutaja kwamba unaweza pia kuandaa** lists za default username **na** passwords **na kujaribu kufanya** bruteforce ya services kwa [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua companies zote zilizo ndani ya scope na assets zao, sasa ni wakati wa kutafuta domains zilizo ndani ya scope.

_Tafadhali, kumbuka kwamba katika techniques zilizopendekezwa hapa chini unaweza pia kupata subdomains na taarifa hiyo haipaswi kupuuzwa._

Kwanza kabisa unapaswa kutafuta **main domain**(s) za kila company. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kwa kuwa umepata IP ranges zote za domains, unaweza kujaribu kufanya **reverse dns lookups** kwenye **IPs hizo ili kupata domains zaidi zilizo ndani ya scope**. Jaribu kutumia dns server ya victim au dns server inayojulikana (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Ili hii ifanye kazi, administrator lazima awashe PTR manually.\
Unaweza pia kutumia online tool kwa maelezo haya: [http://ptrarchive.com/](http://ptrarchive.com).\
Kwa ranges kubwa, tools kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) ni muhimu kwa ku-automate reverse lookups na enrichment.

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata **information** nyingi za kuvutia kama **jina la organisation**, **anwani**, **barua pepe**, nambari za simu... Lakini jambo la kuvutia zaidi ni kwamba unaweza kupata **assets zaidi zinazohusiana na kampuni** ikiwa utafanya **reverse whois lookups kwa kutumia mojawapo ya fields hizo** (kwa mfano whois registries nyingine ambapo email hiyo hiyo inaonekana).\
Unaweza kutumia online tools kama:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bure** (Web na API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bure**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bure**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bure**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **bure**, API si bure.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Si bure
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Si Bure (searches **100 za bure** pekee)
- [https://www.domainiq.com/](https://www.domainiq.com) - Si Bure
- [https://securitytrails.com/](https://securitytrails.com/) - Si bure (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Si bure (API)

Unaweza ku-automate kazi hii kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji whoxy API key).\
Unaweza pia kufanya automatic reverse whois discovery kwa kutumia [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Kumbuka kwamba unaweza kutumia technique hii kugundua domain names zaidi kila unapopata domain mpya.**

### **Trackers**

Ukipata **ID ileile ya tracker ileile** kwenye pages 2 tofauti, unaweza kudhani kwamba **pages zote mbili** **zinasimamiwa na team ileile**.\
Kwa mfano, ukiona **Google Analytics ID** ileile au **Adsense ID** ileile kwenye pages kadhaa.

Kuna pages na tools kadhaa zinazokuruhusu kutafuta kwa kutumia trackers hawa na wengine:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (inatafuta sites zinazohusiana kwa kutumia analytics/trackers zinazoshirikiwa)

### **Favicon**

Je, ulijua kwamba tunaweza kupata domains na subdomains zinazohusiana na target yetu kwa kutafuta favicon icon hash ileile? Hivi ndivyo hasa tool ya [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), iliyotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2), inavyofanya kazi. Hivi ndivyo ya kuitumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - gundua domains zilizo na favicon icon hash sawa](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa ufupi, favihash itaturuhusu kugundua domains zilizo na favicon icon hash sawa na target yetu.

Zaidi ya hayo, unaweza pia kutafuta technologies ukitumia favicon hash kama ilivyoelezwa katika [**chapisho hili la blogu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hii inamaanisha kwamba ikiwa unajua **hash ya favicon ya version yenye udhaifu ya web tech** unaweza kutafuta katika shodan na **kupata maeneo mengine yenye udhaifu**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Hivi ndivyo unavyoweza **kukokotoa favicon hash** ya tovuti (MMH3 juu ya baiti za favicon zilizowekwa kwenye **base64**):
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

Mambo muhimu ya kukumbuka unapotumia favicon fingerprints:

- **Chukulia hash kama kiashiria, si uthibitisho**: MMH3 ni compact na collisions zinawezekana; operators wanaweza pia kubadilisha favicons au kutumia tena icon inayopotosha kwa makusudi.
- **Probe zaidi ya** `/favicon.ico`: bidhaa nyingi huweka icons katika framework/build paths au kupitia `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URLs, au HTML `<link rel="icon">` tags. Path yenyewe inaweza kutumika kufingerprint product family.
- **Static files mara nyingi hupatikana app isipopatikana**: WAF/SSO/IdP controls zinaweza kulinda dynamic routes lakini bado zikaacha static icons wazi. Kila mara request favicon moja kwa moja na kagua `ETag`, `Last-Modified`, redirects na cache headers kwa vidokezo dhaifu vya version/build.
- **Thibitisha matches kwa signals zinazozunguka**: linganisha title, HTML/body hash, headers, TLS certificate subjects/SANs, Shodan/Censys components, na exposed ports kabla ya kuhitimisha kuwa favicon inatambulisha product.
- **Cluster kwa HTML/body hash unapofanya pivot kwa kiwango kikubwa**: ikiwa hosts wengi wanaoshiriki favicon moja wanaishia kwenye page template moja, fingerprint huwa na nguvu zaidi; ikiwa hash hiyo hiyo inagawanyika katika templates nyingi zisizohusiana, pendelea "generic/shared/honeypot" badala ya product label.
- **Honeypot heuristic**: ikiwa favicon hash hiyo hiyo inaonekana katika HTML signatures nyingi zisizohusiana, random ports, na products zinazokinzana, ichukulie kuwa huenda ni honeypot au generic placeholder badala ya product fingerprint halisi.
- **Tumia 404 probe kwenye targets zisizo wazi**: fetch ukurasa halisi na path isiyokuwepo kama `/_favicon_probe_<8-hex>` katika browser. Matching hosting-provider/parking responses mara nyingi hueleza shared favicons vizuri zaidi kuliko product overlap halisi.
- **Anzisha mappings kutoka detection rules**: Nuclei templates na public favicon datasets zinaweza kutoa mappings zinazojulikana za `favicon` ↔ `product` ↔ `CPE`, ambazo ni muhimu kwa rapid triage baada ya CVE disclosures.
- **Tahadhari kuhusu coverage**: Shodan-style datasets zinalenga IP. CDN-fronted, SNI-routed, anycast, na domain-only surfaces zinaweza kuhesabiwa kwa kiwango cha chini, hivyo hit count ndogo **haimaanishi** deployment ndogo katika ulimwengu halisi.

### **Copyright / Uniq string**

Tafuta ndani ya web pages **strings zinazoweza kushirikiwa na webs tofauti ndani ya organisation moja**. **Copyright string** inaweza kuwa mfano mzuri. Kisha tafuta string hiyo katika **google**, katika **browsers** nyingine au hata katika **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Ni kawaida kuwa na cron job kama vile
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
ili kusasisha vyeti vyote vya domains kwenye server. Hii inamaanisha kwamba hata kama CA iliyotumika kwa hili haiweki muda ilipotengenezwa ndani ya Validity time, inawezekana **kupata domains zinazomilikiwa na kampuni hiyo hiyo kwenye certificate transparency logs**.\
Angalia [**writeup hii kwa maelezo zaidi**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Pia tumia **certificate transparency** logs moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Taarifa za Mail DMARC

Unaweza kutumia tovuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au tool kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) ili kupata **domains na subdomains zinazotumia taarifa sawa za dmarc**.\
Tools nyingine muhimu ni [**spoofcheck**](https://github.com/BishopFox/spoofcheck) na [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Inaonekana ni jambo la kawaida kwa watu kuassign subdomains kwenye IPs zinazomilikiwa na cloud providers na wakati fulani **kupoteza hiyo IP address lakini kusahau kuondoa DNS record**. Kwa hiyo, kwa **ku-spawn VM** kwenye cloud (kama Digital Ocean), kwa hakika utakuwa **umechukua udhibiti wa subdomain(s) fulani**.

[**Post hii**](https://kmsec.uk/blog/passive-takeover/) inaeleza kisa kuhusu hilo na inapendekeza script ambayo **ina-spawn VM kwenye DigitalOcean**, **inapata** **IPv4** ya machine mpya, na **inatafuta kwenye Virustotal domain records** zinazoelekeza kwake.

### **Njia nyingine**

**Kumbuka kwamba unaweza kutumia technique hii kugundua majina zaidi ya domains kila unapopata domain mpya.**

**Shodan**

Kama unavyojua tayari jina la organisation inayomiliki IP space. Unaweza kutafuta kwa kutumia data hiyo kwenye shodan kwa kutumia: `org:"Tesla, Inc."` Kagua hosts zilizopatikana ili kuona domains mpya zisizotarajiwa ndani ya TLS certificate.

Unaweza kufikia **TLS certificate** ya ukurasa mkuu wa web, kupata **Organisation name**, kisha kutafuta jina hilo ndani ya **TLS certificates** za kurasa zote za web zinazojulikana na **shodan** kwa kutumia filter: `ssl:"Tesla Motors"` au kutumia tool kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ni tool inayotafuta **domains zinazohusiana** na domain kuu pamoja na **subdomains** zake, ni nzuri sana.

**Passive DNS / Historical DNS**

Passive DNS data ni nzuri sana kwa kupata **records za zamani na zilizosahaulika** ambazo bado zinatoa majibu au zinaweza kuchukuliwa. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Kutafuta vulnerabilities**

Kagua [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Huenda kampuni fulani **inatumia domain fulani** lakini **imepoteza umiliki wake**. Isajili tu (ikiwa ni nafuu vya kutosha) na uijulishe kampuni.

Ukipata **domain yenye IP iliyo tofauti** na zile ulizopata tayari wakati wa assets discovery, unapaswa kufanya **basic vulnerability scan** (kwa kutumia Nessus au OpenVAS) na [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa **nmap/masscan/shodan**. Kulingana na services zinazoendesha, unaweza kupata kwenye **kitabu hiki tricks kadhaa za "kuzi-attack"**.\
_Note kwamba wakati mwingine domain inahostishwa ndani ya IP isiyodhibitiwa na client, kwa hiyo haiko kwenye scope; kuwa mwangalifu._

## Subdomains

> Tunajua kampuni zote zilizo ndani ya scope, assets zote za kila kampuni na domains zote zinazohusiana na kampuni hizo.

Ni wakati wa kupata subdomains zote zinazowezekana za kila domain iliyopatikana.

> [!TIP]
> Kumbuka kwamba baadhi ya tools na techniques za kutafuta domains zinaweza pia kusaidia kupata subdomains

### **DNS**

Tujaribu kupata **subdomains** kutoka kwenye records za **DNS**. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa iko vulnerable, unapaswa kuripoti hilo).
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
Kuna **tools/APIs nyingine za kuvutia** ambazo hata kama hazijabobea moja kwa moja katika kutafuta subdomains zinaweza kusaidia kupata subdomains, kama vile:

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
- [**API ya bure ya JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** hupata URL zinazojulikana kutoka AlienVault's Open Threat Exchange, Wayback Machine, na Common Crawl kwa domain yoyote iliyotolewa.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Huvinjari wavuti kutafuta faili za JS na kutoa subdomains kutoka humo.
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

Project hii inatoa **bila malipo subdomains zote zinazohusiana na bug-bounty programs**. Unaweza pia kufikia data hii kwa kutumia [chaospy](https://github.com/dr-0x0x/chaospy) au hata kufikia scope inayotumiwa na project hii kupitia [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **comparison** ya nyingi kati ya tools hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu tujaribu kutafuta **subdomains** mpya kwa kufanya brute-force dhidi ya DNS servers tukitumia majina yanayowezekana ya subdomains.

Kwa kitendo hiki utahitaji baadhi ya **common subdomains wordlists kama**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Pia utahitaji IPs za DNS resolvers nzuri. Ili kutengeneza list ya DNS resolvers zinazoaminika, unaweza kupakua resolvers kutoka [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzichuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Tools zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa tool ya kwanza iliyofanya DNS brute-force kwa ufanisi. Ni ya haraka sana, hata hivyo ina uwezekano wa kutoa false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hii, nadhani inatumia resolver 1 tu
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper ya `massdns`, iliyoandikwa kwa go, inayokuruhusu ku-enumerate subdomains halali kwa kutumia active bruteforce, pamoja na ku-resolve subdomains kwa kushughulikia wildcard na kuwezesha input-output kwa urahisi.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Pia hutumia `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) hutumia asyncio kubashiri kwa nguvu majina ya domain kwa njia ya asynchronous.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Raundi ya Pili ya DNS Brute-Force

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na brute-forcing, unaweza kutengeneza marekebisho ya subdomains zilizopatikana ili kujaribu kupata nyingine zaidi. Zana kadhaa ni muhimu kwa madhumuni haya:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Kwa kupewa domains na subdomains, hutengeneza permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Kwa kupewa domains na subdomains, tengeneza permutations.
- Unaweza kupata **wordlist** ya permutations za goaltdns [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Ikipewa domains na subdomains, hutengeneza permutations. Ikiwa faili la permutations halijaainishwa, gotator itatumia faili lake yenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kutengeneza permutations za subdomains, inaweza pia kujaribu kuzitatua (lakini ni bora kutumia tools zilizotajwa kwenye maoni hapo awali).
- Unaweza kupata **wordlist** ya permutations za altdns [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya permutations, mutations na alteration za subdomains. Zana hii itafanya brute force ya matokeo (hai-support dns wild card).
- Unaweza kupata permutations wordlist ya dmut [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kulingana na domain, **hutengeneza majina mapya yanayowezekana ya subdomains** kwa kutumia patterns zilizoonyeshwa ili kujaribu kugundua subdomains zaidi.

#### Utengenezaji wa smart permutations

- [**regulator**](https://github.com/cramppet/regulator): Kwa maelezo zaidi soma [**chapisho hili**](https://cramppet.github.io/regulator/index.html), lakini kimsingi itachukua **sehemu kuu** kutoka kwenye **subdomains zilizogunduliwa** na kuzichanganya ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni subdomain brute-force fuzzer inayotumia DNS response-guided algorithm rahisi sana lakini yenye ufanisi. Hutumia seti ya data ya ingizo iliyotolewa, kama wordlist maalum au historical DNS/TLS records, ili kutengeneza kwa usahihi domain names nyingine zinazohusiana na kuzipanua zaidi kwa mzunguko, kwa kuzingatia taarifa zilizokusanywa wakati wa DNS scan.
```
echo www | subzuf facebook.com
```
### **Workflow ya Ugunduzi wa Subdomain**

Angalia chapisho hili la blogu nililoandika kuhusu jinsi ya **ku-automate ugunduzi wa subdomain** kutoka kwenye domain kwa kutumia **Trickest workflows**, ili nisiwe na haja ya kuanzisha manually tools nyingi kwenye computer yangu:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ukipata IP address iliyo na **web pages moja au kadhaa** zinazohusiana na subdomains, unaweza kujaribu **kutafuta subdomains nyingine zilizo na webs kwenye IP hiyo** kwa kutafuta katika **OSINT sources** domains zilizo kwenye IP, au kwa **brute-forcing majina ya VHost domain kwenye IP hiyo**.

#### OSINT

Unaweza kupata baadhi ya **VHosts kwenye IPs kwa kutumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs nyingine**.

**Brute Force**

Ikiwa unashuku kuwa subdomain fulani inaweza kuwa imefichwa kwenye web server, unaweza kujaribu kui-brute force:

Wakati **IP ina-redirect kwenda kwenye hostname** (name-based vhosts), fuzz `Host` header moja kwa moja na uiruhusu ffuf **ijifanyie auto-calibrate** ili kuangazia responses zinazotofautiana na default vhost:
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
> Kwa kutumia technique hii unaweza hata kuweza kufikia internal/hidden endpoints.

### **CORS Brute Force**

Wakati mwingine utapata pages zinazorudisha header _**Access-Control-Allow-Origin**_ tu wakati domain/subdomain halali imewekwa kwenye header ya _**Origin**_. Katika hali hizi, unaweza kutumia vibaya tabia hii ili **kugundua** **subdomains** mpya.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Unapotafuta **subdomains**, zingatia kuona kama **inaelekeza** kwenye aina yoyote ya **bucket**, na ikiwa hivyo [**kagua permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa katika hatua hii utakuwa unajua domains zote zilizo ndani ya scope, jaribu [**kubashiri kwa brute force majina yanayowezekana ya buckets na ukague permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Unaweza **kufuatilia** kama **subdomains mpya** za domain zinaundwa kwa kufuatilia Logs za **Certificate Transparency**, kama inavyofanywa na [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Kutafuta vulnerabilities**

Kagua uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inaelekeza kwenye **S3 bucket**, [**kagua permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ukipata **subdomain yenye IP iliyo tofauti** na zile ulizokwisha kupata kwenye assets discovery, unapaswa kufanya **basic vulnerability scan** (kwa kutumia Nessus au OpenVAS) na baadhi ya [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na services zinazoendesha, unaweza kupata **tricks za "kuzishambulia" kwenye kitabu hiki**.\
_Note kwamba wakati mwingine subdomain inahostishwa ndani ya IP ambayo haidhibitiwi na client, hivyo haipo kwenye scope; kuwa mwangalifu._

## IPs

Katika hatua za mwanzo huenda **umepata IP ranges, domains na subdomains**.\
Ni wakati wa **kukusanya IPs zote kutoka kwenye ranges hizo** na kwa **domains/subdomains (DNS queries).**

Kwa kutumia services kutoka kwenye **free APIs** zifuatazo, unaweza pia kupata **IPs zilizotumiwa hapo awali na domains na subdomains**. IPs hizi huenda bado zinamilikiwa na client (na huenda zikakuruhusu kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kukagua domains zinazoelekeza kwenye IP address maalum kwa kutumia tool ya [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Kutafuta vulnerabilities**

**Fanya port scan kwenye IPs zote ambazo si za CDNs** (kwa kuwa kuna uwezekano mkubwa hutapata chochote cha kuvutia humo). Kwenye services zinazoendesha ambazo zimegunduliwa, huenda **ukaweza kupata vulnerabilities**.

**Pata** [**mwongozo**](../pentesting-network/index.html) **kuhusu jinsi ya kuscan hosts.**

## Uwindaji wa Web servers

> Tumepata kampuni zote na assets zao, na tunajua IP ranges, domains na subdomains zilizo ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizotangulia huenda tayari **ulifanya recon ya IPs na domains zilizogunduliwa**, hivyo huenda **umeshapata web servers zote zinazowezekana**. Hata hivyo, ikiwa bado hujafanya hivyo, sasa tutaona baadhi ya **tricks za haraka za kutafuta web servers** ndani ya scope.

Tafadhali zingatia kuwa hii **itaelekezwa kwenye ugunduzi wa web apps**, kwa hiyo unapaswa pia **kufanya vulnerability** na **port scanning** (**ikiwa inaruhusiwa** na scope).

Njia **ya haraka** ya kugundua **ports open** zinazohusiana na **web** servers kwa kutumia [**masscan inaweza kupatikana hapa**](../pentesting-network/index.html#http-port-discovery).\
Tool nyingine rafiki ya kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unapitisha tu orodha ya domains, nayo itajaribu kuunganisha kwenye port 80 (http) na 443 (https). Zaidi ya hayo, unaweza kuielekeza ijARibu ports nyingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sasa kwa kuwa umegundua **web servers zote** zilizopo kwenye scope (miongoni mwa **IPs** za kampuni na **domains** na **subdomains** zote), huenda **hujui pa kuanzia**. Kwa hiyo, tufanye iwe rahisi na tuanze kwa kuchukua screenshots za zote. Kwa **kuangalia tu** **main page**, unaweza kupata endpoints **zisizo za kawaida** ambazo zina uwezekano mkubwa zaidi wa kuwa **vulnerable**.

Ili kutekeleza wazo hili unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kupitia **screenshots** zote ili kukuambia **ni zipi zina uwezekano wa kuwa na vulnerabilities**, na zipi hazina.

## Public Cloud Assets

Ili kupata cloud assets zinazoweza kuwa za kampuni, unapaswa **kuanza na orodha ya keywords zinazoitambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Utahitaji pia wordlists za **maneno yanayotumika kwa kawaida kwenye buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa kutumia maneno hayo unapaswa kutengeneza **permutations** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa wordlists zilizotokana na hapo unaweza kutumia tools kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta Cloud Assets unapaswa **kutafuta zaidi ya buckets za AWS pekee**.

### **Looking for vulnerabilities**

Ukipata vitu kama **buckets zilizo wazi au cloud functions zilizo exposed**, unapaswa **kuzifikia** na kujaribu kuona zinakupatia nini na kama unaweza kuzitumia vibaya.

## Emails

Ukiwa na **domains** na **subdomains** zilizo ndani ya scope, kimsingi una kila kitu **unachohitaji kuanza kutafuta emails**. Hizi ndizo **APIs** na **tools** ambazo zimewahi kunifanyia kazi vizuri zaidi katika kutafuta emails za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - pamoja na APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (free version)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API ya [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails zitakusaidia baadaye kufanya **brute-force kwenye web logins na auth services** (kama SSH). Pia zinahitajika kwa **phishings**. Zaidi ya hayo, APIs hizi zitakupa **taarifa zaidi kuhusu mtu** aliye nyuma ya email, jambo linalofaa kwa phishing campaign.

## Credential Leaks

Ukiwa na **domains,** **subdomains**, na **emails**, unaweza kuanza kutafuta credentials zilizoleak hapo awali zinazohusiana na emails hizo:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ukipata credentials **halali zilizoleak**, huu ni ushindi rahisi sana.

## Secrets Leaks

Credential leaks huhusishwa na hacks za kampuni ambapo **taarifa nyeti zilileak na kuuzwa**. Hata hivyo, kampuni zinaweza kuathiriwa na **leaks nyingine** ambazo taarifa zake hazipo kwenye databases hizo:

### Github Leaks

Credentials na APIs zinaweza ku-leak kwenye **public repositories** za **kampuni** au za **users** wanaofanya kazi katika kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) ili **kupakua** **public repos** zote za **organization** na za **developers** wake, kisha kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yake kiotomatiki.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **text** yote iliyotolewa na **URLs zilizopitishwa** kwake, kwa sababu wakati mwingine **web pages pia huwa na secrets**.

#### Github Dorks

Pia angalia **ukurasa huu** kwa **github dorks** zinazoweza kutumika kutafuta katika organization unayoishambulia:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Wakati mwingine attackers au wafanyakazi tu **huchapisha maudhui ya kampuni kwenye paste site**. Hii inaweza kuwa na **taarifa nyeti** au isiwe nayo, lakini ni muhimu sana kuitafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta katika zaidi ya paste sites 80 kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini zenye manufaa huwa muhimu kila mara katika kupata **taarifa zilizo exposed ambazo hazikupaswa kuwa hapo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina queries nyingi sana, **maelfu kadhaa**, ambazo huwezi kuziendesha manually. Kwa hiyo, unaweza kuchagua 10 unazozipenda au kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuzitumia zote**.

_Note kwamba tools zinazotarajia kutumia database yote kupitia regular Google browser hazitaisha kamwe, kwa sababu google itakublock haraka sana._

### **Looking for vulnerabilities**

Ukipata credentials au API tokens **halali zilizoleak**, huu ni ushindi rahisi sana.

## Public Code Vulnerabilities

Ukigundua kuwa kampuni ina **open-source code**, unaweza **kuichanganua** na kutafuta **vulnerabilities** ndani yake.

**Kulingana na language** kuna **tools** mbalimbali unazoweza kutumia:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Pia kuna services za bure zinazokuruhusu **kuscan public repositories**, kama vile:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Vulnerabilities nyingi** zinazopatikana na bug hunters ziko ndani ya **web applications**, kwa hiyo katika hatua hii ningependa kuzungumzia **web application testing methodology**, na unaweza [**kupata taarifa hizi hapa**](../../network-services-pentesting/pentesting-web/index.html).

Pia nataka kutaja kwa pekee sehemu ya [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwa sababu, ingawa hupaswi kutarajia zipate vulnerabilities nyeti sana, zinafaa kuzitekeleza kwenye **workflows ili kupata taarifa za awali za web.**

## Recapitulation

> Hongera! Kufikia hatua hii tayari umefanya **basic enumeration yote**. Ndiyo, ni basic kwa sababu enumeration nyingi zaidi zinaweza kufanywa (tutaona tricks zaidi baadaye).

Kwa hiyo tayari ume:

1. Kupata **companies** zote zilizo ndani ya scope
2. Kupata **assets** zote zinazomilikiwa na companies (na kufanya vuln scan ikiwa ipo ndani ya scope)
3. Kupata **domains** zote zinazomilikiwa na companies
4. Kupata **subdomains** zote za domains (kuna subdomain takeover?)
5. Kupata **IPs** zote (kutoka na **zisizotoka kwenye CDNs**) zilizo ndani ya scope.
6. Kupata **web servers** zote na kuchukua **screenshot** zao (kuna kitu kisicho cha kawaida kinachostahili kuangaliwa kwa undani?)
7. Kupata **potential public cloud assets** zote zinazomilikiwa na kampuni.
8. **Emails**, **credential leaks**, na **secret leaks** zinazoweza kukupatia **ushindi mkubwa kwa urahisi sana**.
9. **Kufanya pentesting kwenye web zote ulizopata**

## **Full Recon Automatic Tools**

Kuna tools kadhaa zinazoweza kutekeleza sehemu ya hatua zilizopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ni ya zamani kidogo na haijasasishwa

## **References**

- Kozi zote za bure za [**@Jhaddix**](https://twitter.com/Jhaddix) kama vile [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
