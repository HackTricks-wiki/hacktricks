# Mbinu za External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ugundaji wa Mali

> Kwa hivyo walikuambia kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kubaini kampuni hii inamiliki nini kwa kweli.

Lengo la hatua hii ni kupata kampuni zote zinazomilikiwa na kampuni kuu na kisha mali zote za kampuni hizi. Ili kufanya hivyo, tutafanya:

1. Kupata acquisitions za kampuni kuu, hii itatupa kampuni zilizo ndani ya scope.
2. Kupata ASN (ikiwa ipo) ya kila kampuni, hii itatupa IP ranges zinazomilikiwa na kila kampuni
3. Kutumia reverse whois lookups kutafuta rekodi nyingine (majina ya shirika, domains...) zinazohusiana na ile ya kwanza (hii inaweza kufanywa kwa urudufu)
4. Kutumia mbinu nyingine kama shodan `org` and `ssl` filters kutafuta mali nyingine (mbinu ya `ssl` inaweza kufanywa kwa urudufu).

### **Manunuzi**

Kwanza kabisa, tunahitaji kujua ni kampuni gani nyingine zinazomilikiwa na kampuni kuu.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **tafuta** kampuni kuu, na **bonyeza** kwenye "**acquisitions**". Hapo utaona kampuni nyingine zilizonunuliwa na kampuni kuu.\
Chaguo jingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, angalia **SEC/EDGAR filings**, kurasa za **investor relations**, au rejista za kampuni za ndani (km, **Companies House** nchini Uingereza).\
Kwa miti ya kampuni ya kimataifa na subsidiaries, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na database ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, kwa hatua hii unatakiwa kujua kampuni zote ndani ya scope. Sasa tuone jinsi ya kupata mali zao.

### **ASNs**

Autonomous system number (**ASN**) ni nambari ya kipekee iliyotengwa kwa autonomous system (**AS**) na **Internet Assigned Numbers Authority (IANA)**.\
AS ni kundi la blocks za anwani za **IP** ambazo zina sera iliyofafanuliwa kwa wakati wa kufikia mitandao ya nje na zinazosimamiwa na shirika moja lakini zinaweza kuundwa na wapangaji wengi.

Inavutia kutazama kama kampuni imepewa ASN ili kupata **IP ranges** zake. Itakuwa muhimu kufanya **vulnerability test** dhidi ya hosts zote ndani ya scope na kutafuta domains ndani ya anwani hizi za IP.\
Unaweza **kutafuta** kwa jina la kampuni, kwa **IP** au kwa **domain** katika [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na mkoa wa kampuni viungo hivi vinaweza kuwa muhimu kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Hata hivyo, uwezekano mkubwa habari zote muhimu (IP ranges na Whois)** zimetajwa tayari kwenye kiungo cha kwanza.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration kiotomatiki huweka pamoja na kutoa muhtasari wa ASNs mwishoni mwa scan.
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
Unaweza kupata IP ranges za shirika pia ukitumia [http://asnlookup.com/](http://asnlookup.com) (ina API bila malipo).\
Unaweza kupata IP na ASN ya domain ukitumia [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

Kwa hatua hii tunajua **all the assets inside the scope**, hivyo ikiwa umepewa idhini unaweza kuendesha **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) dhidi ya hosts wote.\
Pia, unaweza kuanzisha [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** Shodan, Censys, au ZoomEye **kutafuta** open ports **na kulingana na ulicho pata unapaswa** kusoma kitabu hiki kuhusu jinsi ya pentest huduma mbalimbali zinazoweza kuendeshwa.\
**Pia, inafaa kutaja kwamba unaweza kuandaa baadhi za** default username **na** passwords **lists na kujaribu** bruteforce huduma kwa kutumia [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Tunajua makampuni yote ndani ya scope na assets yao, ni wakati wa kutafuta domeni zilizo ndani ya scope.

_Tafadhali, kumbuka kwamba katika mbinu zilizopendekezwa hapa chini unaweza pia kupata subdomains na habari hiyo haipaswi kudharauliwa._

Kwanza kabisa unapaswa kutafuta **main domain**(s) ya kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Unapokuwa umepata IP ranges zote za domeni unaweza kujaribu kufanya **reverse dns lookups** kwenye zile **IPs ili kupata domeni zaidi ndani ya scope**. Jaribu kutumia seva ya dns ya victim au seva ya dns maarufu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
Unaweza pia kutumia tool ya mtandaoni kupata taarifa hii: [http://ptrarchive.com/](http://ptrarchive.com).\
Kwa ranges kubwa, zana kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) zinafaa ku-automate reverse lookups na enrichment.

### **Reverse Whois (loop)**

Inside a **whois** unaweza kupata taarifa nyingi za kuvutia kama **organisation name**, **address**, **emails**, nambari za simu... Lakini kinachovutia zaidi ni kwamba unaweza kupata **mali zaidi zinazohusiana na kampuni** ukifanya **reverse whois lookups by any of those fields** (kwa mfano, registries zingine za whois ambapo email ile ile inaonekana).\
Unaweza kutumia zana za mtandaoni kama:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bure**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bure**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bure**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Bure** web, API sio bure.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Sio bure
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Sio bure (hutoa **100 free** searches tu)
- [https://www.domainiq.com/](https://www.domainiq.com) - Sio bure
- [https://securitytrails.com/](https://securitytrails.com/) - Sio bure (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Sio bure (API)

Unaweza ku-automate task hii kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji whoxy API key).\
Unaweza pia kufanya ugundufu wa automatic reverse whois kwa kutumia [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

Kumbuka kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya domain kila unapopata domain mpya.

### **Trackers**

Ikiwa utapata **same ID of the same tracker** katika kurasa 2 tofauti unaweza kudhani kwamba **both pages** zinadhibitiwa na **the same team**.\
Kwa mfano, ikiwa unaona **Google Analytics ID** sawa au **Adsense ID** sawa kwenye kurasa kadhaa.

Kuna kurasa na zana zinazokuwezesha kutafuta kwa kutumia trackers hizi na nyingine:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (inapata tovuti zinazohusiana kwa analytics/trackers zilizosambazwa)

### **Favicon**

Je, ulikuwa unajua kwamba tunaweza kupata domains na subdomains zinazoambatana na target wetu kwa kutafuta favicon icon hash ile ile? Hili ndilo hasa jambo ambalo tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) iliyotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2) inafanya. Hapa ni jinsi ya kuitumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - gundua domains zilizo na favicon icon hash ile ile](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa kifupi, favihash itaturuhusu kugundua domains ambazo zina favicon icon hash ile ile kama target yetu.

Zaidi ya hayo, unaweza pia kutafuta teknolojia kwa kutumia favicon hash kama ilivyoelezwa katika [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hii inamaanisha kwamba ikiwa unajua **hash of the favicon of a vulnerable version of a web tech** unaweza kuitafuta kwenye shodan na **find more vulnerable places**:
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

### **Hakimiliki / Uniq string**

Tafuta ndani ya kurasa za wavuti **strings ambazo zinaweza kushirikiwa kati ya tovuti tofauti ndani ya shirika moja**. **Hakimiliki string** inaweza kuwa mfano mzuri. Kisha tafuta kamba hiyo katika **google**, katika **browsers** nyingine au hata katika **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Ni kawaida kuwa na cron job kama
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. Hii ina maana kwamba hata kama CA iliyotumika kwa hili haweka wakati ilipotengenezwa kwenye Validity time, inawezekana **kugundua domains zinazomilikiwa na kampuni ileile katika certificate transparency logs**.\
Angalia hii [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Tumia pia **certificate transparency** logs moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Unaweza kutumia tovuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au zana kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) kupata **domains na subdomain zinazoshare taarifa za dmarc**.\
Zana nyingine muhimu ni [**spoofcheck**](https://github.com/BishopFox/spoofcheck) na [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Inaonekana ni kawaida watu kuwapangia subdomains kwenye IPs zinazomilikiwa na cloud providers na wakati fulani **kupoteza hiyo IP lakini kusahau kuondoa rekodi ya DNS**. Kwa hivyo, kwa **spawning a VM** katika cloud (kama Digital Ocean) utaweza kwa kweli kuwa **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) inaelezea hadithi kuhusu hili na inapendekeza script ambayo **spawns a VM in DigitalOcean**, **gets** the **IPv4** ya mashine mpya, na **searches in Virustotal for subdomain records** zinazoelekeza kwake.

### **Other ways**

**Kumbuka kwamba unaweza kutumia technique hii kugundua majina zaidi ya domain kila unapopata domain mpya.**

**Shodan**

Kama tayari unajua jina la shirika linalomiliki IP space, unaweza kutafuta kwa data hiyo kwenye shodan ukitumia: `org:"Tesla, Inc."` Angalia hosts zilizopatikana kwa ajili ya domains zisizotarajiwa kwenye TLS certificate.

Unaweza kufungua **TLS certificate** ya ukurasa mkuu wa wavuti, kupata **Organisation name** kisha kutafuta jina hilo ndani ya **TLS certificates** za kurasa zote za wavuti zinazoonekana kwenye **shodan** kwa filter : `ssl:"Tesla Motors"` au tumia zana kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ni zana inayotafuta **domains related** na kikoa kuu na **subdomains** zao, ni ya kushangaza.

**Passive DNS / Historical DNS**

Passive DNS data ni nzuri kupata **rekodi za zamani na zilizosahaulika** ambazo bado zinaweza kujibu au ambazo zinaweza kuchukuliwa. Tazama:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Angalia kwa baadhi ya [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Labda kampuni fulani inatumia domain fulani lakini wamepoteza umiliki. Rekebisha tu (ikiwa ni nafuu) na ujulishe kampuni.

Ikiwa unatoka **domain yoyote yenye IP tofauti** na zile ulizopata tayari katika assets discovery, unapaswa kufanya **basic vulnerability scan** (ukitumia Nessus au OpenVAS) na baadhi ya [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa **nmap/masscan/shodan**. Kulingana na services zinazotumika unaweza kupata katika **this book some tricks to "attack" them**.\
_Note kwamba wakati mwingine domain imehost wa ndani ya IP isiyodhibitiwa na mteja, hivyo si katika scope, kuwa mwangalifu._

## Subdomains

> Tunajua kampuni zote zilizo ndani ya kikomo, mali zote za kila kampuni na kikoa/kikoa zote zinazohusiana na kampuni hizo.

Ni wakati wa kupata subdomains zote zinazowezekana za kila domain iliyopatikana.

> [!TIP]
> Kumbuka kwamba baadhi ya zana na mbinu za kupata domains zinaweza pia kusaidia kupata subdomains

### **DNS**

Tujaribu kupata **subdomains** kutoka kwa **DNS records**. Pia tunapaswa kujaribu **Zone Transfer** (Ikiwa dhaifu, unapaswa kuiripoti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Njia ya haraka zaidi ya kupata subdomains nyingi ni kutafuta katika vyanzo vya nje. Zana zinazotumika zaidi ni zifuatazo (kwa matokeo bora, sanidi API keys):

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
Kuna **zana/API nyingine za kuvutia** ambazo, hata kama hazibobei moja kwa moja katika kutafuta subdomains, zinaweza kuwa msaada katika kupata subdomains, kama:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Inatumia API [https://sonar.omnisint.io](https://sonar.omnisint.io) kupata subdomains
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
- [**gau**](https://github.com/lc/gau)**:** huchota URLs zilizojulikana kutoka kwa AlienVault's Open Threat Exchange, the Wayback Machine, na Common Crawl kwa domain yoyote.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Wanachimba wavuti kutafuta faili za JS na kutoa subdomains kutoka huko.
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

Mradi huu unatoa kwa **bure subdomains zote zinazohusiana na bug-bounty programs**. Unaweza kufikia data hii pia kwa kutumia [chaospy](https://github.com/dr-0x0x/chaospy) au hata kufikia scope inayotumika na mradi huu [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **mlinganisho** wa zana nyingi hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Tujaribu kupata subdomains mpya kwa brute-forcing DNS servers kwa kutumia majina yanayowezekana ya subdomains.

Kwa hatua hii utahitaji baadhi ya **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Na pia IPs za DNS resolvers nzuri. Ili kuunda orodha ya trusted DNS resolvers unaweza kupakua resolvers kutoka [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzichuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa zana ya kwanza iliyofanya DNS brute-force kwa ufanisi. Ni ya haraka sana, hata hivyo ina uwezekano wa false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Nadhani hii inatumia 1 resolver tu
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper wa `massdns`, imeandikwa kwa go, inayokuruhusu kuorodhesha subdomains halali kwa kutumia active bruteforce, pamoja na kutatua subdomains kwa wildcard handling na msaada rahisi wa input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Pia inatumia `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) inatumia asyncio kufanya brute force kwa majina ya kikoa kwa njia isiyo ya sinkrono.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Raundi ya Pili ya DNS Brute-Force

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na brute-forcing, unaweza kuunda mabadiliko ya subdomains ulizopata ili kujaribu kupata zaidi. Zana kadhaa zinasaidia kwa madhumuni haya:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Inazalisha permutations za domains na subdomains zilizotolewa.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Kwa kupewa domains na subdomains, inazalisha permutations.
- Unaweza kupata goaltdns permutations **wordlist** hapa: [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Ikipewa domains na subdomains, inazalisha permutations. Iwapo hakuna faili ya permutations iliyoainishwa, gotator itatumia yake mwenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kuzalisha subdomains permutations, pia inaweza kujaribu kuzitatua (lakini ni bora kutumia zana zilizotajwa hapo awali).
- Unaweza kupata altdns permutations **wordlist** katika [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya permutations, mutations na mabadiliko ya subdomains. Zana hii itafanya brute force matokeo (haiungi mkono dns wild card).
- Unaweza kupata dmut permutations wordlist [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kutokana na domain, huunda **majina mapya ya subdomains yanayowezekana** kulingana na mifumo iliyoonyeshwa ili kujaribu kugundua subdomains zaidi.

#### Uundaji wa mchanganyiko mahiri

- [**regulator**](https://github.com/cramppet/regulator): Kwa maelezo zaidi soma [**post**](https://cramppet.github.io/regulator/index.html) lakini kwa msingi wake, itachukua **sehemu kuu** kutoka kwa **subdomains zilizogunduliwa** na kuyachanganya ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni subdomain brute-force fuzzer iliyoshikamana na algorithm ya DNS reponse-guided iliyo rahisi sana lakini yenye ufanisi. Inatumia seti ya data ya pembejeo iliyotolewa, kama wordlist iliyobinafsishwa au rekodi za kihistoria za DNS/TLS, ili kwa usahihi kusintetiza majina zaidi ya domain zinazolingana na kuyapanua zaidi katika mzunguko kulingana na taarifa zilizokusanywa wakati wa DNS scan.
```
echo www | subzuf facebook.com
```
### **Mtiririko wa Ugunduzi wa Subdomain**

Angalia chapisho la blogu nililoandika kuhusu jinsi ya **kuweka otomatiki ugunduzi wa subdomain** kutoka kwa domain kwa kutumia **Trickest workflows** ili nisihitaji kuzindua kwa mikono zana nyingi kwenye kompyuta yangu:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ikiwa umepata anwani ya IP inayojumuisha **ukurasa wa wavuti mmoja au kadhaa** unaomilikiwa na subdomains, unaweza kujaribu **kutafuta subdomains nyingine zenye wavuti kwenye IP hiyo** kwa kuangalia katika vyanzo vya **OSINT** kwa ajili ya domains katika IP au kwa **kufanya brute-forcing majina ya domain ya VHost kwenye IP hiyo**.

#### OSINT

Unaweza kupata baadhi ya **VHosts katika IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au other APIs**.

**Brute Force**

Ikiwa una shaka kuwa subdomain fulani inaweza kujificha kwenye web server, unaweza kujaribu kuitafuta kwa brute force:

Wakati the **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly na uiruhusu ffuf **auto-calibrate** ili kuonyesha majibu yanayotofautiana na default vhost:
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
> Kwa mbinu hii unaweza hata kufikia internal/hidden endpoints.

### **CORS Brute Force**

Wakati mwingine utapata kurasa ambazo zinarejesha kichwa cha _**Access-Control-Allow-Origin**_ tu wakati domain/subdomain halali imewekwa katika kichwa cha _**Origin**_. Katika mazingira haya, unaweza kutumia tabia hii vibaya ili **gundua** subdomains mpya.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Wakati unatafuta **subdomains** angalia kama inafanya **pointing** kwa aina yoyote ya **bucket**, na katika hali hiyo [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa kwa sasa utakuwa unajua domain zote ndani ya scope, jaribu [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Ufuatiliaji**

Unaweza **monitor** kama **new subdomains** za domain zinaundwa kwa kufuatilia **Certificate Transparency** Logs kama [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) inavyofanya.

### **Kutafuta vulnerabilities**

Angalia uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inafanya **pointing** kwa **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ikiwa unatambua **subdomain with an IP different** tofauti na zile ulizozipata kwenye assets discovery, unapaswa kufanya **basic vulnerability scan** (ukitumia Nessus au OpenVAS) na baadhi ya [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa **nmap/masscan/shodan**. Kulingana na services zinazotumika unaweza kupata katika **this book some tricks to "attack" them**.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

Katika hatua za awali unaweza kuwa umepata baadhi ya **IP ranges, domains and subdomains**.\
Ni wakati wa kukusanya **all the IPs from those ranges** na pia kwa **domains/subdomains (DNS queries).**

Kwa kutumia huduma kutoka kwa **free apis** zifuatazo unaweza pia kupata **previous IPs used by domains and subdomains**. IP hizi zinaweza bado kumilikiwa na mteja (na zinaweza kukuruhusu kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kuangalia domains zinazoonyesha anwani maalum ya IP kwa kutumia tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

Fanya port scan kwa IP zote ambazo hazitoki kwa CDNs (kwa kuwa kuna uwezekano mkubwa hautapata chochote cha kuvutia huko). Katika services zinazofanya kazi ulizogundua unaweza kupata vulnerabilities.

Pata [guide](../pentesting-network/index.html) kuhusu jinsi ya scan hosts.

## Kutafuta web servers

> Tumeipata kampuni zote na assets zao na tunajua IP ranges, domains na subdomains ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizopita huenda tayari umefanya baadhi ya **recon of the IPs and domains discovered**, hivyo unaweza kuwa **already found all the possible web servers**. Hata hivyo, kama hujafanya bado, sasa tutaona baadhi ya **fast tricks to search for web servers** ndani ya scope.

Tafadhali, kumbuka kwamba hii itakuwa **oriented for web apps discovery**, hivyo unapaswa **perform the vulnerability** na **port scanning** pia (**if allowed** by the scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Tool nyingine rafiki kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unaweka orodha ya domains na itajaribu kuungana kwa port 80 (http) na 443 (https). Zaidi ya hayo, unaweza kuonyesha kujaribu port nyingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Picha za skrini**

Sasa baada ya kugundua **all the web servers** present in the scope (among the **IPs** of the company and all the **domains** and **subdomains**) huenda **hujui wapi kuanza**. Hivyo, tufanye iwe rahisi na aanze kwa kuchukua picha za skrini za zote. Kwa kuangalia tu kwenye **main page** unaweza kupata endpoints zisizo za kawaida ambazo zina uwezekano mkubwa wa kuwa **vulnerable**.

Ili kutekeleza wazo hili unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kukagua **screenshots** zote ili kukueleza **ni nini kina uwezekano wa kuwa na vulnerabilities**, na ni nini sio.

## Mali za Public Cloud

Ili kupata mali za cloud zinazowezekana zinazomilikiwa na kampuni unapaswa **kuanza na orodha ya maneno muhimu yanayomtambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Pia utahitaji wordlists za **maneno ya kawaida yanayotumika katika buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa kutumia maneno hayo unapaswa kuzalisha **permutations** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa taarifa zaidi).

Kwa wordlists zitakazotokana unaweza kutumia zana kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta Cloud Assets unapaswa **kutazama zaidi ya buckets tu katika AWS**.

### **Kutafuta vulnerabilities**

Ikiwa utapata vitu kama **open buckets au cloud functions exposed** unapaswa **kuvifungua** na kujaribu kuona vinakupa nini na ikiwa unaweza kuvitumia.

## Barua pepe

Kwa **domains** na **subdomains** ndani ya scope una karibu yote unayohitaji kuanza kutafuta barua pepe. Hizi ni **APIs** na **tools** ambazo zimefanya kazi vizuri kunipatia barua pepe za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Kutafuta vulnerabilities**

Barua pepe zitakuwa muhimu baadaye kwa **brute-force web logins and auth services** (kama SSH). Pia, zinahitajika kwa **phishings**. Zaidi ya hayo, APIs hizi zitakupa hata zaidi ya **info kuhusu mtu** aliye nyuma ya barua pepe, ambayo ni muhimu kwa kampeni ya phishing.

## Credential Leaks

Kwa **domains,** **subdomains**, na **emails** unaweza kuanza kutafuta credentials zilizo leak katika zamani zinazomilikiwa na barua pepe hizo:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta vulnerabilities**

Ikiwa utapata **valid leaked** credentials, hili ni ushindi rahisi sana.

## Secrets Leaks

Credential leaks zinahusiana na hacks za kampuni ambapo **sensitive information was leaked and sold**. Hata hivyo, kampuni zinaweza kuathiriwa na **leaks** nyingine ambazo taarifa zake haziko katika those databases:

### Github Leaks

Credentials na API zinaweza kuwa leaked katika **public repositories** za **kampuni** au za **watumiaji** wanaofanya kazi kwa kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) kupakua repos zote za **organization** na za **developers** wake na kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yao moja kwa moja.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **text** zote za URLs zilizotolewa kwa sababu wakati mwingine **web pages pia zinaweza kuwa na secrets**.

#### Github Dorks

Angalia pia ukurasa huu kwa **github dorks** zinazoweza kutafutwa ndani ya shirika unalolilenga:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Wakati mwingine watakora au hata wafanyakazi watachapisha maudhui ya kampuni kwenye tovuti za paste. Hii inaweza kuwa au isiwe na **sensitive information**, lakini ni muhimu kuitafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta katika zaidi ya tovuti za paste 80 kwa wakati mmoja.

### Google Dorks

Google dorks za zamani bado ni muhimu kutafuta **taarifa zilizofichuliwa ambazo hazipaswi kuwa huko**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu ya queries ambayo huwezi kuendesha kwa mikono. Kwa hivyo, unaweza kuchukua 10 unazopenda zaidi au unaweza kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuziendesha zote**.

_Kumbuka kwamba zana zinazotarajiwa kuendesha database yote kupitia browser ya kawaida ya Google zitakomesha kwa muda mchache kwani google itakuzuia haraka sana._

### **Kutafuta vulnerabilities**

Ikiwa utapata **valid leaked** credentials au API tokens, hili ni ushindi rahisi sana.

## Public Code Vulnerabilities

Ikiwa umegundua kuwa kampuni ina **open-source code** unaweza kuichambua na kutafuta **vulnerabilities** ndani yake.

**Kulingana na lugha** kuna **tools** tofauti unaweza kutumia:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Kuna pia huduma za bure zinazoruhusu ku**scan public repositories**, kama:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Wengi wa vulnerabilities** zinazopatikana na bug hunters ziko ndani ya **web applications**, hivyo kwa hatua hii ningependa kuzungumzia **web application testing methodology**, na unaweza [**kupata taarifa hizi hapa**](../../network-services-pentesting/pentesting-web/index.html).

Ninataka pia kutaja kwa njia maalum sehemu ya [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwani, ingawa haufanani kutegemea zizi kupata vulnerabilities za hali ya juu, zinasaidia kuziweka kwenye **workflows** kupata taarifa za awali za web.

## Muhtasari

> Hongera! Kwa hatua hii umefanya tayari **all the basic enumeration**. Ndiyo, ni msingi kwa sababu kuna mengi zaidi ya enumeration yanayoweza kufanywa (tutategea zaidi mbinu baadaye).

Hivyo tayari umefanya:

1. Kupata kampuni zote ndani ya scope
2. Kupata assets zote zinazomilikiwa na kampuni (na kufanya skanning ya vuln ikiwa iko kwa scope)
3. Kupata domains zote zinazomilikiwa na kampuni
4. Kupata subdomains zote za domains (je, kuna subdomain takeover?)
5. Kupata IPs zote (kutoka na sio kutoka CDN) ndani ya scope.
6. Kupata web servers zote na kuchukua screenshot ya kila moja (kuna kitu chochote cha kushangaza kinachostahili uchunguzi wa ndani?)
7. Kupata potential public cloud assets zote zinazomilikiwa na kampuni.
8. **Emails**, **credentials leaks**, na **secret leaks** ambazo zinaweza kukupa **ushindi mkubwa kwa urahisi**.
9. Pentesting all the webs you found

## **Zana za Otomatiki za Full Recon**

Kuna zana kadhaa ambazo zinaweza kutekeleza sehemu ya hatua zilizopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **Marejeo**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
