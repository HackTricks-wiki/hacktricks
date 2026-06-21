# Mbinu ya External Recon

{{#include ../../banners/hacktricks-training.md}}

## Uvumbuzi wa Assets

> Hivyo uliambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kubaini kampuni hiyo kwa kweli inamiliki nini.

Lengo la hatua hii ni kupata **kampuni zote zinazomilikiwa na kampuni kuu** na kisha **assets** zote za kampuni hizo. Ili kufanya hivyo, tutafanya:

1. Kupata acquisitions za kampuni kuu, hii itatupatia kampuni zilizo ndani ya scope.
2. Kupata ASN (ikiwa ipo) ya kila kampuni, hii itatupatia IP ranges zinazomilikiwa na kila kampuni
3. Kutumia reverse whois lookups kutafuta entries nyingine (majina ya organisation, domains...) zinazohusiana na ya kwanza (hii inaweza kufanywa kwa kujirudia)
4. Kutumia mbinu nyingine kama shodan `org` na `ssl` filters kutafuta assets nyingine (mbinu ya `ssl` inaweza kufanywa kwa kujirudia).

### **Acquisitions**

Kwanza kabisa, tunahitaji kujua ni kampuni zipi **nyingine zinazomilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **kutafuta** **kampuni kuu**, na **kubofya** "**acquisitions**". Huko utaona kampuni nyingine zilizonunuliwa na ya kwanza.\
Chaguo jingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, angalia **SEC/EDGAR filings**, kurasa za **investor relations**, au local corporate registries (kwa mfano, **Companies House** nchini Uingereza).\
Kwa corporate trees na subsidiaries za kimataifa, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na database ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, katika hatua hii unapaswa kujua kampuni zote zilizo ndani ya scope. Hebu tuchunguze jinsi ya kupata assets zao.

### **ASNs**

An autonomous system number (**ASN**) ni nambari ya kipekee inayotolewa kwa **autonomous system** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
**AS** inajumuisha **blocks** za **IP addresses** ambazo zina sera iliyofafanuliwa wazi ya kufikia mitandao ya nje na husimamiwa na shirika moja lakini huenda zikawa na operators kadhaa.

Ni jambo la kuvutia kubaini kama **kampuni imepewa ASN yoyote** ili kupata **IP ranges** zake. Itakuwa muhimu kufanya **vulnerability test** dhidi ya hosts zote zilizo ndani ya **scope** na **kutafuta domains** ndani ya IP hizo.\
Unaweza **kutafuta** kwa jina la kampuni, kwa **IP** au kwa **domain** katika [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na eneo la kampuni, linki hizi zinaweza kuwa muhimu kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Hata hivyo, pengine taarifa zote muhimu** (IP ranges na Whois) **tayari zinaonekana kwenye linki ya kwanza.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration hujumajiendesha hukusanya na kufupisha ASNs mwishoni mwa skani.
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
Unaweza kupata masafa ya IP ya shirika pia ukitumia [http://asnlookup.com/](http://asnlookup.com) (ina API ya bure).\
Unaweza kupata IP na ASN ya domain ukitumia [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta udhaifu**

Kwa sasa tunajua **rasilimali zote zilizo ndani ya scope**, kwa hiyo ikiwa unaruhusiwa unaweza kuzindua **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) juu ya host zote.\
Pia, unaweza kuzindua baadhi ya [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** Shodan, Censys, au ZoomEye **ili kupata** open ports **na kutegemea unachopata unapaswa** kuangalia katika kitabu hiki jinsi ya pentest huduma kadhaa zinazowezekana zinazoendeshwa.\
**Pia, inaweza kuwa vyema kutaja kwamba unaweza pia kuandaa baadhi ya** default username **na** passwords **lists na kujaribu** bruteforce services kwa kutumia [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua makampuni yote yaliyo ndani ya scope na rasilimali zake, ni wakati wa kutafuta domains zilizo ndani ya scope.

_Kumbuka, kwamba katika mbinu zifuatazo zinazokusudiwa unaweza pia kupata subdomains na taarifa hiyo haipaswi kupuuzwa._

Kwanza kabisa unapaswa kutafuta **main domain**(s) ya kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Baada ya kupata masafa yote ya IP ya domains unaweza kujaribu kufanya **reverse dns lookups** kwenye hizo **IP ili kupata domains zaidi zilizo ndani ya scope**. Jaribu kutumia baadhi ya dns server ya mhanga au baadhi ya dns server zinazojulikana sana (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Ili hii ifanye kazi, msimamizi lazima awashe PTR kwa mkono.\
Unaweza pia kutumia tool ya mtandaoni kwa taarifa hii: [http://ptrarchive.com/](http://ptrarchive.com).\
Kwa ranges kubwa, tools kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) ni muhimu kwa ku-automate reverse lookups na enrichment.

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata **information** nyingi za kuvutia kama **organisation name**, **address**, **emails**, nambari za simu... Lakini cha kuvutia zaidi ni kwamba unaweza kupata **more assets related to the company** ukifanya **reverse whois lookups by any of those fields** (kwa mfano rekodi nyingine za whois ambako email ileile inaonekana).\
Unaweza kutumia tools za mtandaoni kama:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Unaweza ku-automate kazi hii kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji whoxy API key).\
Unaweza pia kufanya reverse whois discovery ya kiotomatiki kwa [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Kumbuka kwamba unaweza kutumia technique hii kugundua domain names zaidi kila unapopata domain mpya.**

### **Trackers**

Ukipata **same ID of the same tracker** kwenye kurasa 2 tofauti unaweza kudhani kwamba **kurasa zote mbili** zinasimamiwa na timu ileile.\
Kwa mfano, ukiona **Google Analytics ID** ileile au **Adsense ID** ileile kwenye kurasa kadhaa.

Kuna baadhi ya kurasa na tools zinazoruhusu kutafuta kwa trackers hizi na zaidi:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Je, unajua kwamba tunaweza kupata related domains na subdomains kwa target yetu kwa kuangalia favicon icon hash ileile? Hii ndiyo hasa ambacho tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) iliyotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2) hufanya. Hivi ndivyo ya kuitumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa kifupi, favihash itaturuhusu kugundua domains ambazo zina favicon icon hash sawa na lengo letu.

Zaidi ya hayo, unaweza pia kutafuta technologies kwa kutumia favicon hash kama ilivyoelezwa katika [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hiyo inamaanisha kwamba ikiwa unajua **hash ya favicon ya toleo lenye udhaifu la web tech** unaweza kutafuta kama iko shodan na **kupata maeneo zaidi yenye udhaifu**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Hivi ndivyo unavyoweza **kuhesabu favicon hash** ya web:
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
Unaweza pia kupata favicon hashes kwa kiwango kikubwa kwa [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) kisha pivot katika Shodan/Censys.

### **Copyright / Uniq string**

Tafuta ndani ya kurasa za wavuti **strings ambazo zinaweza kushirikiwa kati ya tovuti tofauti ndani ya shirika lile lile**. **Copyright string** inaweza kuwa mfano mzuri. Kisha tafuta string hiyo katika **google**, katika **browsers** nyingine au hata katika **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Ni kawaida kuwa na cron job kama vile
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. Hii ina maana kwamba hata ikiwa CA iliyotumiwa kwa hili haijaweka muda ilipotengenezwa katika Validity time, inawezekana **kupata domains zinazomilikiwa na kampuni moja kwenye certificate transparency logs**.\
Angalia [**writeup hii kwa maelezo zaidi**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Pia tumia **certificate transparency** logs moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Unaweza kutumia web kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au tool kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) ili kupata **domains na subdomain zinazoshiriki taarifa ileile ya dmarc**.\
Tools nyingine zenye manufaa ni [**spoofcheck**](https://github.com/BishopFox/spoofcheck) na [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Inaonekana ni kawaida kwa watu kuassign subdomains kwa IPs zinazomilikiwa na cloud providers na wakati fulani **kupoteza IP hiyo lakini kusahau kuondoa DNS record**. Hivyo, kwa **ku-spawn VM** tu kwenye cloud (kama Digital Ocean), kwa kweli utakuwa **ukichukua baadhi ya subdomain(s)**.

[**Post hii**](https://kmsec.uk/blog/passive-takeover/) inaeleza hadithi kuhusu hilo na inapendekeza script inayoweza **ku-spawn VM katika DigitalOcean**, **kupata** **IPv4** ya machine mpya, na **kutafuta katika Virustotal records za subdomain** zinazoelekeza kwake.

### **Other ways**

**Kumbuka kwamba unaweza kutumia technique hii kugundua domain names zaidi kila unapopata domain mpya.**

**Shodan**

Kama unavyojua tayari jina la organisation inayomiliki IP space. Unaweza kutafuta kwa data hiyo katika shodan kwa kutumia: `org:"Tesla, Inc."` Angalia hosts zilizopatikana kwa domains mpya zisizotarajiwa kwenye TLS certificate.

Unaweza kufikia **TLS certificate** ya main web page, kupata **jina la Organisation** na kisha kutafuta jina hilo ndani ya **TLS certificates** za web pages zote zinazojulikana na **shodan** kwa filter : `ssl:"Tesla Motors"` au tumia tool kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ni tool inayotafuta **domains zinazohusiana** na main domain na **subdomains** zake, ni ya kushangaza sana.

**Passive DNS / Historical DNS**

Data ya Passive DNS ni nzuri kwa kupata **old and forgotten records** ambazo bado zinaresolve au zinaweza kuchukuliwa. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Angalia baadhi ya [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Labda kampuni fulani **inatumia domain fulani** lakini **imepoteza umiliki** wake. Iisajili tu (kama ni ya bei nafuu) na ijulishe kampuni.

Ukikuta **domain yoyote yenye IP tofauti** na zile ulizokwisha kupata kwenye asset discovery, unapaswa kufanya **basic vulnerability scan** (ukitumia Nessus au OpenVAS) na baadhi ya [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na huduma zinazofanya kazi unaweza kupata kwenye **kitabu hiki baadhi ya tricks za "kuzipiga"**.\
_Kumbuka kwamba wakati mwingine domain inahostiwa ndani ya IP ambayo haidhibitiwi na mteja, kwa hiyo haipo kwenye scope, kuwa makini._

## Subdomains

> Tunajua makampuni yote ndani ya scope, assets zote za kila kampuni na domains zote zinazohusiana na makampuni hayo.

Ni wakati wa kupata subdomains zote zinazowezekana za kila domain iliyopatikana.

> [!TIP]
> Kumbuka kwamba baadhi ya tools na techniques za kupata domains zinaweza pia kusaidia kupata subdomains

### **DNS**

Tujaribu kupata **subdomains** kutoka kwenye **DNS** records. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa ina udhaifu, unapaswa kuiripoti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Njia ya haraka zaidi ya kupata subdomains nyingi ni kutafuta katika vyanzo vya nje. **tools** zinazotumika zaidi ni hizi zifuatazo (kwa matokeo bora sanidi API keys):

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
Kuna **zana/zana za API nyingine za kuvutia** ambazo hata kama hazijabobea moja kwa moja katika kutafuta subdomains bado zinaweza kuwa na manufaa kwa kupata subdomains, kama vile:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Hutumia API [https://sonar.omnisint.io](https://sonar.omnisint.io) ili kupata subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** hupata URLs zinazojulikana kutoka AlienVault's Open Threat Exchange, the Wayback Machine, na Common Crawl kwa domain yoyote iliyotolewa.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Zinafanya uchambuzi wa tovuti kutafuta faili za JS na kutoa subdomains kutoka humo.
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

Mradi huu hutoa kwa **bure subdomains zote zinazohusiana na bug-bounty programs**. Unaweza pia kufikia data hii kwa kutumia [chaospy](https://github.com/dr-0x0x/chaospy) au hata kufikia scope inayotumiwa na mradi huu [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **comparison** ya zana nyingi kati ya hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Tujaribu kupata **subdomains** mpya kwa kufanya brute-force kwenye DNS servers kwa kutumia majina yanayowezekana ya subdomain.

Kwa hatua hii utahitaji baadhi ya **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Na pia IPs za DNS resolvers wazuri. Ili kutengeneza orodha ya trusted DNS resolvers, unaweza kupakua resolvers kutoka [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuziweka kwenye filter. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa zana ya kwanza iliyofanya DNS brute-force kwa ufanisi. Ni ya haraka sana lakini huwa na uwezekano wa false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hii, nafikiri inatumia tu resolver 1
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper juu ya `massdns`, iliyoandikwa kwa go, inayokuruhusu kuorodhesha subdomains halali kwa kutumia active bruteforce, pamoja na kufanya resolve ya subdomains kwa kushughulikia wildcard na support rahisi ya input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Pia hutumia `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) hutumia asyncio kufanya brute force ya majina ya domain kwa njia ya asynchronous.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Raundi ya Pili ya DNS Brute-Force

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na brute-forcing, unaweza kutengeneza mabadiliko ya subdomains zilizopatikana ili kujaribu kupata zaidi. Zana kadhaa zinafaa kwa kusudi hili:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Ukijpewa domains na subdomains huzalisha permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Ukipewa domains na subdomains, tengeneza permutations.
- Unaweza kupata **wordlist** ya permutations za **goaltdns** [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Iwapo domains na subdomains zitatolewa, tengeneza permutations. Ikiwa hakuna faili ya permutations iliyoonyeshwa, gotator itatumia yake yenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kuzalisha permutations za subdomains, pia inaweza kujaribu kuzi-resolve (lakini ni bora kutumia zana zilizotajwa hapo awali).
- Unaweza kupata **wordlist** ya permutations za altdns [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Chombo kingine cha kufanya permutations, mutations na alteration za subdomains. Chombo hiki kitafanya brute force ya matokeo (hakisaidii dns wild card).
- Unaweza kupata wordlist ya permutations ya dmut [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kulingana na domain, hu**generate new potential subdomains names** kulingana na patterns zilizoonyeshwa ili kujaribu kugundua subdomains zaidi.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Kwa maelezo zaidi soma hii [**post**](https://cramppet.github.io/regulator/index.html) lakini kimsingi itachukua **main parts** kutoka kwa **discovered subdomains** na kuzichanganya ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni subdomain brute-force fuzzer iliyounganishwa na algorithm rahisi sana lakini yenye ufanisi ya kuongozwa na majibu ya DNS. Hutumia seti ya data ya ingizo iliyotolewa, kama wordlist iliyobinafsishwa au rekodi za kihistoria za DNS/TLS, ili kuunda kwa usahihi majina zaidi ya domain yanayolingana na kuyaongeza zaidi katika mzunguko kulingana na taarifa zilizokusanywa wakati wa uchunguzi wa DNS.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Angalia chapisho hili la blog nililoandika kuhusu jinsi ya **ku-automate subdomain discovery** kutoka kwenye domain kwa kutumia **Trickest workflows** ili nisiwe na haja ya kuzindua manually zana nyingi kwenye kompyuta yangu:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Kama umepata IP address yenye **ukurasa mmoja au zaidi wa web** unaohusiana na subdomains, unaweza kujaribu **kupata subdomains nyingine zenye webs kwenye IP hiyo** kwa kuangalia vyanzo vya **OSINT** kwa domains ndani ya IP au kwa **brute-forcing VHost domain names** kwenye IP hiyo.

#### OSINT

Unaweza kupata baadhi ya **VHosts kwenye IPs ukitumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs zingine**.

**Brute Force**

Ikiwa unashuku kuwa subdomain fulani inaweza kufichwa kwenye web server unaweza kujaribu kuifanya brute force:

Wakati **IP ina redirect kwenda hostname** (name-based vhosts), fuzz `Host` header moja kwa moja na ruhusu ffuf **auto-calibrate** ili kuonyesha responses ambazo zinatofautiana na default vhost:
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
> Kwa mbinu hii unaweza hata kuweza kufikia internal/hidden endpoints.

### **CORS Brute Force**

Wakati mwingine utapata pages zinazorudisha header _**Access-Control-Allow-Origin**_ tu pale domain/subdomain sahihi inapowekwa kwenye header _**Origin**_. Katika hali hizi, unaweza kutumia vibaya tabia hii ku**gundua** **subdomains** mpya.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Wakati wa kutafuta **subdomains** angalia kama ina **pointing** kwenda kwenye aina yoyote ya **bucket**, na katika hali hiyo [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa kufikia hatua hii utakuwa unajua domains zote ndani ya scope, jaribu [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Unaweza **monitor** ikiwa **new subdomains** za domain zimeundwa kwa kufuatilia **Certificate Transparency** Logs; [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)ndicho kinachofanya hilo.

### **Looking for vulnerabilities**

Angalia uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** ina **pointing** kwenda kwenye **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ukikuta **subdomain yenye IP tofauti** na zile ambazo tayari umepata katika discovery ya assets, unapaswa kufanya **basic vulnerability scan** (ukitumia Nessus au OpenVAS) na pia [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na huduma zinazokuwa zinafanya kazi unaweza kupata **tricks za "attack"** hizo katika **book hii**.\
_Kumbuka kwamba wakati mwingine subdomain huwa hosted ndani ya IP ambayo haidhibitiwi na client, kwa hiyo haipo kwenye scope, kuwa mwangalifu._

## IPs

Katika hatua za awali huenda ulikuwa **umepata baadhi ya IP ranges, domains na subdomains**.\
Sasa ni wakati wa **kukusanya tena IPs zote kutoka kwenye ranges hizo** na kwa **domains/subdomains (DNS queries).**

Kwa kutumia services kutoka kwenye **free apis** zifuatazo unaweza pia kupata **previous IPs used by domains and subdomains**. IPs hizi huenda bado zinamilikiwa na client (na huenda zikakusaidia kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kuangalia domains zinazoelekeza kwenye anwani fulani ya IP kwa kutumia tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan IPs zote zisizomilikiwa na CDNs** (kwa sababu kwa uwezekano mkubwa hutapata chochote cha kuvutia humo). Katika running services zilizogunduliwa unaweza **kupata vulnerabilities**.

**Pata** [**guide**](../pentesting-network/index.html) **kuhusu jinsi ya ku scan hosts.**

## Web servers hunting

> Tumepata kampuni zote na assets zao na tunajua IP ranges, domains na subdomains ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizopita huenda tayari umeshafanya baadhi ya **recon ya IPs na domains zilizogunduliwa**, hivyo huenda **tayari umepata web servers zote zinazowezekana**. Hata hivyo, kama hukufanya hivyo sasa tutaona baadhi ya **fast tricks za kutafuta web servers** ndani ya scope.

Tafadhali, kumbuka kuwa hii itakuwa **imeelekezwa kwenye web apps discovery**, kwa hiyo unapaswa pia **kufanya vulnerability** na **port scanning** (**kama inaruhusiwa** na scope).

A **fast method** ya kugundua **ports open** zinazohusiana na **web** servers kwa kutumia [**masscan** inaweza kupatikana hapa](../pentesting-network/index.html#http-port-discovery).\
Chombo kingine rafiki cha kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unachofanya ni kupitisha orodha ya domains na itajaribu kuunganishwa kwenye port 80 (http) na 443 (https). Zaidi ya hayo, unaweza kuonyesha ijaribu ports nyingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Picha za skrini**

Sasa kwa kuwa umegundua **web servers zote** zilizopo ndani ya scope (miongoni mwa **IPs** za kampuni na **domains** zote na **subdomains**) huenda **hujui pa kuanzia**. Kwa hivyo, tufanye iwe rahisi na tuanze kwa kuchukua picha za skrini za zote. Kwa **kuangalia tu** **ukurasa mkuu** unaweza kupata endpoints **za ajabu** ambazo zina **uwezekano mkubwa** wa kuwa **vulnerable**.

Ili kutekeleza wazo hili unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kisha kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kuzipitia picha zote za skrini ili ikuambie **nini huenda kina vulnerabilities**, na nini hakina.

## Public Cloud Assets

Ili kupata cloud assets zinazowezekana za kampuni unapaswa **kuanza na orodha ya keywords zinazoitambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Pia utahitaji wordlists za **maneno ya kawaida yanayotumiwa katika buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa maneno hayo unapaswa kutengeneza **permutations** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa taarifa zaidi).

Kwa wordlists hizo zilizopatikana unaweza kutumia tools kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapochunguza Cloud Assets unapaswa utafute zaidi ya buckets tu katika AWS.

### **Kutafuta vulnerabilities**

Ukikuta vitu kama **open buckets au cloud functions exposed** unapaswa **kuvikagua** na ujaribu kuona vinakupa nini na kama unaweza kuvitumia vibaya.

## Emails

Kwa **domains** na **subdomains** zilizo ndani ya scope tayari una yote unayohitaji ili kuanza kutafuta emails. Hizi ndizo **APIs** na **tools** ambazo zimenifanyia kazi vizuri zaidi ili kupata emails za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (free version)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API ya [**https://minelead.io/**](https://minelead.io/) (free version)

### **Kutafuta vulnerabilities**

Emails zitakuwa muhimu baadaye kwa **brute-force web logins na auth services** (kama SSH). Pia, zinahitajika kwa **phishings**. Zaidi ya hayo, hizi APIs zitakupa hata **info zaidi kuhusu mtu** aliye nyuma ya email, jambo ambalo ni muhimu kwa campaign ya phishing.

## Credential Leaks

Kwa **domains,** **subdomains**, na **emails** unaweza kuanza kutafuta credentials zilizovuja zamani zinazohusiana na hizo emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta vulnerabilities**

Ukikuta credentials **halali zilizovuja**, huu ni ushindi rahisi sana.

## Secrets Leaks

Credential leaks zinahusiana na hacks za makampuni ambapo **taarifa nyeti zilivuja na kuuzwa**. Hata hivyo, makampuni yanaweza kuathiriwa na **leaks nyingine** ambazo taarifa zake hazipo katika databases hizo:

### Github Leaks

Credentials na APIs zinaweza kuvujishwa katika **public repositories** za **kampuni** au za **watumiaji** wanaofanya kazi katika kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) kupakua **public repos** zote za **organization** na za **developers** wake na kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yake kiotomatiki.

**Leakos** pia inaweza kutumiwa kuendesha **gitleaks** dhidi ya **text** yote inayotolewa na **URLs passed** kwake kwani wakati mwingine **web pages pia huwa na secrets**.

#### Github Dorks

Angalia pia **ukurasa huu** kwa potential **github dorks** ambazo unaweza pia kutafuta katika organization unayoshambulia:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Wakati mwingine washambuliaji au hata wafanyakazi wata**chapisha content ya kampuni katika paste site**. Hii inaweza kuwa na au isiyo na **sensitive information**, lakini ni ya kuvutia sana kuitafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta katika zaidi ya 80 paste sites kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini za thamani huwa muhimu kila wakati ili kupata **taarifa zilizo exposed ambazo hazipaswi kuwepo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu kadhaa ya possible queries ambazo huwezi kuendesha manually. Kwa hivyo, unaweza kuchukua 10 unazopenda zaidi au unaweza kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **ili kuziendesha zote**.

_Kumbuka kwamba tools zinazotarajia kuendesha database yote kwa kutumia regular Google browser hazitaisha kamwe kwa sababu google itakuzuia haraka sana._

### **Kutafuta vulnerabilities**

Ukikuta **valid leaked** credentials au API tokens, huu ni ushindi rahisi sana.

## Public Code Vulnerabilities

Ukigundua kwamba kampuni ina **open-source code** unaweza **kuichambua** na kutafuta **vulnerabilities** ndani yake.

**Kulingana na language** kuna tofauti **tools** ambazo unaweza kutumia:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Pia kuna free services zinazoruhusu **scan public repositories**, kama vile:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Wengi wa vulnerabilities** vinavyopatikana na bug hunters huwa ndani ya **web applications**, hivyo kwa hatua hii ningependa kuzungumzia **web application testing methodology**, na unaweza [**kupata taarifa hii hapa**](../../network-services-pentesting/pentesting-web/index.html).

Pia nataka kutoa special mention kwa sehemu [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwani, ingawa hupaswi kutarajia zikupatie vulnerabilities nyeti sana, zinasaidia sana kuzitekeleza kwenye **workflows ili kupata baadhi ya web information ya awali.**

## Recapitulation

> Hongera! Katika hatua hii tayari umefanya **enumeration yote ya msingi**. Ndiyo, ni ya msingi kwa sababu bado kuna enumeration nyingi zaidi zinazoweza kufanywa (tutaona zaidi mbinu baadaye).

Kwa hiyo tayari umepata:

1. Kupata **companies** zote zilizo ndani ya scope
2. Kupata **assets** zote zinazomilikiwa na kampuni hizo (na kufanya vuln scan ikiwa zipo ndani ya scope)
3. Kupata **domains** zote zinazomilikiwa na kampuni hizo
4. Kupata **subdomains** zote za domains hizo (subdomain takeover yoyote?)
5. Kupata **IPs** zote (kutoka na **zisizotoka kwenye CDNs**) zilizo ndani ya scope.
6. Kupata **web servers** zote na kuchukua **screenshot** zao (kuna kitu cha ajabu kinachostahili kuangaliwa zaidi?)
7. Kupata **potential public cloud assets** zote zinazomilikiwa na kampuni.
8. **Emails**, **credentials leaks**, na **secret leaks** ambazo zinaweza kukupa **ushindi mkubwa kwa urahisi sana**.
9. **Pentesting webs zote ulizopata**

## **Full Recon Automatic Tools**

Kuna tools kadhaa huko ambazo zitatekeleza sehemu ya hatua zilizopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Kidogo ya zamani na haijasasishwa

## **References**

- Kozi zote za bure za [**@Jhaddix**](https://twitter.com/Jhaddix) kama [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
