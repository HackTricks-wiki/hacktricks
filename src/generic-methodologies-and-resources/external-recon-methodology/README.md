# Methodolojia ya External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ugunduzi wa assets

> Hivyo uliambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kubaini kampuni hii kwa kweli inamiliki nini.

Lengo la hatua hii ni kupata kampuni zote **zinazomilikiwa na kampuni kuu** na kisha **assets** zote za kampuni hizi. Ili kufanya hivyo, tutafanya:

1. Pata acquisitions za kampuni kuu, hii itatupa kampuni zilizo ndani ya scope.
2. Pata ASN (kama ipo) ya kila kampuni, hii itatupa IP ranges zinazomilikiwa na kila kampuni
3. Tumia reverse whois lookups kutafuta entries nyingine (majina ya organisation, domains...) zinazohusiana na ya kwanza (hii inaweza kufanywa recursively)
4. Tumia mbinu nyingine kama shodan `org`na `ssl`filters kutafuta assets nyingine (ujanja wa `ssl` unaweza kufanywa recursively).

### **Acquisitions**

Kwanza kabisa, tunahitaji kujua ni **kampuni zipi nyingine zinamilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **tafuta** **kampuni kuu**, na **bonyeza** "**acquisitions**". Hapo utaona kampuni nyingine zilizonunuliwa na ile kuu.\
Chaguo jingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, angalia **SEC/EDGAR filings**, kurasa za **investor relations**, au sajili za kampuni za eneo husika (mfano, **Companies House** nchini Uingereza).\
Kwa miti ya kampuni za kimataifa na subsidiaries, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na hifadhidata ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, kwa hatua hii unapaswa kujua kampuni zote zilizo ndani ya scope. Hebu tubaini jinsi ya kupata assets zao.

### **ASNs**

Namba ya autonomous system (**ASN**) ni **namba ya kipekee** inayotolewa kwa **autonomous system** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
**AS** inajumuisha **blocks** za **IP addresses** ambazo zina sera iliyoainishwa wazi ya kufikia mitandao ya nje na husimamiwa na shirika moja lakini zinaweza kujumuisha waendeshaji kadhaa.

Ni jambo la kuvutia kubaini kama **kampuni imepewa ASN yoyote** ili kupata **IP ranges** zake.\
Itakuwa muhimu kufanya **vulnerability test** dhidi ya **hosts** zote zilizo ndani ya **scope** na **kutafuta domains** ndani ya IP hizi.\
Unaweza **kutafuta** kwa jina la kampuni, kwa **IP** au kwa **domain** katika [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na eneo la kampuni viungo hivi vinaweza kusaidia kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Hata hivyo, huenda taarifa zote muhimu** (IP ranges na Whois)** tayari zinaonekana kwenye kiungo cha kwanza.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration hujumakusanya na kufupisha ASNs kiotomatiki mwishoni mwa scan.
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
Unaweza pia kupata safu za IP za shirika kwa kutumia [http://asnlookup.com/](http://asnlookup.com) (ina API ya bure).\
Unaweza kupata IP na ASN ya domain kwa kutumia [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta udhaifu**

Kwa wakati huu tunajua **rasilimali zote zilizo ndani ya scope**, kwa hivyo kama umepewa ruhusa unaweza kuzindua **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) juu ya hosts zote.\
Pia, unaweza kuzindua baadhi ya [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** Shodan, Censys, au ZoomEye **ili kupata** ports zilizo wazi **na kulingana na utakachopata unapaswa** kuangalia kwenye kitabu hiki jinsi ya pentest huduma kadhaa zinazoweza kuwa zinaendeshwa.\
**Pia, inaweza kuwa muhimu kutaja kwamba unaweza pia kuandaa baadhi ya** default username **na** passwords **lists na kujaribu** bruteforce huduma kwa kutumia [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua kampuni zote zilizo ndani ya scope na rasilimali zake, ni wakati wa kutafuta domains zilizo ndani ya scope.

_Tafadhali, kumbuka kwamba katika mbinu zifuatazo zilizo kusudiwa unaweza pia kupata subdomains na taarifa hiyo haipaswi kudharauliwa._

Kwanza kabisa unapaswa kutafuta **main domain**(s) za kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kwa kuwa umepata safu zote za IP za domains unaweza kujaribu kufanya **reverse dns lookups** kwenye hizo **IPs ili kupata domains zaidi zilizo ndani ya scope**. Jaribu kutumia baadhi ya dns server ya mhanga au baadhi ya well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Ili hili lifanye kazi, msimamizi lazima awashe PTR kwa mikono.\
Unaweza pia kutumia zana ya mtandaoni kwa taarifa hii: [http://ptrarchive.com/](http://ptrarchive.com).\
Kwa masafa makubwa, zana kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) ni muhimu kwa kuendesha reverse lookups na enrichment kiotomatiki.

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata taarifa nyingi za kuvutia kama **organisation name**, **address**, **emails**, nambari za simu... Lakini kilicho hata cha kuvutia zaidi ni kwamba unaweza kupata **more assets related to the company** ukifanya **reverse whois lookups by any of those fields** (kwa mfano registries nyingine za whois ambako email ileile inaonekana).\
Unaweza kutumia zana za mtandaoni kama:

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

Unaweza kuendesha kazi hii kiotomatiki kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji whoxy API key).\
Unaweza pia kufanya reverse whois discovery ya kiotomatiki kwa [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Kumbuka kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya domain kila wakati unapopata domain mpya.**

### **Trackers**

Ukipata **same ID of the same tracker** kwenye kurasa 2 tofauti unaweza kudhani kwamba **kurasa zote mbili** zinasimamiwa na timu ileile.\
Kwa mfano, ukiiona **Google Analytics ID** ileile au **Adsense ID** ileile kwenye kurasa kadhaa.

Kuna kurasa na zana kadhaa zinazokuwezesha kutafuta kwa trackers hizi na zaidi:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (hupata sites zinazohusiana kwa analytics/trackers zinazoshirikiwa)

### **Favicon**

Je, ulijua kwamba tunaweza kupata related domains na subdomains za lengo letu kwa kuangalia favicon icon hash ileile? Hivi ndivyo zana [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) iliyotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2) hufanya. Hivi ndivyo ya kutumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa ufupi, favihash itaturuhusu kugundua domains ambazo zina favicon icon hash sawa na ya lengo letu.

Zaidi ya hayo, unaweza pia kutafuta technologies ukitumia favicon hash kama ilivyoelezewa katika [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hiyo ina maana kwamba ikiwa unajua **hash ya favicon ya toleo lenye udhaifu la web tech** unaweza kutafuta ikiwa katika shodan na **kupata maeneo zaidi yenye udhaifu**:
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
Unaweza pia kupata favicon hashes kwa kiwango kikubwa kwa kutumia [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) kisha kufanya pivot katika Shodan/Censys.

### **Copyright / Uniq string**

Tafuta ndani ya kurasa za web **strings ambazo zinaweza kushirikiwa kati ya webs tofauti katika shirika hilohilo**. **Copyright string** inaweza kuwa mfano mzuri. Kisha tafuta string hiyo katika **google**, katika **browsers** nyingine au hata katika **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Ni kawaida kuwa na cron job kama vile
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
ili kufanya upya vyeti vyote vya domain kwenye server. Hii inamaanisha kwamba hata kama CA iliyotumika kwa hili haijaweka muda ilipozalishwa ndani ya Validity time, inawezekana **kupata domains zinazomilikiwa na kampuni ileile katika certificate transparency logs**.\
Angalia [**writeup hii kwa taarifa zaidi**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Pia tumia **certificate transparency** logs moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Taarifa za Mail DMARC

Unaweza kutumia web kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au tool kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) ili kupata **domains na subdomain zinazoshiriki taarifa ileile ya dmarc**.\
Vifaa vingine muhimu ni [**spoofcheck**](https://github.com/BishopFox/spoofcheck) na [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Inaonekana ni kawaida kwa watu kuassign subdomains kwa IPs zinazomilikiwa na cloud providers na wakati fulani **kupoteza hiyo IP address lakini kusahau kuondoa DNS record**. Kwa hivyo, kwa **kuanzisha VM** kwenye cloud (kama Digital Ocean), kwa kweli utakuwa **unateka baadhi ya subdomain(s)**.

[**Post hii**](https://kmsec.uk/blog/passive-takeover/) inaeleza hadithi kuhusu hilo na inapendekeza script ambayo **inaanzisha VM katika DigitalOcean**, **inapata** **IPv4** ya machine mpya, na **kutafuta katika Virustotal kwa records za subdomain** zinazoelekeza kwake.

### **Njia nyingine**

**Kumbuka kwamba unaweza kutumia technique hii kugundua majina zaidi ya domain kila wakati unapopata domain mpya.**

**Shodan**

Kama tayari unajua jina la organisation inayomiliki IP space. Unaweza kutafuta kwa data hiyo kwenye shodan kwa kutumia: `org:"Tesla, Inc."` Kagua hosts zilizopatikana kwa domains mpya zisizotarajiwa ndani ya TLS certificate.

Unaweza kufikia **TLS certificate** ya main web page, kupata jina la **Organisation** kisha kutafuta jina hilo ndani ya **TLS certificates** za kurasa zote za web zinazojulikana na **shodan** kwa kutumia filter : `ssl:"Tesla Motors"` au tumia tool kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ni tool inayotafuta **domains zinazohusiana** na main domain na **subdomains** zake, ya kushangaza sana.

**Passive DNS / Historical DNS**

Data ya Passive DNS ni nzuri kupata **records za zamani na zilizosahaulika** ambazo bado zinajibu au zinazoweza kutwaliwa. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Kutafuta vulnerabilities**

Kagua kwa baadhi ya [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Huenda kampuni fulani **inatumia domain fulani** lakini **imepoteza ownership** yake. Isajili tu (kama ni nafuu vya kutosha) na iwarifu kampuni.

Ukikuta **domain yoyote yenye IP tofauti** na zile ambazo tayari umepata katika asset discovery, unapaswa kufanya **basic vulnerability scan** (kwa kutumia Nessus au OpenVAS) na pia **port scan** fulani [**kwa nmap/masscan/shodan**](../pentesting-network/index.html#discovering-hosts-from-the-outside). Kulingana na huduma zinazofanya kazi unaweza kupata katika **kitabu hiki baadhi ya tricks za "kuwashambulia"**.\
_Kumbuka kwamba wakati mwingine domain hostiwa ndani ya IP ambayo haidhibitiwi na client, kwa hiyo haiko ndani ya scope, kuwa makini._

## Subdomains

> Tunajua kampuni zote zilizo ndani ya scope, assets zote za kila kampuni na domains zote zinazohusiana na kampuni hizo.

Ni wakati wa kupata subdomains zote zinazowezekana za kila domain iliyopatikana.

> [!TIP]
> Kumbuka kwamba baadhi ya tools na techniques za kupata domains pia zinaweza kusaidia kupata subdomains

### **DNS**

Hebu jaribu kupata **subdomains** kutoka kwenye records za **DNS**. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa ina vulnerability, unapaswa kuiripoti).
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
Kuna **zana zingine/APIs za kuvutia** ambazo hata kama hazijabobea moja kwa moja katika kutafuta subdomains bado zinaweza kuwa muhimu kupata subdomains, kama:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Hutumia API [https://sonar.omnisint.io](https://sonar.omnisint.io) kupata subdomains
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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Zinafagia tovuti kwa kutafuta faili za JS na kutoa subdomains kutoka hapo.
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

Project hii inatoa **bure subdomains zote zinazohusiana na bug-bounty programs**. Unaweza pia kufikia data hii kwa kutumia [chaospy](https://github.com/dr-0x0x/chaospy) au hata kufikia scope inayotumiwa na project hii [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **comparison** ya nyingi kati ya hizi tools hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Tujaribu kupata **subdomains** mpya kwa brute-forcing DNS servers kwa kutumia majina yanayowezekana ya subdomains.

Kwa hatua hii utahitaji baadhi ya **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Na pia IPs za DNS resolvers wazuri. Ili kutengeneza orodha ya trusted DNS resolvers unaweza kupakua resolvers kutoka [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzichuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ndiyo ilikuwa zana ya kwanza iliyofanya DNS brute-force kwa ufanisi. Ni ya haraka sana lakini huwa na false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hiki nadhani hutumia tu resolver 1
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper ya `massdns`, iliyoandikwa kwa go, inayokuwezesha kuorodhesha subdomains halali kwa kutumia active bruteforce, pamoja na kutatua subdomains zenye wildcard handling na support rahisi ya input-output.
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
### Mzunguko wa Pili wa DNS Brute-Force

Baada ya kupata subdomains kwa kutumia open sources na brute-forcing, unaweza kuunda mabadiliko ya subdomains zilizopatikana ili kujaribu kupata zaidi. Zana kadhaa ni muhimu kwa madhumuni haya:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Kwa kupewa domains na subdomains hutengeneza permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Ukipewa domains na subdomains tengeneza permutations.
- Unaweza kupata **wordlist** ya permutations za goaltdns [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Ukipewa domains na subdomains tengeneza permutations. Ikiwa hakuna faili ya permutations iliyoonyeshwa, gotator itatumia yake yenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kutengeneza mabadiliko ya subdomains, pia inaweza kujaribu kuyarejesha (lakini ni bora kutumia zana zilizotajwa awali).
- Unaweza kupata **wordlist** ya mabadiliko ya altdns [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Chombo kingine cha kufanya permutations, mutations na alteration za subdomains. Chombo hiki kitafanya brute force ya matokeo (hakina support ya dns wild card).
- Unaweza kupata wordlist ya permutations ya dmut katika [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kulingana na domain, **huzalisha majina mapya yanayowezekana ya subdomains** kulingana na pattern zilizobainishwa ili kujaribu kugundua subdomains zaidi.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Kwa maelezo zaidi soma [**post**](https://cramppet.github.io/regulator/index.html) hii, lakini kwa msingi itachukua **main parts** kutoka kwa **discovered subdomains** na kuziunganisha ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni subdomain brute-force fuzzer iliyounganishwa na algorithm rahisi sana lakini yenye ufanisi inayoongozwa na majibu ya DNS. Inatumia seti ya data ya ingizo iliyotolewa, kama vile tailored wordlist au rekodi za kihistoria za DNS/TLS, ili kuunda kwa usahihi domain names zaidi zinazolingana na kuzipanua zaidi katika mzunguko kulingana na taarifa zilizokusanywa wakati wa DNS scan.
```
echo www | subzuf facebook.com
```
### **Kazi ya Kugundua Subdomain**

Angalia chapisho hili la blogu nililoandika kuhusu jinsi ya **kufanya otomatiki kugundua subdomain** kutoka kwenye domain kwa kutumia **Trickest workflows** ili nisiwe na haja ya kuzindua kwa mikono zana nyingi kwenye kompyuta yangu:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Ukipata anwani ya IP yenye **ukurasa mmoja au zaidi wa web** unaohusiana na subdomains, unaweza kujaribu **kupata subdomains nyingine zenye webs kwenye IP hiyo** kwa kuangalia **vyanzo vya OSINT** kwa domains katika IP au kwa **kutumia brute-force majina ya domain ya VHost kwenye IP hiyo**.

#### **OSINT**

Unaweza kupata baadhi ya **VHosts katika IPs kwa kutumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs nyingine**.

**Brute Force**

Ukiyashuku kuwa subdomain fulani inaweza kujificha kwenye web server unaweza kujaribu kuifanya brute force:

Wakati **IP inaredirect kwenda kwenye hostname** (name-based vhosts), fanya fuzz kwenye `Host` header moja kwa moja na uruhusu ffuf **auto-calibrate** ili kuonyesha responses zinazotofautiana na default vhost:
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

Wakati mwingine utaona kurasa ambazo hurudisha header _**Access-Control-Allow-Origin**_ tu pale domain/subdomain halali inapowekwa kwenye header ya _**Origin**_. Katika hali hizi, unaweza kutumia vibaya tabia hii ili **kugundua** **subdomains** mpya.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Wakati wa kutafuta **subdomains** angalia ikiwa inatazama kwenye aina yoyote ya **bucket**, na katika hali hiyo [**angalia permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa kufikia hatua hii utakuwa unajua domains zote ndani ya scope, jaribu [**brute force majina yanayowezekana ya bucket na angalia permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Unaweza **monitor** ikiwa **new subdomains** za domain zimeundwa kwa kufuatilia Logs za **Certificate Transparency** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)hufanya.

### **Looking for vulnerabilities**

Angalia uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inaelekeza kwenye **S3 bucket**, [**angalia permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ukikuta **subdomain yenye IP tofauti** na zile ambazo tayari umezipata katika assets discovery, unapaswa kufanya **basic vulnerability scan** (ukitumia Nessus au OpenVAS) na pia [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa **nmap/masscan/shodan**. Kulingana na huduma zinazoendeshwa unaweza kupata **katika kitabu hiki mbinu za "kuattack"** hizo huduma.\
_Kumbuka kwamba wakati mwingine subdomain inahostiwa ndani ya IP ambayo haidhibitiwi na client, kwa hiyo haimo kwenye scope, kuwa makini._

## IPs

Katika hatua za mwanzo huenda ulikuwa ume**pata baadhi ya IP ranges, domains na subdomains**.\
Ni wakati wa **kukusanya upya IPs zote kutoka kwenye hizo ranges** na kwa **domains/subdomains (DNS queries).**

Kwa kutumia services kutoka kwenye **free apis** zifuatazo unaweza pia kupata **previous IPs zilizotumiwa na domains na subdomains**. IPs hizi bado zinaweza kumilikiwa na client (na zinaweza kukuruhusu kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kuangalia domains zinazolenga IP address mahususi kwa kutumia tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Fanya port scan kwa IPs zote ambazo hazihusiani na CDNs** (kwa sababu kwa uwezekano mkubwa hutapata kitu cha kuvutia huko). Katika services zinazoendeshwa zilizogunduliwa unaweza **kuwa na uwezo wa kupata vulnerabilities**.

**Tafuta** [**guide**](../pentesting-network/index.html) **kuhusu jinsi ya kuchanganua hosts.**

## Web servers hunting

> Tumepata kampuni zote na assets zao na tunajua IP ranges, domains na subdomains ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizopita huenda tayari ulikuwa umefanya baadhi ya **recon ya IPs na domains zilizogunduliwa**, hivyo huenda **tayari ulikuwa umepata web servers zote zinazowezekana**. Hata hivyo, ikiwa hujafanya hivyo, sasa tutaona baadhi ya **njia za haraka za kutafuta web servers** ndani ya scope.

Tafadhali, kumbuka kwamba hii itakuwa **imeelekezwa kwenye ugunduzi wa web apps**, kwa hiyo unapaswa **kufanya vulnerability** na **port scanning** pia (**kama inaruhusiwa** na scope).

**Njia ya haraka** ya kugundua **ports wazi** zinazohusiana na **web** servers kwa kutumia [**masscan** inaweza kupatikana hapa](../pentesting-network/index.html#http-port-discovery).\
Chombo kingine rafiki cha kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unachohitaji ni kupitisha orodha ya domains na itajaribu kuunganisha kwenye port 80 (http) na 443 (https). Zaidi ya hayo, unaweza kuonyesha ujaribu ports nyingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Sasa kwa kuwa umegundua **web servers zote** zilizo ndani ya scope (miongoni mwa **IPs** za kampuni na **domains** zote pamoja na **subdomains**) huenda **hujui pa kuanzia**. Hivyo, tufanye iwe rahisi na tuanze kwa kuchukua screenshots za zote. Kwa **kuangalia** tu **main page** unaweza kupata endpoints **za ajabu** ambazo zina **uwezekano zaidi** wa kuwa **vulnerable**.

Ili kutekeleza wazo hili unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kuchambua **screenshots** zote ili kukuambia **zipi zina uwezekano wa kuwa na vulnerabilities**, na zipi hazina.

## Public Cloud Assets

Ili kupata potential cloud assets zinazomilikiwa na kampuni unapaswa **kuanza na orodha ya keywords zinazoitambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Pia utahitaji wordlists za **maneno ya kawaida yanayotumiwa kwenye buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa kutumia maneno hayo unapaswa kutengeneza **permutations** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa wordlists zinazotokana na hapo unaweza kutumia tools kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kuwa unapotafuta Cloud Assets unapaswa u**tafuta zaidi ya buckets tu kwenye AWS**.

### **Looking for vulnerabilities**

Ukipata vitu kama **open buckets au cloud functions exposed** unapaswa **kuzifikia** na ujaribu kuona zinakupa nini na kama unaweza kuzitumia vibaya.

## Emails

Kwa kutumia **domains** na **subdomains** zilizo ndani ya scope, kimsingi una kila kitu unach**ohitaji kuanza kutafuta emails**. Hizi ndizo **APIs** na **tools** zilizonifanyia kazi vizuri zaidi kupata emails za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (free version)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API ya [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails zitakuwa muhimu baadaye kwa **brute-force web logins na auth services** (kama SSH). Pia zinahitajika kwa **phishings**. Zaidi ya hayo, hizi APIs zitakupa hata **info zaidi kuhusu mtu** aliye nyuma ya email, jambo ambalo linafaa kwa campaign ya phishing.

## Credential Leaks

Kwa kutumia **domains,** **subdomains**, na **emails** unaweza kuanza kutafuta credentials zilizovuja awali zinazohusiana na hizo emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Ukipata credentials **halali zilizovuja**, huu ni ushindi rahisi sana.

## Secrets Leaks

Credential leaks zinahusiana na hacks za kampuni ambapo **sensitive information ilivuja na kuuzwa**. Hata hivyo, kampuni zinaweza kuathiriwa na **leaks nyingine** ambazo info yake haipo kwenye databases hizo:

### Github Leaks

Credentials na APIs zinaweza kuvuja kwenye **public repositories** za **kampuni** au za **users** wanaofanya kazi kwa kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) kupakua **public repos** zote za **organization** na za **developers** wake na kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yake kiotomatiki.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **text** zote za **URLs zilizopewa** kama wakati mwingine **web pages pia huwa na secrets**.

#### Github Dorks

Angalia pia **page** hili kwa potential **github dorks** ambazo unaweza pia kutafuta kwenye organization unayoshambulia:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Wakati mwingine attackers au wafanyakazi tu wata**chapisha content ya kampuni kwenye paste site**. Hii inaweza kuwa na au isiyo na **sensitive information**, lakini ni ya kuvutia sana kuitafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta kwenye zaidi ya paste sites 80 kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini za thamani huwa muhimu kila wakati kupata **exposed information ambayo haikupaswa kuwa hapo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu kadhaa ya possible queries ambazo huwezi kuziendesha manually. Hivyo, unaweza kuchukua zile 10 unazopenda zaidi au unaweza kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuziendesha zote**.

_Kumbuka kwamba tools zinazotarajia kuendesha database yote kwa kutumia browser ya kawaida ya Google hazitaisha kamwe kwani google itakubana haraka sana._

### **Looking for vulnerabilities**

Ukipata credentials **halali zilizovuja** au API tokens, huu ni ushindi rahisi sana.

## Public Code Vulnerabilities

Ukipata kwamba kampuni ina **open-source code** unaweza **kuichambua** na kutafuta **vulnerabilities** humo.

**Kulingana na language** kuna **tools** tofauti unazoweza kutumia:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Pia kuna free services zinazokuwezesha **kuchanganua public repositories**, kama vile:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Wengi wa vulnerabilities** zinazopatikana na bug hunters ziko ndani ya **web applications**, kwa hivyo hapa ningependa kuzungumzia **web application testing methodology**, na unaweza [**kupata taarifa hii hapa**](../../network-services-pentesting/pentesting-web/index.html).

Pia nataka kutaja kwa umakini sehemu ya [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwani, ingawa hupaswi kutarajia zikupatie vulnerabilities kali sana, zinafaa sana kuziingiza kwenye **workflows ili kupata baadhi ya taarifa za awali kuhusu web**.

## Recapitulation

> Hongera! Hadi sasa tayari umefanya **all the basic enumeration**. Ndiyo, ni basic kwa sababu enumerations nyingi zaidi zinaweza kufanywa (tutaona tricks zaidi baadaye).

Kwa hiyo tayari ume:

1. Kupata **kampuni zote** zilizo ndani ya scope
2. Kupata **assets zote** zinazomilikiwa na kampuni (na kufanya vuln scan ikiwa iko ndani ya scope)
3. Kupata **domains zote** zinazomilikiwa na kampuni
4. Kupata **subdomains zote** za domains (subdomain takeover yoyote?)
5. Kupata **IPs zote** (kutoka na **zisizo kutoka CDNs**) zilizo ndani ya scope.
6. Kupata **web servers zote** na kuchukua **screenshot** zake (kuna chochote cha ajabu kinachostahili kuangaliwa zaidi?)
7. Kupata **potential public cloud assets zote** zinazomilikiwa na kampuni.
8. **Emails**, **credentials leaks**, na **secret leaks** ambazo zinaweza kukupatia **ushindi mkubwa kwa urahisi sana**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Kuna tools kadhaa huko ambazo zitafanya sehemu ya vitendo vilivyopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Kidogo ni ya zamani na haijasasishwa

## **References**

- Kozi zote za bure za [**@Jhaddix**](https://twitter.com/Jhaddix) kama [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
