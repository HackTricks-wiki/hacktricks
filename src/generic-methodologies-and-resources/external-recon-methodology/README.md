# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Ugunduzi wa Mali

> Kwa hivyo ulisema kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya upeo, na unataka kujua kampuni hii inamiliki nini hasa.

Lengo la awamu hii ni kupata **makampuni yanayomilikiwa na kampuni kuu** na kisha **mali** za makampuni haya. Ili kufanya hivyo, tutafanya:

1. Kupata ununuzi wa kampuni kuu, hii itatupa makampuni ndani ya upeo.
2. Kupata ASN (ikiwa ipo) ya kila kampuni, hii itatupa anuwai za IP zinazomilikiwa na kila kampuni.
3. Kutumia utafutaji wa reverse whois kutafuta entries nyingine (majina ya mashirika, domaini...) zinazohusiana na ya kwanza (hii inaweza kufanywa kwa njia ya kurudi).
4. Kutumia mbinu nyingine kama shodan `org` na `ssl` filters kutafuta mali nyingine (hila ya `ssl` inaweza kufanywa kwa njia ya kurudi).

### **Ununuzi**

Kwanza kabisa, tunahitaji kujua ni **makampuni gani mengine yanayomilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **tafuta** kampuni **kuu**, na **bonyeza** kwenye "**ununuzi**". Huko utaona makampuni mengine yaliyonunuliwa na kampuni kuu.\
Chaguo lingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **ununuzi**.

> Sawa, katika hatua hii unapaswa kujua makampuni yote ndani ya upeo. Hebu tuone jinsi ya kupata mali zao.

### **ASNs**

Nambari ya mfumo huru (**ASN**) ni **nambari ya kipekee** iliyotolewa kwa **mfumo huru** (AS) na **Mamlaka ya Nambari za Mtandao (IANA)**.\
**AS** inajumuisha **vizuizi** vya **anwani za IP** ambazo zina sera iliyofafanuliwa wazi kwa kufikia mitandao ya nje na zinatawaliwa na shirika moja lakini zinaweza kuwa na waendeshaji kadhaa.

Ni ya kuvutia kupata ikiwa **kampuni ina ASN yoyote iliyotolewa** ili kupata **anuwai zake za IP.** Itakuwa ya kuvutia kufanya **mtihani wa udhaifu** dhidi ya **michakato** yote ndani ya **upeo** na **kutafuta domaini** ndani ya anuwai hizi za IP.\
Unaweza **kutafuta** kwa jina la kampuni, kwa **IP** au kwa **domain** katika [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Kulingana na eneo la kampuni, viungo hivi vinaweza kuwa na manufaa kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amerika Kaskazini),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Amerika ya Kusini),** [**RIPE NCC**](https://www.ripe.net) **(Ulaya). Hata hivyo, labda taarifa zote** muhimu **(anuwai za IP na Whois)** tayari zinaonekana katika kiungo cha kwanza.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Pia, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** uchambuzi wa subdomain unakusanya na kujumlisha ASNs kiotomatiki mwishoni mwa skana.
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Kutafuta udhaifu**

Katika hatua hii tunajua **rasilimali zote ndani ya upeo**, hivyo ikiwa umepewa ruhusa unaweza kuzindua **scanner ya udhaifu** (Nessus, OpenVAS) juu ya mwenyeji wote.\
Pia, unaweza kuzindua baadhi ya [**skana za bandari**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** shodan **kupata** bandari wazi **na kulingana na kile unachokipata unapaswa** kuangalia katika kitabu hiki jinsi ya pentest huduma kadhaa zinazoweza kukimbia.\
**Pia, inaweza kuwa na faida kutaja kwamba unaweza pia kuandaa baadhi ya** orodha za majina ya mtumiaji ya kawaida **na** nywila **na kujaribu** bruteforce huduma na [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua kampuni zote ndani ya upeo na rasilimali zao, ni wakati wa kutafuta majina ya kikoa ndani ya upeo.

_Tafadhali, kumbuka kwamba katika mbinu zilizopendekezwa hapa chini unaweza pia kupata subdomains na kwamba taarifa hiyo haipaswi kupuuziliwa mbali._

Kwanza kabisa unapaswa kutafuta **kikoa kikuu**(s) cha kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kama umepata anuwai zote za IP za majina ya kikoa unaweza kujaribu kufanya **reverse dns lookups** kwenye hizo **IPs ili kupata majina mengine ya kikoa ndani ya upeo**. Jaribu kutumia seva ya dns ya mwathirika au seva maarufu ya dns (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Kwa hili kufanyika, msimamizi lazima aweke kwa mikono PTR.\
Unaweza pia kutumia chombo cha mtandaoni kwa habari hii: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata habari nyingi za kuvutia kama **jina la shirika**, **anwani**, **barua pepe**, nambari za simu... Lakini kinachovutia zaidi ni kwamba unaweza kupata **mali zaidi zinazohusiana na kampuni** ikiwa utatekeleza **reverse whois lookups kwa yoyote ya maeneo hayo** (kwa mfano, rejista nyingine za whois ambapo barua pepe hiyo inaonekana).\
Unaweza kutumia zana za mtandaoni kama:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bila malipo**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bila malipo**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bila malipo**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Bila malipo** mtandaoni, si bure API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Si bure
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Si Bure (tu **100 bure** utafutaji)
- [https://www.domainiq.com/](https://www.domainiq.com) - Si Bure

Unaweza kuendesha kazi hii kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji funguo ya API ya whoxy).\
Unaweza pia kufanya ugunduzi wa moja kwa moja wa reverse whois kwa kutumia [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Kumbuka kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya kikoa kila wakati unapata kikoa kipya.**

### **Trackers**

Ikiwa unapata **ID sawa ya tracker sawa** katika kurasa 2 tofauti unaweza kudhani kwamba **kurasa zote mbili** zinadhibitiwa na **timu moja**.\
Kwa mfano, ikiwa unaona **Google Analytics ID** sawa au **Adsense ID** sawa kwenye kurasa kadhaa.

Kuna kurasa na zana ambazo zinakuwezesha kutafuta kwa trackers hizi na zaidi:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Je, unajua kwamba tunaweza kupata maeneo yanayohusiana na sub domains kwa lengo letu kwa kutafuta hash ya ikoni ya favicon sawa? Hii ndiyo hasa inayo fanywa na chombo [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) kilichotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2). Hapa kuna jinsi ya kuitumia:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - gundua maeneo yenye hash sawa ya favicon icon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa ufupi, favihash itaturuhusu kugundua maeneo ambayo yana hash sawa ya favicon icon kama lengo letu.

Zaidi ya hayo, unaweza pia kutafuta teknolojia ukitumia hash ya favicon kama ilivyoelezwa katika [**hiki kipande cha blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Hii inamaanisha kwamba ikiwa unajua **hash ya favicon ya toleo lenye udhaifu la teknolojia ya wavuti** unaweza kutafuta katika shodan na **kupata maeneo mengine yenye udhaifu**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Hii ndiyo jinsi unavyoweza **kuhesabu hash ya favicon** ya wavuti:
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
### **Copyright / Uniq string**

Tafuta ndani ya kurasa za wavuti **nyuzi ambazo zinaweza kushirikiwa kati ya wavuti tofauti katika shirika moja**. **Nyuzi za hakimiliki** zinaweza kuwa mfano mzuri. Kisha tafuta nyuzi hiyo katika **google**, katika **vivinjari** vingine au hata katika **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Ni kawaida kuwa na kazi ya cron kama
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
kuongeza upya vyeti vyote vya kikoa kwenye seva. Hii inamaanisha kwamba hata kama CA iliyotumika kwa hili haipangi wakati ilizalishwa katika Wakati wa Uhalali, inawezekana **kupata maeneo yanayomilikiwa na kampuni moja katika kumbukumbu za uwazi wa vyeti**.\
Angalia hii [**andika kwa maelezo zaidi**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Taarifa za Barua DMARC

Unaweza kutumia wavuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au chombo kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) kupata **maeneo na subdomain zinazoshiriki taarifa sawa za dmarc**.

### **Kuchukua kwa Pasifiki**

Inaonekana ni kawaida kwa watu kupeana subdomains kwa IP ambazo zinamilikiwa na watoa huduma wa wingu na kwa wakati fulani **kupoteza anwani hiyo ya IP lakini kusahau kuondoa rekodi ya DNS**. Hivyo, tu **kuanzisha VM** katika wingu (kama Digital Ocean) utakuwa kweli **ukichukua baadhi ya subdomains**.

[**Post hii**](https://kmsec.uk/blog/passive-takeover/) inaelezea hadithi kuhusu hilo na inapendekeza skripti ambayo **inaanzisha VM katika DigitalOcean**, **inapata** **IPv4** ya mashine mpya, na **inatafuta katika Virustotal kwa rekodi za subdomain** zinazopointia kwake.

### **Njia Nyingine**

**Kumbuka kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya kikoa kila wakati unapata kikoa kipya.**

**Shodan**

Kama unavyojua jina la shirika linalomiliki nafasi ya IP. Unaweza kutafuta kwa data hiyo katika shodan ukitumia: `org:"Tesla, Inc."` Angalia mwenyeji waliopatikana kwa maeneo mapya yasiyotarajiwa katika cheti cha TLS.

Unaweza kufikia **cheti cha TLS** cha ukurasa mkuu, kupata **jina la Shirika** na kisha kutafuta jina hilo ndani ya **vyeti vya TLS** vya kurasa zote za wavuti zinazojulikana na **shodan** kwa kichujio: `ssl:"Tesla Motors"` au tumia chombo kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) ni chombo kinachotafuta **maeneo yanayohusiana** na kikoa kikuu na **subdomains** zake, ni ya kushangaza sana.

### **Kutafuta udhaifu**

Angalia kwa baadhi ya [kuchukua kikoa](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Labda kampuni fulani inatumia **kikoa fulani** lakini wame **poteza umiliki**. Jisajili (ikiwa ni ya bei nafuu) na uwajulishe kampuni hiyo.

Ikiwa utapata **kikoa chochote chenye IP tofauti** na zile ulizozipata tayari katika ugunduzi wa mali, unapaswa kufanya **skani ya msingi ya udhaifu** (ukitumia Nessus au OpenVAS) na baadhi ya [**skani ya bandari**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa **nmap/masscan/shodan**. Kulingana na huduma zipi zinazoendesha unaweza kupata katika **kitabu hiki hila za "kuvamia" hizo**.\
_Kumbuka kwamba wakati mwingine kikoa kinahostiwa ndani ya IP ambayo haidhibitiwi na mteja, hivyo si katika upeo, kuwa makini._

## Subdomains

> Tunajua kampuni zote ndani ya upeo, mali zote za kila kampuni na maeneo yote yanayohusiana na kampuni hizo.

Ni wakati wa kutafuta subdomains zote zinazowezekana za kila kikoa kilichopatikana.

> [!TIP]
> Kumbuka kwamba baadhi ya zana na mbinu za kutafuta maeneo zinaweza pia kusaidia kutafuta subdomains

### **DNS**

Hebu jaribu kupata **subdomains** kutoka kwa **rekodi za DNS**. Tunapaswa pia kujaribu kwa **Transfer ya Zone** (Ikiwa inahatarisha, unapaswa kuiripoti).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Njia ya haraka zaidi ya kupata subdomains nyingi ni kutafuta katika vyanzo vya nje. Zana zinazotumika zaidi ni zifuatazo (kwa matokeo bora, weka funguo za API):

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
Kuna **zana/APIs nyingine za kuvutia** ambazo hata kama hazijabobea moja kwa moja katika kutafuta subdomains zinaweza kuwa na manufaa katika kutafuta subdomains, kama vile:

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
- [**gau**](https://github.com/lc/gau)**:** inapata URLs zinazojulikana kutoka kwa Open Threat Exchange ya AlienVault, Wayback Machine, na Common Crawl kwa ajili ya kikoa chochote kilichotolewa.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Wanakusanya data kutoka mtandao wakitafuta faili za JS na kutoa subdomains kutoka hapo.
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

Mradi huu unatoa **bure subdomains zote zinazohusiana na programu za bug-bounty**. Unaweza kufikia data hii pia ukitumia [chaospy](https://github.com/dr-0x0x/chaospy) au hata kufikia upeo unaotumika na mradi huu [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **kulinganisha** ya zana nyingi hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu jaribu kutafuta **subdomains** mpya kwa kuburuza DNS servers kwa kutumia majina ya subdomain yanayowezekana.

Kwa hatua hii utahitaji baadhi ya **orodha za maneno ya subdomains za kawaida kama**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Na pia IPs za resolvers nzuri za DNS. Ili kuunda orodha ya resolvers wa DNS wanaoaminika unaweza kupakua resolvers kutoka [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuwasafisha. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa zana ya kwanza iliyofanya DNS brute-force kwa ufanisi. Ni haraka sana hata hivyo inakabiliwa na matokeo ya uwongo.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Hii nadhani inatumia resolver 1 tu.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni kifungashio cha `massdns`, kilichoandikwa kwa go, kinachokuruhusu kuorodhesha subdomains halali kwa kutumia bruteforce ya moja kwa moja, pamoja na kutatua subdomains kwa kushughulikia wildcard na msaada rahisi wa ingizo-tofauti.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Pia inatumia `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) inatumia asyncio kufanya brute force majina ya domain kwa njia isiyo ya kawaida.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Second DNS Brute-Force Round

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na brute-forcing, unaweza kuunda mabadiliko ya subdomains yaliyopatikana ili kujaribu kupata zaidi. Zana kadhaa ni muhimu kwa kusudi hili:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Imepewa majina ya domain na subdomains inazalisha permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Imepewa maeneo na subdomains, tengeneza permutations.
- Unaweza kupata permutations za goaltdns **wordlist** **hapa** [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Imepewa majina ya domain na subdomain, inazalisha permutations. Ikiwa faili la permutations halijatajwa, gotator itatumia faili lake mwenyewe.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kuzalisha permutations za subdomains, inaweza pia kujaribu kuzitatua (lakini ni bora kutumia zana zilizotajwa hapo awali).
- Unaweza kupata permutations za altdns **wordlist** katika [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya permutations, mutations na mabadiliko ya subdomains. Zana hii itafanya brute force matokeo (haipokei dns wild card).
- Unaweza kupata orodha ya maneno ya permutations ya dmut [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kulingana na kikoa, in **zalisha majina mapya ya subdomain** kulingana na mifumo iliyoonyeshwa ili kujaribu kugundua subdomain zaidi.

#### Uzalishaji wa permutations smart

- [**regulator**](https://github.com/cramppet/regulator): Kwa maelezo zaidi soma hii [**post**](https://cramppet.github.io/regulator/index.html) lakini kimsingi itapata **sehemu kuu** kutoka kwa **subdomains zilizogunduliwa** na itazichanganya ili kupata subdomains zaidi.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni fuzzer ya brute-force ya subdomain iliyoandaliwa na algorithm rahisi lakini yenye ufanisi inayotegemea majibu ya DNS. Inatumia seti ya data za pembejeo zilizotolewa, kama vile orodha ya maneno iliyoundwa maalum au rekodi za kihistoria za DNS/TLS, ili kuunda kwa usahihi majina zaidi ya domain yanayohusiana na kupanua zaidi katika mzunguko kulingana na taarifa zilizokusanywa wakati wa skana ya DNS.
```
echo www | subzuf facebook.com
```
### **Mchakato wa Kugundua Subdomain**

Angalia chapisho la blogu nililoandika kuhusu jinsi ya **kujiandaa kugundua subdomain** kutoka kwa domain kwa kutumia **michakato ya Trickest** ili nisiwe na haja ya kuzindua zana nyingi kwa mkono kwenye kompyuta yangu:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Makaratasi ya Kijamii**

Ikiwa umepata anwani ya IP inayojumuisha **ukurasa mmoja au kadhaa wa wavuti** zinazomilikiwa na subdomains, unaweza kujaribu **kutafuta subdomains nyingine zikiwa na wavuti katika IP hiyo** kwa kutafuta katika **vyanzo vya OSINT** kwa domains katika IP au kwa **kujaribu nguvu za VHost majina ya domain katika IP hiyo**.

#### OSINT

Unaweza kupata baadhi ya **VHosts katika IPs kwa kutumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs nyingine**.

**Brute Force**

Ikiwa unashuku kwamba subdomain fulani inaweza kufichwa katika seva ya wavuti unaweza kujaribu kujaribu nguvu:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> Kwa kutumia mbinu hii unaweza hata kufikia mwisho wa ndani/uliokithiri.

### **CORS Brute Force**

Wakati mwingine utaona kurasa ambazo hurudisha tu kichwa _**Access-Control-Allow-Origin**_ wakati jina halali la kikoa/subdomain limewekwa katika kichwa _**Origin**_. Katika hali hizi, unaweza kutumia tabia hii **kuvumbua** **subdomains** mpya.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Wakati unatafuta **subdomains** angalia kama in **elekeza** kwenye aina yoyote ya **bucket**, na katika hali hiyo [**angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa katika hatua hii utajua majina yote ya domain ndani ya upeo, jaribu [**kujaribu majina ya bucket yanayowezekana na kuangalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Unaweza **kufuatilia** kama **subdomains mpya** za domain zinaundwa kwa kufuatilia **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)inafanya.

### **Looking for vulnerabilities**

Angalia uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inaelekeza kwenye **S3 bucket**, [**angalia ruhusa**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ikiwa utapata **subdomain yenye IP tofauti** na zile ulizozipata tayari katika ugunduzi wa mali, unapaswa kufanya **skani ya msingi ya udhaifu** (ukitumia Nessus au OpenVAS) na baadhi ya [**skani za bandari**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na huduma zinazotumika unaweza kupata katika **kitabu hiki hila za "kuvamia" hizo**.\
_Kumbuka kwamba wakati mwingine subdomain inahostiwa ndani ya IP ambayo haidhibitiwi na mteja, hivyo si katika upeo, kuwa makini._

## IPs

Katika hatua za awali huenda umekuwa **ukipata baadhi ya anuwai za IP, majina ya domain na subdomains**.\
Ni wakati wa **kukusanya IP zote kutoka kwa anuwai hizo** na kwa **majina ya domain/subdomains (maswali ya DNS).**

Kwa kutumia huduma kutoka **apis za bure** zifuatazo unaweza pia kupata **IPs za awali zilizotumika na majina ya domain na subdomains**. IP hizi zinaweza bado kumilikiwa na mteja (na zinaweza kukuruhusu kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kuangalia majina ya domain yanayoelekeza kwenye anwani maalum ya IP kwa kutumia chombo [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Skani bandari zote za IP ambazo hazihusiani na CDNs** (kwa kuwa huenda usipate kitu chochote cha kuvutia huko). Katika huduma zinazotumika zilizogunduliwa unaweza kuwa **na uwezo wa kupata udhaifu**.

**Pata** [**mwongozo**](../pentesting-network/index.html) **kuhusu jinsi ya skani wenyeji.**

## Web servers hunting

> Tumegundua kampuni zote na mali zao na tunajua anuwai za IP, majina ya domain na subdomains ndani ya upeo. Ni wakati wa kutafuta seva za wavuti.

Katika hatua za awali huenda tayari umekuwa umefanya baadhi ya **recon ya IPs na majina ya domain yaliyogunduliwa**, hivyo huenda umekuwa **umepata seva zote zinazowezekana za wavuti**. Hata hivyo, ikiwa hujapata tutakuwa sasa tunaona baadhi ya **hila za haraka za kutafuta seva za wavuti** ndani ya upeo.

Tafadhali, kumbuka kwamba hii itakuwa **imeelekezwa kwa ugunduzi wa programu za wavuti**, hivyo unapaswa **kufanya udhaifu** na **skani za bandari** pia (**ikiwa inaruhusiwa** na upeo).

Njia **ya haraka** ya kugundua **bandari wazi** zinazohusiana na **seva** za wavuti kwa kutumia [**masscan** inaweza kupatikana hapa](../pentesting-network/index.html#http-port-discovery).\
Chombo kingine rafiki cha kutafuta seva za wavuti ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unapita tu orodha ya majina ya domain na itajaribu kuungana na bandari 80 (http) na 443 (https). Zaidi ya hayo, unaweza kuonyesha kujaribu bandari nyingine:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Mifano**

Sasa kwamba umepata **seva zote za wavuti** zilizopo katika upeo (katika **IPs** za kampuni na **domeni** zote na **subdomeni**) huenda **hujui wapi pa kuanzia**. Hivyo, hebu iwe rahisi na tuanze kwa kuchukua mifano ya skrini ya zote. Kwa **kuangalia tu** kwenye **ukurasa mkuu** unaweza kupata **nukta** za mwisho ambazo zinaweza kuwa **na hatari** zaidi.

Ili kutekeleza wazo lililopendekezwa unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kukagua **mifano ya skrini** zote ili kukuambia **nini kinaweza kuwa na hatari**, na nini hakina.

## Mali za Umma za Wingu

Ili kupata mali za wingu zinazoweza kuwa za kampuni unapaswa **kuanza na orodha ya maneno muhimu yanayofafanua kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Utahitaji pia orodha za maneno za **maneno ya kawaida yanayotumiwa katika makundi**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa maneno hayo unapaswa kuunda **mabadiliko** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa orodha za maneno zilizopatikana unaweza kutumia zana kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapoitafuta Mali za Wingu unapaswa **kuangalia zaidi ya makundi tu katika AWS**.

### **Kuangalia hatari**

Ikiwa unapata vitu kama **makundi ya wazi au kazi za wingu zilizofichuliwa** unapaswa **kuziingilia** na kujaribu kuona kile wanachokupa na ikiwa unaweza kuzitumia vibaya.

## Barua pepe

Pamoja na **domeni** na **subdomeni** ndani ya upeo unayo kila kitu unachohitaji **kuanza kutafuta barua pepe**. Hizi ndizo **APIs** na **zana** ambazo zimefanya kazi bora zaidi kwangu kupata barua pepe za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - na APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (toleo la bure)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (toleo la bure)
- API ya [**https://minelead.io/**](https://minelead.io/) (toleo la bure)

### **Kuangalia hatari**

Barua pepe zitakuwa na manufaa baadaye kwa **kujaribu kuingia kwenye wavuti na huduma za uthibitishaji** (kama SSH). Pia, zinahitajika kwa **phishings**. Zaidi ya hayo, hizi APIs zitakupa hata zaidi **habari kuhusu mtu** nyuma ya barua pepe, ambayo ni muhimu kwa kampeni ya phishing.

## Mvuvi wa Akida

Pamoja na **domeni,** **subdomeni**, na **barua pepe** unaweza kuanza kutafuta akida zilizovuja katika siku za nyuma zinazohusiana na hizo barua pepe:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kuangalia hatari**

Ikiwa unapata **akida zilizovuja** halali, hii ni ushindi rahisi sana.

## Mvuvi wa Siri

Mvuvi wa akida unahusiana na uvunjaji wa kampuni ambapo **habari nyeti ilivuja na kuuzwa**. Hata hivyo, kampuni zinaweza kuathiriwa na **mvuvi mwingine** ambao habari yake haipo katika hizo databasi:

### Mvuvi wa Github

Akida na APIs zinaweza kuvuja katika **hifadhi za umma** za **kampuni** au za **watumiaji** wanaofanya kazi kwa kampuni hiyo ya github.\
Unaweza kutumia **zana** [**Leakos**](https://github.com/carlospolop/Leakos) **kupakua** hifadhi zote za **umma** za **taasisi** na za **waendelezaji** wake na kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yao kiotomatiki.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **maandishi** yaliyotolewa **URLs yaliyopitishwa** kwake kwani wakati mwingine **kurasa za wavuti pia zina siri**.

#### Github Dorks

Angalia pia **ukurasa** huu kwa **github dorks** zinazoweza kutafutwa katika shirika unaloshambulia:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Mvuvi wa Pastes

Wakati mwingine washambuliaji au wafanyakazi tu wata **chapisha maudhui ya kampuni katika tovuti ya paste**. Hii inaweza kuwa na au isiwe na **habari nyeti**, lakini ni ya kuvutia kutafuta.\
Unaweza kutumia zana [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta katika zaidi ya tovuti 80 za paste kwa wakati mmoja.

### Mvuvi wa Google

Dorks za zamani lakini za dhahabu daima ni muhimu kupata **habari iliyofichuliwa ambayo haipaswi kuwa hapo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelezo kadhaa **elfu** ya maswali yanayoweza kutekelezwa ambayo huwezi kuyatekeleza kwa mikono. Hivyo, unaweza kuchukua 10 zako unazopenda au unaweza kutumia **zana kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuziendesha zote**.

_Kumbuka kwamba zana zinazotarajia kuendesha database yote kwa kutumia kivinjari cha kawaida cha Google hazitamalizika kamwe kwani google itakuzuia haraka sana._

### **Kuangalia hatari**

Ikiwa unapata **akida zilizovuja** halali au token za API, hii ni ushindi rahisi sana.

## Hatari za Kanuni za Umma

Ikiwa umepata kwamba kampuni ina **kanuni za chanzo wazi** unaweza **kuchambua** na kutafuta **hatari** juu yake.

**Kulingana na lugha** kuna zana tofauti unazoweza kutumia:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Pia kuna huduma za bure zinazokuruhusu **kuchunguza hifadhi za umma**, kama:

- [**Snyk**](https://app.snyk.io/)

## [**Mbinu ya Pentesting Wavuti**](../../network-services-pentesting/pentesting-web/index.html)

**Wingi wa hatari** zinazopatikana na wawindaji wa makosa ziko ndani ya **maombi ya wavuti**, hivyo katika hatua hii ningependa kuzungumzia **mbinu ya kupima maombi ya wavuti**, na unaweza [**kupata habari hii hapa**](../../network-services-pentesting/pentesting-web/index.html).

Ningependa pia kutoa kumbukumbu maalum kwa sehemu [**Zana za Skana za Kiotomatiki za Wavuti**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwani, usitarajie zipate hatari nyeti sana, zinakuwa na manufaa kutekeleza kwenye **mchakato wa kupata habari za awali za wavuti.**

## Muhtasari

> Hongera! Katika hatua hii tayari umetekeleza **kuhesabu msingi**. Ndio, ni msingi kwa sababu kuna hesabu zaidi inayoweza kufanywa (tutaona hila zaidi baadaye).

Hivyo tayari umepata:

1. Kupata **kampuni zote** ndani ya upeo
2. Kupata **mali zote** zinazomilikiwa na kampuni (na kufanya skana za hatari ikiwa ziko ndani ya upeo)
3. Kupata **domeni zote** zinazomilikiwa na kampuni
4. Kupata **subdomeni zote** za domeni (je, kuna kuchukuliwa kwa subdomeni?)
5. Kupata **IPs** zote (kutoka na **sio kutoka CDNs**) ndani ya upeo.
6. Kupata **seva zote za wavuti** na kuchukua **mifano ya skrini** zao (je, kuna kitu chochote cha ajabu kinachostahili kuangaliwa kwa undani?)
7. Kupata **mali zote za umma za wingu** zinazomilikiwa na kampuni.
8. **Barua pepe**, **mvuvi wa akida**, na **mvuvi wa siri** ambazo zinaweza kukupa **ushindi mkubwa kwa urahisi sana**.
9. **Pentesting wavuti zote ulizozipata**

## **Zana za Kiotomatiki za Upelelezi Kamili**

Kuna zana kadhaa huko nje ambazo zitatekeleza sehemu ya vitendo vilivyopendekezwa dhidi ya upeo fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Kidogo zamani na haijasasishwa

## **Marejeleo**

- Kozi zote za bure za [**@Jhaddix**](https://twitter.com/Jhaddix) kama [**Mbinu ya Wawindaji wa Makosa v4.0 - Toleo la Upelelezi**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
