# Mbinu ya External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ugunduzi wa assets

> Kwa hiyo umeambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kubaini kampuni hiyo inamiliki nini hasa.

Lengo la awamu hii ni kupata **kampuni zote zinazomilikiwa na kampuni kuu**, kisha **assets** zote za kampuni hizo. Ili kufanya hivyo, tutafanya yafuatayo:<sup>[[1]](#references)</sup>

1. Tafuta ununuzi uliofanywa na kampuni kuu; hii itatupatia kampuni zilizo ndani ya scope.
2. Tafuta ASN (ikiwa ipo) ya kila kampuni; hii itatupatia masafa ya IP yanayomilikiwa na kila kampuni.
3. Tumia reverse whois lookups kutafuta maingizo mengine (majina ya mashirika, domains...) yanayohusiana na la kwanza (hili linaweza kufanywa kwa kurudia).
4. Tumia mbinu nyingine kama vichujio vya `org` na `ssl` vya shodan kutafuta assets nyingine (mbinu ya `ssl` inaweza kufanywa kwa kurudia).

### **Ununuzi**

Kwanza, tunahitaji kujua **ni kampuni gani nyingine zinazomilikiwa na kampuni kuu**.\
Njia moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **kutafuta** **kampuni kuu**, kisha **kubofya** "**acquisitions**". Hapo utaona kampuni nyingine zilizonunuliwa na kampuni kuu.\
Njia nyingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, angalia **nyaraka za SEC/EDGAR**, kurasa za **mahusiano na wawekezaji**, au sajili za kampuni za eneo husika (kwa mfano, **Companies House** nchini UK).\
Ili kuona muundo wa kampuni za kimataifa na kampuni tanzu, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na hifadhidata ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, kufikia hapa unapaswa kujua kampuni zote zilizo ndani ya scope. Hebu tubaini jinsi ya kupata assets zake.

### **ASNs**

Nambari ya mfumo huru (**ASN**) ni **nambari ya kipekee** inayotolewa kwa **mfumo huru** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
**AS** ina **vitalu** vya **anwani za IP** vyenye sera iliyobainishwa wazi ya kufikia mitandao ya nje, na husimamiwa na shirika moja lakini inaweza kujumuisha waendeshaji kadhaa.

Ni muhimu kubaini kama **kampuni imepewa ASN yoyote** ili kupata **masafa yake ya IP.** Itakuwa muhimu kufanya **jaribio la udhaifu** dhidi ya **host** zote zilizo ndani ya **scope** na **kutafuta domains** ndani ya IP hizi.\
Unaweza **kutafuta** kwa **jina** la kampuni, **IP** au **domain** kwenye [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na eneo la kampuni, viungo hivi vinaweza kusaidia kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amerika Kaskazini),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Amerika ya Kusini),** [**RIPE NCC**](https://www.ripe.net) **(Ulaya). Hata hivyo, huenda taarifa zote muhimu** (masafa ya IP na Whois) **tayari zinaonekana kwenye kiungo cha kwanza.**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Pia, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration hukusanya na kutoa muhtasari wa ASNs kiotomatiki mwishoni mwa scan.

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

### **Kutafuta vulnerabilities**

Kwa wakati huu tunajua **assets zote zilizo ndani ya scope**, kwa hivyo ikiwa una ruhusa, unaweza kuendesha **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) kwenye hosts zote.\
Pia, unaweza kuendesha baadhi ya [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** Shodan, Censys, au ZoomEye **ili kupata** open ports **na kulingana na utakachopata, unapaswa** kuangalia katika kitabu hiki jinsi ya kufanya pentest kwenye huduma mbalimbali zinazoweza kuwa zinaendeshwa.\
**Pia, inafaa kutaja kwamba unaweza pia kuandaa orodha za** default username **na** passwords **kisha ujaribu kufanya** bruteforce kwenye huduma kwa kutumia [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua kampuni zote zilizo ndani ya scope na assets zake; sasa ni wakati wa kutafuta domains zilizo ndani ya scope.

_Tafadhali kumbuka kuwa katika mbinu zinazopendekezwa hapa chini unaweza pia kupata subdomains, na hupaswi kupuuza taarifa hizo._

Kwanza kabisa, unapaswa kutafuta **main domain**(s) za kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kwa kuwa umepata safu zote za IP za domains, unaweza kujaribu kufanya **reverse dns lookups** kwenye **IP hizo ili kupata domains zaidi zilizo ndani ya scope**. Jaribu kutumia dns server ya mwathiriwa au dns server inayojulikana sana (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Ili hili lifanye kazi, msimamizi lazima awashe PTR mwenyewe.\
Unaweza pia kutumia zana ya mtandaoni kupata maelezo haya: [http://ptrarchive.com/](http://ptrarchive.com).\
Kwa ranges kubwa, zana kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) zinafaa kwa kujiendeshea reverse lookups na uongezaji wa taarifa.

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata **taarifa** nyingi za kuvutia kama vile **jina la shirika**, **anwani**, **barua pepe**, nambari za simu... Lakini jambo la kuvutia zaidi ni kwamba unaweza kupata **assets zaidi zinazohusiana na kampuni** ukifanya **reverse whois lookups kwa kutumia mojawapo ya sehemu hizo** (kwa mfano, rekodi nyingine za whois ambako barua pepe hiyo hiyo inaonekana).\
Unaweza kutumia zana za mtandaoni kama hizi:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bila malipo** (Web na API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bila malipo**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bila malipo**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bila malipo**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **bila malipo**, API si ya bure.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Si ya bure
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Si ya bure (utafutaji **100 wa bure** pekee)
- [https://www.domainiq.com/](https://www.domainiq.com) - Si ya bure
- [https://securitytrails.com/](https://securitytrails.com/) - Si ya bure (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Si ya bure (API)

Unaweza kujiendeshea kazi hii kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji ufunguo wa API wa whoxy).\
Unaweza pia kufanya ugunduzi wa reverse whois kiotomatiki kwa kutumia [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Kumbuka kuwa unaweza kutumia mbinu hii kugundua majina zaidi ya domain kila unapopata domain mpya.**

### **Trackers**

Ukipata **ID ileile ya tracker ileile** kwenye kurasa 2 tofauti, unaweza kudhani kuwa **kurasa zote mbili** **zinasimamiwa na timu ileile**.\
Kwa mfano, ukiona **Google Analytics ID** au **Adsense ID** ileile kwenye kurasa kadhaa.

Kuna kurasa na zana zinazokuwezesha kutafuta kwa kutumia trackers hizi na nyingine:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (hupata tovuti zinazohusiana kupitia analytics/trackers zinazoshirikiwa)
- [**StackScan**](https://www.stackscan.com) - **Kiwango cha bure** (Web na API). Fanya pivot kwa asset yoyote inayotolewa, si tracker IDs pekee: njia ya script, jina la bundle inayohifadhiwa kwenye seva yako mwenyewe, au host ambayo asset hupakiwa kutoka kwake; hurejesha kila tovuti inayoitumia

API hurejesha stack ya domain moja, jambo linalofaa kuthibitisha kuwa asset inayochunguzwa ni sehemu ya miundombinu hiyo hiyo:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Hurejesha kila teknolojia iliyotambuliwa pamoja na kategoria yake. Asset pivoting kwa sasa inapatikana kwa wavuti pekee; API inasaidia utafutaji kwa kila domain.

### **Favicon**

Je, unajua kwamba tunaweza kupata domains na subdomains zinazohusiana na lengwa letu kwa kutafuta hash ya ikoni ileile ya favicon? Hivi ndivyo hasa zana ya [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), iliyoundwa na [@m4ll0k2](https://twitter.com/m4ll0k2), inavyofanya. Hivi ndivyo unavyoweza kuitumia:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Matokeo ya Favihash yaliyotumika kugundua domain zinazoshiriki hash ileile ya favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa kifupi, favihash itaturuhusu kugundua domain zilizo na hash ya ikoni ya favicon inayofanana na ya lengwa letu.

![Matokeo ya favihash yaliyotumika kugundua domain zenye hash ileile ya favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Tumia hash ya favicon inayojulikana kama pivot kwenye Shodan au FOFA ili kupata mifano mingine ya teknolojia hiyo hiyo iliyo wazi mtandaoni.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Hivi ndivyo unavyoweza **kuhesabu favicon hash** ya tovuti (MMH3 juu ya bytes za favicon **zilizosimbwa kwa base64**):

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

Unaweza pia kupata favicon hashes kwa kiwango kikubwa kwa kutumia [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) kisha ufanye pivot katika Shodan/Censys.

Chukulia fingerprint za favicon kama vidokezo na uzithibitishe kwa kutumia ishara zinazozizunguka.<sup>[[3]](#references)[[4]](#references)</sup>

- **Chukulia hash kama kiashiria, si uthibitisho**: MMH3 ni fupi; collisions, icons zilizotumiwa tena, na spoofing ya makusudi vinawezekana.
- **Kagua zaidi ya** `/favicon.ico`: chunguza njia za framework/build, faili za manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, data URL za ndani, na tagi za HTML `<link rel="icon">`.
- **Static assets zinaweza kuendelea kupatikana nyuma ya vidhibiti vya WAF/SSO/IdP**: omba icon moja kwa moja na ukague `ETag`, `Last-Modified`, redirects, na cache headers.
- **Thibitisha matches kwa kutumia ishara zinazozizunguka**: linganisha title, HTML/body hash, headers, subjects/SANs za TLS certificate, vipengele vya product, na ports zilizo wazi.
- **Panga kwa HTML/body hash**: template thabiti huimarisha fingerprint; templates tofauti huashiria icon ya jumla au inayoshirikiwa.
- **Chukulia hash inayoonekana katika signatures, ports, na products zisizohusiana kama honeypot au placeholder inayowezekana.**
- **Kwa targets zisizo wazi, linganisha ukurasa halisi na njia isiyokuwepo** kama `/_favicon_probe_<8-hex>`; majibu yanayofanana ya hosting au parking yanaweza kueleza icon inayoshirikiwa.
- **Anza triage kwa kutumia detection rules za Nuclei au public datasets** zinazohusisha favicon hashes na products pamoja na CPEs.
- **Kumbuka pengo la coverage linalotokana na kulenga IP**: nyuso zinazotumia CDN, SNI routing, anycast, na domain-only huenda zikakosekana kwenye datasets zinazofanana na Shodan.

### **Hakimiliki / Mfuatano wa kipekee**

Tafuta ndani ya kurasa za wavuti **mifuatano inayoweza kushirikiwa na tovuti tofauti ndani ya shirika moja**. **Mfuatano wa hakimiliki** unaweza kuwa mfano mzuri. Kisha tafuta mfuatano huo katika **google**, kwenye **vivinjari** vingine, au hata katika **shodan**: `shodan search http.html:"Copyright string"`

### **Muda wa CRT**

Ni kawaida kuwa na kazi ya cron kama vile

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

ili kusasisha vyeti vyote kwenye seva kwa wakati mmoja. Kulinganisha mihuri ya muda ya vyeti au nafasi katika logi za certificate transparency kunaweza kufichua domains zinazohusiana.<sup>[[6]](#references)</sup>

Tumia pia logi za **certificate transparency** moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Taarifa za Mail DMARC

Unaweza kutumia tovuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au zana kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) kutafuta **domains na subdomains zinazotumia taarifa sawa za dmarc**.\
Zana nyingine muhimu ni [**spoofcheck**](https://github.com/BishopFox/spoofcheck) na [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Rekodi ya A iliyoachwa inaweza kufikiwa tena mtoa huduma wa cloud anapokabidhi upya IP. Utafiti uliorejelewa unaonyesha utaratibu wa kutumia fursa hiyo kwa kuanzisha instance na kulinganisha anwani yake na data ya passive DNS; jaribu hali za takeover ndani ya wigo ulioidhinishwa pekee.<sup>[[7]](#references)</sup>

### **Njia nyingine**

Rudia mbinu zinazofaa za ugunduzi kila unapopata domain mpya: kila matokeo yanaweza kufichua majina ya ziada ya vyeti, mahusiano ya passive-DNS, ulinganifu wa favicon na vitambulishi vya shirika ambavyo havikuonekana kwenye seed ya awali.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Kwa kuwa tayari unajua jina la shirika linalomiliki nafasi ya IP, unaweza kutafuta kwa kutumia data hiyo katika shodan: `org:"Tesla, Inc."` Kagua hosts zilizopatikana ili kuona domains mpya zisizotarajiwa kwenye cheti cha TLS.

Unaweza kufikia **cheti cha TLS** cha ukurasa mkuu wa wavuti, kupata **jina la Organisation**, kisha kutafuta jina hilo ndani ya **vyeti vya TLS** vya kurasa zote za wavuti zinazojulikana na **shodan** kwa kutumia kichujio: `ssl:"Tesla Motors"` au utumie zana kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ni zana inayotafuta **domains zinazohusiana** na domain kuu pamoja na **subdomains** zake; inavutia sana.

**Passive DNS / Historical DNS**

Data ya Passive DNS ni nzuri kwa kutafuta **rekodi za zamani na zilizosahaulika** ambazo bado zinatatua au zinaweza kuchukuliwa na mtu mwingine. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Kutafuta udhaifu**

Kagua uwezekano wa [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Huenda kampuni fulani **inatumia domain fulani** lakini **imepoteza umiliki wake**. Isajili tu (ikiwa gharama ni nafuu vya kutosha) kisha uijulishe kampuni.

Ukipata **domain yenye IP tofauti** na zile ulizopata tayari wakati wa ugunduzi wa assets, unapaswa kufanya **uchanganuzi wa msingi wa udhaifu** (kwa kutumia Nessus au OpenVAS) na [**uchanganuzi wa port**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na huduma zinazoendeshwa, unaweza kupata mbinu za **"kuzishambulia"** katika **kitabu hiki**.\
_Kumbuka kwamba wakati mwingine domain huwa kwenye IP isiyodhibitiwa na mteja, kwa hiyo haimo kwenye wigo; kuwa mwangalifu._

## Subdomains

> Tunajua kampuni zote zilizo ndani ya wigo, assets zote za kila kampuni na domains zote zinazohusiana na kampuni hizo.

Ni wakati wa kutafuta subdomains zote zinazowezekana za kila domain iliyopatikana.

> [!TIP]
> Kumbuka kwamba baadhi ya zana na mbinu za kutafuta domains zinaweza pia kusaidia kutafuta subdomains

### **DNS**

Hebu tujaribu kupata **subdomains** kutoka kwenye rekodi za **DNS**. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa ina udhaifu, unapaswa kuripoti).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Kwa API na majukwaa yanayohusu miundombinu, sifa, rekodi za uvujaji na uboreshaji wa data zaidi ya ugunduzi wa subdomain, angalia [katalogi ya API za Reconnaissance na Threat Intelligence](reconnaissance-and-threat-intelligence-apis.md).

Njia ya haraka zaidi ya kupata subdomain nyingi ni kutafuta kwenye vyanzo vya nje. **tools** zinazotumika zaidi ni hizi (kwa matokeo bora, sanidi API keys):


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

Kuna **zana/API nyingine za kuvutia** ambazo, hata kama hazijawekewa utaalamu wa moja kwa moja wa kutafuta subdomains, zinaweza kusaidia kupata subdomains, kama vile:

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

- [**gau**](https://github.com/lc/gau)**:** hupata URL zinazojulikana kutoka AlienVault's Open Threat Exchange, Wayback Machine na Common Crawl kwa kikoa chochote.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hutambaa kwenye wavuti kutafuta faili za JS na kutoa subdomain kutoka humo.

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
- [**activedns.net**](https://activedns.net/)

Mradi huu hutoa **bila malipo subdomains zote zinazohusiana na programu za bug-bounty**. Unaweza pia kufikia data hii kupitia [chaospy](https://github.com/dr-0x0x/chaospy), au hata kufikia scope inayotumiwa na mradi huu kupitia [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Unaweza kupata **ulinganisho** wa zana nyingi kati ya hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu tujaribu kupata **subdomains** mpya kwa kufanya brute-force kwenye seva za DNS kwa kutumia majina yanayowezekana ya subdomains.

Kwa hatua hii utahitaji baadhi ya **wordlists za kawaida za subdomains kama**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Pia utahitaji IP za DNS resolvers nzuri. Ili kuunda orodha ya DNS resolvers zinazoaminika, unaweza kupakua resolvers kutoka [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzichuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ndiyo zana ya kwanza iliyotekeleza DNS brute-force kwa ufanisi. Ina kasi sana, hata hivyo huwa na false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Hii, nadhani hutumia resolver mmoja tu.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper ya `massdns`, iliyoandikwa kwa Go, inayokuwezesha kuorodhesha subdomain halali kwa kutumia bruteforce amilifu, na pia kutatua subdomain kwa kushughulikia wildcard na kutoa msaada rahisi wa ingizo na matokeo.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Pia hutumia `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) hutumia asyncio kufanya brute force majina ya domain kwa njia ya asynchronous.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Raundi ya Pili ya DNS Brute-Force

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na brute-forcing, unaweza kutengeneza mabadiliko ya subdomains zilizopatikana ili kujaribu kupata nyingine zaidi. Zana kadhaa zinafaa kwa kusudi hili:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Ukiipa domains na subdomains, hutengeneza permutations.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Huunda permutations kutokana na domains na subdomains.
  - Unaweza kupata **wordlist** ya permutations za goaltdns [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Ukipewa domains na subdomains, huzalisha permutations. Ikiwa faili la permutations halijaainishwa, gotator itatumia faili lake yenyewe.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kutengeneza permutations za subdomains, inaweza pia kujaribu kuzi-resolve (lakini ni bora kutumia tools zilizotajwa awali).
  - Unaweza kupata **wordlist** ya permutations za altdns [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya permutations, mutations na mabadiliko ya subdomains. Zana hii itafanya brute force ya matokeo (haitumii DNS wildcard).
  - Unaweza kupata wordlist ya permutations ya dmut [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kwa kutegemea domain, **hutengeneza majina mapya yanayoweza kuwa subdomains** kwa kutumia patterns zilizoainishwa, ili kujaribu kugundua subdomains zaidi.

#### Uzalishaji mahiri wa permutations

- [**regulator**](https://github.com/cramppet/regulator): Hujifunza patterns zinazofanana na regex kutoka kwa subdomains zilizogunduliwa na kutengeneza majina yanayoweza kutatuliwa.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni fuzzer ya brute-force ya subdomain, iliyounganishwa na algorithm rahisi sana lakini yenye ufanisi inayoongozwa na majibu ya DNS. Hutumia seti ya data ya ingizo iliyotolewa, kama wordlist maalum au rekodi za kihistoria za DNS/TLS, ili kuunda kwa usahihi majina mengine ya domain yanayolingana na kuyapanua zaidi kwa mizunguko, kulingana na maelezo yanayokusanywa wakati wa uchanganuzi wa DNS.

```
echo www | subzuf facebook.com
```

### **Workflow ya Kugundua Subdomain**

Mifano ya workflow ya Trickest huunganisha OSINT, DNS brute force, na hatua za permutation kwa ajili ya subdomain enumeration inayoweza kurudiwa.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ukipata anwani ya IP yenye **ukurasa mmoja au kadhaa wa wavuti** unaohusiana na subdomain, unaweza kujaribu **kutafuta subdomain nyingine zenye tovuti kwenye IP hiyo** kwa kutafuta **vyanzo vya OSINT** vya domains zilizo kwenye IP, au kwa **kufanya brute force ya majina ya domain ya VHost kwenye IP hiyo**.

#### OSINT

Unaweza kupata baadhi ya **VHosts kwenye IP ukitumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au API nyingine**.

**Brute Force**

Ikiwa unashuku kuwa subdomain fulani inaweza kuwa imefichwa kwenye web server, unaweza kujaribu kuifanya brute force:

Kwa vhosts zinazotumia majina, fuzz `Host` header na utumie auto-calibration ya ffuf kuchuja jibu chaguomsingi.<sup>[[2]](#references)</sup>

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
> Kwa mbinu hii unaweza hata kufikia endpoints za ndani/zilizofichwa.

### **CORS Brute Force**

Wakati mwingine utakutana na kurasa ambazo hurudisha header _**Access-Control-Allow-Origin**_ tu wakati domain/subdomain halali imewekwa kwenye header ya _**Origin**_. Katika hali hizi, unaweza kutumia vibaya tabia hii **kugundua** **subdomains** mpya.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Unapotafuta **subdomains**, angalia kama **inaelekeza** kwenye aina yoyote ya **bucket**; ikifanya hivyo, [**kagua permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Pia, kwa kuwa kufikia hatua hii utakuwa unajua domains zote zilizo ndani ya scope, jaribu [**kubashiri majina ya bucket yanayowezekana kwa brute force na kukagua permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Ufuatiliaji**

Unaweza **kufuatilia** ikiwa **subdomains mpya** zinaundwa kwa domain kwa kufuatilia Logs za **Certificate Transparency** kama [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) inavyofanya.

### **Kutafuta vulnerabilities**

Kagua uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inaelekeza kwenye **S3 bucket**, [**kagua permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ukipata **subdomain yenye IP tofauti** na zile ambazo tayari umegundua wakati wa assets discovery, unapaswa kufanya **basic vulnerability scan** (kwa kutumia Nessus au OpenVAS) na [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na services zinazoendeshwa, unaweza kupata katika **kitabu hiki mbinu za "kuzishambulia"**.\
_Ni vyema kutambua kuwa wakati mwingine subdomain huwa kwenye IP ambayo haidhibitiwi na mteja, kwa hiyo haimo kwenye scope; kuwa mwangalifu._

## IPs

Katika hatua za mwanzo huenda **ulipata baadhi ya IP ranges, domains na subdomains**.\
Ni wakati wa **kukusanya IPs zote kutoka kwenye ranges hizo** na kwa **domains/subdomains (DNS queries).**

Kwa kutumia services kutoka kwenye **free APIs** zifuatazo, unaweza pia kupata **IPs zilizotumiwa awali na domains na subdomains**. Huenda IPs hizo bado zinamilikiwa na mteja (na zinaweza kukuwezesha kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Unaweza pia kutafuta domains zinazoelekeza kwenye anwani maalum ya IP kwa kutumia zana ya [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Kutafuta vulnerabilities**

**Fanya port scan ya IPs zote ambazo si za CDNs** (kwa kuwa kuna uwezekano mkubwa hutapata kitu cha kuvutia humo). Huenda **ukaweza kupata vulnerabilities** katika services zinazoendeshwa ambazo umegundua.

**Pata** [**mwongozo**](../pentesting-network/index.html) **kuhusu jinsi ya kuscan hosts.**

## Kuwinda web servers

> Tumepata makampuni yote na assets zake, na tunajua IP ranges, domains na subdomains zilizo ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizopita huenda tayari ulifanya **recon ya IPs na domains zilizogunduliwa**, kwa hiyo huenda **tayari umepata web servers zote zinazowezekana**. Hata hivyo, ikiwa bado hujazipata, sasa tutaangalia **mbinu za haraka za kutafuta web servers** ndani ya scope.

Tafadhali kumbuka kuwa hatua hii **inalenga ugunduzi wa web apps**, kwa hiyo unapaswa pia **kufanya vulnerability scanning** na **port scanning** (**ikiwa scope inaruhusu**).

[**Njia ya haraka** ya kugundua **ports zilizo wazi** zinazohusiana na web servers kwa kutumia **masscan** inapatikana hapa](../pentesting-network/index.html#http-port-discovery).\
Zana nyingine rafiki ya kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unazipitishia tu orodha ya domains, nazo zitajaribu kuunganishwa kwenye port 80 (http) na 443 (https). Zaidi ya hayo, unaweza kuagiza zijaribu ports nyingine:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Picha za skrini**

Sasa kwa kuwa umegundua **web servers zote** zilizopo kwenye scope (miongoni mwa **IP** za kampuni na **domains** na **subdomains** zote), huenda **hujui pa kuanzia**. Kwa hiyo, tufanye iwe rahisi na tuanze kwa kupiga picha za skrini za zote. Kwa **kutazama tu** **ukurasa mkuu**, unaweza kupata endpoints **zisizo za kawaida** ambazo zina uwezekano mkubwa zaidi wa kuwa **vulnerable**.

Ili kutekeleza wazo hili, unaweza kutumia [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kuchanganua **screenshots** zote na kukuambia **ni zipi huenda zina vulnerabilities**, na zipi hazina.

## Assets za Public Cloud

Ili kupata assets za cloud zinazoweza kuwa za kampuni, unapaswa **kuanza na orodha ya maneno muhimu yanayotambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Pia utahitaji wordlists za **maneno ya kawaida yanayotumiwa kwenye buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa kutumia maneno hayo unapaswa kutengeneza **permutations** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa wordlists zitakazopatikana, unaweza kutumia tools kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta Cloud Assets, unapaswa **kutafuta zaidi ya buckets za AWS pekee**.

### **Kutafuta vulnerabilities**

Ukipata vitu kama **buckets zilizo wazi au cloud functions zilizo wazi**, unapaswa **kuvifikia** na kujaribu kuona vinatoa nini na kama unaweza kuvitumia vibaya.

## Emails

Ukiwa na **domains** na **subdomains** zilizomo kwenye scope, kimsingi una kila kitu **unachohitaji kuanza kutafuta emails**. Hizi ndizo **APIs** na **tools** ambazo zimefanya kazi vizuri zaidi kwangu kutafuta emails za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - pamoja na APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (toleo la bure)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (toleo la bure)
- API ya [**https://minelead.io/**](https://minelead.io/) (toleo la bure)

### **Kutafuta vulnerabilities**

Emails zitakusaidia baadaye **kufanya brute-force ya web logins na auth services** (kama SSH). Pia zinahitajika kwa **phishing**. Zaidi ya hayo, APIs hizi zitakupa **taarifa zaidi kuhusu mtu** aliye nyuma ya email, jambo linalofaa kwa kampeni ya phishing.

## Credential Leaks

Ukiwa na **domains,** **subdomains**, na **emails**, unaweza kuanza kutafuta credentials zilizovuja hapo awali zinazohusiana na emails hizo:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta vulnerabilities**

Ukipata credentials **zilizovuja ambazo bado ni halali**, hili ni jambo rahisi sana kupata ushindi.

## Secrets Leaks

Credential leaks huhusishwa na udukuzi wa kampuni ambapo **taarifa nyeti zilivuja na kuuzwa**. Hata hivyo, kampuni zinaweza kuathiriwa na **leaks nyingine** ambazo taarifa zake hazipo kwenye hifadhidata hizo:

### Github Leaks

Credentials na APIs zinaweza kuvuja kwenye **public repositories** za **kampuni** au za **watumiaji** wanaofanya kazi katika kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) **kupakua** **public repos** zote za **organization** na za **developers** wake na kuendesha [**gitleaks**](https://github.com/zricethezav/gitleaks) juu yake kiotomatiki.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** kwenye **maandishi** yote yaliyo kwenye **URLs zilizopitishwa** kwake, kwani wakati mwingine **kurasa za wavuti pia huwa na secrets**.

#### Github Dorks

Angalia ukurasa wa [GitHub dorks and leaks](github-leaked-secrets.md) ili kupata **GitHub dorks** zinazoweza kutumika kutafuta ndani ya organization.

### Pastes Leaks

Wakati mwingine washambuliaji au wafanyakazi tu **huchapisha maudhui ya kampuni kwenye paste site**. Huenda yakawa na **taarifa nyeti** au yasiwe nayo, lakini ni muhimu sana kuyatafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta kwenye zaidi ya paste sites 80 kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini bora daima husaidia kupata **taarifa zilizo wazi ambazo hazipaswi kuwepo hapo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu kadhaa ya queries zinazowezekana ambazo huwezi kuendesha mwenyewe. Kwa hiyo, unaweza kuchagua 10 unazozipenda au kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuzitafuta zote**.

_Kumbuka kwamba tools zinazotarajia kuendesha hifadhidata nzima kwa kutumia Google browser ya kawaida hazitamaliza, kwani Google itakuzuia haraka sana._

### **Kutafuta vulnerabilities**

Ukipata credentials au API tokens **zilizovuja ambazo bado ni halali**, hili ni jambo rahisi sana kupata ushindi.

## Vulnerabilities kwenye Public Code

Ukigundua kwamba kampuni ina **open-source code**, unaweza **kuichanganua** na kutafuta **vulnerabilities** ndani yake.

**Kulingana na lugha**, kuna **tools** tofauti unazoweza kutumia; angalia orodha ya [tools za kukagua source code](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Pia kuna services za bure zinazokuruhusu **kuchanganua public repositories**, kama vile:

- [**Snyk**](https://app.snyk.io/)

## [**Mbinu ya Pentesting ya Wavuti**](../../network-services-pentesting/pentesting-web/index.html)

**Vulnerabilities nyingi** zinazopatikana na bug hunters ziko ndani ya **web applications**, kwa hiyo katika hatua hii ningependa kuzungumzia **mbinu ya kupima web applications**, na unaweza [**kupata taarifa hizi hapa**](../../network-services-pentesting/pentesting-web/index.html).

Pia ningependa kutaja mahsusi sehemu ya [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwa kuwa, ingawa hupaswi kutarajia zikupatie vulnerabilities nyeti sana, zinafaa kuongezwa kwenye **workflows ili kupata taarifa za awali za wavuti.**

## Muhtasari

> Hongera! Kufikia hapa tayari umekamilisha **enumeration yote ya msingi**. Ndiyo, ni ya msingi kwa sababu kuna enumeration nyingi zaidi zinazoweza kufanywa (tutaona mbinu zaidi baadaye).

Kwa hiyo tayari umefanya yafuatayo:

1. Umepata **kampuni** zote zilizomo kwenye scope
2. Umepata **assets** zote za kampuni hizo (na kufanya vuln scan ikiwa ipo kwenye scope)
3. Umepata **domains** zote za kampuni hizo
4. Umepata **subdomains** zote za domains hizo (kuna uwezekano wa subdomain takeover?)
5. Umepata **IP** zote (kutoka na **zisizotoka kwenye CDNs**) zilizomo kwenye scope.
6. Umepata **web servers** zote na kupiga **screenshot** zake (kuna jambo lisilo la kawaida linalostahili kuchunguzwa zaidi?)
7. Umepata **public cloud assets** zote zinazoweza kuwa za kampuni.
8. **Emails**, **credential leaks**, na **secret leaks** zinazoweza kukupatia **ushindi mkubwa kwa urahisi**.
9. **Pentesting ya webs zote ulizopata**

## **Tools za Kiotomatiki za Full Recon**

Kuna tools kadhaa zinazoweza kutekeleza baadhi ya hatua zilizopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ni ya zamani kidogo na haijasasishwa

## References

- [1] [Jason Haddix – Mbinu ya Bug Hunter v4.0: Toleo la Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Kuhusu Favicons: Kutoka Ikoni za Browser hadi Uelewa wa Attack Surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Kutumia favicon.ico kama Silaha kwa BugBounties, OSINT na Mengineyo](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Kugundua Domains kupitia Shambulio la Time-Correlation kwenye Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Kufichua (na Kuiga) Kampeni ya Gharama Kubwa ya Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Mbinu ya Kipekee ya Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Mchakato Kamili wa Ugunduzi wa Subdomain, Sehemu ya 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Ugunduzi wa Subdomain kwa Brute Force kwa Kutumia Trickest Workflow ya Kiotomatiki, Sehemu ya 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Picha ya skrini ya matokeo ya favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
