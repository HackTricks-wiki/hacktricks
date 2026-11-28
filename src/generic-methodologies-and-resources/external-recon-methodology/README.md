# Mbinu za External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ugunduzi wa assets

Kwa orodha iliyoainishwa ya miradi mingine ya OSINT na ugunduzi wa wavuti, angalia [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint).

> Kwa hiyo umeambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kubaini kampuni hiyo inamiliki nini hasa.

Lengo la awamu hii ni kupata **kampuni zote zinazomilikiwa na kampuni kuu**, kisha kupata **assets** zote za kampuni hizo. Ili kufanya hivyo, tutafanya yafuatayo:<sup>[[1]](#references)</sup>

1. Tafuta kampuni ambazo kampuni kuu imezinunua; hii itatupatia kampuni zilizo ndani ya scope.
2. Tafuta ASN (ikiwa ipo) ya kila kampuni; hii itatupatia safu za IP zinazomilikiwa na kila kampuni.
3. Tumia utafutaji wa reverse whois kutafuta rekodi nyingine (majina ya mashirika, domain...) zinazohusiana na ya kwanza (hili linaweza kufanywa kwa kurudia).
4. Tumia mbinu nyingine kama vichujio vya shodan `org`na `ssl`kutafuta assets nyingine (mbinu ya `ssl` inaweza kufanywa kwa kurudia).

Kwa mpito uliopangwa kutoka subdomain zilizotatuliwa kwenda kwenye HTTP crawling na ugunduzi wa port, angalia [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Ununuzi wa kampuni**

Kwanza kabisa, tunahitaji kujua **ni kampuni gani nyingine zinazomilikiwa na kampuni kuu**.\
Njia moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **kutafuta** **kampuni kuu**, na **kubofya** "**acquisitions**". Hapo utaona kampuni nyingine zilizonunuliwa na kampuni hiyo.\
Njia nyingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, angalia **SEC/EDGAR filings**, kurasa za **investor relations**, au rejista za kampuni za eneo husika (k.m., **Companies House** nchini UK).\
Kwa taarifa za kimataifa kuhusu muundo wa kampuni na kampuni tanzu, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na hifadhidata ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, kwa wakati huu unapaswa kujua kampuni zote zilizo ndani ya scope. Hebu tubaini jinsi ya kupata assets zake.

### **ASNs**

Nambari ya autonomous system (**ASN**) ni **nambari ya kipekee** inayotolewa kwa **autonomous system** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
**AS** ina **blocks** za **IP addresses** zilizo na sera iliyobainishwa wazi ya kufikia mitandao ya nje, na husimamiwa na shirika moja lakini inaweza kuwa na waendeshaji kadhaa.

Ni muhimu kubaini kama **kampuni imepewa ASN yoyote** ili kupata **safu zake za IP.** Itakuwa muhimu kufanya **jaribio la udhaifu** dhidi ya **hosts** zote zilizo ndani ya **scope** na **kutafuta domains** ndani ya IP hizi.\
Unaweza **kutafuta** kwa kutumia **jina** la kampuni, **IP** au **domain** kwenye [**https://bgp.he.net/**](https://bgp.he.net) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na eneo la kampuni, viungo hivi vinaweza kusaidia kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amerika Kaskazini),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Amerika ya Kusini),** [**RIPE NCC**](https://www.ripe.net) **(Ulaya). Hata hivyo, huenda taarifa zote** muhimu **(safu za IP na Whois)** tayari ziko kwenye kiungo cha kwanza.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Pia, enumeration ya [**BBOT**](https://github.com/blacklanternsecurity/bbot) hukusanya na kufupisha ASNs kiotomatiki mwishoni mwa scan.

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

Unaweza pia kupata safu za IP za shirika ukitumia [ASNLookup](https://asnlookup.com/), ambayo ina kiwango kidogo cha matumizi ya API bila malipo.

### **Kutafuta udhaifu**

Kwa sasa tunajua **assets zote zilizo ndani ya scope**, kwa hiyo ikiwa una ruhusa unaweza kuendesha **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) kwenye hosts zote.\
Pia, unaweza kuendesha [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** Shodan, Censys, au ZoomEye **kutafuta** ports zilizo wazi **na kulingana na utakachopata, unapaswa** kuangalia kitabu hiki ili kuona jinsi ya kufanya pentest ya huduma mbalimbali zinazoweza kuwa zinaendeshwa.\
**Pia, inafaa kutaja kwamba unaweza kuandaa orodha za** majina ya watumiaji **na** nywila **chaguomsingi na kujaribu kufanya** bruteforce ya huduma ukitumia [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua kampuni zote zilizo ndani ya scope na assets zake; sasa ni wakati wa kutafuta domains zilizo ndani ya scope.

_Tafadhali kumbuka kwamba katika mbinu zilizopendekezwa hapa chini unaweza pia kupata subdomains, na taarifa hiyo haipaswi kupuuzwa._

Kwanza kabisa, unapaswa kutafuta **domain** kuu ya kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kwa kuwa umepata safu zote za IP za domains, unaweza kujaribu kufanya **reverse DNS lookups** kwenye **IP hizo ili kupata domains zaidi zilizo ndani ya scope**. Jaribu kutumia DNS server ya mwathiriwa au DNS server inayojulikana sana (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Ili hili lifanye kazi, msimamizi lazima awashe PTR mwenyewe.\
Unaweza pia kutumia [SecurityTrails](https://securitytrails.com/) kupata maelezo haya, ingawa data ya kihistoria ya DNS inahitaji mpango wa kulipia.\
Kwa range kubwa, zana kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) zinafaa kwa kuendesha reverse lookups na enrichment kiotomatiki.

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata **maelezo** mengi ya kuvutia kama **jina la shirika**, **anwani**, **barua pepe**, nambari za simu... Lakini kinachovutia zaidi ni kwamba unaweza kupata **assets zaidi zinazohusiana na kampuni** ukifanya **reverse whois lookups kwa kutumia sehemu yoyote kati ya hizo** (kwa mfano, rekodi nyingine za whois ambako barua pepe hiyo hiyo inaonekana).\
Unaweza kutumia zana za mtandaoni kama:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bila malipo** (Web na API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bila malipo**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bila malipo**
- [https://www.whoxy.com/](https://www.whoxy.com) - Kiolesura cha **web kisicholipishwa**; API ya kulipia.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Ya kulipia
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Si ya bure (utafutaji **100 wa bure** pekee)
- [https://www.domainiq.com/](https://www.domainiq.com) - Si ya bure
- [https://securitytrails.com/](https://securitytrails.com/) - Ufikiaji mdogo wa API ya bure kwa DNS/subdomains za sasa; data ya kihistoria na reverse lookups zinahitaji mpango wa kulipia.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Credits 500 za API za bure baada ya kujisajili; hulipiwa baadaye.

Unaweza kuendesha kazi hii kiotomatiki kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji ufunguo wa API wa whoxy).\
Unaweza pia kufanya ugunduzi wa reverse whois kiotomatiki kwa kutumia [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Kumbuka kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya domain kila unapopata domain mpya.**

### **Trackers**

Ukipata **ID ileile ya tracker ileile** kwenye kurasa 2 tofauti, unaweza kudhani kwamba **kurasa zote mbili** **zinasimamiwa na timu ileile**.\
Kwa mfano, ukiona **Google Analytics ID** au **Adsense ID** ileile kwenye kurasa kadhaa.

Kuna baadhi ya kurasa na zana zinazokuwezesha kutafuta kwa kutumia trackers hizi na zaidi:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Huduma ya **web na API ya kulipia** ([bei](https://www.stackscan.com/pricing)); kwa sasa hakuna mpango wa bure unaotangazwa. Fuatilia asset yoyote inayotolewa, si tracker IDs pekee: njia ya script, jina la bundle inayohifadhiwa kwenye seva yako, au host ambako asset hupakiwa, ili kupata kila tovuti inayoitumia.

API hurejesha stack ya domain moja, jambo linalofaa kuthibitisha ikiwa asset inayoshukiwa inahusiana na estate ileile:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Hurejesha kila teknolojia iliyotambuliwa pamoja na kategoria yake. Asset pivoting kwa sasa inapatikana kwenye wavuti pekee, huku API ikiruhusu utafutaji kwa kila domain.

### **Favicon**

Je, unajua kwamba tunaweza kupata domains na subdomains zinazohusiana na lengo letu kwa kutafuta hash ileile ya ikoni ya favicon? Hivi ndivyo hasa zana ya [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), iliyotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2), inavyofanya. Hivi ndivyo unavyoweza kuitumia:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Matokeo ya Favihash yaliyotumika kugundua domain zinazoshiriki hash ya favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa kifupi, favihash itaturuhusu kugundua domain zilizo na hash ya ikoni ya favicon inayofanana na ya lengo letu.

![Matokeo ya favihash yaliyotumika kugundua domain zilizo na hash sawa ya favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Tumia hash ya favicon inayojulikana kama sehemu ya kuanzia ya utafutaji kwenye Shodan au FOFA ili kupata mifano mingine ya teknolojia hiyo iliyo wazi kwa umma.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Hivi ndivyo unavyoweza **kukokotoa hash ya favicon** ya tovuti (MMH3 juu ya byte za favicon zilizowekwa katika **base64**):

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

Unaweza pia kupata favicon hashes kwa kiwango kikubwa ukitumia [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), kisha ufuatilie kwenye Shodan/Censys.

Chukulia alama za favicon kama vidokezo, na uzihakiki kwa kutumia ishara zinazozizunguka.<sup>[[3]](#references)[[4]](#references)</sup>

- **Chukulia hash kama kiashiria, si uthibitisho**: MMH3 ni fupi; migongano, icons zinazotumiwa tena, na udanganyifu wa makusudi vinawezekana.
- **Chunguza zaidi ya** `/favicon.ico`: kagua paths za framework/build, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs, na HTML `<link rel="icon">` tags.
- **Static assets zinaweza kuendelea kufikiwa hata kukiwa na vidhibiti vya WAF/SSO/IdP**: omba icon moja kwa moja na ukague `ETag`, `Last-Modified`, redirects, na cache headers.
- **Hakiki zinazolingana kwa kutumia ishara zinazozizunguka**: linganisha title, HTML/body hash, headers, mada za TLS certificate/SANs, product components, na ports zilizo wazi.
- **Panga kwa HTML/body hash**: template thabiti huimarisha alama; templates mchanganyiko hudokeza icon ya jumla au inayoshirikiwa.
- **Chukulia hash inayoonekana katika signatures, ports, na products zisizohusiana kama honeypot au placeholder inayowezekana.**
- **Kwa targets zisizo wazi, linganisha ukurasa halisi na path isiyokuwepo** kama `/_favicon_probe_<8-hex>`; majibu yanayofanana ya hosting au parking yanaweza kueleza icon inayoshirikiwa.
- **Anza triage kwa kutumia detection rules za Nuclei au public datasets** zinazohusisha favicon hashes na products na CPEs.
- **Kumbuka pengo la coverage linalotokana na kutegemea IP**: CDN-fronted, SNI-routed, anycast, na nyuso za domain-only huenda zisiwepo kwenye datasets zinazofanana na Shodan.

### **Hakimiliki / Uniq string**

Tafuta ndani ya kurasa za wavuti **strings ambazo zinaweza kushirikiwa na tovuti tofauti katika shirika moja**. **String ya hakimiliki** inaweza kuwa mfano mzuri. Kisha tafuta string hiyo kwenye **Google**, kwenye **vivinjari** vingine au hata kwenye **Shodan**: `shodan search http.html:"Copyright string"`

### **Muda wa CRT**

Ni jambo la kawaida kuwa na cron job kama vile

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

ili kufanya upya vyeti vyote kwenye server kwa wakati mmoja. Kulinganisha mihuri ya muda ya vyeti au nafasi zake kwenye certificate-transparency logs kunaweza kufichua domain zinazohusiana.<sup>[[6]](#references)</sup>

Tumia pia logs za **certificate transparency** moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Taarifa za Mail DMARC

Unaweza kutumia tovuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au tool kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) ili kupata **domain na subdomain zinazoshiriki taarifa sawa za dmarc**.\
Huduma nyingine muhimu ni [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Rekodi ya A iliyoachwa inaweza kufikiwa tena pale cloud provider inapokabidhi upya IP. Utafiti uliorejelewa unaonyesha workflow ya kutumia fursa kwa kuanzisha instance na kulinganisha anwani yake na data ya passive DNS; jaribu hali za takeover ndani ya scope iliyoidhinishwa pekee.<sup>[[7]](#references)</sup>

### **Njia nyingine**

Rudia hatua za ugunduzi zinazofaa kila unapopata domain mpya: kila matokeo yanaweza kufichua majina ya ziada ya certificate, uhusiano wa passive-DNS, vinavyolingana na favicon, na vitambulishi vya shirika ambavyo havikuonekana kwenye domain ya mwanzo.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Kwa kuwa tayari unajua jina la shirika linalomiliki eneo la IP, unaweza kutafuta taarifa hiyo kwenye shodan kwa kutumia: `org:"Tesla, Inc."` Kagua hosts zilizopatikana ili kuona domain mpya zisizotarajiwa kwenye TLS certificate.

Unaweza kufikia **TLS certificate** ya ukurasa mkuu wa wavuti, kupata **jina la Organisation**, kisha kutafuta jina hilo ndani ya **TLS certificates** za kurasa zote za wavuti zinazojulikana na **shodan**, kwa kutumia kichujio hiki: `ssl:"Tesla Motors"` au kutumia tool kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ni tool inayotafuta **domain zinazohusiana** na domain kuu na **subdomain** zake; inavutia sana.

**Passive DNS / Historical DNS**

Data ya Passive DNS ni nzuri kwa kupata **rekodi za zamani na zilizosahaulika** ambazo bado zinatatua au ambazo zinaweza kuchukuliwa. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Kutafuta vulnerabilities**

Angalia kama kuna [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Huenda kampuni fulani **inatumia domain fulani** lakini **imepoteza umiliki wake**. Isajili tu (ikiwa ni nafuu vya kutosha) kisha uijulishe kampuni.

Ukipata **domain yoyote yenye IP tofauti** na zile ulizokwisha pata wakati wa ugunduzi wa assets, unapaswa kufanya **basic vulnerability scan** (kwa kutumia Nessus au OpenVAS) na [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kutegemea huduma zinazoendeshwa, unaweza kupata mbinu za **"kuzishambulia"** katika **kitabu hiki**.\
_Kumbuka kuwa wakati mwingine domain huwekwa kwenye IP isiyodhibitiwa na mteja, kwa hiyo haipo kwenye scope; kuwa mwangalifu._

## Subdomains

> Tunajua kampuni zote zilizo ndani ya scope, assets zote za kila kampuni na domain zote zinazohusiana na kampuni hizo.

Ni wakati wa kupata subdomain zote zinazowezekana za kila domain iliyopatikana.

> [!TIP]
> Kumbuka kuwa baadhi ya tools na mbinu za kutafuta domain zinaweza kusaidia pia kutafuta subdomain.

### **DNS**

Hebu tujaribu kupata **subdomain** kutoka kwenye rekodi za **DNS**. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa ina udhaifu, unapaswa kuiripoti).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Kwa APIs na platforms zinazohusu miundombinu, sifa, rekodi za uvujaji wa data na uboreshaji zaidi ya ugunduzi wa subdomain, angalia [orodha ya APIs za Upelelezi na Taarifa za Vitisho](reconnaissance-and-threat-intelligence-apis.md).

Njia ya haraka zaidi ya kupata subdomain nyingi ni kutafuta kwenye vyanzo vya nje. **Tools** zinazotumika zaidi ni hizi (kwa matokeo bora, sanidi API keys):


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

Kuna **tools/APIs nyingine za kuvutia** ambazo, hata kama hazijabobea moja kwa moja katika kutafuta subdomains, zinaweza kusaidia kuzipata, kama vile:

- [**IP.THC.ORG**](https://ip.thc.org) API ya bure

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB API ya bure**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** hukusanya URL zinazojulikana kutoka AlienVault's Open Threat Exchange, Wayback Machine, na Common Crawl kwa domain yoyote iliyotolewa.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Huchunguza wavuti kutafuta faili za JS na kutoa subdomain kutoka humo.

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

- [**Kitafutaji cha subdomain cha Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) inatoa ufikiaji mdogo wa API bila malipo kwa data ya sasa ya DNS na subdomain; data ya kihistoria ya DNS/IP inahitaji mpango wa kulipia.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Mradi huu hutoa **subdomains zote zinazohusiana na programu za bug-bounty bila malipo**. Unaweza kufikia data hii pia ukitumia [chaospy](https://github.com/Moaaz-0x/chaospy), au hata kufikia scope inayotumiwa na mradi huu kupitia [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Unaweza kupata **ulinganisho** wa nyingi ya zana hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu tujaribu kupata **subdomains** mpya kwa kufanya brute-force kwenye DNS servers kwa kutumia majina yanayowezekana ya subdomain.

Kwa hatua hii utahitaji **orodha za maneno za subdomain zinazotumika sana kama**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Pia utahitaji IPs za DNS resolvers nzuri. Ili kutengeneza orodha ya DNS resolvers zinazoaminika, unaweza kupakua resolvers kutoka [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzichuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ilikuwa zana ya kwanza kufanya DNS brute-force kwa ufanisi. Ni ya haraka sana, lakini inaweza kutoa matokeo chanya ya uongo.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Hii nadhani hutumia resolver 1 tu.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper ya `massdns`, iliyoandikwa kwa Go, inayokuwezesha kuorodhesha subdomain halali kwa kutumia active bruteforce, na pia kutatua subdomain kwa kushughulikia wildcard na usaidizi rahisi wa ingizo na matokeo.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Pia hutumia `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) hutumia asyncio kufanya brute force ya majina ya domain kwa njia ya asinchroni.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Raundi ya Pili ya DNS Brute-Force

Baada ya kupata subdomains kwa kutumia vyanzo vya wazi na brute-forcing, unaweza kuunda mabadiliko ya subdomains ulizopata ili kujaribu kupata zaidi. Zana kadhaa zinafaa kwa kusudi hili:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Hupokea domains na subdomains na kuzalisha permutations.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Hupewa domain na subdomain, kisha hutengeneza permutations.
  - Unaweza kupata **wordlist** ya permutations za goaltdns [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Ikipewa domain na subdomain, hutengeneza permutations. Ikiwa faili ya permutations haijaainishwa, gotator itatumia faili yake yenyewe.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kutengeneza permutations za subdomain, inaweza pia kujaribu kuzitatua (lakini ni bora kutumia zana zilizotajwa hapo awali).
  - Unaweza kupata **wordlist** ya permutations za altdns [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya permutations, mutations na mabadiliko ya subdomains. Zana hii itafanya brute force kwenye matokeo (haitumii dns wild card).
  - Unaweza kupata wordlist ya dmut permutations [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kwa kutumia domain, **huzalisha majina mapya ya subdomain yanayowezekana** kulingana na patterns zilizobainishwa ili kujaribu kugundua subdomain zaidi.

#### Uzalishaji mahiri wa permutations

- [**regulator**](https://github.com/cramppet/regulator): Hujifunza patterns zinazofanana na regex kutoka kwa subdomain zilizogunduliwa na huzalisha majina yanayoweza kutumika kujaribu kufanya resolution.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni fuzzer ya brute-force ya subdomain inayotumia algorithm rahisi sana lakini yenye ufanisi, inayoongozwa na majibu ya DNS. Hutumia seti ya data ya ingizo iliyotolewa, kama wordlist iliyoundwa mahususi au rekodi za kihistoria za DNS/TLS, ili kutengeneza kwa usahihi majina mengine ya domain yanayohusiana na kuyapanua zaidi kwa mzunguko, kwa kutegemea taarifa zilizokusanywa wakati wa DNS scan.

```
echo www | subzuf facebook.com
```

### **Mtiririko wa Ugunduzi wa Subdomain**

Mifano ya workflow ya Trickest inachanganya OSINT, DNS brute force na hatua za permutation kwa ajili ya kuorodhesha subdomain kwa njia inayoweza kurudiwa.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ukipata anwani ya IP iliyo na **ukurasa mmoja au kadhaa wa wavuti** unaomilikiwa na subdomain, unaweza kujaribu **kutafuta subdomain nyingine zilizo na tovuti kwenye IP hiyo** kwa kutafuta **vyanzo vya OSINT** vya domains zinazohusishwa na IP hiyo au kwa **kufanya brute force ya majina ya domain ya VHost kwenye IP hiyo**.

#### OSINT

Unaweza kupata baadhi ya **VHosts kwenye IPs ukitumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au APIs nyingine**.

**Brute Force**

Ikiwa unashuku kuwa subdomain fulani inaweza kufichwa kwenye web server, unaweza kujaribu kufanya brute force yake:

Kwa vhosts zinazotegemea jina, fanya fuzzing ya kichwa cha `Host` na utumie auto-calibration ya ffuf kuchuja jibu chaguomsingi.<sup>[[2]](#references)</sup>

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
> Kwa kutumia mbinu hii, unaweza hata kufikia endpoints za ndani/zilizofichwa.

### **CORS Brute Force**

Wakati mwingine utapata kurasa zinazorejesha header _**Access-Control-Allow-Origin**_ tu ikiwa domain/subdomain halali imewekwa kwenye header ya _**Origin**_. Katika hali hizi, unaweza kutumia tabia hii vibaya ili **kubaini** **subdomains** mpya.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Unapotafuta **subdomains**, angalia kama zinaelekeza kwenye aina yoyote ya **bucket**, na zikifanya hivyo [**kagua permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Pia, kwa kuwa kwa wakati huu utajua domains zote zilizo ndani ya scope, jaribu [**kubashiri kwa brute force majina ya bucket yanayowezekana na kukagua permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Ufuatiliaji**

Unaweza **kufuatilia** kama **subdomains mpya** za domain zinaundwa kwa kufuatilia **Certificate Transparency** Logs, kama [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) inavyofanya.

### **Kutafuta vulnerabilities**

Kagua uwezekano wa [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inaelekeza kwenye **S3 bucket**, [**kagua permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Ukipata **subdomain yenye IP tofauti** na zile ulizopata tayari wakati wa asset discovery, unapaswa kufanya **basic vulnerability scan** (kwa kutumia Nessus au OpenVAS) na [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na services zinazoendeshwa, unaweza kupata **mbinu za "kuzishambulia" katika kitabu hiki**.\
_Kumbuka kwamba wakati mwingine subdomain huwa kwenye IP ambayo haidhibitiwi na mteja, hivyo haimo kwenye scope. Kuwa mwangalifu._

## IPs

Katika hatua za mwanzo huenda **ulipata baadhi ya IP ranges, domains na subdomains**.\
Ni wakati wa **kukusanya IPs zote kutoka kwenye ranges hizo**, pamoja na zile za **domains/subdomains (DNS queries).**

Kwa kutumia services kama zifuatazo, unaweza pia kupata **IPs zilizotumiwa awali na domains na subdomains**. Huenda mteja bado anamiliki IPs hizi (na huenda zikakusaidia kupata [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**SecurityTrails**](https://securitytrails.com/) (data ya kihistoria ya DNS/IP inahitaji mpango wa kulipia)

Unaweza pia kutafuta domains zinazoelekeza kwenye IP address maalum kwa kutumia zana ya [**hakip2host**](https://github.com/hakluke/hakip2host) au huduma ya mtandaoni ya reverse IP lookup kama [**NetAPI**](https://netapi.com/lookup-ip/)

### **Kutafuta vulnerabilities**

Fanya **port scan kwenye IPs zote zisizo za CDNs** (kwa kuwa kuna uwezekano mkubwa hutapata chochote cha kuvutia humo). Huenda **ukaweza kupata vulnerabilities** kwenye services zinazoendeshwa zilizogunduliwa.

**Pata** [**mwongozo**](../pentesting-network/index.html) **kuhusu jinsi ya kuscan hosts.**

## Kutafuta web servers

> Tumepata kampuni zote na assets zake, na tunajua IP ranges, domains na subdomains zilizo ndani ya scope. Ni wakati wa kutafuta web servers.

Huenda tayari umefanya **recon ya IPs na domains zilizogunduliwa** katika hatua zilizopita, kwa hiyo unaweza kuwa **umeshapata web servers zote zinazowezekana**. Hata hivyo, kama bado hujafanya hivyo, sasa tutaangalia **mbinu za haraka za kutafuta web servers** ndani ya scope.

Tafadhali kumbuka kwamba hili litaelekezwa kwenye **ugunduzi wa web apps**, kwa hiyo unapaswa pia kufanya **vulnerability scanning** na **port scanning** (**ikiwa scope inaruhusu**).

**Mbinu ya haraka** ya kugundua **ports zilizo wazi** zinazohusiana na **web** servers kwa kutumia [**masscan inaweza kupatikana hapa**](../pentesting-network/index.html#http-port-discovery).\
Zana nyingine rahisi ya kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unapitisha orodha ya domains, nayo itajaribu kuunganisha kwenye port 80 (http) na 443 (https). Pia, unaweza kuielekeza ijaribu ports nyingine:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Picha za skrini**

Sasa kwa kuwa umegundua **web servers zote** zilizopo ndani ya scope (miongoni mwa **IPs** za kampuni na **domains** na **subdomains** zake zote), huenda **hujui pa kuanzia**. Basi, tufanye iwe rahisi: anza tu kwa kupiga picha za skrini za zote. Kwa **kutazama tu** **ukurasa mkuu**, unaweza kupata endpoints **zisizo za kawaida** ambazo zina uwezekano mkubwa zaidi wa kuwa **vulnerable**.

Ili kutekeleza wazo hili, unaweza kutumia [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kuchanganua **picha zote za skrini** na kukuambia **ni zipi ambazo huenda zina vulnerabilities** na zipi hazina.

## Rasilimali za Public Cloud

Ili kupata rasilimali za cloud zinazoweza kuwa za kampuni, unapaswa **kuanza na orodha ya maneno muhimu yanayotambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Pia utahitaji wordlists za **maneno ya kawaida yanayotumiwa kwenye buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, kwa kutumia maneno hayo, unapaswa kutengeneza **permutations** (angalia [**Mzunguko wa Pili wa DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa wordlists zitakazotokana na hatua hiyo, unaweza kutumia tools kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta rasilimali za Cloud, unapaswa **kutafuta zaidi ya buckets za AWS pekee**.

### **Kutafuta vulnerabilities**

Ukipata vitu kama **buckets zilizo wazi au cloud functions zilizo wazi**, unapaswa **kuzifikia** na kujaribu kuona zina nini na kama unaweza kuzitumia vibaya.

## Barua pepe

Ukiwa na **domains** na **subdomains** zilizo ndani ya scope, una karibu kila kitu **unachohitaji ili kuanza kutafuta barua pepe**. Hizi ndizo **APIs** na **tools** ambazo zimefanya kazi vizuri zaidi kwangu katika kutafuta barua pepe za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - pamoja na APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (toleo lisilolipishwa)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (toleo lisilolipishwa)
- API ya [**https://minelead.io/**](https://minelead.io/) (toleo lisilolipishwa)

### **Kutafuta vulnerabilities**

Barua pepe zitakusaidia baadaye kufanya **brute-force kwenye web logins na huduma za auth** (kama SSH). Pia zinahitajika kwa **phishings**. Zaidi ya hayo, APIs hizi zitakupa **taarifa zaidi kuhusu mtu** aliye nyuma ya barua pepe, jambo linalofaa kwa kampeni ya phishing.

## Credential Leaks

Ukiwa na **domains,** **subdomains**, na **barua pepe**, unaweza kuanza kutafuta credentials zilizovuja zamani zinazohusiana na barua pepe hizo:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta vulnerabilities**

Ukipata credentials zilizovuja ambazo **bado ni halali**, huo ni ushindi rahisi sana.

## Secret Leaks

Credential leaks zinahusiana na udukuzi wa kampuni ambapo **taarifa nyeti zilivuja na kuuzwa**. Hata hivyo, kampuni zinaweza kuathiriwa na **leaks nyingine** ambazo taarifa zake hazipo kwenye database hizo:

### Github Leaks

Credentials na APIs zinaweza kuvuja kwenye **public repositories** za **kampuni** au za **watumiaji** wanaofanya kazi katika kampuni hiyo ya github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) **kupakua** **public repos** zote za **organization** na za **developers** wake, kisha kuendesha [**gitleaks**](https://github.com/gitleaks/gitleaks) juu yake kiotomatiki.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **maandishi** yote yaliyotolewa na **URLs zinazopitishwa** kwake, kwa sababu wakati mwingine **web pages pia huwa na secrets**.

#### Github Dorks

Angalia ukurasa wa [GitHub dorks and leaks](github-leaked-secrets.md) ili upate **GitHub dorks** zinazoweza kutumika kutafuta kwenye organization.

### Pastes Leaks

Wakati mwingine washambuliaji au wafanyakazi tu **huchapisha maudhui ya kampuni kwenye paste site**. Haya yanaweza kuwa na **taarifa nyeti** au yasiwe nayo, lakini ni jambo la kuvutia kuyatafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta kwenye zaidi ya paste sites 80 kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini bora bado zinafaa kila wakati kupata **taarifa zilizo wazi ambazo hazikupaswa kuwepo hapo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu kadhaa ya queries zinazowezekana ambazo huwezi kuendesha mwenyewe. Kwa hiyo, unaweza kuchagua 10 unazozipenda au kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuzitekeleza zote**.

_Kumbuka kwamba tools zinazojaribu kuendesha database nzima kwa kutumia Google browser ya kawaida hazitamaliza, kwa sababu Google itakuzuia haraka sana._

### **Kutafuta vulnerabilities**

Ukipata credentials au API tokens zilizovuja ambazo **bado ni halali**, huo ni ushindi rahisi sana.

## Vulnerabilities katika Public Code

Ukipata kwamba kampuni ina **open-source code**, unaweza **kuichanganua** na kutafuta **vulnerabilities** ndani yake.

**Kulingana na lugha**, kuna **tools** tofauti unazoweza kutumia; tazama orodha ya [tools za ukaguzi wa source code](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Pia kuna huduma za bila malipo zinazokuruhusu **kuchanganua public repositories**, kama vile:

- [**Snyk**](https://app.snyk.io/)

## [**Mbinu ya Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Vulnerabilities nyingi** zinazopatikana na bug hunters huwa ndani ya **web applications**, kwa hiyo hapa ningependa kuzungumzia **mbinu ya kupima web applications**. Unaweza [**kupata taarifa hizi hapa**](../../network-services-pentesting/pentesting-web/index.html).

Pia ningependa kutaja maalum sehemu ya [**Tools za open source za Web Automated Scanners**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwa sababu, ingawa hupaswi kutarajia zipate vulnerabilities nyeti sana, zinafaa kuongezwa kwenye **workflows ili kupata taarifa za awali za web.**

## Muhtasari

> Hongera! Kufikia hapa tayari umefanya **enumeration yote ya msingi**. Ndiyo, ni ya msingi kwa sababu kuna enumeration nyingi zaidi zinazoweza kufanywa (tutaona mbinu zaidi baadaye).

Kwa hiyo, tayari umefanya yafuatayo:

1. Umepata **kampuni** zote zilizo ndani ya scope
2. Umepata **assets** zote za kampuni hizo (na kufanya vuln scan ikiwa ipo ndani ya scope)
3. Umepata **domains** zote za kampuni hizo
4. Umepata **subdomains** zote za domains hizo (kuna subdomain takeover?)
5. Umepata **IPs** zote zilizo ndani ya scope (zinazotoka na **zisizotoka kwenye CDNs**).
6. Umepata **web servers** zote na kuzipiga **picha za skrini** (kuna chochote kisicho cha kawaida kinachostahili kuchunguzwa zaidi?)
7. Umepata **rasilimali zote za public cloud zinazoweza kuwa za kampuni**.
8. Umepata **barua pepe**, **credential leaks**, na **secret leaks** zinazoweza kukupa **ushindi mkubwa kwa urahisi sana**.
9. **Umefanya Pentesting kwenye webs zote ulizopata**

## **Tools za Kiotomatiki za Full Recon**

Kuna tools kadhaa zinazoweza kutekeleza baadhi ya hatua zilizopendekezwa dhidi ya scope fulani.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ni ya zamani kidogo na haijasasishwa



## References

- [1] [Jason Haddix – Mbinu ya Bug Hunter v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Kuhusu Favicons: Kutoka Ikoni za Browser hadi Taarifa za Attack Surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Kutumia favicon.ico kama silaha kwa BugBounties, OSINT na mengineyo](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Kugundua Domains kupitia Shambulio la Ulinganishaji wa Muda kwenye Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Kufichua (na Kuiga) Kampeni Ghali ya Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Mbinu ya Kipekee ya Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Mchakato Kamili wa Kugundua Subdomains, Sehemu ya 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Kugundua Subdomains kwa Brute Force kwa Kutumia Trickest Workflow ya Kiotomatiki, Sehemu ya 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Picha ya skrini ya matokeo ya favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
