# Mbinu ya External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ugunduzi wa assets

Kwa orodha iliyopangwa ya miradi zaidi ya OSINT na ugunduzi wa wavuti, angalia [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint).

> Kwa hiyo umeambiwa kwamba kila kitu kinachomilikiwa na kampuni fulani kiko ndani ya scope, na unataka kubaini kampuni hiyo inamiliki nini hasa.

Lengo la awamu hii ni kupata **kampuni zote zinazomilikiwa na kampuni kuu**, kisha kupata **assets** zote za kampuni hizo. Ili kufanya hivyo, tutafanya yafuatayo:<sup>[[1]](#references)</sup>

1. Tafuta ununuzi wa kampuni kuu; hii itatupatia kampuni zilizo ndani ya scope.
2. Tafuta ASN (ikiwa ipo) ya kila kampuni; hii itatupatia anuwai za IP zinazomilikiwa na kila kampuni.
3. Tumia utafutaji wa reverse whois kutafuta maingizo mengine (majina ya mashirika, domains...) yanayohusiana na la kwanza (hili linaweza kufanywa kwa kurudia).
4. Tumia mbinu nyingine kama vichujio vya `org` na `ssl` vya shodan kutafuta assets nyingine (ujanja wa `ssl` unaweza kufanywa kwa kurudia).

Kwa hatua za kukabidhiana kutoka subdomains zilizotatuliwa hadi crawling ya HTTP na ugunduzi wa port, angalia [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Ununuzi**

Kwanza, tunahitaji kujua **ni kampuni gani nyingine zinazomilikiwa na kampuni kuu**.\
Chaguo moja ni kutembelea [https://www.crunchbase.com/](https://www.crunchbase.com), **kutafuta** **kampuni kuu**, na **kubofya** "**acquisitions**". Hapo utaona kampuni nyingine zilizonunuliwa na kampuni kuu.\
Chaguo jingine ni kutembelea ukurasa wa **Wikipedia** wa kampuni kuu na kutafuta **acquisitions**.\
Kwa kampuni za umma, angalia **SEC/EDGAR filings**, kurasa za **investor relations**, au sajili za kampuni za eneo husika (kwa mfano, **Companies House** nchini Uingereza).\
Kwa miundo ya kampuni za kimataifa na kampuni tanzu, jaribu **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) na hifadhidata ya **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Sawa, kufikia hapa unapaswa kuwa unazijua kampuni zote zilizo ndani ya scope. Hebu tujue jinsi ya kupata assets zao.

### **ASNs**

Nambari ya mfumo huru (**ASN**) ni **nambari ya kipekee** inayotolewa kwa **mfumo huru** (AS) na **Internet Assigned Numbers Authority (IANA)**.\
**AS** inajumuisha **blocks** za **anwani za IP** ambazo zina sera iliyofafanuliwa wazi ya kufikia mitandao ya nje na zinasimamiwa na shirika moja, lakini huenda zikawa na waendeshaji kadhaa.

Inafaa kubaini kama **kampuni imepewa ASN yoyote** ili kupata **anuwai zake za IP**. Itakuwa muhimu kufanya **jaribio la vulnerability** dhidi ya **hosts** zote zilizo ndani ya **scope** na **kutafuta domains** ndani ya IP hizi.\
Unaweza **kutafuta** kwa **jina** la kampuni, **IP** au **domain** kwenye [**https://bgp.he.net/**](https://bgp.he.net) **au** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Kulingana na eneo la kampuni, viungo hivi vinaweza kusaidia kukusanya data zaidi:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amerika Kaskazini),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Amerika ya Kusini),** [**RIPE NCC**](https://www.ripe.net) **(Ulaya). Hata hivyo, huenda taarifa zote** muhimu **(anuwai za IP na Whois)** tayari zikaonekana kwenye kiungo cha kwanza.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Pia, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration hukusanya na kufupisha ASNs kiotomatiki mwishoni mwa scan.

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

Unaweza pia kupata safu za IP za shirika kwa kutumia [ASNLookup](https://asnlookup.com/), ambayo ina kiwango kidogo cha API isiyolipishwa.

### **Kutafuta udhaifu**

Kwa hatua hii tunajua **assets zote zilizo ndani ya wigo**, kwa hivyo ikiwa una ruhusa unaweza kuendesha **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) kwenye hosts zote.\
Pia, unaweza kuendesha [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **au kutumia huduma kama** Shodan, Censys, au ZoomEye **kutafuta** ports zilizo wazi **na kulingana na utakachogundua, unapaswa** kutazama kitabu hiki ili kuona jinsi ya kufanya pentest ya huduma mbalimbali zinazoweza kuwa zinaendeshwa.\
**Pia, inaweza kuwa vyema kutaja kwamba unaweza kuandaa orodha za** default username **na** passwords **na kujaribu kufanya** bruteforce kwenye huduma ukitumia [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Tunajua kampuni zote zilizo ndani ya wigo na assets zake; sasa ni wakati wa kutafuta domains zilizo ndani ya wigo.

_Tafadhali kumbuka kwamba katika mbinu zilizopendekezwa hapa chini unaweza pia kupata subdomains, na taarifa hiyo haipaswi kupuuzwa._

Kwanza kabisa unapaswa kutafuta **main domain**(s) za kila kampuni. Kwa mfano, kwa _Tesla Inc._ itakuwa _tesla.com_.

### **Reverse DNS**

Kwa kuwa umepata safu zote za IP za domains, unaweza kujaribu kufanya **reverse dns lookups** kwenye **IPs hizo ili kupata domains zaidi zilizo ndani ya wigo**. Jaribu kutumia dns server ya mwathiriwa au dns server inayojulikana sana (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Ili hili lifanye kazi, msimamizi lazima awashe PTR mwenyewe.\
Unaweza pia kutumia [SecurityTrails](https://securitytrails.com/) kupata maelezo haya, ingawa data ya kihistoria ya DNS inahitaji mpango unaolipiwa.\
Kwa ranges kubwa, zana kama [**massdns**](https://github.com/blechschmidt/massdns) na [**dnsx**](https://github.com/projectdiscovery/dnsx) zinafaa kwa kugeuza reverse lookups na uboreshaji wa data kuwa otomatiki.

### **Reverse Whois (loop)**

Ndani ya **whois** unaweza kupata **taarifa** nyingi za kuvutia, kama vile **jina la shirika**, **anwani**, **barua pepe**, nambari za simu... Lakini kinachovutia zaidi ni kwamba unaweza kupata **assets zaidi zinazohusiana na kampuni** ukifanya **reverse whois lookups kwa kutumia sehemu yoyote kati ya hizo** (kwa mfano, sajili nyingine za whois ambako barua pepe hiyo hiyo inaonekana).\
Unaweza kutumia zana za mtandaoni kama:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bila malipo** (Web na API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bila malipo**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bila malipo**
- [https://www.whoxy.com/](https://www.whoxy.com) - Kiolesura cha web **bila malipo**; API hulipiwa.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Hulipiwa
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Si bure (searches **100 tu bila malipo**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Si bure
- [https://securitytrails.com/](https://securitytrails.com/) - Ufikiaji mdogo wa API bila malipo kwa DNS/subdomains za sasa; data ya kihistoria na reverse lookups huhitaji mpango unaolipiwa.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - API credits 500 bila malipo wakati wa kujisajili; hulipiwa baadaye.

Unaweza kufanya kazi hii kuwa otomatiki kwa kutumia [**DomLink** ](https://github.com/vysecurity/DomLink)(inahitaji whoxy API key).\
Unaweza pia kufanya ugunduzi wa reverse whois kiotomatiki kwa kutumia [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Kumbuka kwamba unaweza kutumia mbinu hii kugundua majina zaidi ya domain kila unapopata domain mpya.**

### **Trackers**

Ukipata **ID ileile ya tracker ileile** kwenye kurasa 2 tofauti, unaweza kudhani kwamba **kurasa zote mbili** **inasimamiwa na timu moja**.\
Kwa mfano, ukiona **Google Analytics ID** ileile au **Adsense ID** ileile kwenye kurasa kadhaa.

Kuna kurasa na zana kadhaa zinazokuwezesha kutafuta trackers hizi na nyinginezo:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Huduma ya web na API **inayolipiwa** ([bei](https://www.stackscan.com/pricing)); kwa sasa hakuna mpango wa bure unaotangazwa. Tafuta uhusiano kwa kutumia asset yoyote inayotolewa, si tracker IDs pekee: njia ya script, jina la bundle inayohifadhiwa kwenye seva yako, au host ambayo asset inapakiwa kutoka kwake; matokeo huonyesha kila site inayoitumia.

API hurejesha stack ya domain moja, jambo linalofaa kuthibitisha kwamba asset inayoshukiwa ni ya mazingira hayo hayo:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Hurejesha kila teknolojia iliyogunduliwa pamoja na kategoria yake. Asset pivoting kwa sasa inatumika kwenye web pekee; API inatoa utafutaji kwa kila domain.

### **Favicon**

Je, unajua kwamba tunaweza kupata domains na subdomains zinazohusiana na target yetu kwa kutafuta hash ya ikoni ileile ya favicon? Hivi ndivyo hasa zana ya [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), iliyotengenezwa na [@m4ll0k2](https://twitter.com/m4ll0k2), inavyofanya. Hivi ndivyo unavyoweza kuitumia:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Matokeo ya Favihash yaliyotumika kugundua vikoa vinavyoshiriki hash ya favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kwa kifupi, favihash hutuwezesha kugundua vikoa vyenye hash ya ikoni ya favicon inayofanana na ya lengo letu.

![Matokeo ya favihash yaliyotumika kugundua vikoa vyenye hash sawa ya favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Tumia hash ya favicon inayojulikana kama pivot ya Shodan au FOFA kutafuta matukio mengine ya teknolojia hiyo yaliyo wazi kwa umma.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Hivi ndivyo unavyoweza **kukokotoa favicon hash** ya tovuti (MMH3 juu ya byte za favicon zilizo **base64-encoded**):

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

Unaweza pia kupata favicon hashes kwa kiwango kikubwa kwa kutumia [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), kisha ukatumia matokeo hayo kutafuta kwenye Shodan/Censys.

Chukulia alama za vidole za favicon kama vidokezo na uzihakiki kwa kutumia ishara zinazozizunguka.<sup>[[3]](#references)[[4]](#references)</sup>

- **Chukulia hash kama kiashirio, si uthibitisho**: MMH3 ni fupi; migongano, aikoni zinazotumiwa tena, na udanganyifu wa makusudi vinawezekana.
- **Chunguza zaidi ya** `/favicon.ico`: kagua njia za framework/build, faili za manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, URL za data zilizo ndani ya ukurasa, na tagi za HTML `<link rel="icon">`.
- **Huenda assets tuli zikaendelea kufikiwa hata nyuma ya vidhibiti vya WAF/SSO/IdP**: omba aikoni moja kwa moja na kagua `ETag`, `Last-Modified`, redirects, na cache headers.
- **Thibitisha ulinganifu kwa kutumia ishara zinazouzunguka**: linganisha title, HTML/body hash, headers, subjects/SANs za cheti cha TLS, vipengele vya bidhaa, na ports zilizo wazi.
- **Panga katika makundi kwa HTML/body hash**: template inayolingana huimarisha alama ya kidole; templates mchanganyiko huashiria aikoni ya jumla au inayoshirikiwa.
- **Chukulia hash inayoonekana kwenye saini, ports, na bidhaa zisizohusiana kama honeypot au placeholder inayowezekana.**
- **Kwa targets zisizo wazi, linganisha ukurasa halisi na njia isiyokuwepo** kama `/_favicon_probe_<8-hex>`; majibu yanayofanana ya hosting au ukurasa wa parking yanaweza kueleza aikoni inayoshirikiwa.
- **Anza uchunguzi kwa kutumia sheria za utambuzi za Nuclei au datasets za umma** zinazohusisha favicon hashes na bidhaa pamoja na CPEs.
- **Kumbuka pengo la ufunikaji linalotokana na IP**: nyuso zinazopitia CDN, zinazoelekezwa kwa SNI, anycast, na zinazotegemea domain pekee huenda zikakosekana kwenye datasets za aina ya Shodan.

### **Hakimiliki / Mfuatano wa kipekee**

Tafuta ndani ya kurasa za wavuti **mifuatano inayoweza kushirikiwa na tovuti mbalimbali za shirika moja**. **Mfuatano wa hakimiliki** unaweza kuwa mfano mzuri. Kisha tafuta mfuatano huo kwenye **Google**, kwenye **vivinjari** vingine, au hata kwenye **Shodan**: `shodan search http.html:"Copyright string"`

### **Muda wa CRT**

Ni kawaida kuwa na cron job kama vile

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

ili kufanya upya vyeti vyote kwenye seva kwa wakati mmoja. Kulinganisha mihuri ya muda ya vyeti au nafasi za kumbukumbu za certificate-transparency kunaweza kufichua domains zinazohusiana.<sup>[[6]](#references)</sup>

Tumia pia kumbukumbu za **certificate transparency** moja kwa moja:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Taarifa za DMARC ya barua pepe

Unaweza kutumia tovuti kama [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) au zana kama [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) ili kupata **domains na subdomains zinazotumia taarifa sawa za DMARC**.\
Huduma nyingine yenye manufaa ni [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Rekodi ya A iliyoachwa inaweza kufikiwa tena mtoa huduma wa cloud anapokabidhi upya IP. Utafiti uliorejelewa unaonyesha mtiririko wa kazi wa kutumia fursa hii kwa kuanzisha instance na kulinganisha anwani yake na data ya passive DNS; jaribu hali za takeover ndani ya wigo ulioidhinishwa pekee.<sup>[[7]](#references)</sup>

### **Njia nyingine**

Rudia hatua zinazofaa za ugunduzi kila unapopata domain mpya: kila matokeo yanaweza kufichua majina zaidi ya vyeti, uhusiano wa passive-DNS, ulinganifu wa favicon na vitambulishi vya shirika ambavyo havikuonekana kwenye seed ya awali.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Kama unavyojua tayari jina la shirika linalomiliki nafasi ya IP, unaweza kutafuta kwa kutumia data hiyo kwenye shodan kwa amri hii: `org:"Tesla, Inc."` Kagua hosts zilizopatikana ili kuona domains mpya zisizotarajiwa kwenye cheti cha TLS.

Unaweza kufikia **cheti cha TLS** cha ukurasa mkuu wa wavuti, kupata **jina la Shirika**, kisha kutafuta jina hilo kwenye **vyeti vya TLS** vya kurasa zote za wavuti zinazojulikana na **shodan** kwa kichujio hiki: `ssl:"Tesla Motors"` au utumie zana kama [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ni zana inayotafuta **domains zinazohusiana** na domain kuu na **subdomains** zake; ni nzuri sana.

**Passive DNS / Historical DNS**

Data ya Passive DNS ni nzuri kwa kupata **rekodi za zamani na zilizosahaulika** ambazo bado zinatatuliwa au ambazo zinaweza kuchukuliwa. Angalia:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Kutafuta udhaifu**

Kagua uwezekano wa [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Huenda kampuni fulani **inatumia domain fulani** lakini **imepoteza umiliki wake**. Isajili tu (ikiwa ni nafuu vya kutosha) na uijulishe kampuni.

Ukipata **domain yoyote yenye IP tofauti** na zile ulizopata tayari kwenye ugunduzi wa assets, unapaswa kufanya **uchanganuzi wa msingi wa udhaifu** (kwa kutumia Nessus au OpenVAS) na [**uchanganuzi wa port**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na huduma zinazoendeshwa, unaweza kupata **mbinu kadhaa za "kuzishambulia" kwenye kitabu hiki**.\
_Kumbuka kwamba wakati mwingine domain inapangishwa kwenye IP isiyodhibitiwa na mteja, hivyo haimo kwenye wigo; kuwa mwangalifu._

## Subdomains

> Tunajua kampuni zote zilizo ndani ya wigo, assets zote za kila kampuni na domains zote zinazohusiana na kampuni hizo.

Ni wakati wa kutafuta subdomains zote zinazowezekana za kila domain tuliyopata.

> [!TIP]
> Kumbuka kwamba baadhi ya zana na mbinu za kutafuta domains zinaweza pia kusaidia kupata subdomains

### **DNS**

Tujaribu kupata **subdomains** kutoka kwenye rekodi za **DNS**. Tunapaswa pia kujaribu **Zone Transfer** (Ikiwa kuna udhaifu, unapaswa kuuripoti).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Kwa APIs na platforms zinazoshughulikia miundombinu, reputation, rekodi za breach, na enrichment zaidi ya ugunduzi wa subdomain, tazama [katalogi ya APIs za Reconnaissance na Threat-Intelligence](reconnaissance-and-threat-intelligence-apis.md).

Njia ya haraka zaidi ya kupata subdomain nyingi ni kutafuta kwenye vyanzo vya nje. **Tools** zinazotumika zaidi ni hizi (kwa matokeo bora zaidi, sanidi API keys):


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

Kuna **tools/APIs nyingine za kuvutia** ambazo, hata kama hazijaelekezwa moja kwa moja kutafuta subdomains, zinaweza kusaidia kupata subdomains, kama vile:

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

- [**gau**](https://github.com/lc/gau)**:** hupata URL zinazojulikana kutoka AlienVault's Open Threat Exchange, Wayback Machine, na Common Crawl kwa kikoa chochote.

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

- [**SecurityTrails**](https://securitytrails.com/) hutoa ufikiaji mdogo wa API bila malipo kwa data ya sasa ya DNS na subdomain; data ya kihistoria ya DNS/IP inahitaji mpango unaolipiwa.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Mradi huu hutoa **subdomain zote zinazohusiana na programu za bug-bounty bila malipo**. Unaweza pia kufikia data hii kupitia [chaospy](https://github.com/Moaaz-0x/chaospy), au hata kufikia scope inayotumiwa na mradi huu kupitia [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Unaweza kupata **ulinganisho** wa zana nyingi kati ya hizi hapa: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hebu tutafute **subdomain** mpya kwa kufanya brute-force kwenye seva za DNS kwa kutumia majina yanayowezekana ya subdomain.

Kwa hatua hii utahitaji baadhi ya **wordlist za subdomain za kawaida kama**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Pia utahitaji IP za DNS resolver nzuri. Ili kutengeneza orodha ya DNS resolver zinazoaminika, unaweza kupakua resolver kutoka [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) na kutumia [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kuzichuja. Au unaweza kutumia: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Zana zinazopendekezwa zaidi kwa DNS brute-force ni:

- [**massdns**](https://github.com/blechschmidt/massdns): Hii ndiyo zana ya kwanza iliyofanya DNS brute-force kwa ufanisi. Ni ya haraka sana, hata hivyo inaweza kutoa matokeo chanya ya uongo.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Hii, nafikiri, hutumia resolver 1 tu.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ni wrapper ya `massdns`, iliyoandikwa kwa go, inayokuwezesha kuorodhesha subdomains halali kwa kutumia bruteforce inayotumika, na pia kutatua subdomains kwa kushughulikia wildcard na kusaidia kwa urahisi ingizo na matokeo.

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

Baada ya kupata subdomains kupitia vyanzo vya wazi na brute-forcing, unaweza kutengeneza mabadiliko ya subdomains zilizopatikana ili kujaribu kupata nyingine zaidi. Zana kadhaa zinafaa kwa kusudi hili:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Ukiipa domains na subdomains, hutengeneza permutations.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Kwa kutumia domains na subdomains, zalisha permutations.
  - Unaweza kupata **wordlist** ya permutations za goaltdns [**hapa**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Ikipewa domains na subdomains, hutengeneza permutations. Ikiwa faili ya permutations haijaonyeshwa, gotator itatumia yake yenyewe.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Mbali na kutengeneza permutations za subdomains, inaweza pia kujaribu kuzitatua (lakini ni bora kutumia tools zilizotajwa hapo awali).
  - Unaweza kupata **wordlist** ya permutations za altdns [**hapa**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Zana nyingine ya kufanya permutations, mutations na mabadiliko ya subdomains. Zana hii itafanya brute force ya matokeo (haitumii dns wild card).
  - Unaweza kupata orodha ya maneno ya dmut permutations [**hapa**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Kwa kutumia domain, **hutengeneza majina mapya ya subdomain yanayoweza kuwepo** kulingana na pattern zilizoonyeshwa ili kujaribu kugundua subdomain zaidi.

#### Uzalishaji mahiri wa permutations

- [**regulator**](https://github.com/cramppet/regulator): Hujifunza pattern zinazofanana na regex kutoka kwa subdomain zilizogunduliwa na kutengeneza majina yanayoweza kutatuliwa.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ni fuzzer ya subdomain brute-force iliyounganishwa na algoriti rahisi sana lakini yenye ufanisi inayoongozwa na DNS response. Hutumia seti ya data ya ingizo iliyotolewa, kama wordlist iliyobinafsishwa au rekodi za kihistoria za DNS/TLS, ili kuzalisha kwa usahihi majina mengine ya domain yanayohusiana na kuyaendeleza zaidi kwa mzunguko, kulingana na taarifa iliyokusanywa wakati wa DNS scan.

```
echo www | subzuf facebook.com
```

### **Workflow ya Ugunduzi wa Subdomain**

Mifano ya workflow ya Trickest inachanganya OSINT, DNS brute force, na hatua za permutation kwa ajili ya subdomain enumeration inayoweza kurudiwa.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ukipata anwani ya IP yenye **ukurasa mmoja au kadhaa wa wavuti** wa subdomain, unaweza kujaribu **kutafuta subdomain nyingine zenye tovuti kwenye IP hiyo** kwa kutafuta **vyanzo vya OSINT** ili kupata domain zilizo kwenye IP hiyo, au kwa **kubashiri kwa brute force majina ya domain ya VHost kwenye IP hiyo**.

#### OSINT

Unaweza kupata baadhi ya **VHosts kwenye IP kwa kutumia** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **au API nyingine**.

**Brute Force**

Ukishuku kwamba subdomain fulani inaweza kuwa imefichwa kwenye web server, unaweza kujaribu kuibashiri kwa brute force:

Kwa vhosts zinazotegemea jina, jaribu thamani mbalimbali kwenye kichwa cha `Host` na utumie auto-calibration ya ffuf kuchuja jibu chaguomsingi.<sup>[[2]](#references)</sup>

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
> Kwa kutumia technique hii, unaweza hata kufikia endpoints za ndani/zilizofichwa.

### **CORS Brute Force**

Wakati mwingine utapata kurasa zinazorejesha header _**Access-Control-Allow-Origin**_ tu wakati domain/subdomain halali imewekwa kwenye header ya _**Origin**_. Katika hali hizi, unaweza kutumia vibaya tabia hii ili **kugundua** **subdomain** mpya.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Unapotafuta **subdomains**, angalia ikiwa **inaelekeza** kwenye aina yoyote ya **bucket**, na ikiwa ni hivyo [**kagua ruhusa**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Pia, kwa kuwa kwa sasa utakuwa unajua domains zote zilizo ndani ya scope, jaribu [**kubashiri kwa nguvu majina ya bucket yanayowezekana na kukagua ruhusa**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Ufuatiliaji**

Unaweza **kufuatilia** ikiwa **subdomains mpya** za domain zinaundwa kwa kufuatilia logi za **Certificate Transparency**, kama [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) inavyofanya.

### **Kutafuta udhaifu**

Kagua uwezekano wa [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ikiwa **subdomain** inaelekeza kwenye **S3 bucket**, [**kagua ruhusa**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Ukipata **subdomain yenye IP tofauti** na zile ulizokwisha kupata wakati wa ugunduzi wa assets, unapaswa kufanya **uchanganuzi wa msingi wa udhaifu** (kwa kutumia Nessus au OpenVAS) na pia [**uchanganuzi wa ports**](../pentesting-network/index.html#discovering-hosts-from-the-outside) kwa kutumia **nmap/masscan/shodan**. Kulingana na huduma zinazoendeshwa, unaweza kupata mbinu kadhaa za **"kuzishambulia" katika kitabu hiki**.\
_Kumbuka kuwa wakati mwingine subdomain huwekwa kwenye IP ambayo haidhibitiwi na mteja, kwa hiyo haiko ndani ya scope; kuwa mwangalifu._

## IPs

Katika hatua za mwanzo huenda **ulipata baadhi ya masafa ya IP, domains na subdomains**.\
Ni wakati wa **kukusanya IP zote kutoka kwenye masafa hayo** na za **domains/subdomains (kwa kutumia DNS queries).**

Kwa kutumia huduma kama hizi zifuatazo, unaweza pia kupata **IP zilizotumiwa awali na domains na subdomains**. Huenda IP hizi bado zinamilikiwa na mteja (na zinaweza kukuwezesha kupata [**mbinu za kukwepa CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**SecurityTrails**](https://securitytrails.com/) (data ya kihistoria ya DNS/IP inahitaji mpango wa kulipia)

Unaweza pia kuangalia domains zinazoelekeza kwenye anwani mahususi ya IP kwa kutumia zana ya [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Kutafuta udhaifu**

**Changanua ports za IP zote ambazo si za CDN** (kwani kuna uwezekano mkubwa hutapata chochote cha kuvutia humo). Huenda **ukaweza kupata udhaifu** katika huduma zinazoendeshwa ulizogundua.

**Pata** [**mwongozo**](../pentesting-network/index.html) **kuhusu jinsi ya kuchanganua hosts.**

## Kutafuta web servers

> Tumepata kampuni zote na assets zake, na tunajua masafa ya IP, domains na subdomains zilizo ndani ya scope. Ni wakati wa kutafuta web servers.

Katika hatua zilizopita huenda tayari umefanya **uchunguzi wa awali wa IP na domains ulizogundua**, kwa hiyo huenda **tayari umepata web servers zote zinazowezekana**. Hata hivyo, ikiwa bado hujazipata, sasa tutaangalia baadhi ya **mbinu za haraka za kutafuta web servers** zilizo ndani ya scope.

Tafadhali kumbuka kuwa hii **inalenga kugundua web apps**, kwa hiyo unapaswa pia **kuchanganua udhaifu** na **ports** (**ikiwa scope inaruhusu**).

[**Mbinu ya haraka** ya kugundua **ports zilizo wazi** zinazohusiana na web servers kwa kutumia **masscan** inapatikana hapa](../pentesting-network/index.html#http-port-discovery).\
Zana nyingine rahisi ya kutafuta web servers ni [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) na [**httpx**](https://github.com/projectdiscovery/httpx). Unatoa tu orodha ya domains na itajaribu kuunganisha kwenye port 80 (http) na 443 (https). Unaweza pia kubainisha ports nyingine za kujaribu:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Picha za skrini**

Sasa kwa kuwa umepata **web servers zote** zilizopo ndani ya scope (miongoni mwa **IPs** za kampuni na **domains** na **subdomains** zote), huenda **hujui pa kuanzia**. Kwa hiyo, tufanye iwe rahisi: anza tu kwa kupiga picha za skrini za zote. Kwa **kuangalia tu** **ukurasa mkuu**, unaweza kupata endpoints **zisizo za kawaida** ambazo zina uwezekano mkubwa zaidi wa kuwa **vulnerable**.

Ili kutekeleza wazo hili, unaweza kutumia [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) au [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Zaidi ya hayo, unaweza kutumia [**eyeballer**](https://github.com/BishopFox/eyeballer) kuchanganua **screenshots** zote na kukuambia **ni zipi zinazoweza kuwa na vulnerabilities**, na zipi hazina.

## Public Cloud Assets

Ili kupata cloud assets zinazoweza kuwa za kampuni, unapaswa **kuanza kwa orodha ya keywords zinazotambulisha kampuni hiyo**. Kwa mfano, kwa kampuni ya crypto unaweza kutumia maneno kama: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Utahitaji pia wordlists zenye **maneno ya kawaida yanayotumika kwenye buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Kisha, tumia maneno hayo kutengeneza **permutations** (angalia [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kwa maelezo zaidi).

Kwa wordlists zitakazotokana na hatua hiyo, unaweza kutumia tools kama [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **au** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Kumbuka kwamba unapotafuta Cloud Assets, unapaswa kut**afuta zaidi ya buckets za AWS pekee**.

### **Kutafuta vulnerabilities**

Ukipata vitu kama **buckets zilizo wazi au cloud functions zilizowekwa wazi**, unapaswa **kuzifikia** na kujaribu kuona zinakupa nini na kama unaweza kuzitumia vibaya.

## Emails

Ukiwa na **domains** na **subdomains** zilizo ndani ya scope, kimsingi una kila kitu **unachohitaji kuanza kutafuta emails**. Hizi ndizo **APIs** na **tools** ambazo zimefanya kazi vizuri zaidi kwangu kutafuta emails za kampuni:

- [**theHarvester**](https://github.com/laramies/theHarvester) - pamoja na APIs
- API ya [**https://hunter.io/**](https://hunter.io/) (toleo la bure)
- API ya [**https://app.snov.io/**](https://app.snov.io/) (toleo la bure)
- API ya [**https://minelead.io/**](https://minelead.io/) (toleo la bure)

### **Kutafuta vulnerabilities**

Emails zitasaidia baadaye **kufanya brute-force kwenye web logins na auth services** (kama SSH). Pia zinahitajika kwa **phishing**. Zaidi ya hayo, APIs hizi zitakupa **maelezo zaidi kuhusu mtu** aliye nyuma ya email, jambo linalosaidia kwenye kampeni ya phishing.

## Credential Leaks

Ukiwa na **domains,** **subdomains**, na **emails**, unaweza kuanza kutafuta credentials zilizovuja hapo awali na zinazohusiana na emails hizo:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Kutafuta vulnerabilities**

Ukipata credentials **halali zilizovuja**, hili ni jambo rahisi sana kufanikisha.

## Secrets Leaks

Credential leaks hutokana na hacks za kampuni ambapo **taarifa nyeti zilivuja na kuuzwa**. Hata hivyo, kampuni zinaweza kuathiriwa na **leaks nyingine** ambazo taarifa zake hazipo kwenye databases hizo:

### Github Leaks

Credentials na APIs zinaweza kuvuja kwenye **public repositories** za **kampuni** au za **watumiaji** wanaofanya kazi katika kampuni hiyo ya Github.\
Unaweza kutumia **tool** [**Leakos**](https://github.com/carlospolop/Leakos) **kupakua** **public repos** zote za **organization** na za **developers** wake, kisha kuendesha [**gitleaks**](https://github.com/gitleaks/gitleaks) juu yake kiotomatiki.

**Leakos** pia inaweza kutumika kuendesha **gitleaks** dhidi ya **URLs za maandishi** zinazotolewa na kupitishwa kwake, kwa kuwa wakati mwingine **kurasa za wavuti huwa na secrets**.

#### Github Dorks

Angalia ukurasa wa [GitHub dorks and leaks](github-leaked-secrets.md) ili kupata **GitHub dorks** zinazoweza kutumika kutafuta ndani ya organization.

### Pastes Leaks

Wakati mwingine washambuliaji au wafanyakazi huchapisha **maudhui ya kampuni kwenye paste site**. Huenda yakawa au yasiwe na **taarifa nyeti**, lakini ni muhimu sana kuyatafuta.\
Unaweza kutumia tool [**Pastos**](https://github.com/carlospolop/Pastos) kutafuta kwenye zaidi ya paste sites 80 kwa wakati mmoja.

### Google Dorks

Google dorks za zamani lakini bora bado zinafaa kutafuta **taarifa zilizowekwa wazi ambazo hazipaswi kuwepo hapo**. Tatizo pekee ni kwamba [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) ina maelfu kadhaa ya queries zinazowezekana ambazo huwezi kuendesha mwenyewe. Kwa hiyo, unaweza kuchagua 10 unazopenda zaidi au kutumia **tool kama** [**Gorks**](https://github.com/carlospolop/Gorks) **kuziendesha zote**.

_Kumbuka kwamba tools zinazojaribu kuendesha database nzima kwa kutumia Google browser ya kawaida hazitamaliza, kwa kuwa Google itakuzuia haraka sana._

### **Kutafuta vulnerabilities**

Ukipata credentials au API tokens **halali zilizovuja**, hili ni jambo rahisi sana kufanikisha.

## Public Code Vulnerabilities

Ukigundua kuwa kampuni ina **open-source code**, unaweza **kuichanganua** na kutafuta **vulnerabilities** ndani yake.

**Kulingana na lugha**, kuna **tools** tofauti unazoweza kutumia; tazama orodha ya [tools za kukagua source code](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Pia kuna huduma za bure zinazokuruhusu **kuchanganua public repositories**, kama vile:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Vulnerabilities nyingi** zinazopatikana na bug hunters huwa ndani ya **web applications**, kwa hiyo katika hatua hii ningependa kueleza **mbinu ya kupima web applications**; unaweza [**kupata maelezo haya hapa**](../../network-services-pentesting/pentesting-web/index.html).

Pia ningependa kutaja hasa sehemu ya [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), kwa sababu, ingawa hupaswi kutarajia zipate vulnerabilities nyeti sana, zinafaa kuongezwa kwenye **workflows ili kupata taarifa za awali za web.**

## Muhtasari

> Hongera! Kufikia hapa tayari umekamilisha **enumeration yote ya msingi**. Ndiyo, ni ya msingi kwa sababu kuna enumeration nyingi zaidi zinazoweza kufanywa (tutaona mbinu nyingine baadaye).

Kwa hiyo, tayari umefanya yafuatayo:

1. Umepata **kampuni** zote zilizo ndani ya scope
2. Umepata **assets** zote za kampuni hizo (na kufanya vuln scan ikiwa zimo kwenye scope)
3. Umepata **domains** zote za kampuni hizo
4. Umepata **subdomains** zote za domains hizo (kuna subdomain takeover?)
5. Umepata **IPs** zote (za **CDNs na zisizotoka CDNs**) zilizo ndani ya scope.
6. Umepata **web servers** zote na kupiga **screenshot** zake (kuna chochote kisicho cha kawaida kinachostahili kuchunguzwa zaidi?)
7. Umepata **public cloud assets** zote zinazoweza kuwa za kampuni.
8. **Emails**, **credential leaks**, na **secret leaks** zinazoweza kukupa **ushindi mkubwa kwa urahisi sana**.
9. **Kufanya pentesting kwenye webs zote ulizopata**

## **Full Recon Automatic Tools**

Kuna tools kadhaa zinazoweza kutekeleza baadhi ya hatua zilizopendekezwa dhidi ya scope iliyotolewa.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ni ya zamani kidogo na haijasasishwa



## References

- [1] [Jason Haddix – Mbinu ya Bug Hunter v4.0: Toleo la Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Kuhusu Favicons: Kutoka Ikoni za Browser hadi Taarifa za Attack Surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Kutumia favicon.ico kama silaha kwa BugBounties, OSINT na mengineyo](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Kugundua Domains kwa kutumia Time-Correlation Attack kwenye Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Kufichua (na Kuiga) Kampeni Ghali ya Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Mbinu ya Kipekee ya Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Mchakato Kamili wa Kugundua Subdomains, Sehemu ya 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Kugundua Subdomains kwa Brute Force Kamili kwa kutumia Trickest Workflow ya Kiotomatiki, Sehemu ya 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Picha ya skrini ya matokeo ya favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
