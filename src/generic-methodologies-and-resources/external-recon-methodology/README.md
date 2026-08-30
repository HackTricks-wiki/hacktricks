# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## संपत्तियों की खोज

> तो आपको बताया गया कि किसी company से संबंधित सब कुछ scope के अंदर है, और आप यह पता लगाना चाहते हैं कि वास्तव में उस company के स्वामित्व में क्या-क्या है।

इस phase का लक्ष्य **main company के स्वामित्व वाली सभी companies** और फिर इन companies की सभी **assets** प्राप्त करना है। ऐसा करने के लिए, हम:<sup>[[1]](#references)</sup>

1. Main company के acquisitions खोजेंगे, जिससे हमें scope के अंदर की companies मिलेंगी।
2. प्रत्येक company का ASN (यदि कोई हो) खोजेंगे, जिससे प्रत्येक company के स्वामित्व वाली IP ranges मिलेंगी।
3. पहली entry से संबंधित अन्य entries (organisation names, domains...) खोजने के लिए reverse whois lookups का उपयोग करेंगे (यह recursively किया जा सकता है)।
4. अन्य assets खोजने के लिए shodan के `org` और `ssl` filters जैसी अन्य techniques का उपयोग करेंगे (`ssl` trick recursively की जा सकती है)।

### **Acquisitions**

सबसे पहले, हमें यह जानना होगा कि **main company के स्वामित्व वाली अन्य companies कौन-सी हैं**।\
एक विकल्प [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाना, **main company को search** करना और "**acquisitions**" पर **click** करना है। वहां आपको main company द्वारा acquired अन्य companies दिखाई देंगी।\
दूसरा विकल्प main company के **Wikipedia** page पर जाकर **acquisitions** खोजना है।\
Public companies के लिए **SEC/EDGAR filings**, **investor relations** pages या local corporate registries (जैसे UK में **Companies House**) देखें।\
Global corporate trees और subsidiaries के लिए **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएं।

> ठीक है, इस point पर आपको scope के अंदर की सभी companies पता होनी चाहिए। अब देखते हैं कि उनकी assets कैसे खोजी जाएं।

### **ASNs**

An autonomous system number (**ASN**) एक **unique number** है, जो **Internet Assigned Numbers Authority (IANA)** द्वारा किसी **autonomous system** (AS) को assign किया जाता है।\
एक **AS** में **IP addresses** के **blocks** होते हैं, जिनकी external networks तक access के लिए स्पष्ट रूप से defined policy होती है और जिन्हें एक single organisation administer करती है, लेकिन इनमें कई operators शामिल हो सकते हैं।

यह पता लगाना उपयोगी है कि **company को कोई ASN assign किया गया है या नहीं**, ताकि उसकी **IP ranges** खोजी जा सकें। **Scope** के अंदर मौजूद सभी **hosts** पर **vulnerability test** करना और इन IPs के अंदर **domains** खोजना उपयोगी होगा।\
आप company के **name**, **IP** या **domain** से [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **या** [**https://ipinfo.io/**](https://ipinfo.io/) पर **search** कर सकते हैं।\
**Company के region के आधार पर, अधिक data gather करने के लिए ये links उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe)।** वैसे, संभवतः पहली link में ही सारी **useful information** **(IP ranges और Whois)** मिल जाती है।
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
साथ ही, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration scan के अंत में ASNs को स्वचालित रूप से aggregate और summarize करता है।
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
आप [http://asnlookup.com/](http://asnlookup.com) का उपयोग करके किसी organisation की IP ranges भी खोज सकते हैं (इसमें free API है)।\
आप [http://ipv4info.com/](http://ipv4info.com) का उपयोग करके किसी domain का IP और ASN खोज सकते हैं।

### **Vulnerabilities की तलाश**

इस बिंदु पर हमें **scope के अंदर मौजूद सभी assets** का पता है, इसलिए यदि आपको अनुमति हो तो आप सभी hosts पर कोई **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप कुछ [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या Shodan, Censys, या ZoomEye जैसी services का उपयोग करके** खुले ports **खोज सकते हैं और आपको जो भी मिले, उसके आधार पर** इस book में यह देखना चाहिए कि चल रही संभावित services का pentest कैसे किया जाता है।\
**यह भी उल्लेख करना उपयोगी हो सकता है कि आप कुछ** default username **और** passwords **lists भी तैयार कर सकते हैं और [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) का उपयोग करके services को** bruteforce **करने का प्रयास कर सकते हैं।**

## Domains

> हमें scope के अंदर मौजूद सभी companies और उनके assets का पता है, अब scope के अंदर मौजूद domains खोजने का समय है।

_कृपया ध्यान दें कि निम्नलिखित प्रस्तावित techniques में आप subdomains भी खोज सकते हैं और उस information को कमतर नहीं आंकना चाहिए।_

सबसे पहले आपको प्रत्येक company के **main domain**(s) की तलाश करनी चाहिए। उदाहरण के लिए, _Tesla Inc._ के लिए यह _tesla.com_ होगा।

### **Reverse DNS**

चूंकि आपको domains की सभी IP ranges मिल गई हैं, इसलिए आप उन **IPs पर reverse dns lookups** करने का प्रयास कर सकते हैं, ताकि **scope के अंदर मौजूद अधिक domains खोजे जा सकें**। Victim के किसी dns server या किसी well-known dns server (1.1.1.1, 8.8.8.8) का उपयोग करने का प्रयास करें।
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
इसके काम करने के लिए administrator को PTR manually enable करना होगा।\
आप इस जानकारी के लिए एक online tool का भी उपयोग कर सकते हैं: [http://ptrarchive.com/](http://ptrarchive.com)।\
बड़े ranges के लिए, [**massdns**](https://github.com/blechschmidt/massdns) और [**dnsx**](https://github.com/projectdiscovery/dnsx) जैसे tools reverse lookups और enrichment को automate करने के लिए उपयोगी हैं।

### **Reverse Whois (loop)**

एक **whois** के अंदर आपको बहुत-सी दिलचस्प **information** जैसे **organisation name**, **address**, **emails**, phone numbers... मिल सकती हैं। लेकिन इससे भी अधिक दिलचस्प बात यह है कि आप **reverse whois lookups** करके **company से संबंधित अधिक assets** खोज सकते हैं, यदि आप इनमें से किसी भी field का उपयोग करें (उदाहरण के लिए, अन्य whois registries जहाँ वही email दिखाई देता है)।\
आप online tools का उपयोग कर सकते हैं:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web और API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, API के लिए free नहीं।
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Free नहीं
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Free नहीं (केवल **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Free नहीं
- [https://securitytrails.com/](https://securitytrails.com/) - Free नहीं (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Free नहीं (API)

आप [**DomLink** ](https://github.com/vysecurity/DomLink) का उपयोग करके इस task को automate कर सकते हैं (इसके लिए whoxy API key आवश्यक है)।\
आप [amass](https://github.com/OWASP/Amass) के साथ कुछ automatic reverse whois discovery भी कर सकते हैं: `amass intel -d tesla.com -whois`

**ध्यान दें कि हर बार जब आपको कोई नया domain मिले, तो आप इस technique का उपयोग करके अधिक domain names खोज सकते हैं।**

### **Trackers**

यदि आपको 2 अलग-अलग pages में **same tracker की same ID** मिलती है, तो आप मान सकते हैं कि **दोनों pages** **same team द्वारा managed** हैं।\
उदाहरण के लिए, यदि आपको कई pages पर वही **Google Analytics ID** या वही **Adsense ID** दिखाई देती है।

कुछ pages और tools हैं जो आपको इन trackers और अन्य चीज़ों के आधार पर search करने देते हैं:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (shared analytics/trackers के आधार पर related sites खोजता है)
- [**StackScan**](https://www.stackscan.com) - **Free tier** (Web और API)। केवल tracker IDs ही नहीं, बल्कि किसी भी served asset पर pivot करें: script path, self-hosted bundle name, या वह host जहाँ से कोई asset load होता है; यह उस asset को रखने वाली हर site को लौटाता है।

API किसी single domain का stack लौटाती है, जो यह confirm करने के लिए उपयोगी है कि कोई candidate asset उसी estate से संबंधित है:
```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
"https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```
प्रत्येक detected technology को उसकी category के साथ लौटाता है। Asset pivoting वर्तमान में केवल web तक सीमित है, जबकि API per-domain lookup को कवर करती है।

### **Favicon**

क्या आपको पता है कि उसी favicon icon hash को खोजकर हम अपने target से संबंधित domains और subdomains ढूँढ सकते हैं? [@m4ll0k2](https://twitter.com/m4ll0k2) द्वारा बनाया गया [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool बिल्कुल यही करता है। इसका उपयोग इस प्रकार करें:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सरल शब्दों में, favihash हमें ऐसे domains खोजने की अनुमति देता है जिनका favicon icon hash हमारे target के समान हो।

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

समान technology के अन्य exposed instances खोजने के लिए किसी ज्ञात favicon hash को Shodan या FOFA pivot के रूप में उपयोग करें।<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
इस तरह आप किसी web का **favicon hash** **calculate** कर सकते हैं (**base64-encoded** favicon bytes पर MMH3):
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
आप [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) के साथ बड़े पैमाने पर favicon hashes भी प्राप्त कर सकते हैं और फिर Shodan/Censys में pivot कर सकते हैं।

favicon fingerprints को leads के रूप में लें और आसपास के signals से उन्हें validate करें।<sup>[[3]](#references)[[4]](#references)</sup>

- **hash को indicator मानें, proof नहीं**: MMH3 compact है; collisions, reused icons और deliberate spoofing संभव हैं।
- **सिर्फ** `/favicon.ico` **से अधिक probe करें**: framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs और HTML `<link rel="icon">` tags की जांच करें।
- **WAF/SSO/IdP controls के पीछे static assets अभी भी reachable हो सकते हैं**: icon को सीधे request करें और `ETag`, `Last-Modified`, redirects तथा cache headers की समीक्षा करें।
- **matches को आसपास के signals से validate करें**: title, HTML/body hash, headers, TLS certificate subjects/SANs, product components और exposed ports की तुलना करें।
- **HTML/body hash के आधार पर cluster करें**: consistent template fingerprint को मजबूत करता है; mixed templates किसी generic या shared icon का संकेत देते हैं।
- **अलग-अलग signatures, ports और products में दिखाई देने वाले hash को संभावित honeypot या placeholder मानें।**
- **ambiguous targets पर किसी वास्तविक page की तुलना किसी nonexistent path से करें**, जैसे `/_favicon_probe_<8-hex>`; matching hosting या parking responses shared icon की व्याख्या कर सकते हैं।
- **Nuclei detection rules या public datasets से triage शुरू करें**, जो favicon hashes को products और CPEs से map करते हैं।
- **IP-centric coverage gap को याद रखें**: CDN-fronted, SNI-routed, anycast और domain-only surfaces Shodan-जैसे datasets में अनुपस्थित हो सकते हैं।

### **Copyright / Uniq string**

Web pages के अंदर ऐसे **strings खोजें जो एक ही organisation की अलग-अलग webs में साझा हो सकते हैं**। **copyright string** इसका एक अच्छा उदाहरण हो सकता है। फिर उस string को **google**, अन्य **browsers** या यहां तक कि **shodan** में भी खोजें: `shodan search http.html:"Copyright string"`

### **CRT Time**

अक्सर इस तरह का cron job मौजूद होता है
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
एक server पर सभी certificates को एक ही समय में renew करने के लिए। Certificate timestamps या certificate-transparency log positions को correlate करने से संबंधित domains का पता चल सकता है।<sup>[[6]](#references)</sup>

**certificate transparency** logs का सीधे भी उपयोग करें:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

**एक ही dmarc information साझा करने वाले domains और subdomains** खोजने के लिए आप [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी web service या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे tool का उपयोग कर सकते हैं।\
अन्य उपयोगी tools [**spoofcheck**](https://github.com/BishopFox/spoofcheck) और [**dmarcian**](https://dmarcian.com/) हैं।

### **Passive Takeover**

एक abandoned A record तब reachable हो सकता है जब कोई cloud provider किसी IP को फिर से assign करता है। संदर्भित research एक opportunistic workflow दिखाती है, जो एक instance provision करती है और उसके address को passive DNS data के साथ correlate करती है; takeover scenarios को केवल authorized scope के भीतर test करें।<sup>[[7]](#references)</sup>

### **अन्य तरीके**

जब भी आपको कोई नया domain मिले, लागू discovery pivots को दोहराएँ: प्रत्येक result अतिरिक्त certificate names, passive-DNS relationships, favicon matches और organization identifiers उजागर कर सकता है, जो original seed से दिखाई नहीं दे रहे थे।<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

जैसा कि आप पहले से ही उस organisation का नाम जानते हैं जिसके पास IP space है। आप Shodan में इस data का उपयोग करके search कर सकते हैं: `org:"Tesla, Inc."` नए unexpected domains के लिए पाए गए hosts के TLS certificate जाँचें।

आप मुख्य web page के **TLS certificate** को access करके **Organisation name** प्राप्त कर सकते हैं और फिर **Shodan** द्वारा ज्ञात सभी web pages के **TLS certificates** में उस name को filter `ssl:"Tesla Motors"` के साथ search कर सकते हैं, या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे tool का उपयोग कर सकते हैं।

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)एक ऐसा tool है जो किसी main domain से संबंधित **domains** और उनके **subdomains** खोजता है, काफी शानदार है।

**Passive DNS / Historical DNS**

Passive DNS data ऐसे **old और forgotten records** खोजने के लिए बहुत उपयोगी है जो अभी भी resolve होते हैं या जिनका takeover किया जा सकता है। यहाँ देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Vulnerabilities की तलाश**

कुछ [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) की जाँच करें। हो सकता है कि कोई company **किसी domain का उपयोग कर रही हो**, लेकिन उसने **ownership खो दी हो**। यदि यह पर्याप्त सस्ता हो, तो इसे register करें और company को सूचित करें।

यदि आपको कोई ऐसा **domain मिले जिसका IP अलग हो** उन IPs से जिन्हें आपने assets discovery में पहले ही खोज लिया है, तो आपको एक **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **nmap/masscan/shodan** के साथ करना चाहिए। कौन-सी services चल रही हैं, इसके आधार पर आप **इस book में उन्हें "attack" करने की कुछ tricks** खोज सकते हैं।\
_ध्यान दें कि कभी-कभी domain ऐसे IP के अंदर hosted होता है जिसे client control नहीं करता, इसलिए वह scope में नहीं होता; सावधान रहें।_

## Subdomains

> हमें scope के अंदर मौजूद सभी companies, प्रत्येक company के सभी assets और companies से संबंधित सभी domains का पता है।

अब प्रत्येक पाए गए domain के सभी संभावित subdomains खोजने का समय है।

> [!TIP]
> ध्यान दें कि domains खोजने के लिए उपयोग किए जाने वाले कुछ tools और techniques subdomains खोजने में भी सहायता कर सकते हैं।

### **DNS**

आइए **DNS** records से **subdomains** प्राप्त करने का प्रयास करें। हमें **Zone Transfer** के लिए भी प्रयास करना चाहिए (यदि यह vulnerable हो, तो इसकी report करें)।
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

बहुत सारे subdomains प्राप्त करने का सबसे तेज़ तरीका external sources में search करना है। सबसे अधिक उपयोग किए जाने वाले **tools** निम्नलिखित हैं (बेहतर परिणामों के लिए API keys configure करें):

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
ऐसे **अन्य रोचक tools/APIs** भी हैं जो subdomains खोजने में सीधे specialized न होने पर भी subdomains खोजने के लिए उपयोगी हो सकते हैं, जैसे:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** subdomains प्राप्त करने के लिए API [https://sonar.omnisint.io](https://sonar.omnisint.io) का उपयोग करता है
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC निःशुल्क API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) निःशुल्क API
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
- [**gau**](https://github.com/lc/gau)**:** किसी भी दिए गए domain के लिए AlienVault's Open Threat Exchange, Wayback Machine और Common Crawl से ज्ञात URLs प्राप्त करता है।
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **और** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ये JS files की तलाश में web को scrape करते हैं और उनमें से subdomains extract करते हैं।
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
- [**securitytrails.com**](https://securitytrails.com/) में subdomains और IP history खोजने के लिए एक free API है
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

यह project **bug-bounty programs से संबंधित सभी subdomains free में** उपलब्ध कराता है। आप इस data को [chaospy](https://github.com/dr-0x0x/chaospy) का उपयोग करके भी access कर सकते हैं या इस project द्वारा उपयोग किया गया scope यहां access कर सकते हैं: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

आप इनमें से कई tools की **comparison** यहां पा सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

संभावित subdomain names का उपयोग करके DNS servers पर brute-forcing करते हुए नए **subdomains** खोजने का प्रयास करते हैं।

इस action के लिए आपको कुछ **common subdomains wordlists जैसे** इनकी आवश्यकता होगी:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

और अच्छे DNS resolvers के IPs भी। Trusted DNS resolvers की list बनाने के लिए, आप [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) से resolvers download करके उन्हें filter करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग कर सकते हैं। या आप इसका उपयोग कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे अधिक recommended tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह पहला ऐसा tool था जिसने effective DNS brute-force किया। यह बहुत fast है, लेकिन false positives की संभावना रहती है।
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): इसमें, मेरे विचार से, केवल 1 resolver का उपयोग होता है
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के आसपास बनाया गया, go में लिखा गया एक wrapper है, जो आपको active bruteforce का उपयोग करके valid subdomains enumerate करने के साथ-साथ wildcard handling और आसान input-output support के साथ subdomains resolve करने की सुविधा देता है।
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): यह `massdns` का भी उपयोग करता है।
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) asyncio का उपयोग करके domain names को asynchronously brute force करता है।
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### दूसरा DNS Brute-Force चरण

Open sources और brute-forcing का उपयोग करके subdomains खोजने के बाद, आप मिले हुए subdomains के alterations बना सकते हैं, ताकि और भी subdomains खोजे जा सकें। इस उद्देश्य के लिए कई tools उपयोगी हैं:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** दिए गए domains और subdomains से permutations generate करता है।
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains से permutations generate करें।
- आप goaltdns की permutations **wordlist** [**यहाँ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) प्राप्त कर सकते हैं।
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains से permutations generate करता है। यदि permutations file निर्दिष्ट नहीं की गई है, तो gotator अपनी स्वयं की file का उपयोग करेगा।
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains के permutations generate करने के अलावा, यह उन्हें resolve करने का प्रयास भी कर सकता है (लेकिन पिछले commented tools का उपयोग करना बेहतर है)।
- आप altdns permutations की **wordlist** [**यहाँ**](https://github.com/infosec-au/altdns/blob/master/words.txt) प्राप्त कर सकते हैं।
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomains पर permutations, mutations और alteration करने का एक अन्य tool। यह result को brute force करेगा (यह dns wild card को support नहीं करता)।
- आप dmut permutations wordlist [**यहाँ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) प्राप्त कर सकते हैं।
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** किसी domain के आधार पर, यह संकेतित patterns के अनुसार **नए संभावित subdomains नाम generate करता है**, ताकि अधिक subdomains खोजने का प्रयास किया जा सके।

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): यह खोजे गए subdomains से regex-जैसे patterns सीखता है और resolve करने के लिए candidate names generate करता है।<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है, जो बेहद सरल लेकिन प्रभावी DNS response-guided algorithm से जुड़ा है। यह उपलब्ध input data, जैसे किसी विशेष उद्देश्य के लिए तैयार की गई wordlist या ऐतिहासिक DNS/TLS records, का उपयोग करके अधिक संबंधित domain names को सटीक रूप से तैयार करता है और DNS scan के दौरान एकत्र की गई जानकारी के आधार पर उन्हें loop में और भी विस्तृत करता है।
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest workflow examples repeatable subdomain enumeration के लिए OSINT, DNS brute force और permutation stages को combine करते हैं।<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

यदि आपको ऐसा IP address मिला है जिसमें subdomains से संबंधित **एक या कई web pages** हैं, तो आप **OSINT sources** में किसी IP पर मौजूद domains खोजकर या उस **IP में VHost domain names को brute-force** करके **उस IP पर मौजूद अन्य subdomains और webs खोजने** का प्रयास कर सकते हैं।

#### OSINT

आप [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs का उपयोग करके IPs में कुछ VHosts खोज सकते हैं**।

**Brute Force**

यदि आपको संदेह है कि कोई subdomain किसी web server में छिपा हो सकता है, तो आप उसे brute force करने का प्रयास कर सकते हैं:

Name-based vhosts के लिए, `Host` header को fuzz करें और default response को filter करने के लिए ffuf के auto-calibration का उपयोग करें।<sup>[[2]](#references)</sup>
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
> इस technique से आप internal/hidden endpoints तक भी access प्राप्त कर सकते हैं।

### **CORS Brute Force**

कभी-कभी आपको ऐसे pages मिलेंगे जो _**Origin**_ header में valid domain/subdomain सेट होने पर ही _**Access-Control-Allow-Origin**_ header return करते हैं। इन scenarios में, आप इस behaviour का abuse करके नए **subdomains** **discover** कर सकते हैं।
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** की तलाश करते समय ध्यान रखें कि क्या यह किसी प्रकार के **bucket** की ओर **pointing** कर रहा है, और ऐसी स्थिति में [**permissions check करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)**।**\
साथ ही, इस बिंदु पर आपको scope के अंदर मौजूद सभी domains पता होंगे, इसलिए [**संभावित bucket names को brute force करें और permissions check करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

### **Monitorization**

आप **Certificate Transparency** Logs को monitor करके यह **monitor** कर सकते हैं कि किसी domain के **new subdomains** बनाए गए हैं या नहीं, जैसा कि [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) करता है।

### **Looking for vulnerabilities**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
यदि **subdomain** किसी **S3 bucket** की ओर pointing कर रहा है, तो [**permissions check करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

यदि आपको assets discovery में पहले से मिले IPs से **different IP वाला कोई subdomain** मिलता है, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **nmap/masscan/shodan** के साथ करना चाहिए। कौन-सी services चल रही हैं, इसके आधार पर आप **इस book में उन्हें "attack" करने के कुछ tricks पा सकते हैं**।\
_ध्यान दें कि कभी-कभी subdomain ऐसे IP के अंदर hosted होता है जिसे client control नहीं करता, इसलिए वह scope में नहीं होता; सावधान रहें।_

## IPs

प्रारंभिक steps में आपको शायद **कुछ IP ranges, domains और subdomains मिले होंगे**।\
अब उन ranges से **सभी IPs recollect करने** और **domains/subdomains के लिए (DNS queries करने)** का समय है।

निम्नलिखित **free APIs** की services का उपयोग करके आप **domains और subdomains द्वारा पहले उपयोग किए गए IPs** भी खोज सकते हैं। ये IPs अभी भी client के ownership में हो सकते हैं (और आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) खोजने में सहायता कर सकते हैं)।

- [**https://securitytrails.com/**](https://securitytrails.com/)

आप [**hakip2host**](https://github.com/hakluke/hakip2host) tool का उपयोग करके यह भी जाँच सकते हैं कि कौन-से domains किसी specific IP address की ओर pointing कर रहे हैं।

### **Looking for vulnerabilities**

**CDNs से संबंधित न होने वाले सभी IPs का port scan करें** (क्योंकि बहुत अधिक संभावना है कि आपको वहाँ कुछ interesting नहीं मिलेगा)। खोजी गई running services में आपको **vulnerabilities मिल सकती हैं**।

**hosts को scan करने के तरीके के बारे में एक** [**guide**](../pentesting-network/index.html) **खोजें।**

## Web servers hunting

> हमने सभी companies और उनके assets खोज लिए हैं और हमें scope के अंदर मौजूद IP ranges, domains और subdomains पता हैं। अब web servers खोजने का समय है।

पिछले steps में आपने संभवतः **खोजे गए IPs और domains का कुछ recon पहले ही किया होगा**, इसलिए हो सकता है कि आपको **सभी possible web servers पहले ही मिल गए हों**। हालांकि, यदि ऐसा नहीं हुआ है, तो अब हम scope के अंदर web servers खोजने के कुछ **fast tricks** देखेंगे।

कृपया ध्यान दें कि यह **web apps discovery के लिए oriented** होगा, इसलिए आपको **vulnerability** और **port scanning** भी करना चाहिए (**यदि scope द्वारा allowed हो**)।

[**masscan** का उपयोग करके web servers से संबंधित **open ports** discover करने का एक **fast method** [**यहाँ पाया जा सकता है**](../pentesting-network/index.html#http-port-discovery)।\
Web servers खोजने के लिए एक अन्य friendly tool [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx) है। आप केवल domains की एक list pass करते हैं और यह port 80 (http) और 443 (https) से connect करने का प्रयास करेगा। इसके अतिरिक्त, आप अन्य ports को try करने के लिए भी indicate कर सकते हैं:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

अब जब आपने scope में मौजूद **सभी web servers** (कंपनी के **IPs** तथा सभी **domains** और **subdomains** में) खोज लिए हैं, तो संभवतः आपको **पता नहीं होगा कि कहाँ से शुरू करें**। इसलिए इसे सरल बनाते हैं और सबसे पहले सभी के screenshots लेते हैं। केवल **main page** पर **नज़र डालने** से ही आपको ऐसे **weird** endpoints मिल सकते हैं जिनके **vulnerable** होने की संभावना अधिक होती है।

प्रस्तावित विचार को लागू करने के लिए आप [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** का उपयोग कर सकते हैं।**

इसके अलावा, आप सभी **screenshots** पर [**eyeballer**](https://github.com/BishopFox/eyeballer) चला सकते हैं, ताकि यह आपको बता सके कि इनमें से **किनमें vulnerabilities होने की संभावना है** और किनमें नहीं।

## Public Cloud Assets

किसी कंपनी से संबंधित संभावित cloud assets खोजने के लिए आपको **सबसे पहले उन keywords की सूची से शुरू करना चाहिए जो उस कंपनी की पहचान करते हों**। उदाहरण के लिए, किसी crypto company के लिए आप ऐसे शब्दों का उपयोग कर सकते हैं: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

आपको **buckets में उपयोग किए जाने वाले सामान्य शब्दों** की wordlists की भी आवश्यकता होगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, उन शब्दों से आपको **permutations** बनानी चाहिए (अधिक जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

प्राप्त wordlists के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** जैसे tools का उपयोग कर सकते हैं।**

याद रखें कि Cloud Assets खोजते समय आपको **AWS में केवल buckets से अधिक चीज़ों की तलाश करनी चाहिए**।

### **Looking for vulnerabilities**

यदि आपको **open buckets या exposed cloud functions** जैसी चीज़ें मिलती हैं, तो आपको **उन तक पहुंचना चाहिए** और यह देखने का प्रयास करना चाहिए कि वे आपको क्या प्रदान करती हैं तथा क्या आप उनका दुरुपयोग कर सकते हैं।

## Emails

Scope में मौजूद **domains** और **subdomains** के साथ आपके पास मूल रूप से **emails की खोज शुरू करने के लिए आवश्यक सब कुछ** है। किसी कंपनी के emails खोजने के लिए मेरे लिए सबसे अच्छे काम करने वाले ये **APIs** और **tools** हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs के साथ
- [**https://hunter.io/**](https://hunter.io/) का API (free version)
- [**https://app.snov.io/**](https://app.snov.io/) का API (free version)
- [**https://minelead.io/**](https://minelead.io/) का API (free version)

### **Looking for vulnerabilities**

Emails बाद में **web logins और auth services** (जैसे SSH) पर **brute-force** करने में उपयोगी होंगे। इसके अलावा, वे **phishings** के लिए भी आवश्यक हैं। इतना ही नहीं, ये APIs आपको email के पीछे मौजूद **व्यक्ति के बारे में और अधिक info** भी देंगे, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**domains,** **subdomains** और **emails** के साथ आप उन emails से संबंधित अतीत में **leaked credentials** खोजना शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

यदि आपको **valid leaked** credentials मिलते हैं, तो यह बहुत आसान जीत है।

## Secrets Leaks

Credential leaks उन companies के hacks से संबंधित होते हैं जिनमें **sensitive information leak होकर बेची गई**। हालांकि, companies अन्य **leaks** से भी प्रभावित हो सकती हैं, जिनकी जानकारी उन databases में मौजूद नहीं होती:

### Github Leaks

Company के **public repositories** या उस github company के लिए काम करने वाले **users** के repositories में credentials और APIs leak हो सकते हैं।\
आप [**Leakos**](https://github.com/carlospolop/Leakos) **tool** का उपयोग करके किसी **organization** और उसके **developers** के सभी **public repos** **download** कर सकते हैं तथा उन पर [**gitleaks**](https://github.com/zricethezav/gitleaks) स्वतः चला सकते हैं।

**Leakos** का उपयोग दिए गए **URLs** से प्राप्त सभी **text** पर **gitleaks** चलाने के लिए भी किया जा सकता है, क्योंकि कभी-कभी **web pages में भी secrets होते हैं**।

#### Github Dorks

Organization में खोजे जा सकने वाले संभावित **GitHub dorks** के लिए [GitHub dorks and leaks page](github-leaked-secrets.md) देखें।

### Pastes Leaks

कभी-कभी attackers या केवल workers किसी **paste site पर company content publish** कर देते हैं। इसमें **sensitive information** हो भी सकती है और नहीं भी, लेकिन इसे खोजना बहुत उपयोगी है।\
आप एक ही समय में 80 से अधिक paste sites में खोजने के लिए [**Pastos**](https://github.com/carlospolop/Pastos) tool का उपयोग कर सकते हैं।

### Google Dorks

पुराने लेकिन उपयोगी Google dorks हमेशा **ऐसी exposed information खोजने** में सहायक होते हैं जो वहां नहीं होनी चाहिए। एकमात्र समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में संभावित queries की **कई हजार** entries हैं, जिन्हें आप manually नहीं चला सकते। इसलिए, आप अपनी पसंद की 10 queries चुन सकते हैं या उन सभी को चलाने के लिए [**Gorks**](https://github.com/carlospolop/Gorks) **जैसे किसी tool** का उपयोग कर सकते हैं।

_ध्यान दें कि जो tools regular Google browser का उपयोग करके पूरे database को चलाने का प्रयास करते हैं, वे कभी समाप्त नहीं होंगे, क्योंकि Google आपको बहुत जल्द block कर देगा।_

### **Looking for vulnerabilities**

यदि आपको **valid leaked** credentials या API tokens मिलते हैं, तो यह बहुत आसान जीत है।

## Public Code Vulnerabilities

यदि आपको पता चलता है कि company के पास **open-source code** है, तो आप उसका **analyse** कर सकते हैं और उसमें **vulnerabilities** खोज सकते हैं।

**Language के आधार पर** अलग-अलग **tools** उपलब्ध हैं; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) की सूची देखें।

ऐसी free services भी उपलब्ध हैं जो आपको **public repositories scan** करने देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunters द्वारा खोजी जाने वाली **अधिकांश vulnerabilities** **web applications** के अंदर होती हैं। इसलिए इस बिंदु पर मैं **web application testing methodology** के बारे में बताना चाहता हूं, और आप [**यह जानकारी यहां पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) section का विशेष उल्लेख भी करना चाहता हूं, क्योंकि, हालांकि आपको उनसे बहुत sensitive vulnerabilities खोजने की उम्मीद नहीं करनी चाहिए, फिर भी वे **workflows में प्रारंभिक web information प्राप्त करने के लिए उपयोगी** होते हैं।

## Recapitulation

> बधाई हो! इस बिंदु तक आपने **सभी basic enumeration** पूरी कर ली है। हां, यह basic है क्योंकि इससे कहीं अधिक enumeration की जा सकती है (बाद में और tricks देखेंगे)।

अब तक आपने:

1. Scope में मौजूद सभी **companies** खोज लीं
2. Companies से संबंधित सभी **assets** खोज लिए (और यदि scope में था तो कुछ vuln scan भी किया)
3. Companies से संबंधित सभी **domains** खोज लिए
4. Domains के सभी **subdomains** खोज लिए (कोई subdomain takeover?)
5. Scope में मौजूद सभी **IPs** (CDNs से और **CDNs से नहीं**) खोज लिए।
6. सभी **web servers** खोज लिए और उनके **screenshots** ले लिए (क्या कोई weird चीज़ है जिस पर गहराई से ध्यान देना चाहिए?)
7. Company से संबंधित सभी **potential public cloud assets** खोज लिए।
8. **Emails**, **credentials leaks** और **secret leaks**, जो आपको **बहुत आसानी से बड़ी जीत** दिला सकते हैं।
9. **सभी खोजे गए webs की Pentesting**

## **Full Recon Automatic Tools**

ऐसे कई tools उपलब्ध हैं जो दिए गए scope के विरुद्ध प्रस्तावित actions का कुछ भाग कर सकते हैं।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - थोड़ा पुराना है और updated नहीं है

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
