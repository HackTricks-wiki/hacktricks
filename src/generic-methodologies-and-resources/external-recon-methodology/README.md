# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> तो आपको बताया गया कि किसी कंपनी से संबंधित हर चीज़ scope के अंदर है, और आप यह पता लगाना चाहते हैं कि यह कंपनी वास्तव में किन चीज़ों की मालिक है।

इस चरण का लक्ष्य **main company के स्वामित्व वाली सभी companies** और फिर इन companies के सभी **assets** प्राप्त करना है। ऐसा करने के लिए हम:

1. Main company के acquisitions खोजेंगे, जिससे हमें scope के अंदर आने वाली companies मिलेंगी।
2. प्रत्येक company का ASN (यदि कोई हो) खोजेंगे, जिससे प्रत्येक company के स्वामित्व वाली IP ranges मिलेंगी।
3. पहली company से संबंधित अन्य entries (organisation names, domains...) खोजने के लिए reverse whois lookups का उपयोग करेंगे (इसे recursively किया जा सकता है)।
4. अन्य assets खोजने के लिए shodan `org` और `ssl` filters जैसी techniques का उपयोग करेंगे (`ssl` trick को recursively किया जा सकता है)।

### **Acquisitions**

सबसे पहले, हमें यह जानना होगा कि **main company के स्वामित्व वाली अन्य companies कौन-सी हैं**।\
एक विकल्प है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाना, **main company को search** करना और "**acquisitions**" पर **click** करना। वहाँ आपको main company द्वारा acquired अन्य companies दिखाई देंगी।\
दूसरा विकल्प है main company के **Wikipedia** page पर जाकर **acquisitions** खोजना।\
Public companies के लिए **SEC/EDGAR filings**, **investor relations** pages या local corporate registries (जैसे UK में **Companies House**) देखें।\
Global corporate trees और subsidiaries के लिए **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएँ।

> ठीक है, इस बिंदु पर आपको scope के अंदर आने वाली सभी companies का पता होना चाहिए। अब देखते हैं कि उनके assets कैसे खोजे जाएँ।

### **ASNs**

एक autonomous system number (**ASN**) एक **unique number** है, जिसे **Internet Assigned Numbers Authority (IANA)** द्वारा किसी **autonomous system** (AS) को assign किया जाता है।\
एक **AS** में **IP addresses** के **blocks** होते हैं, जिनकी external networks तक access के लिए स्पष्ट रूप से परिभाषित policy होती है और जिन्हें एक organisation administer करती है, लेकिन इनमें कई operators शामिल हो सकते हैं।

यह पता लगाना उपयोगी है कि **company को कोई ASN assign किया गया है या नहीं**, ताकि उसकी **IP ranges** खोजी जा सकें। **Scope** के अंदर मौजूद सभी **hosts** के विरुद्ध **vulnerability test** करना और इन IPs के अंदर **domains** खोजना उपयोगी होगा।\
आप company के **name**, **IP** या **domain** से [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **या** [**https://ipinfo.io/**](https://ipinfo.io/) पर **search** कर सकते हैं।\
**Company के region के आधार पर, अधिक data gather करने के लिए ये links उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe)।** वैसे, संभवतः पहली link में ही सभी **useful information** **(IP ranges और Whois)** पहले से दिखाई देती है।
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
साथ ही, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** का**
enumeration स्कैन के अंत में ASNs को स्वचालित रूप से aggregate और summarize करता है।
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
आप किसी organisation की IP ranges [http://asnlookup.com/](http://asnlookup.com) का उपयोग करके भी खोज सकते हैं (इसमें free API है)।\
आप किसी domain का IP और ASN [http://ipv4info.com/](http://ipv4info.com) का उपयोग करके खोज सकते हैं।

### **Looking for vulnerabilities**

इस point पर हमें **scope के अंदर मौजूद सभी assets** का पता है, इसलिए यदि आपको अनुमति है, तो आप सभी hosts पर कोई **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप कुछ [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या Shodan, Censys या ZoomEye जैसी services का उपयोग करके** खुले ports **खोज सकते हैं और आपको जो भी मिले, उसके आधार पर** इस book में देखें कि चल रही विभिन्न संभावित services का pentest कैसे किया जाता है।\
**यह बताना भी उपयोगी हो सकता है कि आप कुछ** default username **और** passwords **की lists तैयार करके** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) के साथ services को **bruteforce** करने का प्रयास कर सकते हैं।

## Domains

> हमें scope के अंदर मौजूद सभी companies और उनके assets का पता है; अब scope के अंदर मौजूद domains खोजने का समय है।

_कृपया ध्यान दें कि नीचे दी गई techniques से आप subdomains भी खोज सकते हैं और उस information को कम नहीं आंकना चाहिए।_

सबसे पहले आपको प्रत्येक company के **main domain**(s) खोजने चाहिए। उदाहरण के लिए, _Tesla Inc._ के लिए यह _tesla.com_ होगा।

### **Reverse DNS**

चूंकि आपको domains की सभी IP ranges मिल चुकी हैं, इसलिए आप उन **IPs पर reverse dns lookups** करने का प्रयास कर सकते हैं, ताकि **scope के अंदर मौजूद अधिक domains खोजे जा सकें**। Victim के किसी dns server या किसी well-known dns server (1.1.1.1, 8.8.8.8) का उपयोग करने का प्रयास करें।
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, administrator को PTR manually enable करना होगा।\
आप इस जानकारी के लिए एक online tool भी उपयोग कर सकते हैं: [http://ptrarchive.com/](http://ptrarchive.com)।\
बड़े ranges के लिए, [**massdns**](https://github.com/blechschmidt/massdns) और [**dnsx**](https://github.com/projectdiscovery/dnsx) जैसे tools reverse lookups और enrichment को automate करने में उपयोगी हैं।

### **Reverse Whois (loop)**

एक **whois** के अंदर आपको बहुत सारी रोचक **information** मिल सकती है, जैसे **organisation name**, **address**, **emails**, phone numbers... लेकिन इससे भी अधिक रोचक बात यह है कि आप **reverse whois lookups** करके **company से संबंधित अधिक assets** खोज सकते हैं, इनमें से किसी भी field का उपयोग करके (उदाहरण के लिए, ऐसी अन्य whois registries जहाँ वही email दिखाई देता है)।\
आप online tools का उपयोग कर सकते हैं:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web और API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, API free नहीं है।
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Free नहीं है
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Free नहीं है (केवल **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Free नहीं है
- [https://securitytrails.com/](https://securitytrails.com/) - Free नहीं है (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Free नहीं है (API)

आप [**DomLink** ](https://github.com/vysecurity/DomLink) का उपयोग करके इस task को automate कर सकते हैं (इसके लिए whoxy API key आवश्यक है)।\
आप [amass](https://github.com/OWASP/Amass) के साथ कुछ automatic reverse whois discovery भी कर सकते हैं: `amass intel -d tesla.com -whois`

**ध्यान दें कि हर बार नया domain मिलने पर अधिक domain names खोजने के लिए आप इस technique का उपयोग कर सकते हैं।**

### **Trackers**

यदि 2 अलग-अलग pages में **same tracker का same ID** मिलता है, तो आप मान सकते हैं कि **दोनों pages** को **same team** manage करती है।\
उदाहरण के लिए, यदि आपको कई pages पर same **Google Analytics ID** या same **Adsense ID** दिखाई दे।

कुछ pages और tools हैं जो आपको इन trackers और अन्य चीजों के आधार पर search करने देते हैं:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (shared analytics/trackers के आधार पर related sites खोजता है)

### **Favicon**

क्या आपको पता है कि same favicon icon hash को खोजकर हम अपने target से संबंधित domains और subdomains खोज सकते हैं? [@m4ll0k2](https://twitter.com/m4ll0k2) द्वारा बनाया गया [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool ठीक यही करता है। इसे उपयोग करने का तरीका यहां दिया गया है:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - समान favicon icon hash वाले domains खोजें](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सरल शब्दों में, favihash हमें ऐसे domains खोजने की सुविधा देता है जिनका favicon icon hash हमारे target के समान हो।

इसके अलावा, आप favicon hash का उपयोग करके technologies भी search कर सकते हैं, जैसा कि [**इस blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) में बताया गया है। इसका अर्थ है कि यदि आपको **किसी vulnerable web tech version के favicon का hash** पता है, तो आप Shodan में search करके **अधिक vulnerable जगहें खोज सकते हैं**:<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
इस तरह किसी web का **favicon hash** **calculate** कर सकते हैं ( **base64-encoded** favicon bytes पर **MMH3**):
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
आप [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) के साथ बड़े स्तर पर favicon hashes भी प्राप्त कर सकते हैं और फिर Shodan/Censys में pivot कर सकते हैं।

favicon fingerprints का उपयोग करते समय याद रखने योग्य बातें:<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash को indicator मानें, proof नहीं**: MMH3 compact है और collisions संभव हैं; operators favicons को बदल भी सकते हैं या जानबूझकर भ्रामक icon का पुनः उपयोग कर सकते हैं।
- **`/favicon.ico` से अधिक paths को probe करें**: कई products framework/build paths या `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URLs, या HTML `<link rel="icon">` tags के माध्यम से icons expose करते हैं। Path स्वयं किसी product family का fingerprint हो सकता है।
- **जब app reachable न हो, तब भी static files अक्सर reachable होती हैं**: WAF/SSO/IdP controls dynamic routes को protect कर सकते हैं, लेकिन static icons फिर भी expose हो सकते हैं। हमेशा favicon को सीधे request करें और कमजोर version/build hints के लिए `ETag`, `Last-Modified`, redirects तथा cache headers की समीक्षा करें।
- **Matches को आसपास के signals से validate करें**: किसी favicon के product की पहचान करने का निष्कर्ष निकालने से पहले title, HTML/body hash, headers, TLS certificate subjects/SANs, Shodan/Censys components और exposed ports की तुलना करें।
- **बड़े स्तर पर pivot करते समय HTML/body hash के आधार पर cluster करें**: यदि किसी favicon को share करने वाले अधिकांश hosts एक ही page template में सिमट जाते हैं, तो fingerprint अधिक मजबूत है; यदि वही hash कई असंबंधित templates में विभाजित होता है, तो product label के बजाय `"generic/shared/honeypot"` को प्राथमिकता दें।
- **Honeypot heuristic**: यदि वही favicon hash कई असंबंधित HTML signatures, random ports और conflicting products में दिखाई देता है, तो इसे वास्तविक product fingerprint के बजाय संभावित honeypot या generic placeholder मानें।
- **Ambiguous targets पर 404 probe का उपयोग करें**: browser में एक वास्तविक page और `/_favicon_probe_<8-hex>` जैसे nonexistent path को fetch करें। समान hosting-provider/parking responses अक्सर true product overlap की तुलना में shared favicons की बेहतर व्याख्या करते हैं।
- **Detection rules से mappings bootstrap करें**: Nuclei templates और public favicon datasets ज्ञात `favicon` ↔ `product` ↔ `CPE` mappings प्रदान कर सकते हैं, जो CVE disclosures के बाद rapid triage के लिए उपयोगी हैं।
- **Coverage caveat**: Shodan-style datasets IP-centric होते हैं। CDN-fronted, SNI-routed, anycast और domain-only surfaces की गिनती कम हो सकती है, इसलिए कम hit count का अर्थ **यह नहीं है** कि real-world deployment कम है।

### **Copyright / Uniq string**

Web pages के अंदर ऐसे **strings खोजें जो एक ही organisation की अलग-अलग webs में साझा हो सकते हैं**। **Copyright string** इसका एक अच्छा उदाहरण हो सकता है। फिर उस string को **google**, अन्य **browsers** या यहां तक कि **shodan** में search करें: `shodan search http.html:"Copyright string"`

### **CRT Time**

अक्सर ऐसा cron job होना सामान्य है જેમ કે
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
सर्वर पर सभी domain certificates को renew करने के लिए। इसका अर्थ है कि भले ही इसके लिए उपयोग किया गया CA, Validity time में certificate के generate होने का समय सेट न करता हो, फिर भी **certificate transparency logs में एक ही company से संबंधित domains खोजे जा सकते हैं**।\
अधिक जानकारी के लिए यह [**writeup देखें**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).<sup>[[6]](#references)</sup>

इसके अलावा **certificate transparency** logs का सीधे उपयोग करें:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

आप [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी web service या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे tool का उपयोग करके **समान dmarc information साझा करने वाले domains और subdomains** खोज सकते हैं।\
अन्य उपयोगी tools हैं [**spoofcheck**](https://github.com/BishopFox/spoofcheck) और [**dmarcian**](https://dmarcian.com/)।

### **Passive Takeover**

ऐसा होना आम है कि लोग subdomains को cloud providers से संबंधित IPs पर assign कर देते हैं और किसी समय **उस IP address को खो देते हैं, लेकिन DNS record हटाना भूल जाते हैं**। इसलिए, cloud (जैसे Digital Ocean) में केवल **VM spawn करके** आप वास्तव में **कुछ subdomains(s) पर takeover कर सकते हैं**।

[**यह post**](https://kmsec.uk/blog/passive-takeover/) इसके बारे में एक story बताती है और एक ऐसी script प्रस्तावित करती है जो **DigitalOcean में VM spawn करती है**, नई machine का **IPv4** **प्राप्त करती है**, और Virustotal में **उसकी ओर point करने वाले subdomain records खोजती है**।<sup>[[7]](#references)</sup>

### **अन्य तरीके**

**ध्यान दें कि जब भी आपको कोई नया domain मिले, आप इस technique का उपयोग करके हर बार अधिक domain names खोज सकते हैं।**

**Shodan**

जैसा कि आप पहले से जानते हैं कि IP space का owner organisation का नाम क्या है। आप Shodan में इस data का उपयोग करके खोज सकते हैं: `org:"Tesla, Inc."` मिले हुए hosts में TLS certificate के अंदर नए और अप्रत्याशित domains देखें।

आप मुख्य web page के **TLS certificate** को access करके **Organisation name** प्राप्त कर सकते हैं और फिर उस नाम को **Shodan** द्वारा ज्ञात सभी web pages के **TLS certificates** में filter `ssl:"Tesla Motors"` के साथ खोज सकते हैं, या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे tool का उपयोग कर सकते हैं।

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)एक ऐसा tool है जो किसी main domain से **संबंधित domains** और उनके **subdomains** खोजता है, काफी शानदार है।

**Passive DNS / Historical DNS**

Passive DNS data ऐसे **पुराने और भूले हुए records** खोजने के लिए बहुत उपयोगी है जो अभी भी resolve होते हैं या जिनका takeover किया जा सकता है। इन्हें देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Vulnerabilities खोजना**

कुछ [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) के लिए जाँच करें। हो सकता है कोई company **किसी domain का उपयोग कर रही हो**, लेकिन **उसका ownership खो चुकी हो**। यदि यह पर्याप्त सस्ता हो तो इसे register करें और company को सूचित करें।

यदि आपको कोई ऐसा **domain मिले जिसका IP**, assets discovery में पहले से मिले IPs से **अलग हो**, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करना चाहिए, जिसमें **nmap/masscan/shodan** का उपयोग हो। चल रही services के आधार पर आप **इस book में उन्हें "attack" करने के कुछ tricks** खोज सकते हैं।\
_ध्यान दें कि कभी-कभी domain ऐसे IP के अंदर hosted होता है जो client के नियंत्रण में नहीं होता, इसलिए वह scope में नहीं होता; सावधान रहें।_

## Subdomains

> हमें scope के अंदर मौजूद सभी companies, प्रत्येक company के सभी assets और companies से संबंधित सभी domains के बारे में पता है।

अब प्रत्येक पाए गए domain के सभी संभावित subdomains खोजने का समय है।

> [!TIP]
> ध्यान दें कि domains खोजने के लिए उपयोग किए जाने वाले कुछ tools और techniques, subdomains खोजने में भी मदद कर सकते हैं।

### **DNS**

आइए **DNS** records से **subdomains** प्राप्त करने का प्रयास करें। हमें **Zone Transfer** के लिए भी प्रयास करना चाहिए (यदि vulnerable हो, तो इसकी report करें)।
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

बहुत सारे subdomains प्राप्त करने का सबसे तेज़ तरीका external sources में search करना है। बेहतर परिणामों के लिए API keys configure करने वाले सबसे अधिक उपयोग किए जाने वाले **tools** निम्नलिखित हैं:

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
**अन्य उपयोगी tools/APIs** भी हैं, जो सीधे तौर पर subdomains खोजने में specialized न होने पर भी subdomains खोजने में उपयोगी हो सकते हैं, जैसे:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) का उपयोग करके subdomains प्राप्त करता है
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC निःशुल्क API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) मुफ्त API
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
- [**gau**](https://github.com/lc/gau)**:** किसी भी दिए गए domain के लिए AlienVault's Open Threat Exchange, Wayback Machine और Common Crawl से ज्ञात URLs fetch करता है।
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ये JS files की तलाश में web को scrape करते हैं और उनमें से subdomains extract करते हैं।
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
- [**securitytrails.com**](https://securitytrails.com/) में subdomains और IP history को search करने के लिए एक free API है
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

यह project **bug-bounty programs से संबंधित सभी subdomains free में** उपलब्ध कराता है। आप इस data को [chaospy](https://github.com/dr-0x0x/chaospy) का उपयोग करके भी access कर सकते हैं या इस project द्वारा उपयोग किए गए scope को भी access कर सकते हैं: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

आप इनमें से कई tools का **comparison** यहां पा सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

आइए संभावित subdomain names का उपयोग करके DNS servers पर brute-forcing करते हुए नए **subdomains** खोजने का प्रयास करें।

इस action के लिए आपको कुछ **common subdomains wordlists की आवश्यकता होगी**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

साथ ही अच्छे DNS resolvers के IPs भी आवश्यक होंगे। Trusted DNS resolvers की list generate करने के लिए, आप [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) से resolvers download करके उन्हें filter करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग कर सकते हैं। या आप इसका उपयोग कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे recommended tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह effective DNS brute-force करने वाला पहला tool था। यह बहुत fast है, हालांकि इसमें false positives की संभावना रहती है।
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): मेरे विचार से यह केवल 1 resolver का उपयोग करता है।
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के चारों ओर लिखा गया go wrapper है, जो active bruteforce का उपयोग करके valid subdomains enumerate करने की अनुमति देता है, साथ ही wildcard handling और आसान input-output support के साथ subdomains को resolve करने की सुविधा देता है।
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): यह `massdns` का भी उपयोग करता है।
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) domain names को asynchronous तरीके से brute force करने के लिए asyncio का उपयोग करता है।
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### दूसरा DNS Brute-Force राउंड

Open sources और brute-forcing का उपयोग करके subdomains खोजने के बाद, आप पाए गए subdomains में alterations generate कर सकते हैं, ताकि और भी अधिक subdomains खोजे जा सकें। इस उद्देश्य के लिए कई tools उपयोगी हैं:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** दिए गए domains और subdomains के permutations generate करता है।
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains से permutations generate करता है।
- आप goaltdns permutations की **wordlist** [**यहाँ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) प्राप्त कर सकते हैं।
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains से permutations generate करता है। यदि permutations file निर्दिष्ट नहीं की गई है, तो gotator अपनी file का उपयोग करेगा।
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Subdomains की permutations generate करने के अलावा, यह उन्हें resolve करने का भी प्रयास कर सकता है (लेकिन previous में comment किए गए tools का उपयोग करना बेहतर है)।
- आप altdns की permutations **wordlist** [**यहाँ**](https://github.com/infosec-au/altdns/blob/master/words.txt) प्राप्त कर सकते हैं।
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomains की permutations, mutations और alteration करने के लिए एक अन्य tool। यह result को brute force करेगा (यह dns wild card को support नहीं करता)।
- dmut permutations wordlist [**यहाँ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) प्राप्त कर सकते हैं।
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** किसी domain के आधार पर यह दिए गए patterns के अनुसार **नए संभावित subdomains names generate करता है**, ताकि अधिक subdomains discover किए जा सकें।

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): अधिक जानकारी के लिए यह [**post**](https://cramppet.github.io/regulator/index.html) पढ़ें, लेकिन यह मूल रूप से **discovered subdomains** से **मुख्य हिस्से** प्राप्त करके उन्हें मिलाकर अधिक subdomains खोजेगा।<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है, जो बेहद सरल लेकिन प्रभावी DNS response-guided algorithm के साथ काम करता है। यह दिए गए input data के सेट, जैसे tailored wordlist या historical DNS/TLS records, का उपयोग करके अधिक संबंधित domain names को सटीक रूप से synthesize करता है और DNS scan के दौरान एकत्रित जानकारी के आधार पर उन्हें loop में और विस्तारित करता है।
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

मेरे द्वारा लिखी गई इस blog post को देखें, जिसमें बताया गया है कि **Trickest workflows का उपयोग करके subdomain discovery को automate** कैसे करें, ताकि मुझे अपने computer पर कई tools को manually launch न करना पड़े:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

अगर आपको ऐसा IP address मिला है जिसमें subdomains से संबंधित **एक या कई web pages** हैं, तो आप **OSINT sources** में किसी IP के domains खोजकर या उस IP में **VHost domain names को brute-force करके**, उस IP पर मौजूद **अन्य subdomains जिनमें web pages हैं** उन्हें खोजने का प्रयास कर सकते हैं।

#### OSINT

आप [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs का उपयोग करके IPs में कुछ VHosts खोज सकते हैं**।

**Brute Force**

अगर आपको संदेह है कि किसी web server में कोई subdomain hidden हो सकता है, तो आप उसे brute force करने का प्रयास कर सकते हैं:

जब **IP किसी hostname पर redirect करता है** (name-based vhosts), तो `Host` header को सीधे fuzz करें और ffuf को **auto-calibrate** करने दें, ताकि default vhost से अलग responses को highlight किया जा सके:<sup>[[2]](#references)</sup>
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

कभी-कभी आपको ऐसे pages मिलेंगे जो _**Origin**_ header में कोई valid domain/subdomain सेट किए जाने पर ही _**Access-Control-Allow-Origin**_ header return करते हैं। इन scenarios में, आप इस behaviour का abuse करके नए **subdomains** **discover** कर सकते हैं।
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** खोजते समय ध्यान रखें कि क्या वह किसी प्रकार के **bucket** की ओर **pointing** कर रहा है, और यदि ऐसा हो तो [**permissions check करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)**।**\
साथ ही, इस चरण तक आपको scope के अंदर मौजूद सभी domains का पता होगा, इसलिए [**संभावित bucket names को brute force करें और permissions check करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

### **निगरानी**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) द्वारा किए जाने वाले **Certificate Transparency** Logs की निगरानी करके आप यह **monitor** कर सकते हैं कि किसी domain के **नए subdomains** बनाए गए हैं या नहीं।

### **vulnerabilities की खोज**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जांच करें।\
यदि **subdomain** किसी **S3 bucket** की ओर point कर रहा है, तो [**permissions check करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

यदि आपको कोई ऐसा **subdomain मिले जिसका IP अलग हो** और जो assets discovery में पहले से मिले IPs से अलग हो, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **nmap/masscan/shodan** के साथ करना चाहिए। चल रही services के आधार पर, आपको **इस book में उन्हें "attack" करने के कुछ tricks मिल सकते हैं**।\
_ध्यान दें कि कभी-कभी subdomain ऐसे IP पर hosted होता है जिसे client control नहीं करता, इसलिए वह scope में नहीं होता; सावधान रहें।_

## IPs

प्रारंभिक चरणों में आपको संभवतः **कुछ IP ranges, domains और subdomains मिले होंगे**।\
अब उन ranges से **सभी IPs एकत्र करने** और **domains/subdomains (DNS queries)** के लिए ऐसा करने का समय है।

निम्नलिखित **free apis** की services का उपयोग करके आप **domains और subdomains द्वारा पहले उपयोग किए गए IPs** भी ढूंढ सकते हैं। ये IPs अभी भी client के ownership में हो सकते हैं (और आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) ढूंढने में मदद कर सकते हैं)।

- [**https://securitytrails.com/**](https://securitytrails.com/)

आप [**hakip2host**](https://github.com/hakluke/hakip2host) tool का उपयोग करके उन domains की भी जांच कर सकते हैं जो किसी specific IP address की ओर point कर रहे हैं।

### **vulnerabilities की खोज**

**CDNs से संबंधित न होने वाले सभी IPs का port scan करें** (क्योंकि संभवतः आपको वहां कुछ interesting नहीं मिलेगा)। खोजी गई running services में आपको **vulnerabilities मिल सकती हैं**।

**एक** [**guide**](../pentesting-network/index.html) **ढूंढें जिसमें hosts को scan करने का तरीका बताया गया हो।**

## Web servers की खोज

> हमने सभी companies और उनके assets ढूंढ लिए हैं और हमें scope के अंदर मौजूद IP ranges, domains और subdomains का पता है। अब web servers खोजने का समय है।

पिछले चरणों में आपने संभवतः **खोजे गए IPs और domains का कुछ recon पहले ही कर लिया होगा**, इसलिए हो सकता है कि आपको **सभी संभावित web servers पहले ही मिल गए हों**। हालांकि, यदि ऐसा नहीं हुआ है, तो अब हम scope के अंदर web servers खोजने के लिए कुछ **तेज़ tricks** देखेंगे।

कृपया ध्यान दें कि यह **web apps discovery के लिए oriented** होगा, इसलिए आपको **vulnerability** और **port scanning** भी करना चाहिए (**यदि scope द्वारा allowed हो**)।

[**masscan** का उपयोग करके web servers से संबंधित **open ports** discover करने का एक **fast method** [यहां मिल सकता है](../pentesting-network/index.html#http-port-discovery)।\
Web servers खोजने के लिए एक अन्य friendly tool [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx) है। आप केवल domains की एक list pass करते हैं और यह port 80 (http) और 443 (https) से connect करने का प्रयास करेगा। इसके अतिरिक्त, आप अन्य ports को try करने के लिए भी indicate कर सकते हैं:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

अब जब आपने scope में मौजूद **सभी web servers** (कंपनी के **IPs** और सभी **domains** तथा **subdomains** में) खोज लिए हैं, तो संभवतः आपको **पता नहीं होगा कि शुरुआत कहाँ से करें**। इसलिए इसे सरल बनाते हैं और सबसे पहले सभी के screenshots लेते हैं। केवल **main page** पर **नज़र डालकर** ही आप ऐसे **weird** endpoints खोज सकते हैं जिनके **vulnerable** होने की संभावना अधिक हो।

प्रस्तावित विचार को लागू करने के लिए आप [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** का उपयोग कर सकते हैं।**

इसके अलावा, आप सभी **screenshots** पर [**eyeballer**](https://github.com/BishopFox/eyeballer) चला सकते हैं, ताकि यह बताया जा सके कि इनमें से **किसमें vulnerabilities होने की संभावना है** और किसमें नहीं।

## Public Cloud Assets

किसी कंपनी से संबंधित संभावित cloud assets खोजने के लिए आपको **ऐसे keywords की सूची से शुरुआत करनी चाहिए जो उस कंपनी की पहचान करते हों**। उदाहरण के लिए, किसी crypto कंपनी के लिए आप इस तरह के शब्दों का उपयोग कर सकते हैं: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

आपको buckets में उपयोग किए जाने वाले **common words** की wordlists की भी आवश्यकता होगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, इन शब्दों से आपको **permutations** generate करने चाहिए (अधिक जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

प्राप्त wordlists के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** जैसे tools का उपयोग कर सकते हैं।**

याद रखें कि Cloud Assets खोजते समय आपको **AWS में केवल buckets से अधिक चीज़ों की तलाश करनी चाहिए**।

### **Looking for vulnerabilities**

यदि आपको **open buckets या exposed cloud functions** जैसी चीज़ें मिलती हैं, तो आपको **उन तक access करना चाहिए** और यह देखने का प्रयास करना चाहिए कि वे आपको क्या प्रदान करती हैं और क्या आप उनका abuse कर सकते हैं।

## Emails

Scope में मौजूद **domains** और **subdomains** के साथ आपके पास मूल रूप से **emails खोजना शुरू करने के लिए आवश्यक सब कुछ** है। किसी कंपनी के emails खोजने के लिए ये वे **APIs** और **tools** हैं जिन्होंने मेरे लिए सबसे अच्छा काम किया है:

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs के साथ
- [**https://hunter.io/**](https://hunter.io/) का API (free version)
- [**https://app.snov.io/**](https://app.snov.io/) का API (free version)
- [**https://minelead.io/**](https://minelead.io/) का API (free version)

### **Looking for vulnerabilities**

बाद में **web logins और auth services** (जैसे SSH) पर **brute-force** करने में Emails उपयोगी होंगी। इसके अलावा, **phishings** के लिए भी इनकी आवश्यकता होती है। ये APIs आपको email के पीछे मौजूद **व्यक्ति के बारे में और भी अधिक info** देंगी, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**domains,** **subdomains** और **emails** के साथ आप उन emails से संबंधित अतीत में leaked credentials खोजना शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

यदि आपको **valid leaked** credentials मिलते हैं, तो यह बहुत आसानी से मिलने वाली जीत है।

## Secrets Leaks

Credential leaks उन कंपनियों के hacks से संबंधित होते हैं जिनमें **sensitive information leak होकर बेच दी गई**। हालांकि, कंपनियां **अन्य leaks** से भी प्रभावित हो सकती हैं, जिनकी info उन databases में नहीं होती:

### Github Leaks

Credentials और APIs कंपनी के **public repositories** में या उस **github कंपनी** के लिए काम करने वाले **users** के repositories में leak हो सकते हैं।\
आप [**Leakos**](https://github.com/carlospolop/Leakos) **tool** का उपयोग करके किसी **organization** और उसके **developers** के सभी **public repos** **download** कर सकते हैं और उन पर [**gitleaks**](https://github.com/zricethezav/gitleaks) चला सकते हैं।

**Leakos** का उपयोग दिए गए **URLs** से प्राप्त सभी **text** पर **gitleaks** चलाने के लिए भी किया जा सकता है, क्योंकि कभी-कभी **web pages में भी secrets होते हैं**।

#### Github Dorks

संभावित **github dorks** के लिए इस **page** को भी देखें, जिन्हें आप जिस organization को attack कर रहे हैं उसमें खोज सकते हैं:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

कभी-कभी attackers या केवल workers किसी **paste site में company content publish** कर देते हैं। इसमें **sensitive information** हो भी सकती है और नहीं भी, लेकिन इसे खोजना बहुत उपयोगी है।\
एक ही समय में 80 से अधिक paste sites में खोजने के लिए आप [**Pastos**](https://github.com/carlospolop/Pastos) tool का उपयोग कर सकते हैं।

### Google Dorks

पुराने लेकिन उपयोगी Google dorks हमेशा **ऐसी exposed information खोजने के लिए उपयोगी होते हैं जो वहां नहीं होनी चाहिए**। एकमात्र समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **हज़ारों** संभावित queries होती हैं, जिन्हें आप manually नहीं चला सकते। इसलिए आप अपनी पसंद की 10 queries चुन सकते हैं या [**Gorks**](https://github.com/carlospolop/Gorks) **जैसे tool का उपयोग करके उन सभी को चला सकते हैं**।

_ध्यान दें कि जो tools regular Google browser का उपयोग करके पूरे database को चलाने की कोशिश करते हैं, वे कभी समाप्त नहीं होंगे, क्योंकि Google आपको बहुत जल्दी block कर देगा।_

### **Looking for vulnerabilities**

यदि आपको **valid leaked** credentials या API tokens मिलते हैं, तो यह बहुत आसानी से मिलने वाली जीत है।

## Public Code Vulnerabilities

यदि आपको पता चलता है कि कंपनी के पास **open-source code** है, तो आप उसका **analyse** कर सकते हैं और उसमें **vulnerabilities** खोज सकते हैं।

**भाषा के आधार पर** ऐसे अलग-अलग **tools** हैं जिनका आप उपयोग कर सकते हैं:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

कुछ free services भी हैं जो **public repositories को scan** करने की सुविधा देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunters द्वारा खोजी जाने वाली **अधिकांश vulnerabilities** **web applications** में होती हैं, इसलिए इस बिंदु पर मैं **web application testing methodology** के बारे में बताना चाहता हूं, और आप [**यह जानकारी यहां पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) section का विशेष उल्लेख भी करना चाहता हूं, क्योंकि आपको इनसे बहुत संवेदनशील vulnerabilities मिलने की उम्मीद नहीं करनी चाहिए, फिर भी **कुछ प्रारंभिक web information प्राप्त करने के लिए उन्हें workflows में लागू करना उपयोगी होता है।**

## Recapitulation

> बधाई हो! इस बिंदु पर आपने **सभी basic enumeration** पूरी कर ली है। हां, यह basic है क्योंकि इससे कहीं अधिक enumeration की जा सकती है (बाद में और tricks देखेंगे)।

अब तक आपने:

1. Scope के अंदर मौजूद सभी **companies** खोज ली हैं
2. कंपनियों से संबंधित सभी **assets** खोज लिए हैं (और यदि scope में हो तो कुछ vuln scan भी किए हैं)
3. कंपनियों से संबंधित सभी **domains** खोज लिए हैं
4. Domains के सभी **subdomains** खोज लिए हैं (कोई subdomain takeover?)
5. Scope के अंदर मौजूद सभी **IPs** (CDNs से संबंधित और **CDNs से संबंधित नहीं**) खोज लिए हैं।
6. सभी **web servers** खोजकर उनका **screenshot** ले लिया है (क्या कोई weird चीज़ है जिस पर अधिक गहराई से ध्यान देना चाहिए?)
7. कंपनी से संबंधित सभी **potential public cloud assets** खोज लिए हैं।
8. **Emails**, **credentials leaks** और **secret leaks** खोज लिए हैं, जो आपको **बहुत आसानी से बड़ी जीत** दिला सकते हैं।
9. आपके द्वारा खोजी गई सभी **webs की Pentesting** कर ली है

## **Full Recon Automatic Tools**

ऐसे कई tools उपलब्ध हैं जो दिए गए scope के विरुद्ध प्रस्तावित actions के कुछ हिस्से perform कर सकते हैं।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - थोड़ा पुराना है और update नहीं किया गया है

## References

- [1] [**@Jhaddix**](https://twitter.com/Jhaddix) के सभी free courses, जैसे [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [@Asm0d3us - Weaponizing Favicon Ico For Bugbounties Osint And What Not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [swarm.ptsecurity.com - Discovering Domains Via A Time Correlation Attack](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [kmsec.uk - Passive Takeover](https://kmsec.uk/blog/passive-takeover)
- [8] [cramppet.github.io - Regulator - Index](https://cramppet.github.io/regulator/index.html)

{{#include ../../banners/hacktricks-training.md}}
