# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> तो आपको बताया गया कि किसी कंपनी से जुड़ी हर चीज़ scope में है, और आप पता लगाना चाहते हैं कि वास्तव में इस कंपनी का स्वामित्व किन चीज़ों पर है।

इस चरण का लक्ष्य **मुख्य कंपनी के स्वामित्व वाली सभी कंपनियों** और फिर इन कंपनियों के सभी **assets** का पता लगाना है। ऐसा करने के लिए, हम यह करेंगे:<sup>[[1]](#references)</sup>

1. मुख्य कंपनी के अधिग्रहणों का पता लगाएँ; इससे हमें scope में शामिल कंपनियाँ मिलेंगी।
2. हर कंपनी का ASN (यदि कोई हो) पता लगाएँ; इससे हमें हर कंपनी के स्वामित्व वाली IP ranges मिलेंगी।
3. पहली कंपनी से संबंधित अन्य entries (organisation names, domains...) खोजने के लिए reverse whois lookups का उपयोग करें (इसे recursively किया जा सकता है)।
4. अन्य assets खोजने के लिए shodan के `org`और `ssl`filters जैसे अन्य techniques का उपयोग करें (`ssl` trick को recursively किया जा सकता है)।

### **Acquisitions**

सबसे पहले, हमें यह पता लगाना होगा कि **मुख्य कंपनी के स्वामित्व वाली अन्य कंपनियाँ कौन-सी हैं**।\
एक तरीका है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाकर **मुख्य कंपनी को खोजें**, फिर "**acquisitions**" पर **click** करें। वहाँ आपको मुख्य कंपनी द्वारा अधिग्रहित अन्य कंपनियाँ दिखाई देंगी।\
दूसरा तरीका है मुख्य कंपनी के **Wikipedia** पेज पर जाकर **acquisitions** खोजें।\
सार्वजनिक कंपनियों के लिए, **SEC/EDGAR filings**, **investor relations** पेज या स्थानीय corporate registries (जैसे, UK में **Companies House**) देखें।\
वैश्विक corporate trees और subsidiaries के लिए, **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएँ।

> ठीक है, अब तक आपको scope में शामिल सभी कंपनियों का पता चल जाना चाहिए। अब देखते हैं कि उनके assets कैसे खोजें।

### **ASNs**

एक autonomous system number (**ASN**) वह **unique number** है जिसे **Internet Assigned Numbers Authority (IANA)** किसी **autonomous system** (AS) को असाइन करती है।\
एक **AS** में **IP addresses** के **blocks** होते हैं, जिनकी external networks तक पहुँचने के लिए एक स्पष्ट रूप से परिभाषित policy होती है। इनका प्रशासन एक ही organisation द्वारा किया जाता है, लेकिन ये कई operators से मिलकर बने हो सकते हैं।

यह पता लगाना उपयोगी है कि क्या **कंपनी को कोई ASN असाइन किया गया है**, ताकि उसकी **IP ranges** का पता लगाया जा सके। **Scope** के अंदर मौजूद सभी **hosts** पर **vulnerability test** करना और इन IPs के अंदर **domains** खोजना उपयोगी होगा।\
आप [**https://bgp.he.net/**](https://bgp.he.net) **या** [**https://ipinfo.io/**](https://ipinfo.io/) पर कंपनी के **name**, **IP** या **domain** से **search** कर सकते हैं।\
**कंपनी के region के आधार पर, अधिक data इकट्ठा करने के लिए ये links उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe)। वैसे, संभवतः सारी** उपयोगी जानकारी **(IP ranges और Whois)** पहले link में ही उपलब्ध है।

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

साथ ही, [**BBOT**](https://github.com/blacklanternsecurity/bbot) का enumeration स्कैन के अंत में ASNs को स्वचालित रूप से एकत्रित और सारांशित करता है।

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

आप [ASNLookup](https://asnlookup.com/) का उपयोग करके किसी संगठन की IP ranges भी ढूँढ़ सकते हैं। इसमें सीमित मुफ़्त API tier उपलब्ध है।

### **Vulnerabilities ढूँढ़ना**

इस बिंदु पर हमें **scope के अंदर मौजूद सभी assets** का पता है, इसलिए अगर आपको अनुमति हो, तो आप सभी hosts पर कोई **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या Shodan, Censys या ZoomEye जैसी services का उपयोग करके** खुले ports **ढूँढ़ सकते हैं। आपको जो भी मिले, उसके आधार पर इस किताब में देखें कि चल रही अलग-अलग संभावित services का pentest कैसे करें।**\
**यह भी उल्लेख करना उपयोगी होगा कि आप** default username **और** passwords **की कुछ lists तैयार करके [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) से services को** bruteforce **करने की कोशिश कर सकते हैं।**

## Domains

> हमें scope के अंदर मौजूद सभी कंपनियों और उनकी assets का पता है; अब scope के अंदर मौजूद domains ढूँढ़ने का समय है।

_ध्यान दें कि नीचे दी गई तकनीकों से subdomains भी मिल सकते हैं, और इस जानकारी को कम करके नहीं आँकना चाहिए।_

सबसे पहले, आपको प्रत्येक कंपनी का **main domain** ढूँढ़ना चाहिए। उदाहरण के लिए, _Tesla Inc._ का main domain _tesla.com_ होगा।

### **Reverse DNS**

चूँकि आपको domains की सभी IP ranges मिल गई हैं, आप उन **IPs पर reverse dns lookups** करके **scope के अंदर और domains ढूँढ़ने की कोशिश कर सकते हैं**। Victim के किसी dns server या किसी जाने-माने dns server (1.1.1.1, 8.8.8.8) का उपयोग करें।

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

इसके काम करने के लिए, administrator को PTR को manually enable करना होगा।\
इस जानकारी के लिए आप [SecurityTrails](https://securitytrails.com/) का भी उपयोग कर सकते हैं, हालांकि ऐतिहासिक DNS data के लिए paid plan आवश्यक है।\
बड़े ranges के लिए, reverse lookups और enrichment को automate करने हेतु [**massdns**](https://github.com/blechschmidt/massdns) और [**dnsx**](https://github.com/projectdiscovery/dnsx) जैसे tools उपयोगी हैं।

### **Reverse Whois (loop)**

**whois** में आपको बहुत सारी दिलचस्प **जानकारियाँ** मिल सकती हैं, जैसे **organisation का नाम**, **पता**, **emails**, phone numbers... लेकिन इससे भी ज़्यादा दिलचस्प बात यह है कि इन fields में से किसी के आधार पर **reverse whois lookups** करके आप **कंपनी से जुड़े और assets** खोज सकते हैं (उदाहरण के लिए, अन्य whois registries जहाँ वही email दिखाई देता है)।\
आप इन online tools का उपयोग कर सकते हैं:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web और API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web interface; paid API।
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Paid
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Free नहीं (केवल **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Free नहीं
- [https://securitytrails.com/](https://securitytrails.com/) - मौजूदा DNS/subdomains के लिए सीमित free API access; ऐतिहासिक data और reverse lookups के लिए paid plan आवश्यक है।
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - signup पर 500 free API credits; उसके बाद paid।

आप [**DomLink** ](https://github.com/vysecurity/DomLink) का उपयोग करके इस काम को automate कर सकते हैं (इसके लिए whoxy API key आवश्यक है)।\
आप [amass](https://github.com/owasp-amass/amass) से कुछ automatic reverse whois discovery भी कर सकते हैं: `amass intel -d tesla.com -whois`

**ध्यान दें कि हर बार कोई नया domain मिलने पर, आप इस technique का उपयोग करके और domain names खोज सकते हैं।**

### **Trackers**

अगर आपको 2 अलग-अलग pages पर **एक ही tracker की वही ID** मिलती है, तो आप मान सकते हैं कि **दोनों pages** **एक ही team द्वारा manage किए जाते हैं**।\
उदाहरण के लिए, अगर आपको कई pages पर वही **Google Analytics ID** या वही **Adsense ID** दिखाई दे।

कुछ pages और tools हैं जो आपको इन trackers और अन्य चीज़ों के आधार पर search करने देते हैं:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Paid** web और API service ([pricing](https://www.stackscan.com/pricing)); फिलहाल कोई free plan विज्ञापित नहीं है। किसी भी served asset के आधार पर pivot करें, केवल tracker IDs के आधार पर नहीं: script path, self-hosted bundle name या वह host जहाँ से कोई asset load होता है—और इससे वह हर site मिलती है जहाँ वह मौजूद है।

API एक single domain के लिए stack लौटाती है, जो यह पुष्टि करने में उपयोगी है कि कोई candidate asset उसी estate का हिस्सा है:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

हर detected technology को उसकी category के साथ लौटाता है। Asset pivoting फ़िलहाल केवल web के लिए है; API per-domain lookup को कवर करती है।

### **Favicon**

क्या आपको पता है कि हम एक ही favicon icon hash देखकर अपने target से जुड़े domains और subdomains ढूँढ़ सकते हैं? [@m4ll0k2](https://twitter.com/m4ll0k2) द्वारा बनाया गया [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) tool ठीक यही करता है। इसे इस्तेमाल करने का तरीका यहाँ दिया गया है:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash के परिणाम, जिनका उपयोग समान favicon hash वाले domains खोजने के लिए किया गया](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सीधे शब्दों में कहें, तो favihash हमें ऐसे domains खोजने में मदद करेगा जिनका favicon icon hash हमारे target के समान हो।

![favihash का आउटपुट, जिसका उपयोग समान favicon hash वाले domains खोजने के लिए किया गया](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

किसी ज्ञात favicon hash को Shodan या FOFA pivot के रूप में इस्तेमाल करके उसी technology के अन्य exposed instances खोजें।<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

इस तरह आप किसी web के favicon hash की **गणना** कर सकते हैं (favicon bytes के **base64-encoded** रूप पर MMH3):

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

आप [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) से बड़े पैमाने पर favicon hashes भी प्राप्त कर सकते हैं और फिर Shodan/Censys में pivot कर सकते हैं।

Favicon fingerprints को leads मानें और आसपास के संकेतों से उनकी पुष्टि करें।<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash को proof नहीं, एक indicator मानें**: MMH3 compact होता है; collisions, दोबारा इस्तेमाल किए गए icons और जानबूझकर की गई spoofing संभव है।
- **सिर्फ** `/favicon.ico` **से ज़्यादा की जाँच करें**: framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs और HTML `<link rel="icon">` tags देखें।
- **WAF/SSO/IdP controls के पीछे भी static assets तक पहुँचा जा सकता है**: icon को सीधे request करें और `ETag`, `Last-Modified`, redirects तथा cache headers की समीक्षा करें।
- **आसपास के संकेतों से matches की पुष्टि करें**: title, HTML/body hash, headers, TLS certificate subjects/SANs, product components और exposed ports की तुलना करें।
- **HTML/body hash के आधार पर cluster करें**: एकसमान template fingerprint को मजबूत करता है; अलग-अलग templates किसी generic या shared icon का संकेत देते हैं।
- **अलग-अलग signatures, ports और products में दिखने वाले hash को संभावित honeypot या placeholder मानें।**
- **जिन targets के बारे में स्पष्टता न हो, उनमें असली page की तुलना किसी ऐसे path से करें जो मौजूद न हो**, जैसे `/_favicon_probe_<8-hex>`; hosting या parking responses का एक जैसा होना shared icon की वजह समझा सकता है।
- **ऐसे Nuclei detection rules या public datasets से शुरुआती triage करें** जो favicon hashes को products और CPEs से map करते हैं।
- **IP-केंद्रित coverage gap याद रखें**: CDN-fronted, SNI-routed, anycast और सिर्फ domain पर उपलब्ध surfaces, Shodan जैसे datasets में छूट सकते हैं।

### **Copyright / Uniq string**

Web pages में ऐसे **strings खोजें जो एक ही organisation की अलग-अलग websites पर साझा हो सकते हैं**। **Copyright string** इसका अच्छा उदाहरण हो सकता है। फिर उस string को **google**, दूसरे **browsers** या यहाँ तक कि **shodan** में खोजें: `shodan search http.html:"Copyright string"`

### **CRT Time**

आमतौर पर इस तरह का cron job होता है

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

server पर सभी certificates को एक ही समय में renew करने के लिए। Certificate timestamps या certificate-transparency log positions का correlation करने से संबंधित domains का पता चल सकता है।<sup>[[6]](#references)</sup>

**certificate transparency** logs का सीधे भी उपयोग करें:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

**एक जैसी dmarc information साझा करने वाले domains और subdomains** खोजने के लिए [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी वेबसाइट या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे tool का उपयोग कर सकते हैं।\
एक और उपयोगी service [**dmarcian**](https://dmarcian.com/) है।

### **Passive Takeover**

जब cloud provider किसी IP को दोबारा assign करता है, तो एक छोड़ा हुआ A record फिर से reachable हो सकता है। संदर्भित research में एक opportunistic workflow दिखाया गया है, जिसमें instance provision करके उसके address का passive DNS data से correlation किया जाता है; takeover scenarios को केवल authorized scope में ही test करें।<sup>[[7]](#references)</sup>

### **अन्य तरीके**

जब भी आपको कोई नया domain मिले, तो लागू discovery pivots दोहराएँ: हर result से certificate names, passive-DNS relationships, favicon matches और organization identifiers की अतिरिक्त जानकारी मिल सकती है, जो शुरुआती seed से दिखाई नहीं दी थी।<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

जैसा कि आपको पहले से पता है कि IP space किस organisation का है। आप Shodan में इस data से search कर सकते हैं: `org:"Tesla, Inc."` नए और अप्रत्याशित domains के लिए मिले हुए hosts के TLS certificate देखें।

आप मुख्य web page का **TLS certificate** खोलकर **Organisation name** प्राप्त कर सकते हैं, फिर उस नाम को **Shodan** पर ज्ञात सभी web pages के **TLS certificates** में इस filter से search कर सकते हैं: `ssl:"Tesla Motors"` या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे tool का उपयोग कर सकते हैं।

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) एक ऐसा tool है जो किसी मुख्य domain से संबंधित **domains** और उनके **subdomains** खोजता है; यह बहुत शानदार है।

**Passive DNS / Historical DNS**

Passive DNS data उन **पुराने और भुला दिए गए records** को खोजने में बहुत उपयोगी है, जो अब भी resolve होते हैं या जिनका takeover किया जा सकता है। देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **vulnerabilities की खोज**

कुछ [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) के लिए जाँच करें। हो सकता है कि कोई company **किसी domain का उपयोग कर रही हो**, लेकिन उसने **उसका ownership खो दिया हो**। बस उसे register करें (अगर वह पर्याप्त सस्ता हो) और company को सूचित करें।

अगर आपको कोई ऐसा **domain मिले जिसका IP**, assets discovery में पहले मिले IPs से **अलग हो**, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **nmap/masscan/shodan** से [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करना चाहिए। चल रही services के आधार पर, **इस book में उन्हें "attack" करने की कुछ तरकीबें** मिल सकती हैं।\
_ध्यान दें कि कभी-कभी domain ऐसे IP पर hosted होता है जिसे client नियंत्रित नहीं करता, इसलिए वह scope में नहीं होता। सावधान रहें।_

## Subdomains

> हमें scope में शामिल सभी companies, हर company के सभी assets और उनसे संबंधित सभी domains पता हैं।

अब मिले हुए हर domain के सभी संभावित subdomains खोजने का समय है।

> [!TIP]
> ध्यान दें कि domains खोजने के कुछ tools और techniques, subdomains खोजने में भी मदद कर सकते हैं

### **DNS**

आइए **DNS** records से **subdomains** पाने की कोशिश करें। हमें **Zone Transfer** भी आज़माना चाहिए (अगर यह vulnerable हो, तो इसकी report करें)।

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Infrastructure, reputation, breach records और subdomain discovery से आगे enrichment को कवर करने वाले APIs और platforms के लिए, [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md) देखें।

बहुत सारे subdomains पाने का सबसे तेज़ तरीका external sources में search करना है। सबसे ज़्यादा इस्तेमाल किए जाने वाले **tools** ये हैं (बेहतर results के लिए API keys configure करें):


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

कुछ **अन्य दिलचस्प tools/APIs** भी हैं, जो भले ही सीधे तौर पर subdomains खोजने के लिए विशेषीकृत न हों, फिर भी subdomains खोजने में उपयोगी हो सकते हैं, जैसे:

- [**IP.THC.ORG**](https://ip.thc.org) मुफ़्त API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB मुफ़्त API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) मुफ़्त API

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

- [**gau**](https://github.com/lc/gau)**:** किसी भी दिए गए डोमेन के लिए AlienVault's Open Threat Exchange, Wayback Machine और Common Crawl से ज्ञात URLs प्राप्त करता है।

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ये JS files खोजने के लिए वेब को crawl करते हैं और उनमें से subdomains निकालते हैं।

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

- [**SecurityTrails**](https://securitytrails.com/) मौजूदा DNS और subdomain डेटा के लिए सीमित मुफ्त API access देता है; ऐतिहासिक DNS/IP डेटा के लिए paid plan आवश्यक है।
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

यह project bug-bounty programs से संबंधित **सभी subdomains मुफ्त में** उपलब्ध कराता है। आप [chaospy](https://github.com/Moaaz-0x/chaospy) का उपयोग करके भी इस डेटा को access कर सकते हैं या इस project द्वारा उपयोग किए गए scope को [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) से access कर सकते हैं।

आप इनमें से कई tools की **तुलना** यहाँ पा सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

संभावित subdomain नामों का उपयोग करके DNS servers पर brute-forcing करके नए **subdomains** खोजने की कोशिश करें।

इस काम के लिए आपको कुछ **आम subdomains की wordlists की ज़रूरत होगी**, जैसे:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

आपको अच्छे DNS resolvers के IPs भी चाहिए होंगे। विश्वसनीय DNS resolvers की सूची बनाने के लिए, [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) से resolvers डाउनलोड करें और उन्हें filter करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग करें। या आप यह सूची इस्तेमाल कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे ज़्यादा अनुशंसित tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह प्रभावी DNS brute-force करने वाला पहला tool था। यह बहुत तेज़ है, लेकिन false positives की संभावना रहती है।

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): मेरे विचार से यह केवल 1 resolver का उपयोग करता है.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के आसपास बनाया गया Go wrapper है, जो active brute force का उपयोग करके valid subdomains enumerate करने के साथ-साथ wildcard handling और आसान input-output support के साथ subdomains resolve करने देता है।

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): यह भी `massdns` का उपयोग करता है।

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) domain names को asynchronously brute force करने के लिए asyncio का उपयोग करता है।

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### दूसरा DNS Brute-Force दौर

Open sources और brute-forcing का उपयोग करके subdomains खोजने के बाद, आप और भी subdomains खोजने की कोशिश करने के लिए मिले subdomains के बदलाव बना सकते हैं। इस उद्देश्य के लिए कई tools उपयोगी हैं:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** दिए गए domains और subdomains से permutations बनाता है।

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains से permutations जनरेट करता है।
  - आप goaltdns permutations **wordlist** [**यहाँ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) पा सकते हैं।

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains के permutations जनरेट करता है। अगर permutations file निर्दिष्ट नहीं की गई है, तो gotator अपनी फ़ाइल का उपयोग करेगा।

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Subdomains के permutations generate करने के अलावा, यह उन्हें resolve करने की कोशिश भी कर सकता है (लेकिन पहले बताए गए tools का इस्तेमाल करना बेहतर है)।
  - altdns के permutations की **wordlist** [**यहाँ**](https://github.com/infosec-au/altdns/blob/master/words.txt) मिल सकती है।

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): subdomains के permutations, mutations और alterations करने के लिए एक अन्य tool। यह tool परिणामों को brute force करेगा (यह dns wild card को support नहीं करता)।
  - dmut की permutations wordlist [**यहाँ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) मिल सकती है।

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** डोमेन के आधार पर, यह दिए गए patterns से नए संभावित subdomain नाम बनाता है, ताकि और subdomains खोजे जा सकें।

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): खोजे गए subdomains से regex-जैसे patterns सीखता है और resolve करने के लिए candidate नाम बनाता है।<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है, जो बेहद सरल लेकिन प्रभावी DNS response-guided algorithm के साथ काम करता है। यह इनपुट डेटा के दिए गए सेट, जैसे कि विशेष रूप से तैयार की गई wordlist या ऐतिहासिक DNS/TLS records, का उपयोग करके संबंधित domain names को सटीक रूप से तैयार करता है और DNS scan के दौरान मिली जानकारी के आधार पर उन्हें बार-बार और विस्तृत करता है।

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Trickest workflow के उदाहरण बार-बार subdomain enumeration करने के लिए OSINT, DNS brute force और permutation stages को जोड़ते हैं।<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

अगर आपको ऐसा IP address मिला है जिसमें subdomains से संबंधित **एक या कई web pages** हैं, तो आप **उस IP पर मौजूद अन्य subdomains खोजने** की कोशिश कर सकते हैं। इसके लिए **OSINT sources** में किसी IP के domains खोजें या **उस IP पर VHost domain names को brute-force करें**।

#### OSINT

आप [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs का उपयोग करके IPs में कुछ VHosts खोज सकते हैं**।

**Brute Force**

अगर आपको लगता है कि कोई subdomain web server में छिपा हो सकता है, तो आप उसे brute force करने की कोशिश कर सकते हैं:

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
> इस तकनीक से आप internal/hidden endpoints तक पहुँच भी प्राप्त कर सकते हैं।

### **CORS Brute Force**

कभी-कभी आपको ऐसे pages मिलेंगे जो _**Origin**_ header में valid domain/subdomain सेट होने पर ही _**Access-Control-Allow-Origin**_ header लौटाते हैं। इन स्थितियों में, आप इस व्यवहार का दुरुपयोग करके नए **subdomains** **discover** कर सकते हैं।

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains** खोजते समय ध्यान रखें कि क्या वे किसी प्रकार के **bucket** की ओर **pointing** कर रहे हैं। अगर ऐसा है, तो [**permissions जाँचें**](../../network-services-pentesting/pentesting-web/buckets/index.html)**।**\
साथ ही, इस चरण तक आपको scope के सभी domains पता होंगे, इसलिए [**संभावित bucket names को brute force करके permissions जाँचें**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

### **निगरानी**

आप **Certificate Transparency** Logs को monitor करके यह पता लगा सकते हैं कि किसी domain के **नए subdomains** बनाए गए हैं या नहीं। [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) यही करता है।

### **vulnerabilities की तलाश**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
अगर **subdomain** किसी **S3 bucket** की ओर point कर रहा है, तो [**permissions जाँचें**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

अगर आपको ऐसा कोई **subdomain मिले जिसका IP**, asset discovery में पहले मिले IPs से **अलग हो**, तो **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **nmap/masscan/shodan** से [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करें। चल रही services के आधार पर, आपको **इस book में उन्हें "attack" करने की कुछ तरकीबें** मिल सकती हैं।\
_ध्यान दें कि कभी-कभी subdomain ऐसे IP पर hosted होता है जो client के नियंत्रण में नहीं होता, इसलिए वह scope में नहीं होता। सावधान रहें।_

## IPs

शुरुआती चरणों में आपको **कुछ IP ranges, domains और subdomains मिले होंगे**।\
अब उन ranges से **सभी IPs इकट्ठा करने** और **domains/subdomains के लिए DNS queries करने** का समय है।

नीचे दी गई services का उपयोग करके, आप **domains और subdomains द्वारा पहले इस्तेमाल किए गए IPs** भी ढूँढ़ सकते हैं। हो सकता है कि ये IPs अब भी client के स्वामित्व में हों (और इनसे आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) ढूँढ़ने में मदद मिल सकती है)।

- [**SecurityTrails**](https://securitytrails.com/) (historical DNS/IP data के लिए paid plan की आवश्यकता होती है)

किसी खास IP address की ओर point करने वाले domains भी आप [**hakip2host**](https://github.com/hakluke/hakip2host) tool से जाँच सकते हैं।

### **vulnerabilities की तलाश**

**CDNs से संबंधित न होने वाले सभी IPs का port scan करें** (क्योंकि वहाँ कुछ दिलचस्प मिलने की संभावना बहुत कम है)। खोजी गई चल रही services में आपको **vulnerabilities मिल सकती हैं**।

**Hosts को scan करने के तरीके पर एक** [**guide**](../pentesting-network/index.html) **ढूँढ़ें।**

## Web servers की तलाश

> हमने सभी companies और उनके assets ढूँढ़ लिए हैं और हमें scope के अंदर की IP ranges, domains और subdomains पता हैं। अब web servers खोजने का समय है।

पिछले चरणों में आपने शायद खोजे गए IPs और domains का कुछ **recon** पहले ही कर लिया होगा, इसलिए हो सकता है कि आपको **सभी संभावित web servers पहले ही मिल गए हों**। लेकिन अगर ऐसा नहीं हुआ है, तो अब हम scope के अंदर web servers खोजने की कुछ **तेज़ तरकीबें** देखेंगे।

ध्यान दें कि यह **web apps की खोज पर केंद्रित** होगा, इसलिए आपको **vulnerability** और **port scanning** भी करनी चाहिए (**अगर scope इसकी अनुमति देता है**)।

[**masscan** का उपयोग करके web servers से संबंधित **खुले ports** खोजने का एक **तेज़ तरीका यहाँ दिया गया है**](../pentesting-network/index.html#http-port-discovery)।\
Web servers खोजने के लिए एक और आसान tool है [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx)। आप बस domains की एक list देते हैं और यह port 80 (http) और 443 (https) से connect करने की कोशिश करता है। इसके अलावा, आप अन्य ports पर कोशिश करने का निर्देश भी दे सकते हैं:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

अब जब आपने scope में मौजूद **सभी web servers** खोज लिए हैं (कंपनी के **IPs**, सभी **domains** और **subdomains** में), तो शायद आपको **पता नहीं होगा कि शुरुआत कहाँ से करें**। तो इसे आसान बनाते हैं और सबसे पहले उन सभी के screenshots लेते हैं। सिर्फ़ **मुख्य page पर नज़र डालकर** आप ऐसे **अजीब** endpoints खोज सकते हैं जिनके **vulnerable** होने की **संभावना ज़्यादा** है।

इस विचार को अमल में लाने के लिए आप [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** का इस्तेमाल कर सकते हैं।

इसके अलावा, आप [**eyeballer**](https://github.com/BishopFox/eyeballer) का इस्तेमाल करके सभी **screenshots** को स्कैन करवा सकते हैं, ताकि यह पता चले कि **किनमें vulnerabilities होने की संभावना है** और किनमें नहीं।

## Public Cloud Assets

किसी कंपनी से संबंधित संभावित cloud assets खोजने के लिए, आपको **उस कंपनी की पहचान करने वाले keywords की सूची से शुरुआत करनी चाहिए**। उदाहरण के लिए, किसी crypto कंपनी के लिए आप ऐसे शब्द इस्तेमाल कर सकते हैं: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`।

आपको **buckets में इस्तेमाल होने वाले आम शब्दों** की wordlists भी चाहिए होंगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, इन शब्दों से आपको **permutations** बनाने चाहिए (ज़्यादा जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

इन wordlists से आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** जैसे tools इस्तेमाल कर सकते हैं।

याद रखें कि Cloud Assets खोजते समय आपको **AWS में सिर्फ़ buckets ही नहीं** खोजने चाहिए।

### **vulnerabilities की तलाश**

अगर आपको **open buckets या exposed cloud functions** जैसी चीज़ें मिलें, तो आपको **उन तक पहुँचकर** देखना चाहिए कि वे क्या उपलब्ध कराती हैं और क्या आप उनका दुरुपयोग कर सकते हैं।

## Emails

scope में मौजूद **domains** और **subdomains** के साथ, आपके पास **emails खोजना शुरू करने के लिए ज़रूरी सब कुछ** है। किसी कंपनी के emails खोजने के लिए मेरे अनुभव में सबसे अच्छे रहे **APIs** और **tools** ये हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs के साथ
- [**https://hunter.io/**](https://hunter.io/) का API (free version)
- [**https://app.snov.io/**](https://app.snov.io/) का API (free version)
- [**https://minelead.io/**](https://minelead.io/) का API (free version)

### **vulnerabilities की तलाश**

बाद में **web logins और auth services** (जैसे SSH) पर **brute-force** करने में Emails काम आएंगे। **phishings** के लिए भी इनकी ज़रूरत होती है। इसके अलावा, ये APIs आपको email के पीछे मौजूद **व्यक्ति के बारे में और जानकारी** देंगी, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**domains,** **subdomains**, और **emails** की मदद से आप उन emails से संबंधित, अतीत में हुए credential leaks खोजना शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **vulnerabilities की तलाश**

अगर आपको **valid leaked** credentials मिलते हैं, तो यह बहुत आसानी से मिलने वाली जीत है।

## Secrets Leaks

Credential leaks उन कंपनियों के hacks से जुड़े होते हैं जिनमें **sensitive information leak होकर बेची गई**। हालांकि, कंपनियाँ **अन्य leaks** से भी प्रभावित हो सकती हैं, जिनकी जानकारी उन databases में नहीं होती:

### Github Leaks

Credentials और APIs कंपनी के **public repositories** या उस कंपनी में काम करने वाले **users** के repositories से leak हो सकते हैं।\
आप [**Leakos**](https://github.com/carlospolop/Leakos) **tool** का इस्तेमाल करके किसी **organization** और उसके **developers** के सभी **public repos डाउनलोड** कर सकते हैं और उन पर [**gitleaks**](https://github.com/gitleaks/gitleaks) अपने-आप चला सकते हैं।

**Leakos** का इस्तेमाल उसे दिए गए सभी **text URLs** पर **gitleaks** चलाने के लिए भी किया जा सकता है, क्योंकि कभी-कभी **web pages में भी secrets होते हैं**।

#### Github Dorks

Organization में खोजने के लिए संभावित **GitHub dorks** हेतु [GitHub dorks and leaks page](github-leaked-secrets.md) देखें।

### Pastes Leaks

कभी-कभी attackers या कर्मचारी, किसी paste site पर **कंपनी का content प्रकाशित** कर देते हैं। इसमें **sensitive information हो भी सकती है और नहीं भी**, लेकिन इसे खोजना काफ़ी उपयोगी है।\
एक ही समय में 80 से अधिक paste sites पर खोजने के लिए आप [**Pastos**](https://github.com/carlospolop/Pastos) tool का इस्तेमाल कर सकते हैं।

### Google Dorks

पुराने लेकिन बेहतरीन google dorks, ऐसी **exposed information खोजने के लिए हमेशा उपयोगी हैं जो वहाँ नहीं होनी चाहिए**। एकमात्र समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **हज़ार** संभावित queries हैं जिन्हें आप manually नहीं चला सकते। इसलिए आप अपने पसंदीदा 10 चुन सकते हैं या उन्हें **सभी चलाने के लिए** [**Gorks**](https://github.com/carlospolop/Gorks) **जैसे tool** का इस्तेमाल कर सकते हैं।

_ध्यान दें कि जो tools नियमित Google browser का इस्तेमाल करके पूरा database चलाने की कोशिश करते हैं, वे कभी पूरा नहीं कर पाएँगे, क्योंकि Google आपको बहुत जल्दी block कर देगा।_

### **vulnerabilities की तलाश**

अगर आपको **valid leaked** credentials या API tokens मिलते हैं, तो यह बहुत आसानी से मिलने वाली जीत है।

## Public Code Vulnerabilities

अगर आपको पता चले कि कंपनी का **open-source code** है, तो आप उसका **विश्लेषण** कर सकते हैं और उसमें **vulnerabilities** खोज सकते हैं।

**भाषा के आधार पर**, इस्तेमाल किए जा सकने वाले **tools** अलग-अलग होंगे; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) की सूची देखें।

ऐसी free services भी हैं जिनकी मदद से आप **public repositories scan** कर सकते हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Web Pentesting कार्यप्रणाली**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters को मिलने वाली **ज़्यादातर vulnerabilities** **web applications** में होती हैं, इसलिए इस बिंदु पर मैं **web application testing की कार्यप्रणाली** के बारे में बात करना चाहूँगा। आप [**यह जानकारी यहाँ पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) वाले section का विशेष रूप से ज़िक्र करना चाहता हूँ, क्योंकि भले ही आपको उनसे बहुत संवेदनशील vulnerabilities मिलने की उम्मीद नहीं करनी चाहिए, फिर भी **शुरुआती web जानकारी पाने के लिए workflows में उन्हें शामिल करना उपयोगी है।**

## Recapitulation

> बधाई हो! इस बिंदु तक आपने **सारी बुनियादी enumeration** पूरी कर ली है। हाँ, यह बुनियादी है, क्योंकि इससे कहीं ज़्यादा enumeration की जा सकती है (बाद में और तरकीबें देखेंगे)।

अब तक आपने:

1. scope में मौजूद सभी **कंपनियों** को खोज लिया है
2. कंपनियों से संबंधित सभी **assets** खोज लिए हैं (और scope में होने पर vuln scan भी किया है)
3. कंपनियों से संबंधित सभी **domains** खोज लिए हैं
4. domains के सभी **subdomains** खोज लिए हैं (कोई subdomain takeover तो नहीं?)
5. scope में मौजूद सभी **IPs** खोज लिए हैं (**CDNs से आने वाले और उनसे नहीं आने वाले**)
6. सभी **web servers** खोजकर उनके **screenshots** ले लिए हैं (क्या कोई अजीब चीज़ है जिस पर और ध्यान देना चाहिए?)
7. कंपनी से संबंधित सभी **संभावित public cloud assets** खोज लिए हैं।
8. **Emails**, **credential leaks**, और **secret leaks** खोज लिए हैं, जिनसे आपको **बहुत आसानी से बड़ी जीत** मिल सकती है।
9. मिले सभी **webs की Pentesting** कर ली है

## **Full Recon के Automatic Tools**

ऐसे कई tools उपलब्ध हैं जो दिए गए scope पर प्रस्तावित कार्रवाइयों में से कुछ को पूरा करते हैं।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - काफ़ी पुराना है और updated नहीं है

## References

- [1] [Jason Haddix – Bug Hunter की कार्यप्रणाली v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicons पर: Browser Icons से Attack Surface Intelligence तक](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – BugBounties, OSINT और अन्य चीज़ों के लिए favicon.ico को हथियार बनाना](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency पर Time-Correlation Attack के ज़रिए Domains खोजना](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: एक महँगी Subdomain Takeover Campaign को उजागर करना (और उसका अनुकरण करना)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration का एक अनूठा तरीका](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Subdomain खोजने की पूरी Workflow, भाग 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automated Trickest Workflow से Full Subdomain Brute Force Discovery, भाग 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output का screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
