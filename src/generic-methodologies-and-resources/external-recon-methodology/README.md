# बाहरी Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets की खोज

अतिरिक्त OSINT और web-discovery projects की श्रेणीबद्ध सूची के लिए, [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint) देखें।

> आपको बताया गया था कि किसी कंपनी से जुड़ी हर चीज़ scope में है, और आप पता लगाना चाहते हैं कि वास्तव में इस कंपनी के पास क्या-क्या है।

इस चरण का लक्ष्य **मुख्य कंपनी के स्वामित्व वाली सभी कंपनियों** और फिर उन कंपनियों के सभी **assets** का पता लगाना है। ऐसा करने के लिए, हम:<sup>[[1]](#references)</sup>

1. मुख्य कंपनी के अधिग्रहणों का पता लगाएँगे; इससे हमें scope में आने वाली कंपनियाँ मिलेंगी।
2. हर कंपनी का ASN (यदि कोई हो) पता करेंगे; इससे हमें हर कंपनी के स्वामित्व वाली IP ranges मिलेंगी।
3. अन्य संबंधित प्रविष्टियाँ (organisation names, domains...) खोजने के लिए reverse whois lookups का उपयोग करेंगे (यह प्रक्रिया recursive तरीके से की जा सकती है)।
4. अन्य assets खोजने के लिए shodan के `org` और `ssl` filters जैसी दूसरी techniques का उपयोग करेंगे (`ssl` trick को recursive तरीके से किया जा सकता है)।

Resolved subdomains से HTTP crawling और port discovery तक के staged handoff के लिए, [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline) देखें।

### **अधिग्रहण**

सबसे पहले, हमें पता करना होगा कि **मुख्य कंपनी के स्वामित्व वाली अन्य कंपनियाँ कौन-सी हैं**।\
एक विकल्प है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाकर **मुख्य कंपनी को खोजें** और "**acquisitions**" पर **क्लिक** करें। वहाँ आपको मुख्य कंपनी द्वारा अधिग्रहित अन्य कंपनियाँ दिखेंगी।\
दूसरा विकल्प है मुख्य कंपनी का **Wikipedia** पेज खोलकर **acquisitions** खोजें।\
सार्वजनिक कंपनियों के लिए, **SEC/EDGAR filings**, **investor relations** पेज या स्थानीय corporate registries (जैसे UK में **Companies House**) देखें।\
वैश्विक corporate trees और subsidiaries के लिए, **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएँ।

> ठीक है, इस बिंदु तक आपको scope में आने वाली सभी कंपनियों के बारे में पता होना चाहिए। अब जानें कि उनके assets कैसे खोजें।

### **ASNs**

एक autonomous system number (**ASN**) वह **अद्वितीय संख्या** है जिसे **Internet Assigned Numbers Authority (IANA)** किसी **autonomous system** (AS) को आवंटित करती है।\
एक **AS** में **IP addresses** के **blocks** होते हैं, जिनकी बाहरी networks तक पहुँचने के लिए स्पष्ट रूप से परिभाषित policy होती है। इन्हें एक ही organisation संचालित करती है, लेकिन इनमें कई operators शामिल हो सकते हैं।

यह पता करना उपयोगी है कि **कंपनी को कोई ASN आवंटित किया गया है या नहीं**, ताकि उसकी **IP ranges** का पता चल सके। **Scope** में मौजूद सभी **hosts** पर **vulnerability test** करना और इन IPs के भीतर **domains खोजना** उपयोगी होगा।\
आप [**https://bgp.he.net/**](https://bgp.he.net) **या** [**https://ipinfo.io/**](https://ipinfo.io/) पर कंपनी के **नाम**, **IP** या **domain** से **खोज** कर सकते हैं।\
**कंपनी के क्षेत्र के आधार पर, अधिक data जुटाने के लिए ये links उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe)। वैसे, संभवतः सारी** उपयोगी जानकारी **(IP ranges और Whois)** पहले link पर पहले से उपलब्ध है।

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

साथ ही, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration स्कैन के अंत में ASNs को अपने-आप एकत्रित और सारांशित करता है।

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

आप [ASNLookup](https://asnlookup.com/) का उपयोग करके किसी संगठन की IP रेंज भी ढूँढ़ सकते हैं। इसमें सीमित free API tier उपलब्ध है।

### **vulnerabilities ढूँढ़ना**

इस बिंदु पर हमें **scope के अंदर मौजूद सभी assets** पता हैं, इसलिए अगर आपको अनुमति है, तो आप सभी hosts पर कोई **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या Shodan, Censys या ZoomEye जैसी services का उपयोग करके** open ports **ढूँढ़ सकते हैं। आपको जो मिले, उसके आधार पर यह देखने के लिए इस किताब में खोजें कि चल रही संभावित services का pentest कैसे करें।**\
**यह बताना भी उपयोगी हो सकता है कि आप कुछ** default username **और** passwords **की lists तैयार करके** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **से services पर bruteforce करने की कोशिश कर सकते हैं।**

## डोमेन

> हमें scope में मौजूद सभी कंपनियों और उनके assets के बारे में पता है; अब scope में मौजूद डोमेन ढूँढ़ने का समय है।

_कृपया ध्यान दें कि नीचे बताई गई तकनीकों से आपको subdomains भी मिल सकते हैं और उस जानकारी को कम करके नहीं आँकना चाहिए।_

सबसे पहले, आपको हर कंपनी का **main domain** ढूँढ़ना चाहिए। उदाहरण के लिए, _Tesla Inc._ का main domain _tesla.com_ होगा।

### **Reverse DNS**

चूँकि आपको डोमेन की सभी IP रेंज मिल गई हैं, इसलिए आप उन **IPs पर reverse DNS lookups** करने की कोशिश कर सकते हैं, ताकि **scope में मौजूद और डोमेन ढूँढ़ सकें**। पीड़ित का कोई DNS server या कोई प्रसिद्ध DNS server (1.1.1.1, 8.8.8.8) इस्तेमाल करके देखें।

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

इसके काम करने के लिए, administrator को PTR मैन्युअल रूप से enable करना होगा।\
इस जानकारी के लिए आप [SecurityTrails](https://securitytrails.com/) का भी उपयोग कर सकते हैं, हालांकि historical DNS data के लिए paid plan चाहिए।\
बड़ी ranges के लिए, [**massdns**](https://github.com/blechschmidt/massdns) और [**dnsx**](https://github.com/projectdiscovery/dnsx) जैसे tools reverse lookups और enrichment को automate करने में उपयोगी हैं।

### **Reverse Whois (loop)**

**whois** में आपको बहुत-सी दिलचस्प **जानकारी** मिल सकती है, जैसे **organisation name**, **address**, **emails**, phone numbers... लेकिन इससे भी ज़्यादा दिलचस्प यह है कि इन fields में से किसी के आधार पर **reverse whois lookups** करने पर आपको **कंपनी से संबंधित और assets** मिल सकते हैं (उदाहरण के लिए, अन्य whois registries जहाँ वही email दिखाई देता है)।\
आप इन online tools का उपयोग कर सकते हैं:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web और API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web interface; paid API।
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Paid
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Free नहीं (सिर्फ़ **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Free नहीं
- [https://securitytrails.com/](https://securitytrails.com/) - मौजूदा DNS/subdomains के लिए सीमित free API access; historical और reverse lookups के लिए paid plan चाहिए।
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Signup पर 500 free API credits; उसके बाद paid।

इस काम को [**DomLink** ](https://github.com/vysecurity/DomLink) (इसके लिए whoxy API key चाहिए) से automate किया जा सकता है।\
आप [amass](https://github.com/owasp-amass/amass) से कुछ automatic reverse whois discovery भी कर सकते हैं: `amass intel -d tesla.com -whois`

**ध्यान दें कि हर बार कोई नया domain मिलने पर, इस technique से और domain names खोजे जा सकते हैं।**

### **Trackers**

अगर आपको 2 अलग-अलग pages पर **एक ही tracker की वही ID** मिलती है, तो आप मान सकते हैं कि **दोनों pages** **एक ही team द्वारा managed** हैं।\
उदाहरण के लिए, अगर आपको कई pages पर वही **Google Analytics ID** या वही **Adsense ID** दिखाई देती है।

कुछ pages और tools हैं, जिनकी मदद से आप इन trackers और अन्य चीज़ों के आधार पर search कर सकते हैं:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Paid** web और API service ([pricing](https://www.stackscan.com/pricing)); अभी कोई free plan विज्ञापित नहीं है। किसी भी served asset के आधार पर pivot करें, सिर्फ़ tracker IDs के आधार पर नहीं: जैसे कोई script path, self-hosted bundle name या वह host जहाँ से कोई asset load होता है। यह उन सभी sites को लौटाता है जिन पर वह मौजूद है।

API एक domain के लिए stack लौटाती है, जो यह पुष्टि करने में उपयोगी है कि कोई candidate asset उसी estate का हिस्सा है:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

हर पहचानी गई technology को उसकी category के साथ दिखाता है। Asset pivoting अभी केवल web के लिए उपलब्ध है; API प्रति-domain lookup को कवर करती है।

### **Favicon**

क्या आपको पता है कि एक ही favicon icon hash खोजकर हम अपने target से संबंधित domains और subdomains ढूँढ़ सकते हैं? [@m4ll0k2](https://twitter.com/m4ll0k2) द्वारा बनाया गया [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) tool यही करता है। इसे इस्तेमाल करने का तरीका यहाँ दिया गया है:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![लक्ष्य के समान favicon hash वाले domains खोजने के लिए इस्तेमाल किए गए Favihash के परिणाम](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सरल शब्दों में, favihash हमें ऐसे domains खोजने देता है जिनका favicon icon hash हमारे target के समान हो।

![समान favicon hash वाले domains खोजने के लिए इस्तेमाल किया गया favihash का आउटपुट](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

उसी technology के अन्य exposed instances खोजने के लिए किसी ज्ञात favicon hash को Shodan या FOFA pivot के रूप में इस्तेमाल करें।<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

इस तरह आप किसी वेबसाइट का **favicon hash** (favicon bytes के **base64-encoded** रूप पर MMH3) **गणना** कर सकते हैं:

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

favicon fingerprints को leads मानें और आसपास के संकेतों से उनकी पुष्टि करें।<sup>[[3]](#references)[[4]](#references)</sup>

- **hash को संकेत मानें, प्रमाण नहीं**: MMH3 कॉम्पैक्ट है; collisions, दोबारा इस्तेमाल किए गए icons और जानबूझकर की गई spoofing संभव हैं।
- **सिर्फ** `/favicon.ico` **से अधिक की जाँच करें**: framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs और HTML `<link rel="icon">` tags देखें।
- **WAF/SSO/IdP controls के पीछे भी static assets उपलब्ध हो सकते हैं**: icon को सीधे request करें और `ETag`, `Last-Modified`, redirects तथा cache headers की समीक्षा करें।
- **matches की पुष्टि आसपास के संकेतों से करें**: title, HTML/body hash, headers, TLS certificate subjects/SANs, product components और खुले ports की तुलना करें।
- **HTML/body hash के आधार पर cluster करें**: एकसमान template fingerprint को मजबूत करता है; अलग-अलग templates किसी सामान्य या साझा icon का संकेत देते हैं।
- **अलग-अलग signatures, ports और products में दिखने वाले hash को संभावित honeypot या placeholder मानें।**
- **अस्पष्ट targets पर किसी वास्तविक page की तुलना किसी गैर-मौजूद path** जैसे `/_favicon_probe_<8-hex>` **से करें**; एक जैसी hosting या parking responses साझा icon की वजह समझा सकती हैं।
- **favicon hashes को products और CPEs से जोड़ने वाले Nuclei detection rules या public datasets से शुरुआती triage करें।**
- **IP-केंद्रित coverage gap याद रखें**: CDN-fronted, SNI-routed, anycast और केवल domain पर उपलब्ध surfaces, Shodan-जैसे datasets में छूट सकते हैं।

### **कॉपीराइट / यूनिक स्ट्रिंग**

वेब पेजों में ऐसे **strings खोजें जो एक ही संगठन की अलग-अलग websites पर साझा हो सकते हैं**। **copyright string** इसका अच्छा उदाहरण हो सकता है। फिर उस string को **google**, दूसरे **browsers** या यहाँ तक कि **shodan** में खोजें: `shodan search http.html:"Copyright string"`

### **CRT समय**

ऐसा cron job होना आम है, जैसे कि

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

सर्वर पर सभी certificates को एक ही समय पर renew करने के लिए। Certificate timestamps या certificate-transparency log positions का आपस में मिलान करने से संबंधित domains का पता चल सकता है।<sup>[[6]](#references)</sup>

**certificate transparency** logs का सीधे भी उपयोग करें:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### मेल DMARC जानकारी

**एक जैसी DMARC जानकारी साझा करने वाले domains और subdomains** खोजने के लिए आप [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी वेबसाइट या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे tool का उपयोग कर सकते हैं।\
एक और उपयोगी service [**dmarcian**](https://dmarcian.com/) है।

### **Passive Takeover**

एक छोड़ा हुआ A record तब reachable हो सकता है जब कोई cloud provider उस IP को फिर से assign करे। संदर्भित research में एक opportunistic workflow दिखाया गया है, जो एक instance provision करता है और उसके address का passive DNS data से मिलान करता है; takeover scenarios को केवल authorized scope के भीतर ही test करें।<sup>[[7]](#references)</sup>

### **अन्य तरीके**

जब भी आपको कोई नया domain मिले, लागू discovery pivots को दोहराएँ: हर result से certificate names, passive-DNS relationships, favicon matches और organization identifiers के बारे में अतिरिक्त जानकारी मिल सकती है, जो मूल seed से दिखाई नहीं दी थी।<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

चूँकि अब आपको IP space की मालिक organization का नाम पता है, आप Shodan में इस data से खोज सकते हैं: `org:"Tesla, Inc."` नए और अप्रत्याशित domains के लिए मिले हुए hosts के TLS certificate जाँचें।

आप मुख्य web page का **TLS certificate** देख सकते हैं, **Organisation name** प्राप्त कर सकते हैं और फिर उस नाम को **shodan** को ज्ञात सभी web pages के **TLS certificates** में इस filter से खोज सकते हैं: `ssl:"Tesla Motors"` या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे tool का उपयोग कर सकते हैं।

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)एक ऐसा tool है जो किसी मुख्य domain से **संबंधित domains** और उनके **subdomains** खोजता है; यह काफी शानदार है।

**Passive DNS / Historical DNS**

Passive DNS data उन **पुराने और भुला दिए गए records** को खोजने में बहुत उपयोगी है, जो अभी भी resolve होते हैं या जिनका takeover किया जा सकता है। देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Vulnerabilities की तलाश**

कुछ [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) जाँचें। हो सकता है कि कोई company **किसी domain का उपयोग कर रही हो**, लेकिन उसने **उसका ownership खो दिया हो**। बस उसे register करें (अगर कीमत कम हो) और company को बताएँ।

अगर आपको **ऐसा कोई domain मिले जिसका IP** asset discovery में पहले मिले IPs से अलग हो, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **nmap/masscan/shodan** से कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करना चाहिए। चल रही services के आधार पर, **इस किताब में उन्हें "attack" करने के कुछ तरीके** मिल सकते हैं।\
_ध्यान दें कि कभी-कभी domain ऐसे IP पर hosted होता है जो client के नियंत्रण में नहीं होता, इसलिए वह scope में नहीं आता; सावधान रहें।_

## Subdomains

> हमें scope में आने वाली सभी companies, हर company के सभी assets और उनसे संबंधित सभी domains पता हैं।

अब हर मिले हुए domain के सभी संभावित subdomains खोजने का समय है।

> [!TIP]
> ध्यान दें कि domains खोजने के लिए इस्तेमाल किए गए कुछ tools और techniques, subdomains खोजने में भी मदद कर सकते हैं

### **DNS**

आइए **DNS** records से **subdomains** खोजने की कोशिश करें। हमें **Zone Transfer** की भी कोशिश करनी चाहिए (अगर यह vulnerable हो, तो इसकी report करें)।

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Infrastructure, reputation, breach records और subdomain discovery से आगे enrichment को कवर करने वाले APIs और platforms के लिए, [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md) देखें।

बहुत सारे subdomains पाने का सबसे तेज़ तरीका external sources में खोज करना है। सबसे अधिक इस्तेमाल किए जाने वाले **tools** ये हैं (बेहतर नतीजों के लिए API keys configure करें):


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

कुछ **अन्य दिलचस्प tools/APIs** हैं, जो भले ही subdomains खोजने के लिए सीधे तौर पर विशेषीकृत न हों, लेकिन subdomains खोजने में उपयोगी हो सकते हैं, जैसे:

- [**IP.THC.ORG**](https://ip.thc.org) free API

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

- [**gau**](https://github.com/lc/gau)**:** दिए गए किसी भी domain के लिए AlienVault's Open Threat Exchange, the Wayback Machine और Common Crawl से ज्ञात URLs प्राप्त करता है।

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ये वेब को scrape करके JS files खोजते हैं और उनसे subdomains निकालते हैं।

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

- [**Censys सबडोमेन खोजक**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) वर्तमान DNS और subdomain डेटा के लिए सीमित free API access देता है; ऐतिहासिक DNS/IP डेटा के लिए paid plan आवश्यक है।
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

यह project **bug-bounty programs से संबंधित सभी subdomains मुफ्त में** उपलब्ध कराता है। आप इस डेटा को [chaospy](https://github.com/Moaaz-0x/chaospy) का उपयोग करके भी access कर सकते हैं, या इस project द्वारा उपयोग किए गए scope को यहाँ से access कर सकते हैं: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

इनमें से कई tools की **तुलना** यहाँ देख सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

आइए, संभावित subdomain नामों का उपयोग करके DNS servers पर brute-forcing करके नए **subdomains** खोजने की कोशिश करें।

इसके लिए आपको कुछ **आम subdomains wordlists की आवश्यकता होगी**, जैसे:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

आपको अच्छे DNS resolvers के IPs भी चाहिए होंगे। भरोसेमंद DNS resolvers की सूची बनाने के लिए, [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) से resolvers डाउनलोड करें और उन्हें filter करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग करें। या आप यह सूची इस्तेमाल कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे ज़्यादा सुझाए जाने वाले tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह प्रभावी DNS brute-force करने वाला पहला tool था। यह बहुत तेज़ है, लेकिन इसमें false positives की संभावना रहती है।

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): मुझे लगता है कि यह सिर्फ़ 1 resolver का इस्तेमाल करता है.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के चारों ओर बना Go में लिखा एक wrapper है, जो active bruteforce के ज़रिए मान्य subdomains enumerate करने के साथ-साथ wildcard handling और आसान input-output support के साथ subdomains resolve करने की सुविधा देता है।

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): यह `massdns` का भी उपयोग करता है।

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) डोमेन नामों को asynchronously brute force करने के लिए asyncio का उपयोग करता है।

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### दूसरा DNS Brute-Force Round

Open sources और brute-forcing का उपयोग करके subdomains खोजने के बाद, और भी subdomains खोजने के लिए आप मिले हुए subdomains में बदलाव करके नए रूप बना सकते हैं। इस काम के लिए कई tools उपयोगी हैं:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** दिए गए domains और subdomains से permutations बनाता है।

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains से permutations बनाता है।
  - goaltdns की permutations **wordlist** [**यहाँ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) से प्राप्त कर सकते हैं।

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains से permutations generate करता है। यदि permutations file निर्दिष्ट नहीं है, तो gotator अपनी फ़ाइल का उपयोग करेगा।

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): subdomains के permutations generate करने के अलावा, यह उन्हें resolve करने की कोशिश भी कर सकता है (लेकिन पहले बताए गए tools का उपयोग करना बेहतर है)।
  - altdns के permutations की **wordlist** [**यहाँ**](https://github.com/infosec-au/altdns/blob/master/words.txt) मिल सकती है।

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Subdomains के permutations, mutations और alterations करने के लिए एक अन्य tool। यह परिणाम को brute force करेगा (यह dns wild card को support नहीं करता)।
  - dmut की permutations wordlist [**यहाँ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) मिल सकती है।

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** किसी domain के आधार पर, यह अधिक subdomains खोजने के लिए दिए गए patterns के अनुसार **नए संभावित subdomain नाम बनाता है**।

#### स्मार्ट permutations का निर्माण

- [**regulator**](https://github.com/cramppet/regulator): खोजे गए subdomains से regex-जैसे patterns सीखता है और resolve करने के लिए candidate नाम बनाता है।<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है, जिसमें बेहद सरल लेकिन प्रभावी DNS response-guided algorithm शामिल है। यह दिए गए input data, जैसे कि किसी विशेष उद्देश्य के लिए तैयार की गई wordlist या ऐतिहासिक DNS/TLS records, का उपयोग करके उनसे मेल खाने वाले अधिक domain names को सटीक रूप से तैयार करता है और DNS scan के दौरान एकत्र की गई जानकारी के आधार पर उन्हें बार-बार और भी विस्तृत करता है।

```
echo www | subzuf facebook.com
```

### **Subdomain खोजने का वर्कफ़्लो**

Trickest वर्कफ़्लो के उदाहरण दोहराए जा सकने वाले subdomain enumeration के लिए OSINT, DNS brute force और permutation चरणों को मिलाते हैं।<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

अगर आपको कोई ऐसा IP address मिला है जिसमें subdomains के **एक या कई वेब पेज** हैं, तो आप उस IP पर मौजूद **दूसरे subdomains खोजने** की कोशिश कर सकते हैं। इसके लिए **OSINT sources** में किसी IP से जुड़े domains खोजें या उस IP पर **VHost domain names को brute-force करें**।

#### OSINT

आप [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs का इस्तेमाल करके IPs में कुछ VHosts खोज सकते हैं**।

**Brute Force**

अगर आपको लगता है कि किसी web server में कोई subdomain छिपा हो सकता है, तो आप उसे brute-force करने की कोशिश कर सकते हैं:

Name-based vhosts के लिए, `Host` header को fuzz करें और default response को filter करने के लिए ffuf के auto-calibration का इस्तेमाल करें।<sup>[[2]](#references)</sup>

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
> इस तकनीक से आप internal/hidden endpoints तक भी पहुंच सकते हैं।

### **CORS Brute Force**

कभी-कभी आपको ऐसे pages मिलेंगे जो _**Origin**_ header में valid domain/subdomain सेट होने पर ही _**Access-Control-Allow-Origin**_ header लौटाते हैं। ऐसे मामलों में, आप इस व्यवहार का दुरुपयोग करके नए **subdomains** **discover** कर सकते हैं।

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains** खोजते समय ध्यान दें कि क्या वे किसी प्रकार के **bucket** की ओर **pointing** कर रहे हैं। ऐसा होने पर [**permissions की जाँच करें**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**।**\
साथ ही, चूँकि इस समय तक आपको scope के सभी domains पता होंगे, इसलिए [**संभावित bucket names को brute force करके permissions की जाँच करें**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)।

### **निगरानी**

आप **Certificate Transparency** Logs की निगरानी करके पता लगा सकते हैं कि किसी domain के **नए subdomains** बनाए गए हैं या नहीं। [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) यही करता है।

### **vulnerabilities की खोज**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
अगर **subdomain** किसी **S3 bucket** की ओर point कर रहा है, तो [**permissions की जाँच करें**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)।

अगर आपको कोई ऐसा **subdomain मिले जिसका IP, asset discovery में पहले मिले IPs से अलग हो**, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **nmap/masscan/shodan** से कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करना चाहिए। चल रही services के आधार पर, आपको **इस book में उन्हें "attack" करने की कुछ तरकीबें मिल सकती हैं**।\
_ध्यान दें कि कभी-कभी subdomain ऐसे IP पर host किया जाता है जो client के नियंत्रण में नहीं होता, इसलिए वह scope में नहीं होता। सावधान रहें।_

## IPs

शुरुआती चरणों में आपको **कुछ IP ranges, domains और subdomains मिले होंगे**।\
अब उन ranges से जुड़े सभी IPs और **domains/subdomains (DNS queries)** के IPs इकट्ठा करने का समय है।

नीचे दी गई जैसी services का उपयोग करके, आप **domains और subdomains द्वारा पहले इस्तेमाल किए गए IPs** भी खोज सकते हैं। ये IPs अब भी client के स्वामित्व में हो सकते हैं (और इनसे आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) खोजने में मदद मिल सकती है)।

- [**SecurityTrails**](https://securitytrails.com/) (ऐतिहासिक DNS/IP data के लिए paid plan आवश्यक है)

आप [**hakip2host**](https://github.com/hakluke/hakip2host) tool का उपयोग करके यह भी जाँच सकते हैं कि कौन से domains किसी विशिष्ट IP address की ओर point कर रहे हैं।

### **vulnerabilities की खोज**

**CDNs से संबंधित न होने वाले सभी IPs का port scan करें** (क्योंकि वहाँ आपको कुछ दिलचस्प मिलने की संभावना बहुत कम है)। खोजी गई चल रही services में आपको **vulnerabilities मिल सकती हैं**।

**Hosts को scan करने का तरीका बताने वाली एक** [**guide**](../pentesting-network/index.html) **खोजें।**

## Web servers की खोज

> हमने सभी कंपनियों और उनकी assets का पता लगा लिया है और हमें scope में आने वाली IP ranges, domains और subdomains पता हैं। अब web servers खोजने का समय है।

पिछले चरणों में आपने शायद खोजे गए IPs और domains की **कुछ recon** पहले ही की होगी, इसलिए संभव है कि आपको **सभी संभावित web servers** मिल गए हों। लेकिन अगर ऐसा नहीं हुआ है, तो अब हम scope के भीतर web servers खोजने की कुछ **तेज़ तरकीबें** देखेंगे।

ध्यान दें कि यह **web apps की खोज पर केंद्रित** होगा, इसलिए आपको **vulnerability** और **port scanning** भी करनी चाहिए (**अगर scope इसकी अनुमति देता है**)।

[**masscan** का उपयोग करके web servers से संबंधित खुले **ports** खोजने का एक **तेज़ तरीका यहाँ दिया गया है**](../pentesting-network/index.html#http-port-discovery)।\
Web servers खोजने के लिए एक और आसान tool है [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx)। आपको बस domains की एक list देनी होती है और यह port 80 (http) और 443 (https) से connect करने की कोशिश करेगा। इसके अलावा, आप इसे अन्य ports पर भी कोशिश करने के लिए कह सकते हैं:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

अब जब आपने scope में मौजूद **सभी web servers** खोज लिए हैं (कंपनी के **IPs**, सभी **domains** और **subdomains** में), तो शायद आपको **पता न हो कि शुरुआत कहाँ से करें**। तो इसे आसान बनाते हैं और बस उन सभी के screenshots लेना शुरू करते हैं। सिर्फ़ **मुख्य पेज पर नज़र डालकर** आप ऐसे **अजीब** endpoints ढूँढ़ सकते हैं जिनके **vulnerable** होने की संभावना अधिक है।

इस काम के लिए आप [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** का उपयोग कर सकते हैं।

इसके अलावा, आप [**eyeballer**](https://github.com/BishopFox/eyeballer) का उपयोग करके सभी **screenshots** को जाँच सकते हैं, ताकि यह पता चले कि **किनमें vulnerabilities होने की संभावना है** और किनमें नहीं।

## Public Cloud Assets

किसी कंपनी से संबंधित संभावित cloud assets ढूँढ़ने के लिए, आपको **उस कंपनी की पहचान करने वाले keywords की सूची से शुरुआत करनी चाहिए**। उदाहरण के लिए, crypto कंपनी के लिए आप `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` जैसे शब्द इस्तेमाल कर सकते हैं।

आपको **buckets में इस्तेमाल होने वाले आम शब्दों** की wordlists भी चाहिए होंगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, इन शब्दों से आपको **permutations** बनाने चाहिए (अधिक जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

बनी हुई wordlists के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** जैसे tools का उपयोग कर सकते हैं।

याद रखें कि Cloud Assets खोजते समय आपको AWS में सिर्फ़ **buckets** से अधिक चीज़ें ढूँढ़नी चाहिए।

### **Looking for vulnerabilities**

अगर आपको **खुले buckets या exposed cloud functions** जैसी चीज़ें मिलें, तो आपको **उन तक पहुँचकर** देखना चाहिए कि वे क्या उपलब्ध कराते हैं और क्या उनका दुरुपयोग किया जा सकता है।

## Emails

Scope में मौजूद **domains** और **subdomains** के साथ, आपके पास **emails खोजना शुरू करने के लिए** ज़रूरी लगभग सब कुछ है। किसी कंपनी के emails खोजने के लिए ये **APIs** और **tools** मेरे लिए सबसे कारगर रहे हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs के साथ
- [**https://hunter.io/**](https://hunter.io/) का API (free version)
- [**https://app.snov.io/**](https://app.snov.io/) का API (free version)
- [**https://minelead.io/**](https://minelead.io/) का API (free version)

### **Looking for vulnerabilities**

बाद में **web logins और auth services** (जैसे SSH) पर **brute-force** करने में emails काम आएँगे। **Phishings** के लिए भी इनकी ज़रूरत होती है। इसके अलावा, ये APIs आपको email के पीछे मौजूद **व्यक्ति के बारे में और जानकारी** भी देंगी, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**Domains,** **subdomains** और **emails** के साथ, आप उन emails से जुड़े अतीत में leaked credentials खोजना शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

अगर आपको **valid leaked** credentials मिलते हैं, तो यह बहुत आसान जीत है।

## Secrets Leaks

Credential leaks उन कंपनियों के hacks से जुड़े होते हैं जिनमें **sensitive information leak करके बेची गई थी**। हालाँकि, कंपनियाँ **अन्य leaks** से भी प्रभावित हो सकती हैं, जिनकी जानकारी उन databases में नहीं होती:

### Github Leaks

कंपनी के **public repositories** या उस github कंपनी में काम करने वाले **users** के repositories में credentials और APIs leak हो सकते हैं।\
आप [**Leakos**](https://github.com/carlospolop/Leakos) **tool** का इस्तेमाल करके किसी **organization** और उसके **developers** के सभी **public repos** **download** कर सकते हैं और उन पर [**gitleaks**](https://github.com/gitleaks/gitleaks) अपने-आप चला सकते हैं।

**Leakos** का इस्तेमाल उसे दिए गए सभी **text** और **URLs** पर **gitleaks** चलाने के लिए भी किया जा सकता है, क्योंकि कभी-कभी **web pages में भी secrets होते हैं**।

#### Github Dorks

संस्था में खोजने के लिए संभावित **GitHub dorks** देखने हेतु [GitHub dorks and leaks page](github-leaked-secrets.md) देखें।

### Pastes Leaks

कभी-कभी attackers या कर्मचारी बस कंपनी की सामग्री को **paste site पर प्रकाशित** कर देते हैं। इसमें **sensitive information** हो भी सकती है और नहीं भी, लेकिन इसे खोजना काफ़ी उपयोगी है।\
एक ही समय में 80 से अधिक paste sites पर खोजने के लिए आप [**Pastos**](https://github.com/carlospolop/Pastos) tool का उपयोग कर सकते हैं।

### Google Dorks

पुराने लेकिन कारगर google dorks हमेशा ऐसी **exposed information ढूँढ़ने में उपयोगी होते हैं जो वहाँ नहीं होनी चाहिए**। समस्या बस यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **हज़ार** संभावित queries हैं, जिन्हें आप manually नहीं चला सकते। इसलिए, आप अपने पसंदीदा 10 queries चुन सकते हैं या उन सभी को चलाने के लिए [**Gorks**](https://github.com/carlospolop/Gorks) **जैसे tool** का उपयोग कर सकते हैं।

_ध्यान दें कि जो tools नियमित Google browser का उपयोग करके पूरा database चलाने की कोशिश करते हैं, वे कभी खत्म नहीं होंगे, क्योंकि Google आपको बहुत जल्द block कर देगा।_

### **Looking for vulnerabilities**

अगर आपको **valid leaked** credentials या API tokens मिलते हैं, तो यह बहुत आसान जीत है।

## Public Code Vulnerabilities

अगर आपको पता चलता है कि कंपनी का **open-source code** है, तो आप उसका **विश्लेषण** करके उसमें **vulnerabilities** खोज सकते हैं।

**Language के आधार पर**, आप अलग-अलग **tools** इस्तेमाल कर सकते हैं; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) की सूची देखें।

कुछ free services भी हैं जो आपको **public repositories scan** करने देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunters को मिलने वाली **ज़्यादातर vulnerabilities** **web applications** में होती हैं, इसलिए इस बिंदु पर मैं **web application testing methodology** के बारे में बात करना चाहता हूँ। आप [**यह जानकारी यहाँ पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) वाले section का विशेष उल्लेख भी करना चाहता हूँ। इनसे बहुत संवेदनशील vulnerabilities मिलने की उम्मीद नहीं करनी चाहिए, लेकिन **शुरुआती web जानकारी पाने के लिए इन्हें workflows में शामिल करना** उपयोगी है।

## Recapitulation

> बधाई हो! इस बिंदु पर आपने **सारी बुनियादी enumeration** पूरी कर ली है। हाँ, यह बुनियादी है, क्योंकि इससे कहीं अधिक enumeration की जा सकती है (आगे और tricks देखेंगे)।

तो अब तक आपने:

1. Scope में मौजूद सभी **कंपनियाँ** ढूँढ़ ली हैं
2. कंपनियों से संबंधित सभी **assets** ढूँढ़ लिए हैं (और अगर scope में हो, तो vuln scan भी किया है)
3. कंपनियों से संबंधित सभी **domains** ढूँढ़ लिए हैं
4. Domains के सभी **subdomains** ढूँढ़ लिए हैं (क्या कोई subdomain takeover है?)
5. Scope में मौजूद सभी **IPs** (CDNs से आने वाले और **न आने वाले**) ढूँढ़ लिए हैं।
6. सभी **web servers** ढूँढ़कर उनके **screenshots** ले लिए हैं (क्या कुछ अजीब है जिस पर और गहराई से नज़र डालनी चाहिए?)
7. कंपनी से संबंधित सभी **संभावित public cloud assets** ढूँढ़ लिए हैं।
8. **Emails**, **credential leaks** और **secret leaks** ढूँढ़ लिए हैं, जिनसे **बहुत आसानी से बड़ी जीत** मिल सकती है।
9. आपके मिले सभी **webs की pentesting** कर ली है

## **Full Recon Automatic Tools**

ऐसे कई tools उपलब्ध हैं जो किसी दिए गए scope पर प्रस्तावित कार्रवाइयों में से कुछ को पूरा कर सकते हैं।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - थोड़ा पुराना है और अपडेट नहीं किया गया है



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
