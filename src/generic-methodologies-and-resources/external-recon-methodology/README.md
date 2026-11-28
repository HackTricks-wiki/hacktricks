# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets की खोज

अतिरिक्त OSINT और web-discovery projects की वर्गीकृत सूची के लिए, [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint) देखें।

> आपको बताया गया कि किसी कंपनी से जुड़ी हर चीज़ scope में है, और आप पता लगाना चाहते हैं कि इस कंपनी के वास्तव में कौन-कौन से assets हैं।

इस चरण का लक्ष्य **मुख्य कंपनी के स्वामित्व वाली सभी कंपनियों** और फिर इन कंपनियों के सभी **assets** का पता लगाना है। ऐसा करने के लिए, हम:<sup>[[1]](#references)</sup>

1. मुख्य कंपनी के अधिग्रहणों का पता लगाएंगे; इससे हमें scope में शामिल कंपनियां मिलेंगी।
2. प्रत्येक कंपनी का ASN (यदि कोई हो) पता लगाएंगे; इससे हमें हर कंपनी के स्वामित्व वाली IP ranges मिलेंगी।
3. पहली कंपनी से संबंधित अन्य entries (organisation names, domains...) खोजने के लिए reverse whois lookups का उपयोग करेंगे (यह काम recursively किया जा सकता है)।
4. अन्य assets खोजने के लिए shodan के `org`और `ssl`filters जैसे अन्य तरीकों का उपयोग करेंगे (`ssl` trick को recursively इस्तेमाल किया जा सकता है)।

सुलझाए गए subdomains से HTTP crawling और port discovery तक के staged handoff के लिए, [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline) देखें।

### **अधिग्रहण**

सबसे पहले, हमें यह पता लगाना होगा कि **मुख्य कंपनी के स्वामित्व वाली अन्य कंपनियां कौन-सी हैं**।\
एक तरीका है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाकर **मुख्य कंपनी को खोजें** और "**acquisitions**" पर **क्लिक करें**। वहां आपको मुख्य कंपनी द्वारा अधिग्रहित अन्य कंपनियां दिखेंगी।\
दूसरा तरीका है मुख्य कंपनी के **Wikipedia** पेज पर जाकर **acquisitions** खोजें।\
सार्वजनिक कंपनियों के लिए, **SEC/EDGAR filings**, **investor relations** पेज या स्थानीय corporate registries (जैसे UK में **Companies House**) देखें।\
वैश्विक corporate trees और subsidiaries के लिए, **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएं।

> ठीक है, अब तक आपको scope में आने वाली सभी कंपनियों का पता चल जाना चाहिए। आइए, पता लगाएं कि उनके assets कैसे खोजे जा सकते हैं।

### **ASNs**

एक autonomous system number (**ASN**) **Internet Assigned Numbers Authority (IANA)** द्वारा किसी **autonomous system** (AS) को दिया गया एक **अद्वितीय नंबर** होता है।\
एक **AS** में **IP addresses** के **blocks** होते हैं, जिनमें external networks तक पहुंचने के लिए स्पष्ट रूप से तय की गई policy होती है। इन्हें एक ही organisation द्वारा प्रशासित किया जाता है, हालांकि इनमें कई operators शामिल हो सकते हैं।

यह पता लगाना उपयोगी है कि **कंपनी को कोई ASN सौंपा गया है या नहीं**, ताकि उसकी **IP ranges** मिल सकें। **Scope** में मौजूद सभी **hosts** पर **vulnerability test** करना और इन IPs के भीतर **domains खोजना** उपयोगी होगा।\
आप [**https://bgp.he.net/**](https://bgp.he.net) **या** [**https://ipinfo.io/**](https://ipinfo.io/) पर कंपनी के **नाम**, **IP** या **domain** से **खोज** सकते हैं।\
**कंपनी के क्षेत्र के अनुसार, अधिक data जुटाने के लिए ये links उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe)। वैसे, संभवतः सभी** उपयोगी जानकारी **(IP ranges और Whois)** पहले link में ही उपलब्ध है।

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

इसके अलावा, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** का** enumeration स्कैन के अंत में ASNs को स्वचालित रूप से एकत्रित और सारांशित करता है।

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

आप [ASNLookup](https://asnlookup.com/) का उपयोग करके किसी संगठन की IP ranges भी ढूँढ़ सकते हैं, जिसमें सीमित free API tier उपलब्ध है।

### **कमजोरियों की तलाश**

इस समय हमें **scope के अंदर मौजूद सभी assets** पता हैं, इसलिए अगर आपको अनुमति है, तो आप सभी hosts पर कोई **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या Shodan, Censys, या ZoomEye जैसी services का उपयोग करके** open ports **ढूँढ़ सकते हैं। आपको जो मिले, उसके आधार पर इस किताब में देखें कि चल रही अलग-अलग संभावित services का pentest कैसे करें।**\
**यह भी बताना उपयोगी होगा कि आप** default username **और** passwords **की कुछ lists तैयार करके [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) से services पर** bruteforce **की कोशिश कर सकते हैं।**

## Domains

> हमें scope के अंदर की सभी कंपनियों और उनके assets का पता है। अब scope के अंदर आने वाले domains ढूँढ़ने का समय है।

_ध्यान दें कि नीचे दी गई तकनीकों से subdomains भी मिल सकते हैं, और इस जानकारी को कम करके नहीं आँकना चाहिए।_

सबसे पहले, आपको हर कंपनी का **main domain** ढूँढ़ना चाहिए। उदाहरण के लिए, _Tesla Inc._ का _tesla.com_ होगा।

### **Reverse DNS**

चूँकि आपको domains की सभी IP ranges मिल गई हैं, इसलिए आप उन **IPs पर reverse DNS lookups** करके **scope के अंदर और domains ढूँढ़ने** की कोशिश कर सकते हैं। पीड़ित का कोई DNS server या कोई प्रसिद्ध DNS server (1.1.1.1, 8.8.8.8) इस्तेमाल करें।

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

इसे काम करने के लिए, एडमिनिस्ट्रेटर को PTR को मैन्युअल रूप से enable करना होगा।\
इस जानकारी के लिए आप [SecurityTrails](https://securitytrails.com/) का भी उपयोग कर सकते हैं, हालांकि ऐतिहासिक DNS डेटा के लिए paid plan की आवश्यकता होती है।\
बड़ी ranges के लिए, reverse lookups और enrichment को automate करने के लिए [**massdns**](https://github.com/blechschmidt/massdns) और [**dnsx**](https://github.com/projectdiscovery/dnsx) जैसे tools उपयोगी हैं।

### **Reverse Whois (loop)**

एक **whois** में आपको बहुत-सी दिलचस्प **जानकारी** मिल सकती है, जैसे **संगठन का नाम**, **पता**, **ईमेल**, फ़ोन नंबर... लेकिन इससे भी अधिक दिलचस्प बात यह है कि इन fields में से किसी का उपयोग करके **reverse whois lookups** करने पर आप **कंपनी से जुड़ी और संपत्तियाँ** खोज सकते हैं (उदाहरण के लिए, अन्य whois registries जहाँ वही ईमेल दिखाई देता है)।\
आप इन जैसे online tools का उपयोग कर सकते हैं:

- [https://ip.thc.org/](https://ip.thc.org/) - **मुफ़्त** (Web और API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **मुफ़्त**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **मुफ़्त**
- [https://www.whoxy.com/](https://www.whoxy.com) - **मुफ़्त** web interface; paid API।
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Paid
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - मुफ़्त नहीं (सिर्फ़ **100 मुफ़्त** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - मुफ़्त नहीं
- [https://securitytrails.com/](https://securitytrails.com/) - मौजूदा DNS/subdomains के लिए सीमित मुफ़्त API access; ऐतिहासिक और reverse lookups के लिए paid plan की आवश्यकता होती है।
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - signup पर 500 मुफ़्त API credits; उसके बाद paid।

आप [**DomLink** ](https://github.com/vysecurity/DomLink) का उपयोग करके इस काम को automate कर सकते हैं (इसके लिए whoxy API key चाहिए)।\
आप [amass](https://github.com/owasp-amass/amass) से कुछ automatic reverse whois discovery भी कर सकते हैं: `amass intel -d tesla.com -whois`

**ध्यान दें कि हर बार कोई नया domain मिलने पर, इस technique से आप और domain names खोज सकते हैं।**

### **Trackers**

अगर आपको 2 अलग-अलग pages पर **एक ही tracker की समान ID** मिलती है, तो आप मान सकते हैं कि **दोनों pages** को **एक ही team manage करती है**।\
उदाहरण के लिए, अगर आपको कई pages पर समान **Google Analytics ID** या समान **Adsense ID** दिखाई देती है।

कुछ pages और tools हैं जिनसे आप इन trackers और अन्य चीज़ों के आधार पर खोज कर सकते हैं:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Paid** web और API service ([pricing](https://www.stackscan.com/pricing)); फ़िलहाल किसी मुफ़्त plan का विज्ञापन नहीं किया गया है। किसी भी served asset पर pivot करें, सिर्फ़ tracker IDs पर नहीं: जैसे script path, self-hosted bundle name या वह host जहाँ से कोई asset load होता है। इससे उन सभी sites की जानकारी मिलती है जिन पर वह asset मौजूद है।

API एक domain के लिए stack लौटाती है, जो यह पुष्टि करने में उपयोगी है कि कोई candidate asset उसी estate से संबंधित है:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

हर detected technology को उसकी category के साथ दिखाता है। Asset pivoting अभी केवल web तक सीमित है; API में per-domain lookup उपलब्ध है।

### **Favicon**

क्या आपको पता है कि एक ही favicon icon hash खोजकर हम अपने target से जुड़े domains और subdomains ढूँढ़ सकते हैं? [@m4ll0k2](https://twitter.com/m4ll0k2) द्वारा बनाया गया [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) tool ठीक यही करता है। इसे इस्तेमाल करने का तरीका यहाँ है:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash के परिणाम, जिनका उपयोग समान favicon hash वाले domains खोजने के लिए किया गया](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सीधे शब्दों में कहें, तो favihash हमें ऐसे domains खोजने देता है जिनका favicon icon hash हमारे target के समान हो।

![favihash का output, जिसका उपयोग समान favicon hash वाले domains खोजने के लिए किया गया](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

समान technology के अन्य exposed instances खोजने के लिए किसी ज्ञात favicon hash को Shodan या FOFA में pivot के रूप में इस्तेमाल करें।<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

इस तरह आप किसी वेबसाइट का **favicon hash** (favicon bytes के **base64-encoded** रूप पर MMH3 लागू करके) निकाल सकते हैं:

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

- **Hash को संकेत मानें, प्रमाण नहीं**: MMH3 compact है; collisions, दोबारा इस्तेमाल किए गए icons और जानबूझकर की गई spoofing संभव हैं।
- **सिर्फ** `/favicon.ico` **से अधिक जाँचें**: framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs और HTML `<link rel="icon">` tags देखें।
- **WAF/SSO/IdP controls के पीछे भी static assets तक पहुँच संभव हो सकती है**: icon को सीधे request करें और `ETag`, `Last-Modified`, redirects तथा cache headers की समीक्षा करें।
- **आसपास के संकेतों से matches की पुष्टि करें**: title, HTML/body hash, headers, TLS certificate subjects/SANs, product components और खुले ports की तुलना करें।
- **HTML/body hash के आधार पर cluster करें**: एक समान template fingerprint को मजबूत बनाता है; मिले-जुले templates किसी सामान्य या साझा icon का संकेत देते हैं।
- **अलग-अलग signatures, ports और products में दिखने वाले hash को संभावित honeypot या placeholder मानें।**
- **अस्पष्ट targets पर, किसी वास्तविक page की तुलना किसी गैर-मौजूद path से करें**, जैसे `/_favicon_probe_<8-hex>`; hosting या parking responses का मेल साझा icon की वजह समझा सकता है।
- **Favicon hashes को products और CPEs से जोड़ने वाले Nuclei detection rules या public datasets से शुरुआती triage करें।**
- **IP-केंद्रित coverage gap याद रखें**: CDN-fronted, SNI-routed, anycast और केवल domain पर उपलब्ध surfaces, Shodan-जैसे datasets में छूट सकते हैं।

### **कॉपीराइट / विशिष्ट स्ट्रिंग**

वेब पेजों में ऐसे **strings खोजें जो एक ही संगठन की अलग-अलग websites पर साझा हो सकते हैं**। **Copyright string** इसका एक अच्छा उदाहरण हो सकता है। फिर उस string को **Google**, अन्य **ब्राउज़रों** या यहाँ तक कि **Shodan** में खोजें: `shodan search http.html:"Copyright string"`

### **CRT समय**

आमतौर पर ऐसा cron job होता है जिसमें

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

सर्वर पर सभी certificates एक ही समय में renew करने के लिए। Certificate timestamps या certificate-transparency log positions का मिलान करने से संबंधित domains का पता चल सकता है।<sup>[[6]](#references)</sup>

**certificate transparency** logs का सीधे उपयोग भी करें:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC जानकारी

**एक जैसी DMARC जानकारी साझा करने वाले domains और subdomains** खोजने के लिए [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी वेबसाइट या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे tool का उपयोग कर सकते हैं।\
एक अन्य उपयोगी सेवा [**dmarcian**](https://dmarcian.com/) है।

### **Passive Takeover**

जब cloud provider किसी IP को फिर से आवंटित करता है, तो एक छोड़ा हुआ A record फिर से पहुंच योग्य हो सकता है। संदर्भित शोध में एक opportunistic workflow दिखाया गया है, जो एक instance provision करके उसके address का passive DNS data से मिलान करता है; takeover scenarios की जांच केवल अधिकृत scope के भीतर करें।<sup>[[7]](#references)</sup>

### **अन्य तरीके**

जब भी कोई नया domain मिले, लागू discovery pivots दोहराएं: हर नतीजे से अतिरिक्त certificate names, passive-DNS relationships, favicon matches और organization identifiers मिल सकते हैं, जो मूल seed से दिखाई नहीं दे रहे थे।<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

जैसा कि आप पहले से जानते हैं, IP space का मालिकाना हक किस organization के पास है। Shodan में उस data से खोज करने के लिए यह इस्तेमाल करें: `org:"Tesla, Inc."` नए और अप्रत्याशित domains के लिए मिले हुए hosts के TLS certificate की जांच करें।

आप मुख्य web page का **TLS certificate** खोलकर **Organisation name** प्राप्त कर सकते हैं। फिर उस नाम को **shodan** को ज्ञात सभी web pages के **TLS certificates** में इस filter से खोजें: `ssl:"Tesla Motors"` या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे tool का उपयोग करें।

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)एक ऐसा tool है जो किसी मुख्य domain से **संबंधित domains** और उनके **subdomains** खोजता है। यह काफी शानदार है।

**Passive DNS / Historical DNS**

Passive DNS data ऐसे **पुराने और भुला दिए गए records** खोजने के लिए बहुत उपयोगी है, जो अब भी resolve होते हैं या जिनका takeover किया जा सकता है। यहां देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Vulnerabilities खोजना**

कुछ [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) की जांच करें। हो सकता है कि कोई कंपनी **किसी domain का उपयोग कर रही हो**, लेकिन **उसका ownership खो चुकी हो**। बस उसे register करें (अगर वह पर्याप्त सस्ता हो) और कंपनी को बताएं।

अगर आपको कोई ऐसा **domain मिले जिसका IP, assets discovery में पहले से मिले IPs से अलग हो**, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **nmap/masscan/shodan** से [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करना चाहिए। चल रही services के आधार पर, **इस किताब में उन्हें "attack" करने की कुछ तरकीबें** मिल सकती हैं।\
_ध्यान दें कि कभी-कभी domain ऐसे IP पर host होता है, जिसे client नियंत्रित नहीं करता, इसलिए वह scope में नहीं होता। सावधान रहें।_

## Subdomains

> हमें scope में शामिल सभी कंपनियों, हर कंपनी के सभी assets और कंपनियों से संबंधित सभी domains का पता है।

अब मिले हुए हर domain के सभी संभावित subdomains खोजने का समय है।

> [!TIP]
> ध्यान दें कि domains खोजने वाले कुछ tools और techniques, subdomains खोजने में भी मदद कर सकते हैं।

### **DNS**

आइए **DNS** records से **subdomains** निकालने की कोशिश करें। हमें **Zone Transfer** के लिए भी कोशिश करनी चाहिए (अगर यह vulnerable हो, तो इसकी report करें)।

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Infrastructure, reputation, breach records और subdomain discovery से आगे enrichment को कवर करने वाले APIs और platforms के लिए, [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md) देखें।

कई subdomains पाने का सबसे तेज़ तरीका external sources में खोज करना है। सबसे अधिक उपयोग किए जाने वाले **tools** ये हैं (बेहतर नतीजों के लिए API keys कॉन्फ़िगर करें):


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

ऐसे **अन्य दिलचस्प टूल/API** भी हैं, जो सीधे तौर पर subdomains खोजने के लिए विशेष रूप से बनाए नहीं गए हैं, फिर भी subdomains खोजने में उपयोगी हो सकते हैं, जैसे:

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

- [**gau**](https://github.com/lc/gau)**:** दिए गए किसी भी domain के लिए AlienVault's Open Threat Exchange, the Wayback Machine और Common Crawl से ज्ञात URLs प्राप्त करता है।

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ये वेब पर JS फ़ाइलें खोजते हैं और उनमें से subdomains निकालते हैं।

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

- [**Censys subdomain खोजक**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) वर्तमान DNS और subdomain डेटा के लिए सीमित मुफ़्त API access देता है; ऐतिहासिक DNS/IP डेटा के लिए paid plan चाहिए।
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

यह project **bug-bounty programs से जुड़े सभी subdomains मुफ़्त में** उपलब्ध कराता है। आप [chaospy](https://github.com/Moaaz-0x/chaospy) का इस्तेमाल करके भी इस डेटा को access कर सकते हैं या इस project द्वारा इस्तेमाल किए गए scope को सीधे यहाँ से access कर सकते हैं: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

इनमें से कई tools की **तुलना** यहाँ मिल सकती है: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

आइए संभावित subdomain नामों से DNS servers पर brute-force करके नए **subdomains** खोजने की कोशिश करें।

इसके लिए आपको कुछ **आम subdomains की wordlists चाहिए होंगी, जैसे**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

साथ ही, अच्छे DNS resolvers के IPs भी चाहिए होंगे। भरोसेमंद DNS resolvers की सूची बनाने के लिए, [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) से resolvers डाउनलोड करें और उन्हें फ़िल्टर करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का इस्तेमाल करें। या आप यह सूची इस्तेमाल कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे ज़्यादा सुझाए जाने वाले tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह प्रभावी DNS brute-force करने वाला पहला tool था। यह बहुत तेज़ है, लेकिन इसमें false positives आने की संभावना रहती है।

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): मुझे लगता है कि यह सिर्फ़ 1 resolver इस्तेमाल करता है.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के आसपास बनाया गया Go wrapper है, जो active bruteforce से valid subdomains enumerate करने के साथ-साथ wildcard handling और आसान input-output support के साथ subdomains resolve करने की सुविधा देता है।

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): यह भी `massdns` का उपयोग करता है।

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) डोमेन नामों को एसिंक्रोनस तरीके से brute force करने के लिए asyncio का उपयोग करता है।

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### दूसरा DNS Brute-Force दौर

Open sources और brute-forcing से subdomains खोजने के बाद, आप मिले हुए subdomains में बदलाव करके और भी subdomains खोजने की कोशिश कर सकते हैं। इस काम के लिए कई tools उपयोगी हैं:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** दिए गए domains और subdomains से permutations जनरेट करता है।

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains से permutations जनरेट करता है।
  - आप [**यहाँ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) goaltdns की permutations **wordlist** पा सकते हैं।

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains से permutations बनाता है। अगर permutations फ़ाइल निर्दिष्ट नहीं की गई है, तो gotator अपनी फ़ाइल का उपयोग करेगा।

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): subdomains के permutations जनरेट करने के अलावा, यह उन्हें resolve करने की कोशिश भी कर सकता है (लेकिन पहले बताए गए tools का उपयोग करना बेहतर है)।
  - आप altdns के permutations की **wordlist** [**यहाँ**](https://github.com/infosec-au/altdns/blob/master/words.txt) पा सकते हैं।

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): subdomains के permutations, mutations और alterations करने का एक अन्य tool। यह परिणाम को brute force करेगा (यह DNS wildcard को support नहीं करता)।
  - dmut की permutations wordlist [**यहाँ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) मिल सकती है।

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** किसी domain के आधार पर, यह बताए गए patterns के अनुसार नए संभावित subdomain नाम बनाता है, ताकि और subdomains खोजे जा सकें।

#### स्मार्ट permutations जनरेशन

- [**regulator**](https://github.com/cramppet/regulator): खोजे गए subdomains से regex-जैसे patterns सीखता है और resolve करने के लिए उम्मीदवार नाम बनाता है।<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है, जिसमें बेहद सरल लेकिन प्रभावी DNS response-guided algorithm शामिल है। यह दिए गए input data, जैसे कि विशेष रूप से तैयार की गई wordlist या ऐतिहासिक DNS/TLS records, का उपयोग करके अधिक संबंधित domain names को सटीकता से तैयार करता है और DNS scan के दौरान जुटाई गई जानकारी के आधार पर उन्हें बार-बार और विस्तृत करता है।

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Trickest workflow के उदाहरण repeatable subdomain enumeration के लिए OSINT, DNS brute force और permutation stages को मिलाते हैं।<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

अगर आपको ऐसा IP address मिला है जिसमें subdomains से जुड़े **एक या कई web pages** हैं, तो आप **OSINT sources** में किसी IP पर मौजूद domains खोजकर या **उस IP पर VHost domain names को brute-force करके** यह **पता लगाने की कोशिश कर सकते हैं कि उस IP पर और कौन-से subdomains हैं**।

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
> इस तकनीक से आप internal/hidden endpoints तक भी पहुँच सकते हैं।

### **CORS Brute Force**

कभी-कभी आपको ऐसे पेज मिलेंगे जो _**Origin**_ header में कोई मान्य domain/subdomain सेट होने पर ही _**Access-Control-Allow-Origin**_ header लौटाते हैं। इन स्थितियों में, आप इस व्यवहार का दुरुपयोग करके नए **subdomains** **खोज** सकते हैं।

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains** खोजते समय ध्यान दें कि क्या वे किसी तरह के **bucket** की ओर **point** कर रहे हैं। अगर ऐसा है, तो [**permissions check करें**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**।**\
साथ ही, चूँकि इस समय तक आपको scope के सभी domains पता होंगे, इसलिए [**संभावित bucket names को brute force करने और permissions check करने की कोशिश करें**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)।

### **निगरानी**

आप Certificate Transparency Logs को monitor करके यह **निगरानी** कर सकते हैं कि किसी domain के **नए subdomains** बनाए गए हैं या नहीं। [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) यही करता है।

### **vulnerabilities की तलाश**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
अगर **subdomain** किसी **S3 bucket** की ओर point कर रहा है, तो [**permissions check करें**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)।

अगर आपको कोई ऐसा **subdomain मिलता है जिसका IP** उन IPs से अलग है जिन्हें आपने assets discovery में पहले ही खोज लिया है, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside), **nmap/masscan/shodan** के साथ करना चाहिए। कौन-सी services चल रही हैं, उसके आधार पर आपको **इस किताब में उन्हें "attack" करने के कुछ tricks मिल सकते हैं**।\
_ध्यान दें कि कभी-कभी subdomain ऐसे IP पर host होता है जो client के control में नहीं होता, इसलिए वह scope में नहीं होता। सावधान रहें।_

## IPs

शुरुआती steps में आपको **कुछ IP ranges, domains और subdomains मिले होंगे**।\
अब उन ranges के सभी IPs और **domains/subdomains के IPs (DNS queries के ज़रिए)** इकट्ठा करने का समय है।

नीचे दी गई जैसी services का उपयोग करके, आप **domains और subdomains द्वारा पहले इस्तेमाल किए गए IPs** भी खोज सकते हैं। ये IPs अब भी client के स्वामित्व में हो सकते हैं (और आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) खोजने में मदद कर सकते हैं)।

- [**SecurityTrails**](https://securitytrails.com/) (historical DNS/IP data के लिए paid plan ज़रूरी है)

आप [**hakip2host**](https://github.com/hakluke/hakip2host) tool या [**NetAPI**](https://netapi.com/lookup-ip/) जैसी online reverse IP lookup service का उपयोग करके यह भी देख सकते हैं कि कौन-से domains किसी खास IP address की ओर point कर रहे हैं।

### **vulnerabilities की तलाश**

**वे सभी IPs scan करें जो CDNs से संबंधित नहीं हैं** (क्योंकि वहाँ आपको कुछ दिलचस्प मिलने की संभावना बहुत कम है)। खोजी गई running services में आपको **vulnerabilities मिल सकती हैं**।

**Hosts को scan करने के तरीके की** [**guide**](../pentesting-network/index.html) **देखें।**

## Web servers की खोज

> हमने सभी कंपनियों और उनकी assets का पता लगा लिया है और हमें scope के अंदर की IP ranges, domains और subdomains मालूम हैं। अब web servers खोजने का समय है।

पिछले steps में आपने शायद खोजे गए **IPs और domains का recon** पहले ही कर लिया होगा, इसलिए हो सकता है कि आपको **सभी संभावित web servers पहले ही मिल गए हों**। लेकिन अगर ऐसा नहीं हुआ है, तो अब हम scope के अंदर web servers खोजने के कुछ **तेज़ tricks** देखेंगे।

ध्यान दें कि यह **web apps की खोज पर केंद्रित** होगा, इसलिए आपको vulnerability और port scanning भी करनी चाहिए (**अगर scope इसकी अनुमति देता है**)।

[**masscan** का उपयोग करके web servers से जुड़े **खुले ports** खोजने का एक **तेज़ तरीका यहाँ दिया गया है](../pentesting-network/index.html#http-port-discovery)।\
Web servers खोजने के लिए एक और आसान tool है [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx)। आपको बस domains की एक list देनी होती है और यह port 80 (http) तथा 443 (https) से connect करने की कोशिश करेगा। इसके अलावा, आप इसे दूसरे ports पर कोशिश करने के लिए भी कह सकते हैं:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

अब जब आपने scope में मौजूद **सभी web servers** खोज लिए हैं (कंपनी के **IPs**, और सभी **domains** तथा **subdomains** में), तो शायद आपको **पता नहीं होगा कि शुरुआत कहाँ से करें**। तो इसे आसान बनाते हैं और बस उन सभी के screenshots लेना शुरू करते हैं। सिर्फ़ **मुख्य page पर नज़र डालकर** आप ऐसे **अजीब** endpoints ढूँढ़ सकते हैं जिनके **vulnerable** होने की संभावना ज़्यादा है।

इस विचार को लागू करने के लिए आप [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** का इस्तेमाल कर सकते हैं।**

इसके अलावा, आप [**eyeballer**](https://github.com/BishopFox/eyeballer) से सभी **screenshots** की जाँच करवा सकते हैं, ताकि पता चले कि **किनमें vulnerabilities होने की संभावना है** और किनमें नहीं।

## Public Cloud Assets

किसी कंपनी से संबंधित संभावित cloud assets ढूँढ़ने के लिए आपको **उस कंपनी की पहचान करने वाले keywords की सूची से शुरुआत करनी चाहिए**। उदाहरण के लिए, किसी crypto कंपनी के लिए आप `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` जैसे शब्द इस्तेमाल कर सकते हैं।

आपको **buckets में इस्तेमाल होने वाले आम शब्दों** की wordlists भी चाहिए होंगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, उन शब्दों से आपको **permutations** बनाने चाहिए (अधिक जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

इनसे बनी wordlists के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** जैसे tools इस्तेमाल कर सकते हैं।**

याद रखें कि Cloud Assets खोजते समय आपको **AWS में सिर्फ़ buckets ही नहीं देखने चाहिए**।

### **Looking for vulnerabilities**

अगर आपको **खुले buckets या उजागर cloud functions** जैसी चीज़ें मिलें, तो आपको **उन तक पहुँचकर** देखना चाहिए कि वे क्या उपलब्ध कराते हैं और क्या आप उनका दुरुपयोग कर सकते हैं।

## Emails

scope में मौजूद **domains** और **subdomains** के साथ, आपके पास मूल रूप से **emails खोजना शुरू करने के लिए ज़रूरी सब कुछ** है। किसी कंपनी के emails खोजने के लिए मेरे अनुभव में सबसे अच्छे रहे **APIs** और **tools** ये हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs के साथ
- [**https://hunter.io/**](https://hunter.io/) का API (free version)
- [**https://app.snov.io/**](https://app.snov.io/) का API (free version)
- [**https://minelead.io/**](https://minelead.io/) का API (free version)

### **Looking for vulnerabilities**

बाद में **web logins और auth services** (जैसे SSH) पर **brute-force** करने में emails काम आएँगे। **phishings** के लिए भी इनकी ज़रूरत होगी। इसके अलावा, ये APIs आपको email के पीछे मौजूद **व्यक्ति के बारे में और जानकारी** भी देंगी, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**domains,** **subdomains**, और **emails** की मदद से आप उन emails से जुड़ी, पहले **leak** हुई credentials खोजना शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

अगर आपको **मान्य leaked** credentials मिलें, तो यह बहुत आसान जीत है।

## Secrets Leaks

Credential leaks उन कंपनियों के hacks से जुड़े होते हैं जहाँ **संवेदनशील जानकारी leak करके बेची गई थी**। हालाँकि, कंपनियाँ **अन्य leaks** से भी प्रभावित हो सकती हैं, जिनकी जानकारी उन databases में नहीं होती:

### Github Leaks

Credentials और APIs कंपनी के **public repositories** में या उस GitHub कंपनी के लिए काम करने वाले **users** के repositories में leak हो सकते हैं।\
आप [**Leakos**](https://github.com/carlospolop/Leakos) **tool** का इस्तेमाल करके किसी **organization** और उसके **developers** के सभी **public repos** **download** कर सकते हैं और उन पर [**gitleaks**](https://github.com/gitleaks/gitleaks) अपने-आप चला सकते हैं।

**Leakos** का इस्तेमाल दिए गए **text URLs** पर भी **gitleaks** चलाने के लिए किया जा सकता है, क्योंकि कभी-कभी **web pages में भी secrets होते हैं**।

#### Github Dorks

संगठन में खोजने के लिए संभावित **GitHub dorks** हेतु [GitHub dorks and leaks page](github-leaked-secrets.md) देखें।

### Pastes Leaks

कभी-कभी attackers या सिर्फ़ कर्मचारी किसी paste site पर **कंपनी की सामग्री प्रकाशित कर देते हैं**। इसमें **संवेदनशील जानकारी हो भी सकती है और नहीं भी**, लेकिन इसे खोजना काफ़ी उपयोगी है।\
एक साथ 80 से ज़्यादा paste sites पर खोजने के लिए आप [**Pastos**](https://github.com/carlospolop/Pastos) tool का इस्तेमाल कर सकते हैं।

### Google Dorks

पुराने लेकिन कारगर google dorks, **ऐसी उजागर जानकारी खोजने के लिए हमेशा उपयोगी होते हैं जो वहाँ नहीं होनी चाहिए**। समस्या बस यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **हज़ार** संभावित queries हैं जिन्हें आप हाथ से नहीं चला सकते। इसलिए, आप अपने पसंदीदा 10 चुन सकते हैं या उन्हें **सभी चलाने के लिए** [**Gorks**](https://github.com/carlospolop/Gorks) **जैसे tool** का इस्तेमाल कर सकते हैं।

_ध्यान दें कि जो tools सामान्य Google browser का इस्तेमाल करके पूरा database चलाने की कोशिश करते हैं, वे कभी ख़त्म नहीं होंगे, क्योंकि Google आपको बहुत जल्दी block कर देगा।_

### **Looking for vulnerabilities**

अगर आपको **मान्य leaked** credentials या API tokens मिलें, तो यह बहुत आसान जीत है।

## Public Code Vulnerabilities

अगर आपको पता चले कि कंपनी के पास **open-source code** है, तो आप उसका **विश्लेषण** करके उसमें **vulnerabilities** खोज सकते हैं।

**भाषा के आधार पर** अलग-अलग **tools** उपलब्ध हैं; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) की सूची देखें।

कुछ free services भी हैं जो आपको **public repositories scan** करने देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters द्वारा खोजी गई **अधिकांश vulnerabilities** **web applications** में होती हैं, इसलिए इस बिंदु पर मैं **web application testing methodology** के बारे में बात करना चाहता हूँ। यह जानकारी आप [**यहाँ पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) section का विशेष उल्लेख भी करना चाहता हूँ, क्योंकि इनसे बहुत संवेदनशील vulnerabilities मिलने की उम्मीद भले न हो, लेकिन **शुरुआती web जानकारी पाने के लिए इन्हें workflows में शामिल करना** उपयोगी है।

## Recapitulation

> बधाई हो! इस बिंदु पर आपने **सभी बुनियादी enumeration** कर ली है। हाँ, यह बुनियादी है, क्योंकि इससे कहीं ज़्यादा enumeration की जा सकती है (आगे और तरकीबें देखेंगे)।

अब तक आप:

1. scope में मौजूद सभी **कंपनियाँ** खोज चुके हैं
2. कंपनियों से संबंधित सभी **assets** खोज चुके हैं (और scope में होने पर vuln scan भी कर चुके हैं)
3. कंपनियों से संबंधित सभी **domains** खोज चुके हैं
4. domains के सभी **subdomains** खोज चुके हैं (क्या कोई subdomain takeover है?)
5. scope में मौजूद सभी **IPs** खोज चुके हैं (**CDNs से** और **CDNs से नहीं**)
6. सभी **web servers** खोजकर उनके **screenshots** ले चुके हैं (क्या कुछ अजीब है जिस पर गहराई से नज़र डालनी चाहिए?)
7. कंपनी से संबंधित सभी **संभावित public cloud assets** खोज चुके हैं।
8. **Emails**, **credentials leaks**, और **secret leaks** खोज चुके हैं, जिनसे आपको **आसानी से बड़ी जीत मिल सकती है**।
9. **आपको मिले सभी websites की Pentesting** कर चुके हैं

## **Full Recon Automatic Tools**

कई tools उपलब्ध हैं जो दिए गए scope पर सुझाई गई कार्रवाइयों में से कुछ को अंजाम देते हैं।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - थोड़ा पुराना है और अपडेट नहीं किया गया है



## References

- [1] [Jason Haddix – Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicons पर: Browser Icons से Attack Surface Intelligence तक](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – BugBounties, OSINT और अन्य चीज़ों के लिए favicon.ico को Weaponize करना](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency पर Time-Correlation Attack के ज़रिए Domains खोजना](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: एक महँगी Subdomain Takeover Campaign का पता लगाना (और उसकी नकल करना)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration का एक अनूठा तरीका](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automated Trickest Workflow का उपयोग करके Full Subdomain Brute Force Discovery, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
