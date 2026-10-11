# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets की खोज

> तो आपको बताया गया कि किसी कंपनी से जुड़ी हर चीज़ scope में है, और आप पता लगाना चाहते हैं कि इस कंपनी के वास्तव में कौन-कौन से assets हैं।

इस चरण का लक्ष्य **मुख्य कंपनी के स्वामित्व वाली सभी कंपनियों** और फिर इन कंपनियों के सभी **assets** का पता लगाना है। इसके लिए हम:<sup>[[1]](#references)</sup>

1. मुख्य कंपनी के अधिग्रहणों का पता लगाएंगे, इससे scope में आने वाली कंपनियों का पता चलेगा।
2. हर कंपनी का ASN (यदि कोई हो) पता लगाएंगे, इससे हर कंपनी के स्वामित्व वाली IP ranges मिलेंगी।
3. पहली कंपनी से संबंधित अन्य entries (organisation names, domains...) खोजने के लिए reverse whois lookups का उपयोग करेंगे (यह काम बार-बार किया जा सकता है)।
4. अन्य assets खोजने के लिए shodan के `org` और `ssl` filters जैसी तकनीकों का उपयोग करेंगे (`ssl` trick को बार-बार इस्तेमाल किया जा सकता है)।

### **अधिग्रहण**

सबसे पहले, हमें यह पता लगाना होगा कि **मुख्य कंपनी के स्वामित्व में दूसरी कौन-सी कंपनियां हैं**।\
एक तरीका है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाना, **मुख्य कंपनी को खोजकर**, "**acquisitions**" पर **क्लिक** करना। वहां आपको मुख्य कंपनी द्वारा अधिग्रहित दूसरी कंपनियां दिखेंगी।\
दूसरा तरीका है मुख्य कंपनी का **Wikipedia** पेज देखना और **acquisitions** खोजना।\
सार्वजनिक कंपनियों के लिए, **SEC/EDGAR filings**, **investor relations** पेज या स्थानीय corporate registries (उदाहरण के लिए, UK में **Companies House**) देखें।\
वैश्विक corporate trees और subsidiaries के लिए, **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएं।

> ठीक है, इस बिंदु पर आपको scope में आने वाली सभी कंपनियों का पता होना चाहिए। अब देखते हैं कि उनके assets कैसे खोजें।

### **ASNs**

एक autonomous system number (**ASN**) वह **अद्वितीय संख्या** है जिसे **Internet Assigned Numbers Authority (IANA)** किसी **autonomous system** (AS) को आवंटित करती है।\
एक **AS** में **IP addresses** के **blocks** होते हैं, जिनकी external networks तक पहुंच के लिए स्पष्ट रूप से परिभाषित policy होती है। इनका प्रबंधन एक organisation करती है, लेकिन इनमें कई operators शामिल हो सकते हैं।

यह पता लगाना उपयोगी है कि **कंपनी को कोई ASN आवंटित है या नहीं**, ताकि उसकी **IP ranges** मिल सकें। **scope** में आने वाले सभी **hosts** पर **vulnerability test** करना और इन IPs के भीतर **domains खोजना** उपयोगी होगा।\
आप [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **या** [**https://ipinfo.io/**](https://ipinfo.io/) पर कंपनी के **name**, **IP** या **domain** से **खोज** सकते हैं।\
**कंपनी के क्षेत्र के आधार पर, अधिक data जुटाने के लिए ये links उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe)। हालांकि, संभवतः** उपयोगी जानकारी **(IP ranges और Whois)** पहले link पर ही उपलब्ध है।

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

इसके अलावा, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** की** enumeration स्कैन के अंत में ASNs को अपने-आप aggregate और summarize करती है।

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

आप [http://asnlookup.com/](http://asnlookup.com) का इस्तेमाल करके किसी संगठन की IP ranges भी ढूँढ सकते हैं (इसका free API है)।\
आप [http://ipv4info.com/](http://ipv4info.com) का इस्तेमाल करके किसी domain का IP और ASN ढूँढ सकते हैं।

### **Vulnerabilities ढूँढना**

इस बिंदु पर हमें **scope के अंदर मौजूद सभी assets** का पता है, इसलिए अगर आपको अनुमति हो तो आप सभी hosts पर कोई **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप कुछ [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या Shodan, Censys, या ZoomEye जैसी services का इस्तेमाल करके** open ports **ढूँढ सकते हैं। आपको जो मिले, उसके आधार पर इस किताब में देखें कि चल रही विभिन्न संभावित services का pentest कैसे करें।**\
**यह भी बताना उपयोगी होगा कि आप कुछ** default username **और** passwords **की lists तैयार करके [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) से services को** bruteforce **करने की कोशिश कर सकते हैं।**

## Domains

> हमें scope के अंदर मौजूद सभी कंपनियों और उनके assets का पता है; अब scope के अंदर मौजूद domains ढूँढने का समय है।

_कृपया ध्यान दें कि नीचे बताई गई techniques से subdomains भी मिल सकते हैं और उस जानकारी को कमतर नहीं आँकना चाहिए।_

सबसे पहले, आपको हर कंपनी का **main domain** ढूँढना चाहिए। उदाहरण के लिए, _Tesla Inc._ का main domain _tesla.com_ होगा।

### **Reverse DNS**

चूँकि आपने domains की सभी IP ranges ढूँढ ली हैं, इसलिए आप उन **IPs पर reverse DNS lookups** करने की कोशिश कर सकते हैं, ताकि **scope के अंदर और domains मिल सकें**। Victim का कोई DNS server या कोई well-known DNS server (1.1.1.1, 8.8.8.8) इस्तेमाल करने की कोशिश करें।

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

इसके काम करने के लिए, administrator को PTR को manually enable करना होगा।\
इस जानकारी के लिए आप एक online tool भी इस्तेमाल कर सकते हैं: [http://ptrarchive.com/](http://ptrarchive.com)।\
बड़ी ranges के लिए, [**massdns**](https://github.com/blechschmidt/massdns) और [**dnsx**](https://github.com/projectdiscovery/dnsx) जैसे tools reverse lookups और enrichment को automate करने में उपयोगी हैं।

### **Reverse Whois (loop)**

**whois** में आपको बहुत-सी दिलचस्प **जानकारी** मिल सकती है, जैसे **organisation name**, **address**, **emails**, phone numbers... लेकिन इससे भी ज़्यादा दिलचस्प बात यह है कि आप **इनमें से किसी भी field के आधार पर reverse whois lookups करके कंपनी से जुड़े अन्य assets खोज सकते हैं** (उदाहरण के लिए, अन्य whois registries जहाँ वही email दिखाई देता है)।\
आप online tools का इस्तेमाल कर सकते हैं, जैसे:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web और API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, API free नहीं है।
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Free नहीं
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Free नहीं (केवल **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Free नहीं
- [https://securitytrails.com/](https://securitytrails.com/) - Free नहीं (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Free नहीं (API)

आप [**DomLink** ](https://github.com/vysecurity/DomLink) का इस्तेमाल करके इस task को automate कर सकते हैं (इसके लिए whoxy API key चाहिए)।\
आप [amass](https://github.com/OWASP/Amass) से कुछ automatic reverse whois discovery भी कर सकते हैं: `amass intel -d tesla.com -whois`

**ध्यान दें कि हर बार कोई नया domain मिलने पर, आप इस technique का इस्तेमाल करके और domain names खोज सकते हैं।**

### **Trackers**

अगर आपको 2 अलग-अलग pages पर **एक ही tracker की समान ID** मिलती है, तो आप मान सकते हैं कि **दोनों pages** **एक ही team द्वारा managed हैं**।\
उदाहरण के लिए, अगर आपको कई pages पर वही **Google Analytics ID** या वही **Adsense ID** दिखाई देती है।

कुछ pages और tools हैं जो आपको इन और अन्य trackers के आधार पर search करने देते हैं:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (साझा analytics/trackers के आधार पर संबंधित sites खोजता है)
- [**StackScan**](https://www.stackscan.com) - **Free tier** (Web और API)। केवल tracker IDs ही नहीं, बल्कि serve किए गए किसी भी asset पर pivot करें: कोई script path, self-hosted bundle name, या वह host जहाँ से कोई asset load होता है। यह उन सभी sites को लौटाता है जिन पर वह मौजूद है।

API किसी एक domain का stack लौटाती है, जो यह पुष्टि करने के लिए उपयोगी है कि कोई candidate asset उसी estate का हिस्सा है:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

हर detected technology को उसकी category के साथ लौटाता है। Asset pivoting अभी केवल web के लिए है; API per-domain lookup को कवर करती है।

### **Favicon**

क्या आपको पता है कि हम एक ही favicon icon hash खोजकर अपने target से संबंधित domains और subdomains ढूँढ़ सकते हैं? [@m4ll0k2](https://twitter.com/m4ll0k2) द्वारा बनाया गया [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool यही करता है। इसे इस्तेमाल करने का तरीका यहाँ दिया गया है:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash के परिणाम, जिनका उपयोग समान favicon hash वाले डोमेन खोजने के लिए किया गया](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सीधे शब्दों में कहें, तो favihash हमें ऐसे डोमेन खोजने की सुविधा देता है जिनका favicon icon hash हमारे target के समान हो।

![समान favicon hash वाले डोमेन खोजने के लिए इस्तेमाल किया गया favihash आउटपुट](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

समान तकनीक के अन्य उजागर इंस्टेंस खोजने के लिए किसी ज्ञात favicon hash को Shodan या FOFA pivot के रूप में इस्तेमाल करें।<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

इस तरह आप वेब के **favicon hash** की गणना कर सकते हैं (favicon bytes के **base64-encoded** रूप पर MMH3):

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

- **Hash को प्रमाण नहीं, एक indicator मानें**: MMH3 compact होता है; collisions, दोबारा इस्तेमाल किए गए icons और जानबूझकर की गई spoofing संभव है।
- **सिर्फ** `/favicon.ico` **से आगे भी जाँचें**: framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs और HTML `<link rel="icon">` tags देखें।
- **Static assets, WAF/SSO/IdP controls के पीछे भी reachable रह सकते हैं**: icon को सीधे request करें और `ETag`, `Last-Modified`, redirects तथा cache headers की समीक्षा करें।
- **Matches की पुष्टि आसपास के संकेतों से करें**: title, HTML/body hash, headers, TLS certificate subjects/SANs, product components और exposed ports की तुलना करें।
- **HTML/body hash के आधार पर cluster करें**: एक जैसा template fingerprint को मजबूत करता है; अलग-अलग templates किसी generic या shared icon का संकेत हो सकते हैं।
- **अगर कोई hash असंबंधित signatures, ports और products में दिखे, तो उसे संभावित honeypot या placeholder मानें।**
- **अस्पष्ट targets पर किसी वास्तविक page की तुलना ऐसे nonexistent path से करें** जैसे `/_favicon_probe_<8-hex>`; hosting या parking responses का एक जैसा होना shared icon की वजह समझा सकता है।
- **Nuclei detection rules या ऐसे public datasets से शुरुआती triage करें** जो favicon hashes को products और CPEs से map करते हैं।
- **IP-केंद्रित coverage gap याद रखें**: CDN-fronted, SNI-routed, anycast और केवल domain पर उपलब्ध surfaces, Shodan-जैसे datasets में छूट सकते हैं।

### **Copyright / Uniq string**

वेब पेजों में ऐसे **strings** खोजें जो एक ही organisation की अलग-अलग websites पर साझा हो सकते हैं। **Copyright string** इसका अच्छा उदाहरण हो सकता है। फिर उस string को **google**, दूसरे **browsers**, या यहाँ तक कि **shodan** में खोजें: `shodan search http.html:"Copyright string"`

### **CRT समय**

ऐसा cron job होना आम है जिसमें, उदाहरण के लिए, यह हो:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

सर्वर पर सभी certificates को एक ही समय पर renew करने के लिए। Certificate timestamps या certificate-transparency log positions का मिलान करने से संबंधित domains का पता चल सकता है।<sup>[[6]](#references)</sup>

**certificate transparency** logs का सीधे उपयोग भी करें:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC जानकारी

**एक जैसी DMARC जानकारी साझा करने वाले domains और subdomains** ढूँढ़ने के लिए [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी वेबसाइट या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे tool का उपयोग कर सकते हैं।\
अन्य उपयोगी tools में [**spoofcheck**](https://github.com/BishopFox/spoofcheck) और [**dmarcian**](https://dmarcian.com/) शामिल हैं।

### **Passive Takeover**

एक परित्यक्त A record तब पहुँच योग्य हो सकता है, जब कोई cloud provider उसका IP फिर से असाइन करे। संदर्भित research में एक opportunistic workflow दिखाया गया है, जो एक instance provision करता है और उसके address का passive DNS data से मिलान करता है; takeover scenarios को केवल authorized scope के भीतर test करें।<sup>[[7]](#references)</sup>

### **अन्य तरीके**

जब भी आपको कोई नया domain मिले, लागू discovery pivots को दोहराएँ: हर result से certificate names, passive-DNS relationships, favicon matches और organization identifiers का पता चल सकता है, जो शुरुआती seed से दिखाई नहीं देते थे।<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

जैसा कि आप पहले से जानते हैं कि IP space किस organisation का है। आप Shodan में इस data से खोज सकते हैं: `org:"Tesla, Inc."` नए और अप्रत्याशित domains के लिए मिले hosts के TLS certificate जाँचें।

आप मुख्य web page के **TLS certificate** तक पहुँचकर **Organisation name** प्राप्त कर सकते हैं, फिर उस नाम को **Shodan** को ज्ञात सभी web pages के **TLS certificates** में इस filter से खोज सकते हैं: `ssl:"Tesla Motors"` या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे tool का उपयोग कर सकते हैं।

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)एक ऐसा tool है जो किसी मुख्य domain से **संबंधित domains** और उनके **subdomains** खोजता है—काफ़ी कमाल का।

**Passive DNS / Historical DNS**

Passive DNS data ऐसे **पुराने और भुला दिए गए records** खोजने में बहुत उपयोगी है, जो अब भी resolve होते हैं या जिनका takeover किया जा सकता है। यहाँ देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **कमज़ोरियाँ ढूँढ़ना**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) की जाँच करें। हो सकता है कि कोई कंपनी **किसी domain का उपयोग कर रही हो**, लेकिन **उसका ownership खो चुकी हो**। बस उसे register करें (अगर काफ़ी सस्ता हो) और कंपनी को इसकी जानकारी दें।

अगर आपको कोई ऐसा **domain मिलता है जिसका IP**, assets discovery में पहले मिले IPs से अलग है, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **nmap/masscan/shodan** से [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करना चाहिए। चल रही services के आधार पर, आप **इस किताब में उन्हें "attack" करने की कुछ तरकीबें** पा सकते हैं।\
_ध्यान दें कि कभी-कभी domain ऐसे IP पर hosted होता है जो client के नियंत्रण में नहीं होता, इसलिए वह scope में नहीं है। सावधान रहें।_

## Subdomains

> हमें scope के अंदर की सभी कंपनियों, हर कंपनी के सभी assets और उनसे संबंधित सभी domains की जानकारी है।

अब मिले हर domain के सभी संभावित subdomains ढूँढ़ने का समय है।

> [!TIP]
> ध्यान दें कि domains ढूँढ़ने के कुछ tools और techniques, subdomains ढूँढ़ने में भी मदद कर सकते हैं।

### **DNS**

आइए **DNS** records से **subdomains** ढूँढ़ने की कोशिश करें। हमें **Zone Transfer** भी आज़माना चाहिए (अगर vulnerable हो, तो इसकी report करें)।

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

बहुत सारे subdomains प्राप्त करने का सबसे तेज़ तरीका बाहरी स्रोतों में खोज करना है। सबसे ज़्यादा इस्तेमाल किए जाने वाले **tools** ये हैं (बेहतर परिणामों के लिए API keys कॉन्फ़िगर करें):


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

कुछ **अन्य दिलचस्प tools/APIs** हैं, जो भले ही सीधे तौर पर subdomains खोजने के लिए विशेषीकृत न हों, फिर भी subdomains खोजने में उपयोगी हो सकते हैं, जैसे:

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

- [**JLDC मुफ़्त API**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** किसी भी दिए गए domain के लिए AlienVault's Open Threat Exchange, the Wayback Machine और Common Crawl से ज्ञात URLs प्राप्त करता है।

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ये JS फ़ाइलों की तलाश में वेब को स्क्रैप करते हैं और उनसे subdomains निकालते हैं।

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

- [**securitytrails.com**](https://securitytrails.com/) में subdomains और IP history खोजने के लिए एक free API है
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

यह project **bug-bounty programs से संबंधित सभी subdomains** free में उपलब्ध कराता है। आप [chaospy](https://github.com/dr-0x0x/chaospy) का उपयोग करके भी इस data को access कर सकते हैं या इस project द्वारा उपयोग किए गए scope को यहां access कर सकते हैं: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

आप इनमें से कई tools की **तुलना** यहां देख सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

आइए, संभावित subdomain नामों का उपयोग करके DNS servers पर brute-force चलाकर नए **subdomains** खोजने की कोशिश करें।

इस काम के लिए आपको कुछ **आम subdomains wordlists की ज़रूरत होगी, जैसे**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

आपको अच्छे DNS resolvers के IPs की भी ज़रूरत होगी। भरोसेमंद DNS resolvers की सूची बनाने के लिए, आप [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) से resolvers download कर सकते हैं और उन्हें filter करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग कर सकते हैं। या आप यह भी इस्तेमाल कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे ज़्यादा सुझाए जाने वाले tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह प्रभावी DNS brute-force करने वाला पहला tool था। यह बहुत तेज़ है, लेकिन false positives की संभावना रहती है।

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): मुझे लगता है कि यह बस 1 resolver का उपयोग करता है

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के चारों ओर बनाया गया एक wrapper है, जिसे go में लिखा गया है। इससे active bruteforce के ज़रिए मान्य subdomains enumerate किए जा सकते हैं, साथ ही wildcard handling और आसान input-output support के साथ subdomains resolve किए जा सकते हैं।

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): यह `massdns` का भी उपयोग करता है।

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) डोमेन नामों को असिंक्रोनस रूप से brute force करने के लिए asyncio का उपयोग करता है।

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### दूसरा DNS Brute-Force राउंड

Open sources और brute-forcing से subdomains खोजने के बाद, आप और अधिक subdomains खोजने के लिए मिले हुए subdomains के variations बना सकते हैं। इसके लिए कई tools उपयोगी हैं:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Domains और subdomains दिए जाने पर permutations बनाता है।

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains के permutations जनरेट करता है।
  - आप goaltdns के permutations **wordlist** [**यहाँ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) पा सकते हैं।

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains के आधार पर permutations बनाता है। यदि permutations file निर्दिष्ट नहीं की गई है, तो gotator अपनी फ़ाइल का उपयोग करेगा।

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations जनरेट करने के अलावा, यह उन्हें resolve करने की कोशिश भी कर सकता है (लेकिन पहले बताए गए tools का इस्तेमाल करना बेहतर है)।
  - altdns permutations की **wordlist** [**यहाँ**](https://github.com/infosec-au/altdns/blob/master/words.txt) मिल सकती है।

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): subdomains के permutations, mutations और बदलाव करने के लिए एक अन्य tool। यह परिणाम को brute force करेगा (यह DNS wildcard को support नहीं करता)।
  - आप dmut की permutations wordlist [**यहाँ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) पा सकते हैं।

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** किसी domain के आधार पर, यह बताए गए patterns के आधार पर नए संभावित subdomain names बनाता है, ताकि और subdomains खोजे जा सकें।

#### स्मार्ट permutations जनरेशन

- [**regulator**](https://github.com/cramppet/regulator): खोजे गए subdomains से regex-जैसे patterns सीखता है और resolve करने के लिए candidate names बनाता है।<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है, जो बेहद सरल लेकिन प्रभावी DNS response-guided algorithm के साथ काम करता है। यह दिए गए input data, जैसे कि विशेष रूप से तैयार की गई wordlist या ऐतिहासिक DNS/TLS records, का उपयोग करके संबंधित domain names का सटीक अनुमान लगाता है और DNS scan के दौरान मिली जानकारी के आधार पर उन्हें बार-बार और विस्तृत करता है।

```
echo www | subzuf facebook.com
```

### **सबडोमेन खोज कार्यप्रवाह**

Trickest workflow के उदाहरण दोहराए जा सकने वाले subdomain enumeration के लिए OSINT, DNS brute force और permutation चरणों को जोड़ते हैं।<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

अगर आपको ऐसा IP address मिला है जिसमें subdomains से जुड़े **एक या कई web pages** हैं, तो आप **OSINT sources** में किसी IP के domains खोजकर या **उस IP में VHost domain names को brute-force करके**, **उस IP पर मौजूद अन्य subdomains खोजने** की कोशिश कर सकते हैं।

#### OSINT

आप [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs का उपयोग करके IPs में कुछ VHosts खोज सकते हैं**।

**Brute Force**

अगर आपको संदेह है कि किसी subdomain को web server में छिपाया गया है, तो आप उसे brute force करने की कोशिश कर सकते हैं:

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
> इस technique से आप internal/hidden endpoints तक भी पहुँच सकते हैं।

### **CORS Brute Force**

कभी-कभी आपको ऐसे pages मिलेंगे जो _**Origin**_ header में valid domain/subdomain सेट होने पर ही _**Access-Control-Allow-Origin**_ header लौटाते हैं। इन स्थितियों में, आप इस व्यवहार का दुरुपयोग करके नए **subdomains** **discover** कर सकते हैं।

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains** खोजते समय ध्यान दें कि क्या वे किसी भी तरह के **bucket** की ओर **pointing** कर रहे हैं। अगर ऐसा है, तो [**permissions जाँचें**](../../network-services-pentesting/pentesting-web/buckets/index.html)**।**\
साथ ही, इस चरण तक आपको scope के सभी domains पता होंगे, इसलिए **संभावित bucket names को brute force करने और permissions जाँचने की कोशिश करें**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **निगरानी**

आप **Certificate Transparency** Logs की निगरानी करके पता लगा सकते हैं कि किसी domain के **नए subdomains** बनाए गए हैं या नहीं। [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)ऐसा करता है।

### **vulnerabilities खोजना**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
अगर **subdomain** किसी **S3 bucket** की ओर pointing कर रहा है, तो [**permissions जाँचें**](../../network-services-pentesting/pentesting-web/buckets/index.html).

अगर आपको कोई ऐसा **subdomain मिले जिसका IP**, assets discovery में पहले से मिले IPs से **अलग हो**, तो **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **nmap/masscan/shodan** से [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करें। चल रही services के आधार पर, आपको **इस किताब में उन्हें "attack" करने के कुछ तरीके मिल सकते हैं**।\
_Note करें कि कभी-कभी subdomain ऐसे IP पर hosted होता है जिसे client नियंत्रित नहीं करता, इसलिए वह scope में नहीं होता। सावधान रहें।_

## IPs

शुरुआती चरणों में आपको **कुछ IP ranges, domains और subdomains मिले होंगे**।\
अब उन ranges और **domains/subdomains (DNS queries)** से सभी IPs **इकट्ठा करने** का समय है।

नीचे दी गई **free APIs** की services का उपयोग करके आप **domains और subdomains द्वारा पहले इस्तेमाल किए गए IPs** भी खोज सकते हैं। हो सकता है कि ये IPs अब भी client के स्वामित्व में हों (और आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) खोजने में मदद करें)।

- [**https://securitytrails.com/**](https://securitytrails.com/)

किसी specific IP address की ओर pointing करने वाले domains भी [**hakip2host**](https://github.com/hakluke/hakip2host) tool से खोजे जा सकते हैं।

### **vulnerabilities खोजना**

**CDNs से संबंधित न होने वाले सभी IPs पर port scan करें** (क्योंकि वहाँ शायद कुछ भी दिलचस्प नहीं मिलेगा)। चल रही services में आपको **vulnerabilities मिल सकती हैं**।

**Hosts को scan करने के तरीके पर एक** [**guide**](../pentesting-network/index.html) **खोजें।**

## Web servers की खोज

> हमें सभी कंपनियाँ और उनकी assets मिल गई हैं, और हमें scope के अंदर के IP ranges, domains और subdomains पता हैं। अब web servers खोजने का समय है।

पिछले चरणों में आपने शायद खोजे गए IPs और domains की **कुछ recon पहले ही कर ली होगी**, इसलिए संभव है कि आपको **सभी संभावित web servers पहले ही मिल गए हों**। लेकिन अगर ऐसा नहीं हुआ है, तो अब हम scope के अंदर web servers खोजने के कुछ **तेज़ तरीके** देखेंगे।

ध्यान दें कि यह तरीका **web apps की खोज पर केंद्रित** है, इसलिए आपको vulnerability और port scanning भी **करनी चाहिए** (**अगर scope इसकी अनुमति देता है**)।

[**masscan** का उपयोग करके web servers से संबंधित **खुले ports** खोजने का एक **तेज़ तरीका यहाँ दिया गया है](../pentesting-network/index.html#http-port-discovery)।\
Web servers खोजने के लिए एक और आसान tool है [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx)। आपको बस domains की एक list देनी होती है और यह port 80 (http) और 443 (https) से connect करने की कोशिश करेगा। इसके अलावा, आप दूसरे ports पर भी कोशिश करने का निर्देश दे सकते हैं:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

अब जबकि आपने scope में मौजूद **सभी web servers** खोज लिए हैं (कंपनी के **IPs** और सभी **domains** तथा **subdomains** में), तो शायद आपको **पता नहीं होगा कि शुरुआत कहाँ से करें**। तो इसे आसान बनाते हैं और सबसे पहले उन सभी के screenshots लेते हैं। सिर्फ **मुख्य पेज पर नज़र डालकर** आप ऐसे **अजीब** endpoints खोज सकते हैं जिनके **vulnerable** होने की **संभावना अधिक** है।

इस विचार को लागू करने के लिए आप [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** का इस्तेमाल कर सकते हैं।

इसके अलावा, आप सभी **screenshots** पर [**eyeballer**](https://github.com/BishopFox/eyeballer) चला सकते हैं, ताकि यह आपको बताए कि किनमें **vulnerabilities होने की संभावना है** और किनमें नहीं।

## Public Cloud Assets

किसी कंपनी से संबंधित संभावित cloud assets खोजने के लिए, आपको **उस कंपनी की पहचान करने वाले keywords की सूची से शुरुआत करनी चाहिए**। उदाहरण के लिए, किसी crypto कंपनी के लिए आप `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` जैसे शब्द इस्तेमाल कर सकते हैं।

आपको **buckets में आमतौर पर इस्तेमाल होने वाले शब्दों** की wordlists भी चाहिए होंगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

इसके बाद, इन शब्दों से **permutations** जनरेट करें (अधिक जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

इन wordlists से मिले परिणामों के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** जैसे tools इस्तेमाल कर सकते हैं।

याद रखें कि Cloud Assets खोजते समय आपको **AWS में सिर्फ buckets से अधिक पर नज़र रखनी चाहिए**।

### **Looking for vulnerabilities**

अगर आपको **खुले buckets या exposed cloud functions** जैसी चीज़ें मिलें, तो आपको **उन तक पहुँचकर** देखना चाहिए कि वे क्या उपलब्ध कराते हैं और क्या आप उनका दुरुपयोग कर सकते हैं।

## Emails

Scope में शामिल **domains** और **subdomains** के साथ, आपके पास **emails खोजना शुरू करने के लिए** मूल रूप से वह सब है जिसकी आपको **ज़रूरत है**। कंपनी के emails खोजने के लिए मेरे अनुभव में सबसे अच्छे रहे **APIs** और **tools** ये हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs के साथ
- [**https://hunter.io/**](https://hunter.io/) का API (मुफ़्त संस्करण)
- [**https://app.snov.io/**](https://app.snov.io/) का API (मुफ़्त संस्करण)
- [**https://minelead.io/**](https://minelead.io/) का API (मुफ़्त संस्करण)

### **Looking for vulnerabilities**

बाद में **web logins और auth services** (जैसे SSH) पर **brute-force** करने में emails काम आएँगे। **Phishing** के लिए भी इनकी ज़रूरत होती है। इसके अलावा, ये APIs आपको email के पीछे मौजूद **व्यक्ति के बारे में और जानकारी** भी देंगे, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**Domains,** **subdomains**, और **emails** की मदद से आप उन emails से संबंधित, पहले **leak** हुए credentials खोजना शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

अगर आपको **मान्य leaked** credentials मिलते हैं, तो यह बहुत आसानी से मिलने वाली जीत है।

## Secrets Leaks

Credential leaks उन कंपनियों के hacks से जुड़े होते हैं जहाँ **sensitive information leak करके बेची गई थी**। हालाँकि, कंपनियाँ **अन्य leaks** से भी प्रभावित हो सकती हैं, जिनकी जानकारी उन databases में नहीं होती:

### Github Leaks

कंपनी के **public repositories** या उस कंपनी में काम करने वाले **users** के repositories में credentials और APIs **leak** हो सकते हैं।\
आप [**Leakos**](https://github.com/carlospolop/Leakos) **tool** का इस्तेमाल करके किसी **organization** और उसके **developers** के सभी **public repos download** कर सकते हैं और उन पर [**gitleaks**](https://github.com/zricethezav/gitleaks) अपने-आप चला सकते हैं।

**Leakos** का इस्तेमाल उसे दी गई सभी **text URLs** पर **gitleaks** चलाने के लिए भी किया जा सकता है, क्योंकि कभी-कभी **web pages में भी secrets होते हैं**।

#### Github Dorks

Organization में खोजने के लिए संभावित **GitHub dorks** देखने हेतु [GitHub dorks and leaks page](github-leaked-secrets.md) देखें।

### Pastes Leaks

कभी-कभी attackers या कर्मचारी किसी **paste site पर कंपनी की सामग्री प्रकाशित कर देते हैं**। इसमें **sensitive information हो भी सकती है और नहीं भी**, लेकिन इसे खोजना बहुत उपयोगी है।\
एक ही समय में 80 से अधिक paste sites पर खोजने के लिए आप [**Pastos**](https://github.com/carlospolop/Pastos) tool का इस्तेमाल कर सकते हैं।

### Google Dorks

पुराने लेकिन असरदार Google dorks, **ऐसी exposed information खोजने के लिए हमेशा उपयोगी हैं जो वहाँ नहीं होनी चाहिए**। एकमात्र समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **हज़ार** संभावित queries हैं जिन्हें आप manually नहीं चला सकते। इसलिए, आप अपनी पसंद की 10 queries चुन सकते हैं या उन सभी को चलाने के लिए [**Gorks**](https://github.com/carlospolop/Gorks) **जैसे tool** का इस्तेमाल कर सकते हैं।

_Note करें कि जो tools सामान्य Google browser का इस्तेमाल करके पूरा database चलाने की कोशिश करते हैं, वे कभी खत्म नहीं होंगे, क्योंकि Google आपको बहुत जल्दी block कर देगा।_

### **Looking for vulnerabilities**

अगर आपको **मान्य leaked** credentials या API tokens मिलते हैं, तो यह बहुत आसानी से मिलने वाली जीत है।

## Public Code Vulnerabilities

अगर आपको पता चलता है कि कंपनी के पास **open-source code** है, तो आप उसका **विश्लेषण** करके उसमें **vulnerabilities** खोज सकते हैं।

**Language के आधार पर**, आप अलग-अलग **tools** इस्तेमाल कर सकते हैं; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) की सूची देखें।

ऐसी मुफ़्त services भी हैं जो आपको **public repositories scan** करने देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunters को मिलने वाली **ज़्यादातर vulnerabilities** **web applications** में होती हैं, इसलिए इस बिंदु पर मैं **web application testing methodology** के बारे में बात करना चाहूँगा। यह जानकारी आप [**यहाँ पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) section का विशेष उल्लेख भी करना चाहता हूँ। उनसे बहुत संवेदनशील vulnerabilities मिलने की उम्मीद नहीं करनी चाहिए, लेकिन **कुछ शुरुआती web जानकारी पाने के लिए उन्हें workflows में शामिल करना उपयोगी है।**

## Recapitulation

> बधाई हो! इस बिंदु पर आपने **सभी बुनियादी enumeration** पूरी कर ली है। हाँ, यह बुनियादी है, क्योंकि इससे कहीं अधिक enumeration की जा सकती है (आगे और tricks देखेंगे)।

तो अब तक आपने:

1. Scope में आने वाली सभी **कंपनियों** को खोज लिया है
2. कंपनियों से संबंधित सभी **assets** खोज लिए हैं (और scope में होने पर कुछ vuln scan भी किया है)
3. कंपनियों से संबंधित सभी **domains** खोज लिए हैं
4. Domains के सभी **subdomains** खोज लिए हैं (क्या कोई subdomain takeover है?)
5. Scope में आने वाले सभी **IPs** खोज लिए हैं (**CDNs** से और **CDNs** के अलावा)
6. सभी **web servers** खोज लिए हैं और उनके **screenshots** ले लिए हैं (क्या कुछ अजीब है जिस पर और गहराई से नज़र डालनी चाहिए?)
7. कंपनी से संबंधित सभी **संभावित public cloud assets** खोज लिए हैं।
8. ऐसे **Emails**, **credentials leaks**, और **secret leaks** खोज लिए हैं जो आपको **बहुत आसानी से बड़ी जीत** दिला सकते हैं।
9. मिले सभी **webs की Pentesting** कर ली है

## **Full Recon Automatic Tools**

ऐसे कई tools उपलब्ध हैं जो किसी दिए गए scope पर सुझाई गई कार्रवाइयों में से कुछ को पूरा करेंगे।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - थोड़ा पुराना है और अपडेट नहीं किया गया है

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicons के बारे में: Browser Icons से Attack Surface Intelligence तक](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – BugBounties, OSINT और अन्य कामों के लिए favicon.ico को Weaponize करना](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency पर Time-Correlation Attack के ज़रिए Domains खोजना](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: एक महँगे Subdomain Takeover Campaign का पता लगाना (और उसकी नकल करना)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration का एक अनोखा तरीका](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automated Trickest Workflow का इस्तेमाल करके Full Subdomain Brute Force Discovery, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output का screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
