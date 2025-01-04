# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> तो आपको कहा गया था कि किसी कंपनी से संबंधित सब कुछ दायरे के भीतर है, और आप यह पता लगाना चाहते हैं कि इस कंपनी के पास वास्तव में क्या है।

इस चरण का लक्ष्य **मुख्य कंपनी द्वारा स्वामित्व वाली सभी कंपनियों** और फिर इन कंपनियों के सभी **संपत्तियों** को प्राप्त करना है। ऐसा करने के लिए, हम:

1. मुख्य कंपनी के अधिग्रहणों को खोजेंगे, इससे हमें दायरे के भीतर की कंपनियाँ मिलेंगी।
2. प्रत्येक कंपनी का ASN (यदि कोई हो) खोजेंगे, इससे हमें प्रत्येक कंपनी द्वारा स्वामित्व वाले IP रेंज मिलेंगे।
3. पहले वाले से संबंधित अन्य प्रविष्टियों (संस्थान के नाम, डोमेन...) की खोज के लिए रिवर्स Whois लुकअप का उपयोग करेंगे (यह पुनरावृत्त रूप से किया जा सकता है)।
4. अन्य संपत्तियों की खोज के लिए शोडान `org` और `ssl` फ़िल्टर जैसी अन्य तकनीकों का उपयोग करेंगे (यह `ssl` ट्रिक पुनरावृत्त रूप से की जा सकती है)।

### **Acquisitions**

सबसे पहले, हमें यह जानने की आवश्यकता है कि **मुख्य कंपनी द्वारा स्वामित्व वाली अन्य कंपनियाँ कौन सी हैं**।\
एक विकल्प है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाना, **मुख्य कंपनी** के लिए **खोज** करना, और "**अधिग्रहण**" पर **क्लिक** करना। वहाँ आप मुख्य कंपनी द्वारा अधिग्रहित अन्य कंपनियाँ देखेंगे।\
दूसरा विकल्प है मुख्य कंपनी के **विकिपीडिया** पृष्ठ पर जाना और **अधिग्रहण** के लिए खोज करना।

> ठीक है, इस बिंदु पर आपको दायरे के भीतर सभी कंपनियों के बारे में पता होना चाहिए। चलिए उनके संपत्तियों को खोजने का तरीका समझते हैं।

### **ASNs**

एक स्वायत्त प्रणाली संख्या (**ASN**) एक **विशिष्ट संख्या** है जो **इंटरनेट असाइन नंबर प्राधिकरण (IANA)** द्वारा एक **स्वायत्त प्रणाली** (AS) को असाइन की जाती है।\
एक **AS** में **IP पते** के **ब्लॉक** होते हैं जिनकी बाहरी नेटवर्क तक पहुँचने के लिए स्पष्ट रूप से परिभाषित नीति होती है और इसे एक ही संगठन द्वारा प्रशासित किया जाता है लेकिन यह कई ऑपरेटरों से मिलकर बन सकता है।

यह जानना दिलचस्प है कि क्या **कंपनी ने कोई ASN असाइन किया है** ताकि इसके **IP रेंज** को खोजा जा सके। यह **दायरे** के भीतर सभी **होस्ट** के खिलाफ एक **कमजोरी परीक्षण** करना और इन IPs के भीतर **डोमेन** की खोज करना दिलचस्प होगा।\
आप कंपनी के **नाम**, **IP** या **डोमेन** द्वारा [**https://bgp.he.net/**](https://bgp.he.net)** पर **खोज** कर सकते हैं।\
**कंपनी के क्षेत्र के आधार पर ये लिंक अधिक डेटा इकट्ठा करने के लिए उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(अफ्रीका),** [**Arin**](https://www.arin.net/about/welcome/region/)**(उत्तरी अमेरिका),** [**APNIC**](https://www.apnic.net) **(एशिया),** [**LACNIC**](https://www.lacnic.net) **(लैटिन अमेरिका),** [**RIPE NCC**](https://www.ripe.net) **(यूरोप)। वैसे, शायद सभी** उपयोगी जानकारी **(IP रेंज और Whois)** पहले लिंक में पहले से ही दिखाई देती है।
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
इसके अलावा, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** उपडोमेन enumeration स्वचालित रूप से स्कैन के अंत में ASNs को एकत्रित और संक्षेपित करता है।
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
आप एक संगठन के IP रेंज भी [http://asnlookup.com/](http://asnlookup.com) का उपयोग करके पा सकते हैं (इसमें मुफ्त API है)।\
आप [http://ipv4info.com/](http://ipv4info.com) का उपयोग करके एक डोमेन का IP और ASN पा सकते हैं।

### **कमजोरियों की तलाश**

इस बिंदु पर हम **स्कोप के अंदर सभी संपत्तियों** को जानते हैं, इसलिए यदि आपको अनुमति है तो आप सभी होस्ट पर कुछ **कमजोरी स्कैनर** (Nessus, OpenVAS) लॉन्च कर सकते हैं।\
इसके अलावा, आप कुछ [**पोर्ट स्कैन**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **लॉन्च कर सकते हैं** या **खुले पोर्ट खोजने के लिए** shodan **जैसी सेवाओं का उपयोग कर सकते हैं और जो कुछ भी आप पाते हैं उसके आधार पर आपको इस पुस्तक में देखना चाहिए कि कैसे कई संभावित सेवाओं का पेंटेस्ट करना है।**\
**इसके अलावा, यह उल्लेख करना भी सार्थक हो सकता है कि आप कुछ** डिफ़ॉल्ट उपयोगकर्ता नाम **और** पासवर्ड **सूचियाँ तैयार कर सकते हैं और** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) के साथ सेवाओं को ब्रूटफोर्स करने की कोशिश कर सकते हैं।**

## डोमेन

> हम स्कोप के अंदर सभी कंपनियों और उनकी संपत्तियों को जानते हैं, अब स्कोप के अंदर डोमेन खोजने का समय है।

_कृपया ध्यान दें कि निम्नलिखित प्रस्तावित तकनीकों में आप उपडोमेन भी पा सकते हैं और उस जानकारी को कम नहीं आंका जाना चाहिए।_

सबसे पहले, आपको प्रत्येक कंपनी के **मुख्य डोमेन**(s) की तलाश करनी चाहिए। उदाहरण के लिए, _Tesla Inc._ के लिए _tesla.com_ होगा।

### **रिवर्स DNS**

जैसा कि आपने डोमेन के सभी IP रेंज पा लिए हैं, आप उन **IPs पर अधिक डोमेन खोजने के लिए** **रिवर्स DNS लुकअप** करने की कोशिश कर सकते हैं। पीड़ित के कुछ DNS सर्वर या कुछ प्रसिद्ध DNS सर्वर (1.1.1.1, 8.8.8.8) का उपयोग करने की कोशिश करें।
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
इसका काम करने के लिए, व्यवस्थापक को मैन्युअल रूप से PTR सक्षम करना होगा।\
आप इस जानकारी के लिए एक ऑनलाइन टूल भी उपयोग कर सकते हैं: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

एक **whois** में आप बहुत सारी दिलचस्प **जानकारी** पा सकते हैं जैसे **संस्थान का नाम**, **पता**, **ईमेल**, फोन नंबर... लेकिन जो और भी दिलचस्प है वह यह है कि आप **कंपनी से संबंधित अधिक संपत्तियाँ** पा सकते हैं यदि आप **इनमें से किसी भी क्षेत्र द्वारा रिवर्स Whois लुकअप करते हैं** (उदाहरण के लिए अन्य Whois रजिस्ट्रियों जहां वही ईमेल दिखाई देता है)।\
आप ऑनलाइन टूल का उपयोग कर सकते हैं जैसे:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **मुफ्त**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **मुफ्त**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **मुफ्त**
- [https://www.whoxy.com/](https://www.whoxy.com) - **मुफ्त** वेब, मुफ्त API नहीं।
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - मुफ्त नहीं
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - मुफ्त नहीं (केवल **100 मुफ्त** खोजें)
- [https://www.domainiq.com/](https://www.domainiq.com) - मुफ्त नहीं

आप इस कार्य को स्वचालित कर सकते हैं [**DomLink** ](https://github.com/vysecurity/DomLink)(एक whoxy API कुंजी की आवश्यकता होती है)।\
आप [amass](https://github.com/OWASP/Amass) के साथ कुछ स्वचालित रिवर्स Whois खोज भी कर सकते हैं: `amass intel -d tesla.com -whois`

**ध्यान दें कि आप इस तकनीक का उपयोग हर बार एक नया डोमेन खोजने पर अधिक डोमेन नाम खोजने के लिए कर सकते हैं।**

### **Trackers**

यदि आप 2 विभिन्न पृष्ठों में **एक ही ट्रैकर का एक ही ID** पाते हैं, तो आप मान सकते हैं कि **दोनों पृष्ठ** **एक ही टीम द्वारा प्रबंधित** हैं।\
उदाहरण के लिए, यदि आप कई पृष्ठों पर वही **Google Analytics ID** या वही **Adsense ID** देखते हैं।

कुछ पृष्ठ और उपकरण हैं जो आपको इन ट्रैकर्स द्वारा खोजने की अनुमति देते हैं और अधिक:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

क्या आप जानते हैं कि हम एक ही फेविकॉन आइकन हैश की तलाश करके अपने लक्ष्य से संबंधित डोमेन और उप डोमेन पा सकते हैं? यह ठीक वही है जो [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) टूल [@m4ll0k2](https://twitter.com/m4ll0k2) द्वारा बनाया गया है। इसका उपयोग कैसे करें:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - समान favicon आइकन हैश के साथ डोमेन खोजें](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सरल शब्दों में, favihash हमें उन डोमेन को खोजने की अनुमति देगा जिनका favicon आइकन हैश हमारे लक्ष्य के समान है।

इसके अलावा, आप favicon हैश का उपयोग करके तकनीकों की भी खोज कर सकते हैं जैसा कि [**इस ब्लॉग पोस्ट**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) में समझाया गया है। इसका मतलब है कि यदि आप जानते हैं कि **एक कमजोर वेब तकनीक के favicon का हैश** क्या है, तो आप शोडन में खोज सकते हैं और **अधिक कमजोर स्थानों** को खोज सकते हैं:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
यहाँ बताया गया है कि आप एक वेब का **फेविकॉन हैश** कैसे गणना कर सकते हैं:
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
### **कॉपीराइट / यूनिक स्ट्रिंग**

वेब पृष्ठों के अंदर **स्ट्रिंग्स की खोज करें जो एक ही संगठन में विभिन्न वेब्स के बीच साझा की जा सकती हैं**। **कॉपीराइट स्ट्रिंग** एक अच्छा उदाहरण हो सकता है। फिर उस स्ट्रिंग की **गूगल**, अन्य **ब्राउज़रों** या यहां तक कि **शोडन** में खोज करें: `shodan search http.html:"Copyright string"`

### **CRT समय**

यह सामान्य है कि एक क्रॉन जॉब हो जैसे
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
सर्वर पर सभी डोमेन प्रमाणपत्रों को नवीनीकरण करने के लिए। इसका मतलब है कि भले ही इसके लिए उपयोग किया जाने वाला CA वैधता समय में उत्पन्न होने का समय सेट न करे, यह संभव है कि **प्रमाणपत्र पारदर्शिता लॉग में उसी कंपनी के संबंधित डोमेन को खोजा जा सके**।\
इस [**लेख को अधिक जानकारी के लिए देखें**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)।

### मेल DMARC जानकारी

आप [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी वेबसाइट या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे टूल का उपयोग करके **डोमेन और उपडोमेन जो समान DMARC जानकारी साझा करते हैं** खोज सकते हैं।

### **पैसिव टेकओवर**

स्पष्ट रूप से यह सामान्य है कि लोग उपडोमेन को क्लाउड प्रदाताओं से संबंधित IPs को असाइन करते हैं और किसी बिंदु पर **उस IP पते को खो देते हैं लेकिन DNS रिकॉर्ड को हटाना भूल जाते हैं**। इसलिए, बस **क्लाउड में एक VM स्पॉन करना** (जैसे Digital Ocean) आप वास्तव में **कुछ उपडोमेन(s) पर कब्जा कर रहे होंगे**।

[**यह पोस्ट**](https://kmsec.uk/blog/passive-takeover/) इसके बारे में एक स्टोर को समझाती है और एक स्क्रिप्ट का प्रस्ताव करती है जो **DigitalOcean में एक VM स्पॉन करती है**, **नए मशीन का** **IPv4** **प्राप्त करती है**, और **Virustotal में उपडोमेन रिकॉर्ड** की खोज करती है जो इसे इंगित करते हैं।

### **अन्य तरीके**

**ध्यान दें कि आप इस तकनीक का उपयोग हर बार एक नया डोमेन खोजने पर अधिक डोमेन नाम खोजने के लिए कर सकते हैं।**

**Shodan**

जैसा कि आप पहले से ही IP स्पेस के मालिक संगठन का नाम जानते हैं। आप उस डेटा को shodan में खोज सकते हैं: `org:"Tesla, Inc."` TLS प्रमाणपत्र में नए अप्रत्याशित डोमेन के लिए पाए गए होस्ट की जांच करें।

आप मुख्य वेब पृष्ठ का **TLS प्रमाणपत्र** एक्सेस कर सकते हैं, **संगठन का नाम** प्राप्त कर सकते हैं और फिर **shodan** द्वारा ज्ञात सभी वेब पृष्ठों के **TLS प्रमाणपत्रों** के अंदर उस नाम की खोज कर सकते हैं जिसमें फ़िल्टर है: `ssl:"Tesla Motors"` या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे टूल का उपयोग करें।

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) एक टूल है जो **मुख्य डोमेन से संबंधित डोमेन** और उनके **उपडोमेन** की खोज करता है, काफी अद्भुत।

### **कमजोरियों की खोज**

कुछ [डोमेन टेकओवर](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) के लिए जांचें। शायद कोई कंपनी **किसी डोमेन का उपयोग कर रही है** लेकिन उन्होंने **स्वामित्व खो दिया है**। बस इसे रजिस्टर करें (यदि यह सस्ता है) और कंपनी को सूचित करें।

यदि आप किसी **डोमेन को एक IP के साथ पाते हैं जो पहले से खोजे गए संपत्तियों में से अलग है**, तो आपको एक **बुनियादी कमजोरियों का स्कैन** (Nessus या OpenVAS का उपयोग करके) और कुछ [**पोर्ट स्कैन**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **nmap/masscan/shodan** के साथ करना चाहिए। जिस सेवा का संचालन हो रहा है, आप **इस पुस्तक में कुछ ट्रिक्स "हमला" करने के लिए** खोज सकते हैं।\
&#xNAN;_&#x4E;ote कि कभी-कभी डोमेन एक ऐसे IP में होस्ट किया जाता है जो ग्राहक द्वारा नियंत्रित नहीं होता है, इसलिए यह दायरे में नहीं है, सावधान रहें।_

## उपडोमेन

> हम सभी कंपनियों को जानते हैं जो दायरे में हैं, प्रत्येक कंपनी की सभी संपत्तियों और कंपनियों से संबंधित सभी डोमेन को जानते हैं।

यह समय है कि प्रत्येक पाए गए डोमेन के सभी संभावित उपडोमेन खोजें।

> [!TIP]
> ध्यान दें कि कुछ टूल और तकनीकें जो डोमेन खोजने के लिए उपयोग की जाती हैं, उपडोमेन खोजने में भी मदद कर सकती हैं।

### **DNS**

आइए **DNS** रिकॉर्ड से **उपडोमेन** प्राप्त करने की कोशिश करें। हमें **ज़ोन ट्रांसफर** के लिए भी प्रयास करना चाहिए (यदि कमजोर है, तो आपको इसकी रिपोर्ट करनी चाहिए)।
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

बहुत सारे सबडोमेन प्राप्त करने का सबसे तेज़ तरीका बाहरी स्रोतों में खोज करना है। सबसे अधिक उपयोग किए जाने वाले **tools** निम्नलिखित हैं (बेहतर परिणामों के लिए API कुंजी कॉन्फ़िगर करें):

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
कुछ **अन्य दिलचस्प उपकरण/APIs** जो सीधे तौर पर उपडोमेन खोजने में विशेषज्ञ नहीं हैं, फिर भी उपडोमेन खोजने के लिए उपयोगी हो सकते हैं, जैसे:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) का उपयोग करके उपडोमेन प्राप्त करता है
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC मुफ्त API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** किसी दिए गए डोमेन के लिए AlienVault के Open Threat Exchange, Wayback Machine, और Common Crawl से ज्ञात URLs को लाता है।
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **और** [**subscraper**](https://github.com/Cillian-Collins/subscraper): वे वेब को स्क्रैप करते हैं, JS फ़ाइलों की तलाश करते हैं और वहां से उपडोमेन निकालते हैं।
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
- [**Censys उपडोमेन खोजक**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) में उपडोमेन और IP इतिहास के लिए एक मुफ्त API है
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

यह प्रोजेक्ट **बग-बाउंटी कार्यक्रमों से संबंधित सभी उपडोमेन मुफ्त में** प्रदान करता है। आप इस डेटा को [chaospy](https://github.com/dr-0x0x/chaospy) का उपयोग करके भी एक्सेस कर सकते हैं या यहां तक कि इस प्रोजेक्ट द्वारा उपयोग किए गए दायरे को भी एक्सेस कर सकते हैं [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

आप यहां इन उपकरणों की **तुलना** पा सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS ब्रूट फोर्स**

आइए संभावित उपडोमेन नामों का उपयोग करके DNS सर्वरों को ब्रूट-फोर्स करके नए **उपडोमेन** खोजने की कोशिश करें।

इस क्रिया के लिए आपको कुछ **सामान्य उपडोमेन शब्दसूचियों की आवश्यकता होगी जैसे**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

और अच्छे DNS रिसोल्वर्स के IPs भी। विश्वसनीय DNS रिसोल्वर्स की एक सूची बनाने के लिए आप [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) से रिसोल्वर्स डाउनलोड कर सकते हैं और उन्हें फ़िल्टर करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग कर सकते हैं। या आप उपयोग कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS ब्रूट-फोर्स के लिए सबसे अनुशंसित उपकरण हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह पहला उपकरण था जिसने प्रभावी DNS ब्रूट-फोर्स किया। यह बहुत तेज है हालांकि यह गलत सकारात्मक के प्रति संवेदनशील है।
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): मुझे लगता है कि यह केवल 1 रिसॉल्वर का उपयोग करता है
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के चारों ओर एक wrapper है, जो गो में लिखा गया है, जो आपको सक्रिय ब्रूटफोर्स का उपयोग करके मान्य उपडोमेन की गणना करने की अनुमति देता है, साथ ही वाइल्डकार्ड हैंडलिंग और आसान इनपुट-आउटपुट समर्थन के साथ उपडोमेन को हल करता है।
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): यह भी `massdns` का उपयोग करता है।
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) डोमेन नामों को असिंक्रोनसली ब्रूट फोर्स करने के लिए asyncio का उपयोग करता है।
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Second DNS Brute-Force Round

खुले स्रोतों और ब्रूट-फोर्सिंग का उपयोग करके उपडोमेन खोजने के बाद, आप पाए गए उपडोमेन के परिवर्तनों को उत्पन्न कर सकते हैं ताकि और भी अधिक खोजने की कोशिश की जा सके। इस उद्देश्य के लिए कई उपकरण उपयोगी हैं:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** दिए गए डोमेन और उपडोमेन के लिए permutations उत्पन्न करता है।
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): डोमेन और सबडोमेन दिए जाने पर संयोजन उत्पन्न करें।
- आप [**यहां**](https://github.com/subfinder/goaltdns/blob/master/words.txt) goaltdns संयोजन **शब्दसूची** प्राप्त कर सकते हैं।
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** डोमेन और सबडोमेन दिए जाने पर उत्परिवर्तन उत्पन्न करें। यदि उत्परिवर्तन फ़ाइल निर्दिष्ट नहीं की गई है, तो gotator अपनी स्वयं की फ़ाइल का उपयोग करेगा।
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): उपडोमेन संयोजनों को उत्पन्न करने के अलावा, यह उन्हें हल करने की कोशिश भी कर सकता है (लेकिन पहले टिप्पणी किए गए उपकरणों का उपयोग करना बेहतर है)।
- आप altdns संयोजन **शब्दसूची** [**यहां**](https://github.com/infosec-au/altdns/blob/master/words.txt) प्राप्त कर सकते हैं।
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): उपडोमेन के संयोजन, उत्परिवर्तन और परिवर्तन करने के लिए एक और उपकरण। यह उपकरण परिणाम को ब्रूट फोर्स करेगा (यह dns वाइल्ड कार्ड का समर्थन नहीं करता)।
- आप [**यहां**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) dmut संयोजन शब्द सूची प्राप्त कर सकते हैं।
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** एक डोमेन के आधार पर यह **संकेतित पैटर्न** के आधार पर नए संभावित उपडोमेन नाम **जनरेट** करता है ताकि अधिक उपडोमेन खोजने की कोशिश की जा सके।

#### स्मार्ट परम्यूटेशन जनरेशन

- [**regulator**](https://github.com/cramppet/regulator): अधिक जानकारी के लिए इस [**पोस्ट**](https://cramppet.github.io/regulator/index.html) को पढ़ें लेकिन यह मूल रूप से **खोजे गए उपडोमेन** के **मुख्य भागों** को लेगा और उन्हें मिलाकर अधिक उपडोमेन खोजने की कोशिश करेगा।
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक उपडोमेन ब्रूट-फोर्स फज़्ज़र है जो एक अत्यंत सरल लेकिन प्रभावी DNS प्रतिक्रिया-निर्देशित एल्गोरिदम के साथ जुड़ा हुआ है। यह एक प्रदान किए गए इनपुट डेटा सेट का उपयोग करता है, जैसे कि एक अनुकूलित शब्द सूची या ऐतिहासिक DNS/TLS रिकॉर्ड, ताकि अधिक संबंधित डोमेन नामों को सटीक रूप से संश्लेषित किया जा सके और DNS स्कैन के दौरान एकत्रित जानकारी के आधार पर उन्हें और भी आगे बढ़ाया जा सके।
```
echo www | subzuf facebook.com
```
### **सबडोमेन खोज कार्यप्रवाह**

चेक करें इस ब्लॉग पोस्ट को जो मैंने लिखा है कि कैसे **सबडोमेन खोज को स्वचालित करें** एक डोमेन से **Trickest कार्यप्रवाह** का उपयोग करके ताकि मुझे अपने कंप्यूटर में कई टूल मैन्युअल रूप से लॉन्च करने की आवश्यकता न हो:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / वर्चुअल होस्ट**

यदि आपने एक IP पता पाया है जिसमें **एक या एक से अधिक वेब पृष्ठ** सबडोमेनों से संबंधित हैं, तो आप **उस IP में वेब के साथ अन्य सबडोमेनों को खोजने** की कोशिश कर सकते हैं **OSINT स्रोतों** में IP में डोमेन के लिए देखने या **उस IP में VHost डोमेन नामों को ब्रूट-फोर्स करके**।

#### OSINT

आप कुछ **VHosts को IPs में खोज सकते हैं** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs का उपयोग करके**।

**ब्रूट फोर्स**

यदि आपको संदेह है कि कुछ सबडोमेन एक वेब सर्वर में छिपा हो सकता है, तो आप इसे ब्रूट फोर्स करने की कोशिश कर सकते हैं:
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
> इस तकनीक के साथ, आप आंतरिक/छिपे हुए एंडपॉइंट्स तक भी पहुँच सकते हैं।

### **CORS Brute Force**

कभी-कभी आप ऐसी पृष्ठों को पाएंगे जो केवल _**Access-Control-Allow-Origin**_ हेडर को लौटाते हैं जब _**Origin**_ हेडर में एक मान्य डोमेन/सबडोमेन सेट किया गया हो। इन परिदृश्यों में, आप इस व्यवहार का दुरुपयोग करके **नए** **सबडोमेन** को **खोज** सकते हैं।
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **बकेट्स ब्रूट फोर्स**

जब आप **सबडोमेन** की तलाश कर रहे हों, तो देखें कि क्या यह किसी प्रकार के **बकेट** की ओर **संकेत** कर रहा है, और इस मामले में [**अनुमतियों की जांच करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
इसके अलावा, चूंकि इस बिंदु पर आप दायरे के भीतर सभी डोमेन को जानेंगे, कोशिश करें [**संभावित बकेट नामों को ब्रूट फोर्स करें और अनुमतियों की जांच करें**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **निगरानी**

आप **सर्टिफिकेट ट्रांसपेरेंसी** लॉग्स की निगरानी करके देख सकते हैं कि किसी डोमेन के **नए सबडोमेन** बनाए गए हैं [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)।

### **कमजोरियों की तलाश**

संभावित [**सबडोमेन टेकओवर**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) के लिए जांचें।\
यदि **सबडोमेन** किसी **S3 बकेट** की ओर संकेत कर रहा है, तो [**अनुमतियों की जांच करें**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

यदि आप किसी **सबडोमेन को एक IP अलग** पाते हैं जो आपने पहले से संपत्तियों की खोज में पाया है, तो आपको एक **बुनियादी कमजोरियों का स्कैन** (Nessus या OpenVAS का उपयोग करके) और कुछ [**पोर्ट स्कैन**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **nmap/masscan/shodan** के साथ करना चाहिए। चल रहे सेवाओं के आधार पर, आप **इस पुस्तक में कुछ तरकीबें "हमला" करने के लिए** पा सकते हैं।\
&#xNAN;_&#x4E;ote करें कि कभी-कभी सबडोमेन एक IP के अंदर होस्ट किया जाता है जो ग्राहक द्वारा नियंत्रित नहीं होता है, इसलिए यह दायरे में नहीं है, सावधान रहें।_

## IPs

प्रारंभिक चरणों में, आप **कुछ IP रेंज, डोमेन और सबडोमेन** पा सकते हैं।\
अब **उन रेंज से सभी IPs को इकट्ठा करने** और **डोमेन/सबडोमेन (DNS क्वेरी)** के लिए समय है।

निम्नलिखित **फ्री APIs** की सेवाओं का उपयोग करके, आप **डोमेन और सबडोमेन द्वारा उपयोग किए गए पिछले IPs** भी पा सकते हैं। ये IPs अभी भी ग्राहक के स्वामित्व में हो सकते हैं (और आपको [**CloudFlare बायपास**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) खोजने की अनुमति दे सकते हैं)

- [**https://securitytrails.com/**](https://securitytrails.com/)

आप [**hakip2host**](https://github.com/hakluke/hakip2host) टूल का उपयोग करके एक विशिष्ट IP पते की ओर इशारा करने वाले डोमेन की भी जांच कर सकते हैं।

### **कमजोरियों की तलाश**

**CDNs से संबंधित सभी IPs का पोर्ट स्कैन करें** (क्योंकि आप वहां कुछ दिलचस्प नहीं पाएंगे)। चल रही सेवाओं में, आप **कमजोरियों को खोजने में सक्षम हो सकते हैं**।

**होस्ट स्कैन करने के लिए एक** [**गाइड**](../pentesting-network/index.html) **खोजें।**

## वेब सर्वर शिकार

> हमने सभी कंपनियों और उनके संपत्तियों को खोज लिया है और हम दायरे के भीतर IP रेंज, डोमेन और सबडोमेन जानते हैं। अब वेब सर्वरों की खोज करने का समय है।

पिछले चरणों में, आपने शायद पहले से ही खोजे गए IPs और डोमेन का कुछ **रिपोर्ट किया है**, इसलिए आप **संभावित सभी वेब सर्वरों** को पहले से ही पा चुके होंगे। हालाँकि, यदि आपने नहीं किया है, तो हम अब दायरे के भीतर वेब सर्वरों की खोज के लिए कुछ **तेज़ तरकीबें** देखेंगे।

कृपया ध्यान दें कि यह **वेब ऐप्स की खोज के लिए उन्मुख** होगा, इसलिए आपको **कमजोरियों** और **पोर्ट स्कैनिंग** भी करनी चाहिए (**यदि दायरे द्वारा अनुमति दी गई हो**).

**वेब** सर्वरों से संबंधित **खुले पोर्ट** खोजने के लिए एक **तेज़ विधि** [**masscan** का उपयोग करके यहां पाई जा सकती है](../pentesting-network/index.html#http-port-discovery)।\
वेब सर्वरों की खोज के लिए एक और उपयोगी टूल [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx) है। आप बस डोमेन की एक सूची पास करते हैं और यह पोर्ट 80 (http) और 443 (https) से कनेक्ट करने की कोशिश करेगा। इसके अतिरिक्त, आप अन्य पोर्ट की कोशिश करने के लिए संकेत दे सकते हैं:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

अब जब आपने **सभी वेब सर्वर** खोज लिए हैं जो दायरे में हैं (कंपनी के **IPs** और सभी **डोमेन** और **सबडोमेन** के बीच) तो शायद आप **शुरुआत कहाँ से करें** यह नहीं जानते। तो, इसे सरल बनाते हैं और बस सभी का स्क्रीनशॉट लेना शुरू करते हैं। बस **मुख्य पृष्ठ** पर **नज़र डालकर** आप **अजीब** एंडपॉइंट्स पा सकते हैं जो अधिक **संवेदनशील** हो सकते हैं।

प्रस्तावित विचार को लागू करने के लिए आप [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** का उपयोग कर सकते हैं।**

इसके अलावा, आप फिर [**eyeballer**](https://github.com/BishopFox/eyeballer) का उपयोग कर सकते हैं ताकि सभी **स्क्रीनशॉट्स** पर चलाकर आपको बता सके कि **क्या संभावित रूप से कमजोरियों को शामिल कर सकता है**, और क्या नहीं।

## सार्वजनिक क्लाउड संपत्तियाँ

किसी कंपनी की संभावित क्लाउड संपत्तियों को खोजने के लिए आपको **उस कंपनी की पहचान करने वाले कीवर्ड्स की एक सूची से शुरू करना चाहिए**। उदाहरण के लिए, एक क्रिप्टो कंपनी के लिए आप शब्दों का उपयोग कर सकते हैं: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`।

आपको **बकेट्स में उपयोग किए जाने वाले सामान्य शब्दों** की वर्डलिस्ट भी चाहिए:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, उन शब्दों के साथ आपको **परम्यूटेशन** उत्पन्न करनी चाहिए (अधिक जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

परिणामी वर्डलिस्ट के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** का उपयोग कर सकते हैं।**

याद रखें कि जब आप क्लाउड संपत्तियों की खोज कर रहे हों तो आपको **AWS में बकेट्स से अधिक की तलाश करनी चाहिए**।

### **कमजोरियों की खोज**

यदि आप **खुले बकेट्स या क्लाउड फ़ंक्शंस** खोजते हैं तो आपको **उनका उपयोग करना चाहिए** और देखना चाहिए कि वे आपको क्या प्रदान करते हैं और क्या आप उनका दुरुपयोग कर सकते हैं।

## ईमेल

दायरे में **डोमेन** और **सबडोमेन** के साथ आपके पास **ईमेल खोजने के लिए आवश्यक सभी चीजें** हैं। ये हैं **APIs** और **उपकरण** जो मुझे किसी कंपनी के ईमेल खोजने के लिए सबसे अच्छे लगे हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs के साथ
- [**https://hunter.io/**](https://hunter.io/) का API (फ्री संस्करण)
- [**https://app.snov.io/**](https://app.snov.io/) का API (फ्री संस्करण)
- [**https://minelead.io/**](https://minelead.io/) का API (फ्री संस्करण)

### **कमजोरियों की खोज**

ईमेल बाद में **वेब लॉगिन और ऑथ सेवाओं** (जैसे SSH) के लिए **ब्रूट-फोर्स** करने में सहायक होंगे। इसके अलावा, ये **फिशिंग** के लिए आवश्यक हैं। इसके अलावा, ये APIs आपको ईमेल के पीछे के व्यक्ति के बारे में और भी अधिक **जानकारी** प्रदान करेंगे, जो फिशिंग अभियान के लिए उपयोगी है।

## क्रेडेंशियल लीक

**डोमेन,** **सबडोमेन**, और **ईमेल** के साथ आप उन ईमेल से संबंधित अतीत में लीक हुए क्रेडेंशियल्स की खोज शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **कमजोरियों की खोज**

यदि आप **मान्य लीक** हुए क्रेडेंशियल्स पाते हैं, तो यह एक बहुत आसान जीत है।

## सीक्रेट्स लीक

क्रेडेंशियल लीक उन कंपनियों के हैक से संबंधित हैं जहाँ **संवेदनशील जानकारी लीक और बेची गई**। हालाँकि, कंपनियाँ **अन्य लीक** से प्रभावित हो सकती हैं जिनकी जानकारी उन डेटाबेस में नहीं है:

### गिटहब लीक

क्रेडेंशियल्स और APIs **कंपनी** या उस गिटहब कंपनी के **उपयोगकर्ताओं** के **सार्वजनिक रिपॉजिटरी** में लीक हो सकते हैं।\
आप **उपकरण** [**Leakos**](https://github.com/carlospolop/Leakos) का उपयोग करके किसी **संगठन** और उसके **डेवलपर्स** के सभी **सार्वजनिक रिपॉजिटरी** को **डाउनलोड** कर सकते हैं और उन पर स्वचालित रूप से [**gitleaks**](https://github.com/zricethezav/gitleaks) चला सकते हैं।

**Leakos** का उपयोग सभी **पाठ** प्रदान किए गए **URLs** पर **gitleaks** चलाने के लिए भी किया जा सकता है क्योंकि कभी-कभी **वेब पृष्ठों में भी रहस्य होते हैं**।

#### गिटहब डॉर्क्स

आप उस **पृष्ठ** की भी जांच करें जहाँ संभावित **गिटहब डॉर्क्स** हैं जिन्हें आप उस संगठन में खोज सकते हैं जिसे आप लक्षित कर रहे हैं:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### पेस्ट लीक

कभी-कभी हमलावर या बस कर्मचारी **कंपनी की सामग्री को एक पेस्ट साइट पर प्रकाशित करेंगे**। इसमें **संवेदनशील जानकारी** हो सकती है या नहीं, लेकिन इसे खोजना बहुत दिलचस्प है।\
आप **उपकरण** [**Pastos**](https://github.com/carlospolop/Pastos) का उपयोग करके एक साथ 80 से अधिक पेस्ट साइटों में खोज कर सकते हैं।

### गूगल डॉर्क्स

पुराने लेकिन सुनहरे गूगल डॉर्क्स हमेशा **वहां नहीं होनी चाहिए ऐसी उजागर जानकारी** खोजने के लिए उपयोगी होते हैं। एकमात्र समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **हजारों** संभावित क्वेरीज़ हैं जिन्हें आप मैन्युअल रूप से नहीं चला सकते। इसलिए, आप अपने पसंदीदा 10 को ले सकते हैं या आप **उपकरण जैसे** [**Gorks**](https://github.com/carlospolop/Gorks) **का उपयोग कर सकते हैं** **उन सभी को चलाने के लिए**।

_ध्यान दें कि जो उपकरण नियमित गूगल ब्राउज़र का उपयोग करके सभी डेटाबेस को चलाने की उम्मीद करते हैं, वे कभी समाप्त नहीं होंगे क्योंकि गूगल आपको बहुत जल्दी ब्लॉक कर देगा।_

### **कमजोरियों की खोज**

यदि आप **मान्य लीक** हुए क्रेडेंशियल्स या API टोकन पाते हैं, तो यह एक बहुत आसान जीत है।

## सार्वजनिक कोड कमजोरियाँ

यदि आपने पाया कि कंपनी का **ओपन-सोर्स कोड** है तो आप इसे **विश्लेषण** कर सकते हैं और इसमें **कमजोरियों** की खोज कर सकते हैं।

**भाषा के आधार पर** आप विभिन्न **उपकरणों** का उपयोग कर सकते हैं:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

कुछ मुफ्त सेवाएँ भी हैं जो आपको **सार्वजनिक रिपॉजिटरी** को **स्कैन** करने की अनुमति देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**कमजोरियों** की **अधिकांशता** जो बग हंटर्स द्वारा पाई जाती है, **वेब अनुप्रयोगों** के अंदर होती है, इसलिए इस बिंदु पर मैं एक **वेब अनुप्रयोग परीक्षण पद्धति** के बारे में बात करना चाहता हूँ, और आप [**यहाँ इस जानकारी को पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं [**वेब स्वचालित स्कैनर्स ओपन सोर्स टूल्स**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) अनुभाग का विशेष उल्लेख करना चाहता हूँ, क्योंकि, यदि आप उनसे बहुत संवेदनशील कमजोरियों की खोज करने की उम्मीद नहीं करते हैं, तो वे **प्रारंभिक वेब जानकारी प्राप्त करने के लिए कार्यप्रवाहों में लागू करने के लिए सहायक होते हैं।**

## पुनरावलोकन

> बधाई हो! इस बिंदु पर आपने पहले ही **सभी बुनियादी गणना** कर ली है। हाँ, यह बुनियादी है क्योंकि और भी बहुत अधिक गणना की जा सकती है (बाद में और तरकीबें देखेंगे)।

तो आपने पहले ही:

1. दायरे में सभी **कंपनियों** को खोज लिया
2. कंपनियों से संबंधित सभी **संपत्तियों** को खोज लिया (और यदि दायरे में हो तो कुछ कमजोरियों का स्कैन किया)
3. कंपनियों से संबंधित सभी **डोमेन** को खोज लिया
4. डोमेन के सभी **सबडोमेन** को खोज लिया (क्या कोई सबडोमेन टेकओवर?)
5. दायरे में सभी **IPs** (CDNs से और **नहीं**) को खोज लिया।
6. सभी **वेब सर्वर** को खोज लिया और उनका **स्क्रीनशॉट** लिया (क्या कुछ अजीब है जो गहराई से देखने लायक है?)
7. कंपनी से संबंधित सभी **संभावित सार्वजनिक क्लाउड संपत्तियों** को खोज लिया।
8. **ईमेल**, **क्रेडेंशियल लीक**, और **सीक्रेट लीक** जो आपको **बहुत आसानी से एक बड़ा लाभ** दे सकते हैं।
9. आपने जो भी वेब खोजी हैं उनका **पेंटेस्टिंग** किया।

## **पूर्ण रीकॉन स्वचालित उपकरण**

कुछ उपकरण हैं जो दिए गए दायरे के खिलाफ प्रस्तावित कार्यों के कुछ हिस्सों को करेंगे।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - थोड़ा पुराना और अपडेट नहीं किया गया

## **संदर्भ**

- [**@Jhaddix**](https://twitter.com/Jhaddix) के सभी मुफ्त पाठ्यक्रम जैसे [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
