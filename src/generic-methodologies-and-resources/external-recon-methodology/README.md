# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets की खोज

> तो आपको बताया गया कि किसी कंपनी की सब कुछ scope के अंदर है, और आप यह पता लगाना चाहते हैं कि उस कंपनी के पास वास्तव में क्या-क्या है।

इस चरण का उद्देश्य मुख्य कंपनी द्वारा स्वामित्व वाली सभी **companies** प्राप्त करना और फिर उन कंपनियों की सभी **assets** प्राप्त करना है। ऐसा करने के लिए, हम निम्न करेंगे:

1. मुख्य कंपनी के acquisitions खोजें, इससे हमें scope के अंदर आने वाली कंपनियाँ मिलेंगी।
2. प्रत्येक कंपनी का ASN (यदि कोई हो) खोजें, इससे हमें प्रत्येक कंपनी के द्वारा मालिकाना IP ranges मिलेंगे
3. reverse whois lookups का उपयोग करके पहले एंट्री से संबंधित अन्य एंट्रियाँ (organisation names, domains...) खोजें (यह रीकर्सिव रूप से किया जा सकता है)
4. shodan जैसे अन्य techniques का उपयोग करें — `org` और `ssl` filters से अन्य assets खोजने के लिए (the `ssl` trick रीकर्सिव रूप से किया जा सकता है)।

### **Acquisitions**

सबसे पहले, हमें यह जानना होगा कि मुख्य कंपनी के पास कौन-कौन सी **other companies** हैं।\
एक विकल्प है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाना, मुख्य कंपनी को **search** करना, और "**acquisitions**" पर **click** करना। वहाँ आपको मुख्य कंपनी द्वारा acquired अन्य कंपनियाँ दिखेंगी।\
एक और विकल्प है मुख्य कंपनी के **Wikipedia** पेज पर जाना और **acquisitions** खोजना।\
public companies के लिए, **SEC/EDGAR filings**, **investor relations** पेज, या स्थानीय corporate registries (जैसे UK में **Companies House**) चेक करें।\
global corporate trees और subsidiaries के लिए, **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आजमाएँ।

> ठीक है, इस बिंदु पर आपके पास scope के अंदर आने वाली सभी कंपनियों की सूची होनी चाहिए। आइए पता करें कि उनकी assets कैसे ढूंढनी हैं।

### **ASNs**

An autonomous system number (**ASN**) एक **unique number** है जो एक autonomous system (**AS**) को **Internet Assigned Numbers Authority (IANA)** द्वारा असाइन किया जाता है।\
एक **AS** उन **IP addresses** के **blocks** से मिलकर बना होता है जिनकी बाहरी नेटवर्क तक पहुंच के लिए स्पष्ट नीति होती है और जिन्हें एक ही organisation द्वारा प्रबंधित किया जाता है, हालांकि यह कई operators से मिलकर भी बन सकता है।

यह जानना उपयोगी है कि क्या किसी **company** को कोई **ASN** असाइन किया गया है ताकि उसकी **IP ranges** मिल सकें। यह दिलचस्प होगा कि scope के अंदर मौजूद सभी **hosts** पर एक vulnerability test किया जाए और इन IPs के अंदर domains की तलाश की जाए।\
आप [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **या** [**https://ipinfo.io/**](https://ipinfo.io/) में company **name**, **IP** या **domain** से **search** कर सकते हैं।\
**कंपनी के क्षेत्र के आधार पर ये links और भी उपयोगी हो सकते हैं: **[**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). वैसे भी, संभवतः सारी उपयोगी जानकारी (IP ranges और Whois) पहले लिंक में ही पहले से दिखाई दे जाती है।**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Also, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration स्वचालित रूप से ASNs को scan के अंत में समूहित और सारांशित करता है।
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

इस बिंदु पर हम **all the assets inside the scope** जानते हैं, तो अगर आपको अनुमति है तो आप सभी hosts पर कुछ **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप कुछ [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं या Shodan, Censys, या ZoomEye जैसी सेवाओं का उपयोग करके open ports ढूंढ सकते हैं, और जो कुछ आप पाते हैं उसके आधार पर आपको इस किताब में देखना चाहिए कि कैसे कई संभावित services को pentest किया जाए।\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> हम scope के अंदर की सभी companies और उनके assets जानते हैं, अब scope के अंदर के domains ढूंढने का समय है।
> 
> _कृपया ध्यान दें कि नीचे दिए गए प्रस्तावित techniques में आप subdomains भी पा सकते हैं और इस जानकारी को कम करके नहीं आंका जाना चाहिए._

सबसे पहले आपको प्रत्येक company के **main domain**(s) देखना चाहिए। उदाहरण के लिए, _Tesla Inc._ के लिए यह _tesla.com_ होगा।

### **Reverse DNS**

जैसा कि आपने domains की सभी IP ranges पा ली हैं, आप उन पर **reverse dns lookups** करने की कोशिश कर सकते हैं ताकि आप और domains scope के अंदर खोज सकें। victim के किसी dns server या किसी प्रसिद्ध dns server (1.1.1.1, 8.8.8.8) का उपयोग करने की कोशिश करें।
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
आप इस जानकारी के लिए ऑनलाइन टूल भी उपयोग कर सकते हैं: [http://ptrarchive.com/](http://ptrarchive.com).\
For large ranges, tools like [**massdns**](https://github.com/blechschmidt/massdns) and [**dnsx**](https://github.com/projectdiscovery/dnsx) are useful to automate reverse lookups and enrichment.

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **जानकारियाँ** like **संगठन का नाम**, **पता**, **ईमेल**, फोन नंबर... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
You can use online tools like:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **निःशुल्क**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **निःशुल्क**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **निःशुल्क**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **निःशुल्क** वेब, API मुफ्त नहीं.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com/) - मुफ्त नहीं
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - मुफ्त नहीं (केवल **100 निःशुल्क** सर्च)
- [https://www.domainiq.com/](https://www.domainiq.com) - मुफ्त नहीं
- [https://securitytrails.com/](https://securitytrails.com/) - मुफ्त नहीं (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - मुफ्त नहीं (API)

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
आप इस कार्य को [**DomLink**](https://github.com/vysecurity/DomLink) का उपयोग करके ऑटोमेट कर सकते हैं (इसके लिए whoxy API कुंजी की आवश्यकता होती है)।\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**  
ध्यान दें कि इस तकनीक का उपयोग आप हर बार जब आप एक नया डोमेन पाते हैं तो और डोमेन नाम खोजने के लिए कर सकते हैं।

### **ट्रैकर्स**

यदि आप 2 अलग पृष्ठों में **एक ही tracker की वही ID** पाते हैं तो आप मान सकते हैं कि **दोनों पेज** **एक ही टीम द्वारा प्रबंधित** हैं।\
उदाहरण के लिए, यदि आप कई पृष्ठों पर वही **Google Analytics ID** या वही **Adsense ID** देखते हैं।

There are some pages and tools that let you search by these trackers and more:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Did you know that we can find related domains and subdomains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:  
क्या आप जानते हैं कि हम अपने लक्ष्य से संबंधित डोमेन और सबडोमेन वही favicon icon hash देखकर खोज सकते हैं? यह बिल्कुल वही है जो [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) टूल (जिसे [@m4ll0k2](https://twitter.com/m4ll0k2) ने बनाया है) करता है। इसे इस्तेमाल करने का तरीका यहाँ है:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - समान favicon icon hash वाले डोमेन्स खोजें](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

साधारण शब्दों में, favihash हमें उन डोमेनों का पता लगाने की अनुमति देता है जिनका favicon icon hash हमारे target के समान होता है।

इसके अलावा, आप भी favicon hash का उपयोग करके technologies को खोज सकते हैं जैसा कि [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) में समझाया गया है। इसका मतलब यह है कि यदि आप **hash of the favicon of a vulnerable version of a web tech** जानते हैं तो आप इसे shodan में खोज सकते हैं और **find more vulnerable places**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
इस तरह आप किसी वेबसाइट का **favicon hash** निकाल सकते हैं:
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
You can also get favicon hashes at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

### **कॉपीराइट / यूनिक स्ट्रिंग**

वेब पेजों के अंदर **ऐसी स्ट्रिंग्स खोजें जो एक ही संगठन के विभिन्न वेब्स में साझा की जा सकती हैं**। **कॉपीराइट स्ट्रिंग** एक अच्छा उदाहरण हो सकती है। फिर उस स्ट्रिंग को **google**, अन्य **browsers** में या यहां तक कि **shodan** में खोजें: `shodan search http.html:"Copyright string"`

### **CRT Time**

अक्सर ऐसे cron job होते हैं, जैसे
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
सर्वर पर सभी डोमेन सर्टिफिकेट्स को renew करने के लिए। इसका मतलब है कि भले ही इस काम के लिए इस्तेमाल की गई CA ने Validity समय में जनरेट होने का समय सेट न किया हो, फिर भी **certificate transparency logs में उसी कंपनी से संबंधित domains को ढूँढना** संभव है।\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

आप [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी वेबसाइट या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे टूल का उपयोग करके **एक ही dmarc जानकारी साझा करने वाले domains और subdomain** खोज सकते हैं।\
अन्य उपयोगी टूल हैं [**spoofcheck**](https://github.com/BishopFox/spoofcheck) और [**dmarcian**](https://dmarcian.com/)।

### **Passive Takeover**

ऐसा आम है कि लोग subdomains को cloud providers के IPs पर असाइन कर देते हैं और किसी समय वे **उस IP address को खो देते हैं पर DNS रिकॉर्ड हटाना भूल जाते हैं**। इसलिए, बस किसी cloud (जैसे Digital Ocean) में **एक VM spawn करने** से आप वास्तव में कुछ subdomains(s) को **taking over** कर सकते हैं।

[**This post**](https://kmsec.uk/blog/passive-takeover/) इस बारे में एक कहानी बताता है और एक स्क्रिप्ट प्रस्तावित करता है जो **DigitalOcean में एक VM spawn करता है**, नए मशीन का **IPv4** प्राप्त करता है, और उस IP की ओर इशारा करने वाले subdomain records के लिए **VirusTotal में search करता है**।

### **Other ways**

**ध्यान दें कि आप इस तकनीक का उपयोग हर बार जब आप कोई नया domain पाते हैं तब और अधिक domain नाम खोजने के लिए कर सकते हैं।**

**Shodan**

जैसा कि आपको पहले से पता है, IP space का मालिक संगठन का नाम है। आप shodan में उस जानकारी से खोज सकते हैं: `org:"Tesla, Inc."` मिले हुए hosts के TLS certificate में नए अप्रत्याशित domains की जाँच करें।

आप मुख्य वेब पेज के **TLS certificate** तक पहुंचकर **Organisation name** प्राप्त कर सकते हैं और फिर उस नाम को **shodan** द्वारा ज्ञात सभी वेब पेजों के **TLS certificates** में filter `ssl:"Tesla Motors"` के साथ खोज सकते हैं या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसे टूल का उपयोग कर सकते हैं।

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) एक टूल है जो मुख्य domain से संबंधित **domains** और उनके **subdomains** खोजता है, काफी अच्छा है।

**Passive DNS / Historical DNS**

Passive DNS डेटा उन **पुराने और भूल गए रिकॉर्ड्स** को ढूँढने के लिए बहुत उपयोगी है जो अभी भी resolve होते हैं या जिन्हें take over किया जा सकता है। देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

कुछ [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) की जाँच करें। शायद कोई कंपनी किसी domain का उपयोग कर रही है लेकिन उसने ownership खो दी है। बस इसे रजिस्टर करें (अगर सस्ता हो) और कंपनी को सूचित करें।

यदि आप कोई **domain पाते हैं जिसका IP उन IPs से अलग है जो आपने assets discovery में पहले पाए थे**, तो आपको एक **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **nmap/masscan/shodan** के साथ करना चाहिए। चलने वाली सेवाओं पर निर्भर करते हुए आप **इस book में कुछ tricks पा सकते हैं जो उन्हें "attack" करने के लिए हैं**।\
_Note कि कभी-कभी domain किसी ऐसे IP पर होस्ट होता है जिसे client नियंत्रित नहीं करता, इसलिए यह scope में नहीं हो सकता — सावधान रहें._

## Subdomains

> हमें scope के अंदर सभी कंपनियों, हर कंपनी के सभी assets और कंपनियों से संबंधित सभी domains पता हैं।

अब हर मिले हुए domain के सभी संभावित subdomains खोजने का समय है।

> [!TIP]
> ध्यान दें कि कुछ tools और techniques जो domains खोजने में उपयोग होते हैं, वे subdomains खोजने में भी मदद कर सकते हैं

### **DNS**

आइए **DNS** रिकॉर्ड्स से **subdomains** प्राप्त करने की कोशिश करें। हमें **Zone Transfer** के लिए भी प्रयास करना चाहिए (यदि vulnerable है, तो आपको इसे रिपोर्ट करना चाहिए)।
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

बहुत सारे subdomains प्राप्त करने का सबसे तेज़ तरीका बाहरी स्रोतों में खोज करना है। सबसे अधिक उपयोग किए जाने वाले **tools** निम्नलिखित हैं (बेहतर परिणामों के लिए API keys कॉन्फ़िगर करें):

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
वहां **अन्य दिलचस्प tools/APIs** हैं जो भले ही सीधे subdomains खोजने के लिए विशेषीकृत न हों, फिर भी subdomains खोजने में उपयोगी हो सकते हैं, जैसे:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) का उपयोग करके subdomains प्राप्त करता है
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
- [**gau**](https://github.com/lc/gau)**:** किसी भी दिए गए domain के लिए AlienVault's Open Threat Exchange, Wayback Machine, और Common Crawl से ज्ञात URLs प्राप्त करता है।
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): वे वेब को स्क्रैप करके JS files की तलाश करते हैं और वहाँ से subdomains निकालते हैं।
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
- [**securitytrails.com**](https://securitytrails.com/) के पास subdomains और IP history खोजने के लिए एक मुफ्त API है
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

यह project bug-bounty programs से संबंधित सभी subdomains को मुफ्त में प्रदान करता है। आप इस data को chaospy का उपयोग करके भी एक्सेस कर सकते हैं या इस project द्वारा उपयोग किए गए scope को भी एक्सेस कर सकते हैं [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

आप इन tools की तुलना यहाँ पा सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

आइए संभावित subdomain नामों का उपयोग करके DNS servers को brute-force करके नए **subdomains** खोजने की कोशिश करें।

इस कार्रवाई के लिए आपको कुछ सामान्य subdomains wordlists की आवश्यकता होगी, जैसे:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

और साथ ही अच्छे DNS resolvers के IPs भी। भरोसेमंद DNS resolvers की सूची बनाने के लिए आप resolvers को [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) से डाउनलोड करके [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग करके उन्हें फिल्टर कर सकते हैं। या आप यह भी उपयोग कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे अधिक सुझाए गए tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह पहला tool था जिसने प्रभावी DNS brute-force किया। यह बहुत तेज़ है, हालांकि यह false positives के प्रति प्रवण है।
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): मुझे लगता है यह केवल 1 resolver का उपयोग करता है
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के लिए go में लिखा गया एक wrapper है, जो आपको active bruteforce का उपयोग करके वैध subdomains enumerate करने और wildcard handling तथा आसान input-output समर्थन के साथ उन्हें resolve करने की सुविधा देता है।
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): यह भी `massdns` का उपयोग करता है।
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) asyncio का उपयोग करके डोमेन नामों को असिंक्रोनस रूप से brute force करता है.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### दूसरा DNS Brute-Force राउंड

ओपन सोर्स और brute-forcing का उपयोग करके सबडोमेन खोजने के बाद, आप पाए गए सबडोमेनों के परिवर्तनों को जनरेट करके और भी अधिक ढूँढने की कोशिश कर सकते हैं। इस उद्देश्य के लिए कई टूल उपयोगी हैं:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** दिए गए डोमेन और सबडोमेनों के permutations जनरेट करता है।
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): दी गई domains और subdomains के लिए permutations बनाता है.
- आप goaltdns permutations **wordlist** [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) में पा सकते हैं.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** डोमेन और सबडोमेन देकर permutations जनरेट करता है। अगर कोई permutations फ़ाइल निर्दिष्ट नहीं की गई है तो gotator अपनी खुद की फ़ाइल का उपयोग करेगा।
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): generating subdomains permutations के अलावा, यह उन्हें resolve करने की भी कोशिश कर सकता है (लेकिन previous commented tools का उपयोग करना बेहतर है)।
- आप altdns permutations **wordlist** को [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) से प्राप्त कर सकते हैं।
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomains के permutations, mutations और alteration करने के लिए एक और tool। यह tool परिणामों पर brute force करेगा (यह dns wild card को सपोर्ट नहीं करता)।
- आप dmut permutations wordlist [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) से प्राप्त कर सकते हैं।
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** एक domain के आधार पर यह निर्दिष्ट patterns के अनुसार और अधिक subdomains खोजने की कोशिश करने के लिए **संभावित नए subdomains नाम उत्पन्न करता है**।

#### स्मार्ट permutations जनरेशन

- [**regulator**](https://github.com/cramppet/regulator): अधिक जानकारी के लिए इस [**post**](https://cramppet.github.io/regulator/index.html) को पढ़ें लेकिन यह मूलतः **मुख्य हिस्से** को **खोजे गए subdomains** से निकालेगा और उन्हें मिलाकर और अधिक subdomains खोजेगा।
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है जो एक बेहद सरल और प्रभावी DNS reponse-guided algorithm के साथ जुड़ा हुआ है। यह प्रदान किए गए इनपुट डेटा सेट का उपयोग करता है, जैसे tailored wordlist या historical DNS/TLS records, ताकि यह और अधिक संबंधित domain नामों को सटीक रूप से उत्पन्न कर सके और DNS scan के दौरान एकत्र की गई जानकारी के आधार पर उन्हें एक लूप में और भी आगे बढ़ा सके।
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

यह ब्लॉग पोस्ट देखें जो मैंने लिखा है कि कैसे **subdomain discovery को स्वचालित करना** किसी डोमेन से **Trickest workflows** का उपयोग करके, ताकि मुझे अपने कंप्यूटर पर कई tools को मैन्युअली लॉन्च करने की जरूरत न पड़े:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

यदि आपको कोई IP address मिला है जिसमें **one or several web pages** मौजूद हैं जो subdomains से संबंधित हैं, तो आप उस IP में **find other subdomains with webs in that IP** की कोशिश कर सकते हैं — या तो किसी IP में डोमेन्स के लिए **OSINT sources** में देखकर, या **brute-forcing VHost domain names in that IP** करके।

#### OSINT

आप कुछ **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs** के माध्यम से पा सकते हैं।

**Brute Force**

यदि आपको संदेह है कि कोई subdomain किसी web server में छिपा हो सकता है, तो आप इसे brute force करने की कोशिश कर सकते हैं:

When the **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
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
> इस तकनीक के साथ आप internal/hidden endpoints तक भी पहुँच बना सकते हैं।

### **CORS Brute Force**

कभी-कभी आप ऐसे पेज पाएंगे जो केवल तब ही header _**Access-Control-Allow-Origin**_ लौटाते हैं जब _**Origin**_ header में कोई वैध domain/subdomain सेट किया गया हो। ऐसे मामलों में, आप इस व्यवहार का दुरुपयोग करके नए **subdomains** **खोज** सकते हैं।
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

जब आप **subdomains** की तलाश कर रहे हों तो देखिए कि क्या वह किसी प्रकार के **bucket** की ओर **pointing** कर रहा है, और ऐसे मामलों में [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
साथ ही, इस बिंदु पर क्योंकि आप scope के अंदर सभी डोमेन्स जान चुके होंगे, तो [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) करने की कोशिश करें।

### **Monitorization**

आप यह **monitor** कर सकते हैं कि किसी डोमेन के **new subdomains** बनाए जा रहे हैं या नहीं, जैसा कि **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) करता/करती है।

### **Looking for vulnerabilities**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
यदि **subdomain** किसी **S3 bucket** की ओर pointing कर रहा है, तो [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) करें।

यदि आपको कोई **subdomain with an IP different** मिलता है जो assets discovery में पहले पाए गए IPs से अलग है, तो आपको एक **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करते हुए) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **nmap/masscan/shodan** के साथ करने चाहिए। जिन सेवाओं का पता चलता है, उनके आधार पर आप **this book some tricks to "attack" them** पा सकते हैं।\
_नोट कि कभी-कभी subdomain ऐसे IP पर होस्ट होता है जिसे client नियंत्रित नहीं करता, इसलिए वह scope में नहीं आता — सावधान रहें._

## IPs

प्रारम्भिक चरणों में आप शायद कुछ **IP ranges, domains and subdomains** पाए होंगे।\
अब उन रेंजेस से सभी IPs **recollect** करने और domains/subdomains (DNS queries) के लिए समय है।

Using services from the following **free apis** you can also find **previous IPs used by domains and subdomains**. These IPs might still be owned by the client (and might allow you to find [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

You can also check for domains pointing a specific IP address using the tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (क्योंकि वहाँ आमतौर पर आप कुछ खास नहीं पाएँगे)। जो सेवाएँ चल रही हों उनमें आप संभावित **vulnerabilities** ढूँढ सकते हैं।

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> हमने सभी कंपनियाँ और उनके assets खोज लिए हैं और हमें scope के अंदर IP ranges, domains और subdomains पता हैं। अब web servers की खोज करने का समय है।

पहले के चरणों में आपने शायद पहले से ही discovered IPs और डोमेन्स पर कुछ **recon** किया होगा, इसलिए हो सकता है कि आप पहले से ही सभी संभावित web servers पा चुके हों। हालाँकि, अगर नहीं पाए हैं तो अब हम scope के अंदर web servers खोजने के कुछ तेज़ tricks देखेंगे।

कृपया ध्यान दें कि यह web apps discovery के लिये निर्देशित होगा, इसलिए आपको vulnerability और port scanning भी करना चाहिए (**यदि scope अनुमति देता है**).

एक तेज़ तरीका web से संबंधित open ports खोजने का [**masscan** का उपयोग करने के लिए यहाँ पाया जा सकता है](../pentesting-network/index.html#http-port-discovery).\
वेब सर्वरों की खोज के लिए एक दोस्ताना टूल [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx) भी हैं। आप बस domains की एक list पास करते हैं और यह पोर्ट 80 (http) और 443 (https) से connect करने की कोशिश करेगा। अतिरिक्त रूप से, आप अन्य ports भी ट्राय करने का निर्देश दे सकते हैं:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

अब जब आपने स्कोप में मौजूद **all the web servers** (कंपनी के **IPs** और हर **domains** और **subdomains** के बीच) को खोज लिया है, तो शायद आप **don't know where to start**। इसलिए इसे सरल रखें और बस उन सबका screenshots लेना शुरू करें। सिर्फ **main page** को **taking a look** करके आप ऐसे **weird** endpoints ढूंढ सकते हैं जो अधिक **prone** होते हैं **vulnerable** होने के लिए।

To perform the proposed idea you can use [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

इसके अलावा, आप बाद में [**eyeballer**](https://github.com/BishopFox/eyeballer) का उपयोग करके सभी **screenshots** पर चला सकते हैं ताकि वह आपको बता सके **what's likely to contain vulnerabilities**, और क्या नहीं।

## Public Cloud Assets

किसी कंपनी के संभावित cloud assets खोजने के लिए आपको **start with a list of keywords that identify that company** करने चाहिए। उदाहरण के लिए, एक crypto कंपनी के लिए आप ऐसे शब्द उपयोग कर सकते हैं: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`।

आपको **common words used in buckets** के लिए wordlists भी चाहिए होंगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Phir, उन शब्दों के साथ आपको **permutations** generate करने चाहिए (और अधिक जानकारी के लिए [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें)।

निष्कर्षित wordlists के साथ आप ऐसे tools उपयोग कर सकते हैं जैसे [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

ध्यान रखें कि जब आप Cloud Assets ढूंढ रहे हों तो आपको **look for more than just buckets in AWS**।

### **Looking for vulnerabilities**

यदि आप ऐसी चीजें पाते हैं जैसे **open buckets or cloud functions exposed** तो आपको उन्हें **access them** करके देखना चाहिए कि वे आपको क्या offer करते हैं और क्या आप उनका abuse कर सकते हैं।

## Emails

स्कोप के भीतर मौजूद **domains** और **subdomains** के साथ आपके पास बुनियादी रूप से वह सब है जो आपको **need to start searching for emails**। ये वे **APIs** और **tools** हैं जो मेरी तरफ़ से किसी कंपनी के emails खोजने में सबसे अच्छे साबित हुए हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails बाद में **brute-force web logins and auth services** (जैसे SSH) करने में काम आएँगी। साथ ही, ये **phishings** के लिए ज़रूरी हैं। इसके अलावा, ये APIs आपको उस ईमेल के पीछे के व्यक्ति के बारे में और भी अधिक **info about the person** देंगी, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**domains,** **subdomains**, और **emails** के साथ आप उन emails से संबंधित पहले हुए credentials leaked होने की खोज शुरू कर सकते हैं:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

यदि आप **valid leaked** credentials पाते हैं, तो यह एक बहुत आसान जीत है।

## Secrets Leaks

Credential leaks उन हमलों से संबंधित होते हैं जहाँ कंपनियों की **sensitive information was leaked and sold**। हालाँकि, कंपनियाँ अन्य तरह के **leaks** से भी प्रभावित हो सकती हैं जिनकी जानकारी उन databases में नहीं होती:

### Github Leaks

Credentials और APIs कंपनी के **public repositories** या उस github कंपनी में काम करने वाले **users** के public repos में leaked हो सकते हैं.\
आप इस **tool** [**Leakos**](https://github.com/carlospolop/Leakos) का उपयोग करके किसी **organization** और उसके **developers** के सभी **public repos** को **download** कर सकते हैं और उनके ऊपर स्वतः ही [**gitleaks**](https://github.com/zricethezav/gitleaks) चला सकते हैं।

**Leakos** का उपयोग उन सभी टेक्स्ट-प्रदान URLs पर भी gitleaks चलाने के लिए किया जा सकता है क्योंकि कभी-कभी **web pages also contains secrets**।

#### Github Dorks

संभावित **github dorks** के लिए इस **page** को भी देखें जिसे आप उस organization में सर्च कर सकते हैं जिसे आप target कर रहे हैं:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

कभी-कभी attackers या बस workers कंपनी की सामग्री को किसी paste site पर **publish** कर देते हैं। इसमें संवेदनशील जानकारी हो भी सकती है और नहीं भी — पर इसे खोजना काफी रोचक होता है।\
आप tool [**Pastos**](https://github.com/carlospolop/Pastos) का उपयोग कर सकते हैं जो एक ही समय में 80 से अधिक paste sites में search करता है।

### Google Dorks

पुराने पर भरोसा रखने वाले google dorks हमेशा उपयोगी होते हैं ऐसे **exposed information that shouldn't be there** खोजने के लिए। समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **thousands** संभावित queries हैं जिन्हें आप manually नहीं चला सकते। इसलिए, आप अपने पसंदीदा 10 चुन सकते हैं या आप उन्हें सब चलाने के लिए [**Gorks**](https://github.com/carlospolop/Gorks) जैसे tool का उपयोग कर सकते हैं।

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

यदि आप **valid leaked** credentials या API tokens पाते हैं, तो यह एक बहुत आसान जीत है।

## Public Code Vulnerabilities

यदि आपको पता चलता है कि कंपनी के पास **open-source code** है तो आप उसे **analyse** कर सकते हैं और उस पर vulnerabilities खोज सकते हैं।

**Depending on the language** अलग-अलग **tools** हैं जिन्हें आप उपयोग कर सकते हैं:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

ऐसे मुफ्त services भी हैं जो आपको public repositories स्कैन करने की अनुमति देते हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

बग हंटरों द्वारा पाए जाने वाले **majority of the vulnerabilities** web applications के अंदर ही होते हैं, तो इस बिंदु पर मैं web application testing methodology के बारे में बात करना चाहूँगा, और आप यह जानकारी [**find this information here**](../../network-services-pentesting/pentesting-web/index.html) देख सकते हैं।

मैं विशेष रूप से उस सेक्शन [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) का उल्लेख करना चाहूँगा, क्योंकि भले ही आप उनसे बहुत संवेदनशील vulnerabilities मिलने की उम्मीद न रखें, वे workflows में लागू करने के लिए और प्रारम्भिक web information पाने के लिए काम आते हैं।

## पुनरावलोकन

> Congratulations! इस बिंदु पर आपने पहले ही **all the basic enumeration** कर ली है। हाँ, यह basic है क्योंकि और भी बहुत enumeration किया जा सकता है (बाद में और tricks देखेंगे)।

तो, आपने पहले ही:

1. स्कोप के भीतर सभी **companies** को पाया
2. कंपनियों से संबंधित सभी **assets** पाए (और scope में होने पर कुछ vuln scan भी किए)
3. कंपनियों के सभी **domains** पाए
4. उन domains के सभी **subdomains** पाए (any subdomain takeover?)
5. स्कोप के भीतर सभी **IPs** पाए (from and not from CDNs)
6. सभी **web servers** पाए और उनका **screenshot** लिया (कोई भी अजीब चीज़ जो गहराई से देखने लायक हो?)
7. कंपनी से संबंधित सभी संभावित public cloud assets पाए।
8. **Emails**, **credentials leaks**, और **secret leaks** जो आपको बहुत आसानी से एक बड़ा win दे सकते हैं।
9. आपने मिले हुए सभी webs का **Pentesting**

## **Full Recon Automatic Tools**

ऐसे कई tools हैं जो दिए गए scope के खिलाफ प्रस्तावित कार्यों का कुछ हिस्सा automatic रूप से कर देंगे।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
