# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets की खोज

> तो आपको बताया गया कि किसी कंपनी से संबंधित सब कुछ scope के भीतर है, और आप यह पता लगाना चाहते हैं कि वास्तव में उस कंपनी के पास क्या-क्या है।

इस चरण का लक्ष्य सभी **मुख्य कंपनी के स्वामित्व वाली कंपनियाँ** प्राप्त करना है और फिर इन कंपनियों के सभी **assets**। इसके लिए, हम करेंगे:

1. मुख्य कंपनी के अधिग्रहण (acquisitions) खोजें — इससे हमें scope में आने वाली कंपनियाँ मिलेंगी।
2. प्रत्येक कंपनी का ASN (यदि कोई हो) खोजें — इससे हमें प्रत्येक कंपनी के IP रेंज मिलेंगे।
3. reverse whois lookups का उपयोग करके पहले एंट्री से संबंधित अन्य प्रविष्टियाँ (organisation names, domains...) खोजें (इसे recursive रूप से किया जा सकता है)।
4. shodan के `org` और `ssl` filters जैसे अन्य तकनीकों का उपयोग करके अन्य assets खोजें (`ssl` ट्रिक को recursive रूप से किया जा सकता है)।

### **अधिग्रहण**

पहले हमें पता होना चाहिए कि **मुख्य कंपनी के पास कौन-कौन सी अन्य कंपनियाँ हैं**।\
एक विकल्प है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाना, **खोजें** (search) के लिए **main company** ढूँढना, और "**acquisitions**" पर **क्लिक** करना। वहाँ आपको मुख्य कंपनी द्वारा अधिग्रहित अन्य कंपनियाँ दिखेंगी।\
दूसरा विकल्प है मुख्य कंपनी का **Wikipedia** पेज देखना और **acquisitions** खोजना।\
पब्लिक कंपनियों के लिए, **SEC/EDGAR filings**, **investor relations** पेज, या स्थानीय corporate registries (उदा., UK में **Companies House**) देखें।\
ग्लोबल corporate trees और subsidiaries के लिए, **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएँ।

> ठीक है, इस बिंदु पर आपको scope के भीतर सभी कंपनियों का ज्ञान होना चाहिए। अब उनके assets कैसे ढूँढें, यह पता करते हैं।

### **ASNs**

An autonomous system number (**ASN**) एक **unique number** है जो एक **autonomous system** (AS) को **Internet Assigned Numbers Authority (IANA)** द्वारा आवंटित किया जाता है।\
एक **AS** उन **IP addresses** के **blocks** से मिलकर बनता है जिनका बाहरी नेटवर्क्स तक पहुँचने के लिए स्पष्ट रूप से परिभाषित policy होता है और जिसे एक ही organisation द्वारा मैनेज किया जाता है (हालाँकि यह कई operators से मिलकर बन सकता है)।

यह जानना उपयोगी है कि क्या **किसी कंपनी को कोई ASN असाइन्ड किया गया है** ताकि उसकी **IP ranges** मिल सकें। यह उपयोगी होगा कि scope के अंदर सभी **hosts** पर एक **vulnerability test** किया जाए और इन IPs के अंदर **domains** तलाशे जाएँ।\
आप [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **या** [**https://ipinfo.io/**](https://ipinfo.io/) में कंपनी के **name**, **IP** या **domain** से **search** कर सकते हैं।\
**कंपनी के क्षेत्र के आधार पर ये लिंक और डेटा इकट्ठा करने में उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). वैसे भी, संभवतः सारी** उपयोगी जानकारी **(IP ranges और Whois)** पहले लिंक में ही दिखाई दे जाएगी।
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
इसके अलावा, [**BBOT**](https://github.com/blacklanternsecurity/bbot)** का** enumeration स्वचालित रूप से ASNs को स्कैन के अंत में समेकित और सारांशित करता है।
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

इस बिंदु पर हम **all the assets inside the scope** जानते हैं, इसलिए अगर आपको अनुमति है तो आप सभी hosts पर कुछ **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
इसके अलावा, आप कुछ [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या** Shodan, Censys, या ZoomEye जैसे services **का उपयोग कर** open ports ढूँढ सकते हैं और जो कुछ भी मिलता है उसके आधार पर आपको इस किताब में बताए गए तरीकों से विभिन्न सेवाओं को pentest करने के लिए देखना चाहिए।\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> हम scope के अंदर की सभी कंपनियों और उनके assets को जानते हैं, अब scope के अंदर के domains खोजने का समय है।

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

सबसे पहले आपको हर कंपनी के **main domain**(s) ढूँढने चाहिए। उदाहरण के लिए, _Tesla Inc._ के लिए वह होगा _tesla.com_.

### **Reverse DNS**

जब आपने domains के सभी IP ranges खोज लिए हों तो आप उन IPs पर **reverse dns lookups** कर के scope के अंदर और domains खोजने की कोशिश कर सकते हैं। victim के किसी dns server या कुछ well-known dns servers (1.1.1.1, 8.8.8.8) का उपयोग करने की कोशिश करें।
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
You can also use a online tool for this info: [http://ptrarchive.com/](http://ptrarchive.com).\
For large ranges, tools like [**massdns**](https://github.com/blechschmidt/massdns) and [**dnsx**](https://github.com/projectdiscovery/dnsx) are useful to automate reverse lookups and enrichment.

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
You can use online tools like:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **मुफ्त**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **मुफ्त**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **मुफ्त**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **मुफ्त** वेब, API मुफ्त नहीं।
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - मुफ्त नहीं
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - मुफ़्त नहीं (केवल **100 मुफ्त** खोजें)
- [https://www.domainiq.com/](https://www.domainiq.com) - मुफ़्त नहीं
- [https://securitytrails.com/](https://securitytrails.com/) - मुफ़्त नहीं (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - मुफ़्त नहीं (API)

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
For example, if you see the same **Google Analytics ID** or the same **Adsense ID** on several pages.

There are some pages and tools that let you search by these trackers and more:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Did you know that we can find related domains and subdomains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

सरल शब्दों में, favihash हमें उन डोमेन्स का पता लगाने की अनुमति देता है जिनका वही favicon icon hash हमारे लक्ष्य के समान है।

इसके अलावा, आप [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) में बताए अनुसार favicon hash का उपयोग करके technologies को भी खोज सकते हैं। इसका मतलब है कि यदि आप **hash of the favicon of a vulnerable version of a web tech** जानते हैं तो आप shodan में इसे खोजकर और भी अधिक कमजोर जगहें ढूँढ सकते हैं:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
यहाँ बताया गया है कि आप किसी वेब का **favicon hash की गणना** कैसे कर सकते हैं:
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
आप [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) के साथ बड़े पैमाने पर favicon hashes भी प्राप्त कर सकते हैं और फिर Shodan/Censys में pivot कर सकते हैं।

### **कॉपीराइट / यूनिक स्ट्रिंग**

वेब पेजों के भीतर **ऐसी स्ट्रिंग्स खोजें जो एक ही organisation के विभिन्न वेब्स में साझा हो सकती हैं**। **कॉपीराइट स्ट्रिंग** एक अच्छा उदाहरण हो सकती है। फिर उस स्ट्रिंग को **google**, अन्य **ब्राउज़र्स** या यहाँ तक कि **shodan** में खोजें: `shodan search http.html:"Copyright string"`

### **CRT Time**

आम तौर पर ऐसे cron jobs होते हैं, जैसे
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **same कंपनी के domains को certificate transparency logs में ढूँढना**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

आप [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) जैसी वेबसाइट या [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) जैसे टूल का उपयोग करके **एक ही dmarc information साझा करने वाले domains और subdomain** पता कर सकते हैं।\
अन्य उपयोगी टूल हैं [**spoofcheck**](https://github.com/BishopFox/spoofcheck) और [**dmarcian**](https://dmarcian.com/)।

### **Passive Takeover**

आम तौर पर लोग subdomains को cloud providers के IPs पर पॉइंट करते हैं और किसी बिंदु पर वे IP address खो देते हैं लेकिन DNS रिकॉर्ड हटाना भूल जाते हैं। इसलिए, बस किसी cloud में **VM spawn करने** से (जैसे Digital Ocean) आप वास्तव में कुछ subdomains को **take over** कर सकते हैं।

[**This post**](https://kmsec.uk/blog/passive-takeover/) इसके बारे में एक कहानी बताती है और एक स्क्रिप्ट सुझाती है जो **DigitalOcean में VM spawn करती है**, नई मशीन का **IPv4** लेती है, और **Virustotal में उन subdomain रिकॉर्ड्स की खोज** करती है जो उस IP को पॉइंट करते हैं।

### **Other ways**

**ध्यान दें कि आप इस technique का उपयोग हर बार जब आप कोई नया domain पाते हैं तब और अधिक domain names खोजने के लिए कर सकते हैं।**

**Shodan**

जैसा कि आप पहले से जानते हैं कि IP space का मालिक कौन सा organisation है। आप उस जानकारी से shodan में खोज सकते हैं: `org:"Tesla, Inc."`। मिले हुए hosts के TLS certificate में नए और अनपेक्षित domains की जाँच करें।

आप मुख्य वेब पेज के **TLS certificate** तक पहुँच कर **Organisation name** प्राप्त कर सकते हैं और फिर उस नाम के लिए **shodan** द्वारा ज्ञात सभी वेब पेजों के **TLS certificates** में खोज कर सकते हैं फ़िल्टर के साथ: `ssl:"Tesla Motors"` या [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) जैसा टूल इस्तेमाल कर सकते हैं।

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) एक टूल है जो मुख्य domain से संबंधित **domains** और उनके **subdomains** खोजता है, काफी उपयोगी है।

**Passive DNS / Historical DNS**

Passive DNS data पुराने और भूले हुए रिकॉर्ड्स खोजने के लिए शानदार है जो अभी भी resolve होते हैं या जिन्हें take over किया जा सकता है। देखें:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). शायद कोई कंपनी किसी domain का उपयोग कर रही हो पर वे ownership खो चुके हों। बस उसे रजिस्टर कर लें (अगर सस्ता हो) और कंपनी को सूचित करें।

अगर आपको ऐसा कोई **domain मिले जिसका IP उन IPs से अलग हो** जो आपने assets discovery में पहले ही पाए हैं, तो आपको एक **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) करना चाहिए, जैसे **nmap/masscan/shodan**। जिन सेवाओं के चलने पर निर्भर करता है आप इस book में कुछ ट्रिक्स पा सकते हैं जिनसे आप उन्हें "attack" कर सकते हैं।\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> हम scope के अंदर सभी कंपनियों, हर कंपनी की सभी assets और कंपनियों से संबंधित सभी domains जानते हैं।

यह समय है कि हर मिले हुए domain के सभी संभव subdomains खोजे जाएँ।

> [!TIP]
> ध्यान दें कि domains खोजने के लिए जिन tools और techniques का उपयोग होते हैं वे subdomains खोजने में भी मदद कर सकते हैं

### **DNS**

आइए **DNS** रिकॉर्ड्स से **subdomains** प्राप्त करने का प्रयास करें। हमें **Zone Transfer** के लिए भी कोशिश करनी चाहिए (यदि vulnerable हो तो इसे रिपोर्ट करें)।
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

कई सबडोमेन प्राप्त करने का सबसे तेज़ तरीका बाहरी स्रोतों में खोज करना है। सबसे अधिक उपयोग किए जाने वाले **उपकरण** निम्नलिखित हैं (बेहतर परिणामों के लिए API keys कॉन्फ़िगर करें):

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
अन्य रोचक **tools/APIs** हैं जो सीधे subdomains खोजने में विशेषज्ञ न होने के बावजूद subdomains खोजने में उपयोगी हो सकते हैं, जैसे:

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
- [**gau**](https://github.com/lc/gau)**:** किसी दिए गए डोमेन के लिए AlienVault's Open Threat Exchange, the Wayback Machine, और Common Crawl से ज्ञात URLs प्राप्त करता है।
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): वे वेब को स्क्रैप करके JS फाइलें ढूँढते हैं और वहाँ से subdomains निकालते हैं।
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

यह प्रोजेक्ट **bug-bounty programs से संबंधित सभी subdomains मुफ्त में** प्रदान करता है। आप इस डेटा को [chaospy](https://github.com/dr-0x0x/chaospy) का उपयोग करके भी एक्सेस कर सकते हैं या यहाँ तक कि इस प्रोजेक्ट द्वारा उपयोग किया गया scope भी एक्सेस कर सकते हैं [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

आप इन टूल्स की कई की **तुलना** यहाँ पा सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

आइए संभावित subdomain नामों का उपयोग करके DNS servers को brute-force करके नए **subdomains** खोजने की कोशिश करें।

इस क्रिया के लिए आपको कुछ **common subdomains wordlists like** चाहिए:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

और साथ ही अच्छे DNS resolvers के IPs भी। भरोसेमंद DNS resolvers की सूची बनाने के लिए आप resolvers को [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) से डाउनलोड कर सकते हैं और उन्हें फिल्टर करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग कर सकते हैं। या आप उपयोग कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे अनुशंसित टूल्स हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह पहला टूल था जिसने प्रभावी DNS brute-force किया। यह बहुत तेज़ है, हालांकि यह false positives के प्रति प्रवण है।
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): मुझे लगता है यह सिर्फ 1 resolver का उपयोग करता है
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` का wrapper है, जो go में लिखा गया है, और यह आपको active bruteforce का उपयोग करके valid subdomains enumerate करने के साथ-साथ wildcard handling और आसान input-output support के साथ subdomains resolve करने की अनुमति देता है.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): यह भी `massdns` का उपयोग करता है।
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) asyncio का उपयोग करके डोमेन नामों को असिंक्रोनस रूप से brute force करता है।
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### दूसरा DNS Brute-Force राउंड

open sources और brute-forcing का उपयोग करके subdomains खोज लेने के बाद, आप पाए गए subdomains के परिवर्तन उत्पन्न करके और भी अधिक ढूँढने की कोशिश कर सकते हैं।  

इस उद्देश्य के लिए कई टूल उपयोगी हैं:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** दिए गए domains और subdomains के आधार पर permutations उत्पन्न करता है।
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains के लिए permutations जनरेट करता है.
- आप goaltdns permutations **wordlist** को [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) पर प्राप्त कर सकते हैं.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains से permutations जनरेट करता है। यदि कोई permutations file निर्दिष्ट नहीं है, तो gotator अपनी file का उपयोग करेगा।
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations उत्पन्न करने के अलावा, यह उन्हें resolve करने की कोशिश भी कर सकता है (लेकिन पहले बताए गए tools का उपयोग करना बेहतर है)।
- आप altdns permutations **wordlist** [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) से प्राप्त कर सकते हैं।
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): एक और टूल है जो permutations, mutations और alteration of subdomains को perform करता है। यह टूल result को brute force करेगा (यह dns wild card को सपोर्ट नहीं करता)।
- आप dmut permutations wordlist को [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) से प्राप्त कर सकते हैं।
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** एक domain के आधार पर यह संकेतित patterns के अनुसार और subdomains खोजने की कोशिश करने के लिए **generates new potential subdomains names**।

#### स्मार्ट permutations generation

- [**regulator**](https://github.com/cramppet/regulator): अधिक जानकारी के लिए इस [**post**](https://cramppet.github.io/regulator/index.html) को पढ़ें, लेकिन यह मूल रूप से **main parts** को **discovered subdomains** से निकालेगा और उन्हें मिलाकर और subdomains ढूंढेगा।
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है जो एक बेहद सरल परंतु प्रभावी DNS response-guided algorithm के साथ जुड़ा हुआ है। यह दिए गए इनपुट डेटा सेट का उपयोग करता है, जैसे tailored wordlist या historical DNS/TLS records, ताकि अधिक संबंधित domain names को सटीक रूप से उत्पन्न किया जा सके और DNS scan के दौरान एकत्रित जानकारी के आधार पर उन्हें लूप में और भी बढ़ाया जा सके।
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

मैंने एक ब्लॉग पोस्ट लिखा है जिसमें बताया गया है कि कैसे **automate the subdomain discovery** को किसी domain से **Trickest workflows** का उपयोग करके किया जा सकता है ताकि मुझे अपने कंप्यूटर पर कई **tools** मैन्युअली लॉन्च करने की आवश्यकता न पड़े:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

यदि आपको किसी IP address में ऐसे **one or several web pages** मिले जो subdomains से संबंधित हैं, तो आप उस IP में अन्य subdomains जिनपर webs मौजूद हैं, खोजने के लिए **OSINT sources** में domains के लिए देख सकते हैं या उस IP में **brute-forcing VHost domain names** करके कोशिश कर सकते हैं।

#### OSINT

आप कुछ **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs** का उपयोग करके पा सकते हैं।

**Brute Force**

अगर आपको शक है कि कोई subdomain किसी web server में छिपा हो सकता है, तो आप उसे brute force करने की कोशिश कर सकते हैं:
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
> इस तकनीक के साथ आप internal/hidden endpoints तक भी पहुँच पाने में सक्षम हो सकते हैं।

### **CORS Brute Force**

कभी-कभी आपको ऐसे पृष्ठ मिलेंगे जो केवल तब हेडर _**Access-Control-Allow-Origin**_ लौटाते हैं जब _**Origin**_ हेडर में एक मान्य domain/subdomain सेट किया गया हो। इन परिस्थितियों में, आप इस व्यवहार का दुरुपयोग करके नए **subdomains** को **खोज** सकते हैं।
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

जब आप **subdomains** की तलाश कर रहे हों तो देखें कि क्या यह किसी प्रकार के **bucket** की ओर **pointing** कर रहा है, और उस स्थिति में [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
साथ ही, इस बिंदु पर जब आप scope के अंदर सभी domains को जान चुके होंगे, तो [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) करने की कोशिश करें।

### **Monitorization**

आप यह **monitor** कर सकते हैं कि किसी domain के **new subdomains** बनाए गए हैं या नहीं, जैसा कि **Certificate Transparency** Logs को मॉनिटर करने वाला [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) करता है।

### **Looking for vulnerabilities**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
यदि **subdomain** किसी **S3 bucket** की ओर **pointing** कर रहा है तो [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) करें।

यदि आप कोई ऐसा **subdomain with an IP different** पाते हैं जो आपने assets discovery में पहले नहीं पाया था, तो आपको **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करते हुए) और कुछ [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) nmap/masscan/shodan के साथ करना चाहिए। किस सर्विसेज़ से संबंधित हैं उसके आधार पर आप **this book some tricks to "attack" them** पा सकते हैं।\
_ध्यान दें कि कभी-कभी subdomain किसी ऐसे IP पर होस्ट किया जाता है जो client द्वारा नियंत्रित नहीं होता, इसलिए वह scope में नहीं आता — सावधान रहें।_

## IPs

शुरुआती कदमों में आप हो सकता है कि **found some IP ranges, domains and subdomains** हों।\
अब समय है उन रेंजेज़ से **recollect all the IPs from those ranges** और **domains/subdomains (DNS queries)** के लिए IPs इकट्ठा करने का।

नीचे दिए गए **free apis** की सेवाओं का उपयोग करके आप **previous IPs used by domains and subdomains** भी खोज सकते हैं। ये IPs अभी भी client के स्वामित्व में हो सकते हैं (और आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) खोजने में मदद कर सकते हैं)

- [**https://securitytrails.com/**](https://securitytrails.com/)

आप किसी specific IP address को पॉइंट कर रहे domains की भी जाँच कर सकते हैं टूल [**hakip2host**](https://github.com/hakluke/hakip2host) का उपयोग करके।

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (क्योंकि वहाँ शायद आपको ज्यादा कुछ दिलचस्प नहीं मिलेगा)। जिन चल रही services का पता चलता है उनमें आप **able to find vulnerabilities** हो सकते हैं।

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

पिछले कदमों में आपने संभवतः पहले ही खोजे गए **recon of the IPs and domains discovered** पर कुछ recon किया होगा, इसलिए हो सकता है कि आप पहले से ही सभी संभावित web servers **already found** कर चुके हों। हालांकि, यदि नहीं किया है तो अब हम scope के अंदर web servers खोजने के कुछ तेज़ तरीके देखेंगे।

कृपया ध्यान दें कि यह web apps discovery के लिए **oriented** होगा, इसलिए आपको **perform the vulnerability** और **port scanning** भी करना चाहिए (**if allowed** by the scope)।

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
एक और उपयोगी टूल web servers खोजने के लिए [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx) है। आप बस domains की एक सूची पास करते हैं और यह port 80 (http) और 443 (https) से कनेक्ट करने की कोशिश करेगा। अतिरिक्त रूप से, आप अन्य ports आज़माने के लिए संकेत भी दे सकते हैं:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **स्क्रीनशॉट्स**

अब जब आपने स्कोप में मौजूद **सभी web servers** (कंपनी के **IPs** और सभी **domains** और **subdomains** के बीच) को खोज लिया है तो आपको शायद नहीं पता कहाँ से शुरू करें। तो इसे सरल बनाते हैं और पहले सिर्फ उन सभी का स्क्रीनशॉट लेना शुरू करते हैं। सिर्फ **main page** को देख कर आप **weird** endpoints ढूंढ सकते हैं जो अधिक **prone** होते हैं vulnerable होने के लिए।

प्रस्तावित आइडिया को लागू करने के लिए आप [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** का उपयोग कर सकते हैं। 

इसके अलावा, आप सभी **screenshots** पर चलाने के लिए [**eyeballer**](https://github.com/BishopFox/eyeballer) का उपयोग कर सकते हैं ताकि यह बताये कि क्या **likely to contain vulnerabilities** है, और क्या नहीं है।

## Public Cloud Assets

किसी कंपनी के संभावित cloud assets खोजने के लिए आपको **उस कंपनी की पहचान करने वाले keywords** की एक सूची से शुरू करना चाहिए। उदाहरण के लिए, किसी crypto कंपनी के लिए आप शब्दों का उपयोग कर सकते हैं: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

आपको **common words used in buckets** के wordlists भी चाहिए होंगे:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, उन शब्दों के साथ आपको **permutations** जनरेट करने चाहिए (और अधिक जानकारी के लिए देखें [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round))।

प्राप्त wordlists के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** जैसे tools का उपयोग कर सकते हैं।**

ध्यान रखें कि Cloud Assets खोजते समय आपको AWS में सिर्फ buckets ही नहीं देखना चाहिए।

### **Looking for vulnerabilities**

यदि आप ऐसी चीजें पाते हैं जैसे **open buckets या cloud functions exposed** तो आपको उन्हें **access** करना चाहिए और देखना चाहिए कि वे आपको क्या offer करते हैं और क्या आप उन्हें abuse कर सकते हैं।

## ईमेल

स्कोप के अंदर मौजूद **domains** और **subdomains** के साथ आपके पास मूल रूप से उन ईमेल्स की खोज शुरू करने के लिए सब कुछ है जो आपको चाहिए। ये वे **APIs** और **tools** हैं जिनसे मुझे किसी कंपनी के ईमेल खोजने में सबसे अच्छा परिणाम मिला है:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

ईमेल बाद में **brute-force web logins and auth services** (जैसे SSH) के लिए काम आएँगे। साथ ही, ये **phishings** के लिए भी ज़रूरी होते हैं। इसके अलावा, ये APIs आपको उस ईमेल के पीछे मौजूद व्यक्ति के बारे में और भी अधिक **info** देंगी, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

स्कोप में मौजूद **domains,** **subdomains**, और **emails** के साथ आप उन credentials की तलाश शुरू कर सकते हैं जो पिछले समय में उन ईमेल्स से संबंधित रूप में leak हुए हों:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

यदि आप **valid leaked** credentials पाते हैं, तो यह एक बहुत आसान जीत है।

## Secrets Leaks

Credential leaks उन हैक्स से संबंधित हैं जहाँ **sensitive information was leaked and sold**। हालांकि, कंपनियाँ अन्य प्रकार के leaks से प्रभावित हो सकती हैं जिनकी जानकारी उन databases में नहीं होती:

### Github Leaks

Credentials और APIs सार्वजनिक repositories में leak हो सकते हैं, चाहे वो **company** के या उन **users** के जो उस github कंपनी के लिए काम करते हैं।\
आप **tool** [**Leakos**](https://github.com/carlospolop/Leakos) का उपयोग करके किसी **organization** और उसके **developers** के सभी **public repos** को **download** कर सकते हैं और उन पर स्वचालित रूप से [**gitleaks**](https://github.com/zricethezav/gitleaks) चला सकते हैं।

**Leakos** को उन सभी **text** प्रदान की गई **URLs passed** पर भी gitleaks चलाने के लिए उपयोग किया जा सकता है क्योंकि कभी-कभी **web pages** में भी secrets होते हैं।

#### Github Dorks

इन्हें भी चेक करें—यह **page** संभावित **github dorks** के लिए है जिन्हें आप उस organization में search कर सकते हैं जिस पर आप हमला कर रहे हैं:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

कभी-कभी attackers या बस कर्मचारी किसी paste site पर **company content** प्रकाशित कर देते हैं। इसमें **sensitive information** हो भी सकती है और नहीं भी—पर इसे खोजना बहुत दिलचस्प होता है।\
आप tool [**Pastos**](https://github.com/carlospolop/Pastos) का उपयोग करके एक साथ 80 से अधिक paste sites में खोज कर सकते हैं।

### Google Dorks

पुराने पर प्रभावी google dorks हमेशा उपयोगी होते हैं उन **exposed information that shouldn't be there** को खोजने के लिए। समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में कई **thousands** possible queries हैं जिन्हें आप manually नहीं चला सकते। तो, आप अपनी पसंदीदा 10 queries ले सकते हैं या आप ऐसे **tool** का उपयोग कर सकते हैं जैसे [**Gorks**](https://github.com/carlospolop/Gorks) **उन्हें सभी चलाने के लिए**।

_ध्यान दें कि जो tools पूरी database को regular Google browser का उपयोग करके चलाने की उम्मीद करते हैं वे कभी खत्म नहीं होंगे क्योंकि google आपको बहुत जल्दी block कर देगा।_

### **Looking for vulnerabilities**

यदि आप **valid leaked** credentials या API tokens पाते हैं, तो यह एक बहुत आसान जीत है।

## Public Code Vulnerabilities

यदि आपने पाया कि कंपनी के पास **open-source code** है तो आप उसे **analyse** कर सकते हैं और उस पर **vulnerabilities** खोज सकते हैं।

**Depending on the language** आप विभिन्न **tools** का उपयोग कर सकते हैं:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

ऐसी free services भी हैं जो आपको public repositories स्कैन करने की अनुमति देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

बहुमत vulnerabilities जो bug hunters पाते हैं वे **web applications** के अंदर होते हैं, इसलिए इस बिंदु पर मैं web application testing methodology के बारे में बात करना चाहता हूँ, और आप [**यहाँ यह जानकारी पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं विशेष रूप से सेक्शन [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) का जिक्र करना चाहता हूँ, क्योंकि हालांकि आप उनसे बहुत sensitive vulnerabilities की उम्मीद नहीं कर सकते, वे initial web information पाने के लिए workflows में उपयोगी होते हैं।

## Recapitulation

> बधाई हो! इस बिंदु पर आपने पहले से ही **all the basic enumeration** कर लिया है। हाँ, यह basic है क्योंकि बहुत और enumeration की जा सकती है (बाद में और tricks देखेंगे)।

तो आपने पहले से ही कर लिया है:

1. स्कोप के अंदर **all the companies** को खोजा
2. कंपनियों के सभी **assets** को पाया (और scope में होने पर कुछ vuln scan किया)
3. कंपनियों के सभी **domains** को पाया
4. domains के सभी **subdomains** को पाया (कोई subdomain takeover?)
5. स्कोप के अंदर सभी **IPs** (CDNs से और CDNs से नहीं) को पाया।
6. सभी **web servers** को पाया और उनके **screenshot** लिए (कोई weird चीज जो गहराई से देखने लायक हो?)
7. कंपनी के सभी संभावित **public cloud assets** को पाया।
8. **Emails**, **credentials leaks**, और **secret leaks** जो आपको बहुत आसानी से एक बड़ा जीत दे सकते हैं।
9. आपने मिले हुए सभी वेब्स का **pentesting** किया

## **Full Recon Automatic Tools**

कई ऐसे tools हैं जो दिए गए scope के खिलाफ प्रस्तावित क्रियाओं का हिस्सा perform करेंगे।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
