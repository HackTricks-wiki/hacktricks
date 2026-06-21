# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> तो आपको बताया गया कि किसी कंपनी से संबंधित सब कुछ scope के अंदर है, और आप जानना चाहते हैं कि यह कंपनी वास्तव में क्या own करती है।

इस चरण का लक्ष्य मुख्य company के स्वामित्व वाली सभी **companies** और फिर इन companies के सभी **assets** प्राप्त करना है। ऐसा करने के लिए, हम:

1. मुख्य company के acquisitions ढूँढेंगे, इससे हमें scope के अंदर की companies मिलेंगी।
2. प्रत्येक company का ASN (यदि कोई हो) ढूँढेंगे, इससे हमें प्रत्येक company के owned IP ranges मिलेंगे
3. reverse whois lookups का उपयोग करके अन्य entries (organisation names, domains...) खोजेंगे जो पहले वाले से संबंधित हों (यह recursively किया जा सकता है)
4. अन्य techniques जैसे shodan `org` और `ssl` filters का उपयोग करके अन्य assets खोजेंगे ( `ssl` trick recursively किया जा सकता है)।

### **Acquisitions**

सबसे पहले, हमें यह जानना होगा कि मुख्य company के स्वामित्व में कौन-सी **other companies** हैं।\
एक option है [https://www.crunchbase.com/](https://www.crunchbase.com) पर जाना, **search** करके **main company** ढूँढना, और "**acquisitions**" पर **click** करना। वहाँ आपको मुख्य company द्वारा acquired अन्य companies दिखेंगी।\
दूसरा option है मुख्य company के **Wikipedia** पेज पर जाना और **acquisitions** खोजना।\
Public companies के लिए, **SEC/EDGAR filings**, **investor relations** pages, या local corporate registries (जैसे UK में **Companies House**) देखें।\
Global corporate trees और subsidiaries के लिए, **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) और **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) आज़माएँ।

> ठीक है, इस बिंदु पर आपको scope के अंदर की सभी companies पता होनी चाहिए। चलिए यह पता करते हैं कि उनके assets कैसे ढूँढें।

### **ASNs**

एक autonomous system number (**ASN**) एक **unique number** है जो **Internet Assigned Numbers Authority (IANA)** द्वारा एक **autonomous system** (AS) को assigned किया जाता है।\
एक **AS** **IP addresses** के **blocks** से बना होता है जिनकी external networks तक पहुँचने के लिए अलग से परिभाषित policy होती है और जिन्हें एक ही organisation administer करता है, लेकिन वे कई operators से मिलकर भी बन सकते हैं।

यह देखना दिलचस्प है कि क्या **company have assigned any ASN** ताकि उसके **IP ranges** पता चल सकें। सभी **hosts** जो **scope** के अंदर हैं, उनके खिलाफ **vulnerability test** करना और इन IPs के अंदर **domains** ढूँढना उपयोगी होगा।\
आप company **name**, **IP** या **domain** से [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **या** [**https://ipinfo.io/**](https://ipinfo.io/) में **search** कर सकते हैं।\
**Company के region के अनुसार यह links अधिक data इकट्ठा करने के लिए उपयोगी हो सकते हैं:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). वैसे, शायद सभी** useful information **(IP ranges and Whois)** पहले link में ही दिखाई देती है।
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Also, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration scan के अंत में ASNs को स्वतः aggregate और summarize करता है.
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
आप [http://asnlookup.com/](http://asnlookup.com) का उपयोग करके भी किसी संगठन की IP ranges ढूँढ सकते हैं (इसका free API है)।\
आप [http://ipv4info.com/](http://ipv4info.com) का उपयोग करके किसी domain का IP और ASN ढूँढ सकते हैं।

### **कमज़ोरियाँ ढूँढना**

इस बिंदु पर हमें **scope के अंदर मौजूद सभी assets** पता हैं, इसलिए यदि आपको अनुमति है तो आप सभी hosts पर कोई **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) चला सकते हैं।\
साथ ही, आप कुछ [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) चला सकते हैं **या Shodan, Censys, या ZoomEye जैसी services का उपयोग करके** open ports **ढूँढ सकते हैं और जो भी मिले उसके आधार पर आपको** इस book में देखना चाहिए कि संभावित रूप से चल रही कई services का pentest कैसे किया जाता है।\
**इसके अलावा, यह भी उल्लेख करना उपयोगी हो सकता है कि आप कुछ** default username **और** passwords **की lists तैयार करके** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) के साथ services पर bruteforce करने की कोशिश भी कर सकते हैं।

## Domains

> हमें scope के अंदर की सभी companies और उनके assets पता हैं, अब scope के अंदर के domains ढूँढने का समय है।

_कृपया ध्यान दें कि निम्नलिखित सुझाई गई techniques में आप subdomains भी ढूँढ सकते हैं और उस जानकारी को कम नहीं आँकना चाहिए।_

सबसे पहले आपको प्रत्येक company के **main domain**(s) ढूँढने चाहिए। उदाहरण के लिए, _Tesla Inc._ के लिए यह _tesla.com_ होगा।

### **Reverse DNS**

चूँकि आपने domains की सभी IP ranges ढूँढ ली हैं, आप उन **IPs पर reverse dns lookups** करने की कोशिश कर सकते हैं **ताकि scope के अंदर और domains मिल सकें**। victim के किसी dns server या किसी well-known dns server (1.1.1.1, 8.8.8.8) का उपयोग करने की कोशिश करें
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

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

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
![favihash - समान favicon icon hash वाले domains खोजें](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

साधारण शब्दों में, favihash हमें ऐसे domains खोजने में मदद करेगा जिनका favicon icon hash हमारे target के समान है।

इसके अलावा, आप favicon hash का उपयोग करके technologies भी खोज सकते हैं, जैसा कि [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) में समझाया गया है। इसका मतलब है कि अगर आपको **web tech के किसी vulnerable version के favicon का hash** पता है, तो आप shodan में search करके **और अधिक vulnerable places** ढूंढ सकते हैं:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
यह है कि आप किसी web का **favicon hash** कैसे **calculate** कर सकते हैं:
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
आप [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) के साथ scale पर favicon hashes भी प्राप्त कर सकते हैं और फिर Shodan/Censys में pivot कर सकते हैं।

### **Copyright / Uniq string**

वेब पेजों के अंदर ऐसी **strings** खोजें जो **same organisation** की अलग-अलग webs में साझा की जा सकती हों। **copyright string** एक अच्छा example हो सकता है। फिर उस string को **google**, दूसरे **browsers** या यहाँ तक कि **shodan** में भी खोजें: `shodan search http.html:"Copyright string"`

### **CRT Time**

यह आम है कि एक cron job ऐसी हो जैसे
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **एक ही कंपनी से संबंधित domains को certificate transparency logs में ढूँढना**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Passive DNS data is great to find **old and forgotten records** that still resolve or that can be taken over. Look at:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

> [!TIP]
> Note that some of the tools and techniques to find domains can also help to find subdomains

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

बहुत सारे subdomains प्राप्त करने का सबसे तेज़ तरीका external sources में search करना है। सबसे ज़्यादा इस्तेमाल किए जाने वाले **tools** निम्नलिखित हैं (बेहतर results के लिए API keys configure करें):

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
There are **other interesting tools/APIs** that even if not directly specialised in finding subdomains could be useful to find subdomains, like:

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
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) free API
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
- [**gau**](https://github.com/lc/gau)**:** किसी भी दिए गए डोमेन के लिए AlienVault के Open Threat Exchange, the Wayback Machine, और Common Crawl से ज्ञात URLs प्राप्त करता है।
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ये वेब को स्क्रैप करते हैं JS files खोजने के लिए और उनसे subdomains निकालते हैं.
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
- [**securitytrails.com**](https://securitytrails.com/) के पास subdomains और IP history खोजने के लिए एक free API है
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

यह project **bug-bounty programs** से जुड़े सभी subdomains को **free** में उपलब्ध कराता है। आप इस data को [chaospy](https://github.com/dr-0x0x/chaospy) का उपयोग करके भी access कर सकते हैं, या इस project द्वारा उपयोग किए गए scope को भी access कर सकते हैं [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

आप इन tools में से कई की एक **comparison** यहाँ पा सकते हैं: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

आइए संभावित subdomain names का उपयोग करके DNS servers पर brute-forcing करके नए **subdomains** खोजने की कोशिश करें।

इस action के लिए आपको कुछ **common subdomains wordlists like** की आवश्यकता होगी:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

और साथ में अच्छे DNS resolvers के IPs भी। trusted DNS resolvers की सूची बनाने के लिए, आप [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) से resolvers डाउनलोड कर सकते हैं और उन्हें filter करने के लिए [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) का उपयोग कर सकते हैं। या आप यह उपयोग कर सकते हैं: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force के लिए सबसे recommended tools हैं:

- [**massdns**](https://github.com/blechschmidt/massdns): यह पहला tool था जिसने effective DNS brute-force किया। यह बहुत तेज़ है, हालांकि false positives की संभावना रहती है।
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): यह वाला मुझे लगता है सिर्फ 1 resolver उपयोग करता है
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` के ऊपर एक wrapper है, जो go में लिखा गया है, जो आपको active bruteforce का उपयोग करके valid subdomains enumerate करने की अनुमति देता है, साथ ही wildcard handling और easy input-output support के साथ subdomains resolve करने देता है।
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): यह भी `massdns` का उपयोग करता है।
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) asyncio का उपयोग करके domain names को asynchronously brute force करता है।
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### दूसरा DNS Brute-Force राउंड

open sources और brute-forcing का उपयोग करके subdomains खोज लेने के बाद, आप मिले हुए subdomains के alterations generate कर सकते हैं ताकि और भी अधिक subdomains खोजने की कोशिश की जा सके। इस उद्देश्य के लिए कई tools उपयोगी हैं:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** दिए गए domains और subdomains के आधार पर permutations generate करता है।
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): दिए गए domains और subdomains से permutations generate करें।
- आप goaltdns permutations **wordlist** [**यहाँ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) प्राप्त कर सकते हैं।
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** दिए गए domains और subdomains के आधार पर permutations generate करें। यदि permutations file indicate नहीं की गई है, तो gotator अपनी own file का उपयोग करेगा।
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations generate करने के अलावा, यह उन्हें resolve भी try कर सकता है (लेकिन पहले वाले commented tools का उपयोग करना बेहतर है).
- आप altdns permutations **wordlist** [**यहाँ**](https://github.com/infosec-au/altdns/blob/master/words.txt) प्राप्त कर सकते हैं.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomains के permutations, mutations और alteration करने के लिए एक और tool। यह tool result पर brute force करेगा (यह dns wild card support नहीं करता).
- आप dmut permutations wordlist [**यहाँ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) पा सकते हैं।
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** एक domain के आधार पर यह indicated patterns के अनुसार **new potential subdomains names** generate करता है ताकि और subdomains discover करने की कोशिश की जा सके।

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): अधिक जानकारी के लिए यह [**post**](https://cramppet.github.io/regulator/index.html) पढ़ें, लेकिन यह मूल रूप से **discovered subdomains** से **main parts** लेता है और उन्हें mix करके और subdomains खोजने की कोशिश करता है।
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ एक subdomain brute-force fuzzer है, जो एक बेहद सरल लेकिन प्रभावी DNS response-guided algorithm के साथ जुड़ा है। यह दिए गए input data के सेट का उपयोग करता है, जैसे कि tailored wordlist या historical DNS/TLS records, ताकि अधिक संबंधित domain names को सटीक रूप से synthesize किया जा सके और DNS scan के दौरान gathered information के आधार पर loop में उन्हें और भी expand किया जा सके।
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

इस ब्लॉग पोस्ट को देखें जो मैंने लिखा है कि कैसे **Trickest workflows** का उपयोग करके किसी domain से **subdomain discovery** को automate किया जा सकता है, ताकि मुझे अपने computer पर manually कई tools launch न करने पड़ें:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

अगर आपको एक ऐसा IP address मिला है जिसमें subdomains से संबंधित **एक या कई web pages** हैं, तो आप **OSINT sources** में उस IP में domains ढूँढकर या उस IP में **VHost domain names को brute-force** करके उस IP पर **webs वाले अन्य subdomains** खोजने की कोशिश कर सकते हैं।

#### OSINT

आप [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **या अन्य APIs** का उपयोग करके **IPs में VHosts** ढूँढ सकते हैं।

**Brute Force**

अगर आपको संदेह है कि कोई subdomain web server में छिपा हो सकता है, तो आप उसे brute force करने की कोशिश कर सकते हैं:

जब **IP एक hostname पर redirect करता है** (name-based vhosts), तो सीधे `Host` header को fuzz करें और ffuf को **auto-calibrate** करने दें ताकि default vhost से अलग responses को highlight किया जा सके:
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
> इस technique के साथ आप कभी-कभी internal/hidden endpoints तक भी access कर सकते हैं।

### **CORS Brute Force**

कभी-कभी आपको ऐसे pages मिलेंगे जो केवल तभी _**Access-Control-Allow-Origin**_ header return करते हैं जब _**Origin**_ header में एक valid domain/subdomain set किया गया हो। ऐसे scenarios में, आप इस behaviour का abuse करके नए **subdomains** **discover** कर सकते हैं।
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** की जाँच करते समय देखें कि क्या वह किसी भी प्रकार के **bucket** की ओर **pointing** कर रहा है, और उस स्थिति में [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
साथ ही, चूंकि इस समय तक आपको scope के अंदर के सभी domains पता चल चुके होंगे, [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) करने की कोशिश करें।

### **Monitorization**

आप **Certificate Transparency** Logs की monitoring करके यह पता लगा सकते हैं कि किसी domain के **new subdomains** बनाए गए हैं या नहीं; [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) ऐसा करता है।

### **Looking for vulnerabilities**

संभावित [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) की जाँच करें।\
यदि **subdomain** किसी **S3 bucket** की ओर pointing कर रहा है, तो [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)।

यदि आपको ऐसा कोई **subdomain मिलता है जिसका IP पहले मिले हुए IPs से अलग** है, तो आपको एक **basic vulnerability scan** (Nessus या OpenVAS का उपयोग करके) और **port scan** [**nmap/masscan/shodan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) के साथ करना चाहिए। कौन-सी services चल रही हैं, उसके आधार पर आप **इस book** में उन्हें "attack" करने के लिए कुछ tricks पा सकते हैं।\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

शुरुआती चरणों में आपने संभवतः **कुछ IP ranges, domains और subdomains** पाए होंगे।\
अब समय है उन ranges से सभी **IPs** फिर से इकट्ठा करने का और **domains/subdomains (DNS queries)** के लिए भी।

निम्नलिखित **free apis** की services का उपयोग करके आप domains और subdomains द्वारा पहले उपयोग किए गए **previous IPs** भी खोज सकते हैं। ये IPs अभी भी client के स्वामित्व में हो सकते हैं (और आपको [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) खोजने में मदद कर सकते हैं)

- [**https://securitytrails.com/**](https://securitytrails.com/)

आप tool [**hakip2host**](https://github.com/hakluke/hakip2host) का उपयोग करके किसी specific IP address की ओर pointing करने वाले domains भी check कर सकते हैं

### **Looking for vulnerabilities**

CDNs से संबंधित न होने वाले सभी IPs का **Port scan** करें** (क्योंकि वहाँ आपको संभवतः कुछ भी interesting नहीं मिलेगा)।** पाए गए running services में आपको **vulnerabilities** मिल सकती हैं।

**Hosts को scan करने के तरीके के बारे में एक** [**guide**](../pentesting-network/index.html) **पाएँ।**

## Web servers hunting

> हमने scope के अंदर की सभी companies और उनके assets ढूँढ लिए हैं और IP ranges, domains और subdomains जान लिए हैं। अब web servers खोजने का समय है।

पिछले चरणों में आपने संभवतः discovered IPs और domains की कुछ **recon** पहले ही कर ली होगी, इसलिए हो सकता है कि आप **already सभी possible web servers** ढूँढ चुके हों। हालांकि, यदि नहीं, तो अब हम scope के अंदर web servers खोजने के लिए कुछ **fast tricks** देखने जा रहे हैं।

कृपया ध्यान दें कि यह **web apps discovery** के लिए oriented होगा, इसलिए आपको **vulnerability** और **port scanning** भी करनी चाहिए (**यदि scope द्वारा allowed हो**)।

[**masscan** का उपयोग करके **web** servers से संबंधित **open ports** खोजने का एक **fast method** यहाँ मिल सकता है:](../pentesting-network/index.html#http-port-discovery)\
web servers खोजने के लिए एक और friendly tool है [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) और [**httpx**](https://github.com/projectdiscovery/httpx)। आप बस domains की एक list देते हैं और यह port 80 (http) तथा 443 (https) से connect करने की कोशिश करेगा। इसके अलावा, आप इसे अन्य ports आज़माने के लिए भी बता सकते हैं:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

अब जब आपने scope में मौजूद **सभी web servers** खोज लिए हैं (कंपनी के **IPs** और सभी **domains** और **subdomains** के बीच), तो आप शायद **नहीं जानते कि कहाँ से शुरू करें**। इसलिए, इसे आसान बनाते हैं और बस उन सभी के screenshots लेना शुरू करते हैं। सिर्फ **main page** पर **एक नज़र** डालकर आप **अजीब** endpoints ढूँढ सकते हैं जो **vulnerable** होने की **ज़्यादा संभावना** रखते हैं।

प्रस्तावित idea को लागू करने के लिए आप [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) या [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** का उपयोग कर सकते हैं।

इसके अलावा, आप बाद में [**eyeballer**](https://github.com/BishopFox/eyeballer) का उपयोग करके सभी **screenshots** पर चला सकते हैं ताकि यह बताया जा सके कि **किसमें vulnerabilities होने की संभावना है**, और किसमें नहीं।

## Public Cloud Assets

किसी कंपनी से संबंधित संभावित cloud assets खोजने के लिए आपको **ऐसे keywords की list से शुरू करना चाहिए जो उस कंपनी की पहचान करें**। उदाहरण के लिए, किसी crypto कंपनी के लिए आप `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` जैसे शब्दों का उपयोग कर सकते हैं।

आपको buckets में इस्तेमाल होने वाले **common words** की wordlists भी चाहिए होंगी:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

फिर, उन words के साथ आपको **permutations** generate करनी चाहिएं ([**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) देखें, अधिक जानकारी के लिए)।

इन resulting wordlists के साथ आप [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **या** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** जैसे tools का उपयोग कर सकते हैं।

याद रखें कि Cloud Assets खोजते समय आपको l**ook for more than just buckets in AWS**.

### **Looking for vulnerabilities**

अगर आपको **open buckets या exposed cloud functions** जैसी चीज़ें मिलती हैं, तो आपको **उन्हें access करना चाहिए** और देखना चाहिए कि वे आपको क्या offer करती हैं और क्या आप उनका abuse कर सकते हैं।

## Emails

scope में मौजूद **domains** और **subdomains** के साथ, मूल रूप से आपके पास emails खोजना शुरू करने के लिए ज़रूरी सब कुछ होता है। ये वे **APIs** और **tools** हैं जो मेरे लिए किसी company के emails खोजने में सबसे अच्छे रहे हैं:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails बाद में **brute-force web logins and auth services** (जैसे SSH) के लिए काम आएंगे। साथ ही, वे **phishings** के लिए भी ज़रूरी हैं। इसके अलावा, ये APIs आपको email के पीछे मौजूद **person** के बारे में और भी ज़्यादा **info** देंगी, जो phishing campaign के लिए उपयोगी है।

## Credential Leaks

**domains,** **subdomains**, और **emails** के साथ आप उन emails से संबंधित, past में leaked credentials खोजने शुरू कर सकते हैं:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

अगर आपको **valid leaked** credentials मिलते हैं, तो यह बहुत आसान win है।

## Secrets Leaks

Credential leaks उन company hacks से संबंधित होते हैं जहाँ **sensitive information leaked और sold** हुई थी। हालांकि, कंपनियाँ **other leaks** से भी प्रभावित हो सकती हैं जिनकी info उन databases में नहीं होती:

### Github Leaks

Credentials और APIs, **company** के **public repositories** में या उस github company के लिए काम करने वाले **users** के repos में leaked हो सकते हैं।\
आप [**Leakos**](https://github.com/carlospolop/Leakos) **tool** का उपयोग करके किसी **organization** और उसके **developers** के सभी **public repos** को **download** कर सकते हैं और उन पर स्वचालित रूप से [**gitleaks**](https://github.com/zricethezav/gitleaks) चला सकते हैं।

**Leakos** का उपयोग **gitleaks** को उसके द्वारा दिए गए सभी **text**-based **URLs** पर चलाने के लिए भी किया जा सकता है, क्योंकि कभी-कभी **web pages also contains secrets**.

#### Github Dorks

इस **page** को भी देखें, संभावित **github dorks** के लिए जिन्हें आप उस organization में भी search कर सकते हैं जिस पर आप attack कर रहे हैं:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

कभी-कभी attackers या सिर्फ workers कंपनी की content को किसी paste site पर **publish** कर देते हैं। इसमें **sensitive information** हो भी सकती है और नहीं भी, लेकिन इसे search करना बहुत दिलचस्प होता है।\
आप [**Pastos**](https://github.com/carlospolop/Pastos) tool का उपयोग करके एक ही समय में 80 से अधिक paste sites में search कर सकते हैं।

### Google Dorks

पुराने लेकिन gold google dorks हमेशा **exposed information** खोजने में उपयोगी होते हैं जो वहाँ नहीं होनी चाहिए। एकमात्र समस्या यह है कि [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) में **हज़ारों** संभावित queries हैं जिन्हें आप manually नहीं चला सकते। इसलिए, आप अपने पसंदीदा 10 चुन सकते हैं या [**Gorks**](https://github.com/carlospolop/Gorks) **जैसे tool** का उपयोग करके उन सभी को चला सकते हैं।

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

अगर आपको **valid leaked** credentials या API tokens मिलते हैं, तो यह बहुत आसान win है।

## Public Code Vulnerabilities

अगर आपको पता चलता है कि company के पास **open-source code** है, तो आप उसका **analyse** कर सकते हैं और उसमें vulnerabilities खोज सकते हैं।

**Language के अनुसार** अलग-अलग **tools** हैं जिनका आप उपयोग कर सकते हैं:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

कुछ free services भी हैं जो आपको **public repositories scan** करने देती हैं, जैसे:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters द्वारा मिली **majority of the vulnerabilities** web applications के अंदर होती हैं, इसलिए इस बिंदु पर मैं एक **web application testing methodology** के बारे में बात करना चाहूँगा, और आप [**यह जानकारी यहाँ पा सकते हैं**](../../network-services-pentesting/pentesting-web/index.html)।

मैं विशेष रूप से section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) का भी उल्लेख करना चाहता हूँ, क्योंकि भले ही आप उनसे बहुत sensitive vulnerabilities मिलने की उम्मीद न करें, फिर भी वे **workflows** में उन्हें लागू करके कुछ initial web information प्राप्त करने के लिए उपयोगी होते हैं।

## Recapitulation

> बधाई! इस बिंदु पर आपने पहले ही **सभी basic enumeration** कर ली है। हाँ, इसे basic इसलिए कहा जाता है क्योंकि और भी बहुत कुछ enumeration किया जा सकता है (बाद में और tricks देखेंगे)।

तो आपने पहले ही:

1. scope के अंदर मौजूद सभी **companies** ढूँढ लीं
2. कंपनियों से संबंधित सभी **assets** ढूँढ लिए (और scope में होने पर कुछ vuln scan भी किया)
3. कंपनियों से संबंधित सभी **domains** ढूँढ लिए
4. domains के सभी **subdomains** ढूँढ लिए (कोई subdomain takeover?)
5. scope के अंदर सभी **IPs** (CDNs से और **CDNs के बाहर से**) ढूँढ लिए।
6. सभी **web servers** ढूँढ लिए और उनके **screenshots** ले लिए (कुछ अजीब जो गहराई से देखने लायक हो?)
7. कंपनी से संबंधित सभी संभावित **public cloud assets** ढूँढ लिए।
8. **Emails**, **credentials leaks**, और **secret leaks** जो आपको बहुत आसानी से एक **big win** दे सकते हैं।
9. आपके द्वारा पाए गए सभी webs का **Pentesting**

## **Full Recon Automatic Tools**

ऐसे कई tools हैं जो दिए गए scope के खिलाफ प्रस्तावित कार्यों का कुछ हिस्सा स्वचालित रूप से करेंगे।

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - थोड़ा पुराना है और updated नहीं है

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
