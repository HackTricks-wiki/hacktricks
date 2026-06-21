# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> 그래서 어떤 회사에 속한 모든 것이 범위에 포함된다고 들었고, 이 회사가 실제로 무엇을 소유하고 있는지 알아내고 싶다.

이 단계의 목표는 메인 회사가 소유한 모든 **회사들**을 얻은 다음, 이들 회사의 모든 **assets**를 찾는 것이다. 이를 위해 우리는 다음을 수행한다:

1. 메인 회사의 인수를 찾는다. 그러면 scope 안에 있는 회사들을 얻을 수 있다.
2. 각 회사의 ASN(있다면)을 찾는다. 그러면 각 회사가 소유한 IP 범위를 얻을 수 있다.
3. reverse whois 조회를 사용해 첫 번째 것과 관련된 다른 항목들(organisation names, domains...)을 찾는다. (이는 재귀적으로 수행할 수 있다)
4. shodan `org`and `ssl`필터 같은 다른 기법을 사용해 다른 assets를 찾는다 (`ssl` 트릭도 재귀적으로 수행할 수 있다).

### **Acquisitions**

우선, 메인 회사가 어떤 **다른 회사들을 소유하고 있는지** 알아야 한다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com)에 방문해 **main company**를 **검색**한 뒤 "**acquisitions**"를 **클릭**하는 것이다. 그러면 메인 회사가 인수한 다른 회사들을 볼 수 있다.\
다른 방법은 메인 회사의 **Wikipedia** 페이지를 방문해 **acquisitions**를 검색하는 것이다.\
공개 회사의 경우 **SEC/EDGAR filings**, **investor relations** 페이지, 또는 지역 기업 등록기관(예: 영국의 **Companies House**)을 확인하라.\
글로벌 기업 구조와 자회사를 찾으려면 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/))와 **GLEIF LEI** 데이터베이스 ([https://www.gleif.org/](https://www.gleif.org/))를 시도해보라.

> 좋다, 이 시점이면 scope 안의 모든 회사를 알아야 한다. 이제 그들의 assets를 찾는 방법을 알아보자.

### **ASNs**

autonomous system number (**ASN**)은 **Internet Assigned Numbers Authority (IANA)**가 **autonomous system** (AS)에 할당하는 **고유 번호**이다.\
**AS**는 외부 네트워크에 접근하기 위한 정책이 명확하게 정의된 **IP addresses** 블록들로 구성되며, 단일 organisation이 관리하지만 여러 운영자로 구성될 수도 있다.

회사가 **ASN을 할당받았는지** 확인해 **IP ranges**를 찾는 것이 흥미롭다.\
범위 내의 모든 **hosts**를 대상으로 **vulnerability test**를 수행하고 이 IP들 안의 **domains**를 찾아보는 것이 좋다.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **or** [**https://ipinfo.io/**](https://ipinfo.io/)에서 회사 **이름**, **IP**, 또는 **domain**으로 **검색**할 수 있다.\
**회사의 지역에 따라 다음 링크들이 더 많은 데이터를 수집하는 데 유용할 수 있다:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). 어쨌든, 아마도 모든 유용한 정보** (IP ranges and Whois)**는 이미 첫 번째 링크에 나타난다.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한 [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration은 스캔 শেষে ASN을 자동으로 집계하고 요약합니다.
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

At this point we know **all the assets inside the scope**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **or use services like** Shodan, Censys, or ZoomEye **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> We know all the companies inside the scope and their assets, it's time to find the domains inside the scope.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
이것이 동작하려면, 관리자가 PTR을 수동으로 활성화해야 합니다.\
이 정보를 얻기 위해 온라인 도구도 사용할 수 있습니다: [http://ptrarchive.com/](http://ptrarchive.com).\
큰 범위의 경우, [**massdns**](https://github.com/blechschmidt/massdns)와 [**dnsx**](https://github.com/projectdiscovery/dnsx) 같은 도구가 reverse lookups와 enrichment를 자동화하는 데 유용합니다.

### **Reverse Whois (loop)**

**whois** 안에서는 **organisation name**, **address**, **emails**, 전화번호 등 많은 흥미로운 **정보**를 찾을 수 있습니다. 하지만 더 흥미로운 것은 이러한 필드 중 하나를 사용해 **reverse whois lookups**를 수행하면 **회사와 관련된 더 많은 assets**를 찾을 수 있다는 점입니다(예: 같은 이메일이 나타나는 다른 whois registries).\
다음과 같은 온라인 도구를 사용할 수 있습니다:

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

[**DomLink** ](https://github.com/vysecurity/DomLink)(whoxy API key가 필요함)을 사용해 이 작업을 자동화할 수 있습니다.\
또한 [amass](https://github.com/OWASP/Amass)를 사용해 일부 automatic reverse whois discovery를 수행할 수 있습니다: `amass intel -d tesla.com -whois`

**새 domain을 찾을 때마다 이 technique를 사용해 더 많은 domain names를 발견할 수 있다는 점에 유의하세요.**

### **Trackers**

2개의 서로 다른 페이지에서 **같은 tracker의 같은 ID**를 찾으면, **두 페이지가 같은 팀에 의해 관리된다**고 추정할 수 있습니다.\
예를 들어 여러 페이지에서 같은 **Google Analytics ID**나 같은 **Adsense ID**를 볼 수 있습니다.

이러한 tracker와 그 외 항목으로 검색할 수 있게 해주는 페이지와 도구가 있습니다:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (공유된 analytics/trackers를 기준으로 관련 사이트를 찾음)

### **Favicon**

같은 favicon icon hash를 살펴보면 대상과 관련된 domain과 subdomain을 찾을 수 있다는 사실을 알고 계셨나요? 바로 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 도구가 [@m4ll0k2](https://twitter.com/m4ll0k2)에 의해 하는 일입니다. 사용 방법은 다음과 같습니다:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 동일한 favicon icon hash를 가진 도메인 발견](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash는 대상과 동일한 favicon icon hash를 가진 도메인들을 찾을 수 있게 해줍니다.

또한 [**이 블로그 글**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)에서 설명하듯이 favicon hash를 사용해 technologies를 검색할 수도 있습니다. 즉, **취약한 버전의 web tech의 favicon hash**를 알고 있다면 shodan에서 검색해서 **더 많은 취약한 위치를 찾을 수 있습니다**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
이것은 웹의 **favicon 해시를 계산**하는 방법입니다:
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
[**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`)를 사용해 favicon hashes를 대규모로 수집한 다음 Shodan/Censys에서 pivot할 수도 있습니다.

### **Copyright / Uniq string**

웹 페이지 안에서 **같은 조직의 서로 다른 웹들 사이에서 공유될 수 있는 strings**를 검색합니다. **copyright string**은 좋은 예시가 될 수 있습니다. 그런 다음 그 문자열을 **google**, 다른 **browsers**, 또는 **shodan**에서 검색합니다: `shodan search http.html:"Copyright string"`

### **CRT Time**

다음과 같은 cron job이 있는 경우가 흔합니다:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
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

많은 subdomains를 가장 빠르게 얻는 방법은 external sources에서 검색하는 것이다. 가장 많이 사용되는 **tools**는 다음과 같다(더 나은 결과를 위해 API keys를 설정하라):

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
다음과 같은 **다른 흥미로운 도구/APIs**도 있으며, 비록 직접적으로 subdomains를 찾는 데 특화되어 있지는 않더라도 subdomains를 찾는 데 유용할 수 있습니다:

- [**IP.THC.ORG**](https://ip.thc.org) 무료 API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** [https://sonar.omnisint.io](https://sonar.omnisint.io) API를 사용하여 subdomains를 얻음
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
- [**gau**](https://github.com/lc/gau)**:** AlienVault의 Open Threat Exchange, Wayback Machine, Common Crawl에서 주어진 도메인의 알려진 URL을 가져옵니다.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 웹을 스크랩하여 JS 파일을 찾고, 거기서 subdomains를 추출합니다.
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
- [**securitytrails.com**](https://securitytrails.com/)은 서브도메인과 IP 히스토리를 검색할 수 있는 무료 API를 제공합니다
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

이 프로젝트는 **버그 바운티 프로그램과 관련된 모든 서브도메인**을 무료로 제공합니다. 이 데이터는 [chaospy](https://github.com/dr-0x0x/chaospy)를 사용해서도 접근할 수 있고, 이 프로젝트에서 사용되는 스코프도 [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)에서 확인할 수 있습니다

여기서 이들 도구의 **비교**를 찾을 수 있습니다: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

가능한 서브도메인 이름을 사용해 DNS 서버를 brute-forcing하여 새로운 **서브도메인**을 찾아봅시다.

이 작업을 위해서는 다음과 같은 **일반적인 서브도메인 wordlists**가 필요합니다:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

그리고 좋은 DNS resolver들의 IP도 필요합니다. 신뢰할 수 있는 DNS resolver 목록을 생성하려면 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt)에서 resolvers를 다운로드한 뒤 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용해 필터링할 수 있습니다. 또는 다음을 사용할 수도 있습니다: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force에 가장 추천되는 도구는 다음과 같습니다:

- [**massdns**](https://github.com/blechschmidt/massdns): 효과적인 DNS brute-force를 수행한 최초의 도구였습니다. 매우 빠르지만 false positives가 발생하기 쉽습니다.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 이건 제 생각에 그냥 resolver 1개만 사용하는 것 같습니다
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns)는 `massdns`를 감싸는 go로 작성된 래퍼로, active bruteforce를 사용해 유효한 subdomains를 열거할 수 있게 해주며, wildcard 처리와 쉬운 input-output 지원을 통한 subdomains 해석도 가능합니다.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 또한 `massdns`를 사용합니다.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용하여 도메인 이름을 비동기적으로 브루트 포스합니다.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Second DNS Brute-Force Round

open sources와 brute-forcing을 사용해 subdomains를 찾은 후, 발견된 subdomains의 변형을 생성하여 더 많은 것을 찾아볼 수 있습니다. 이 목적에는 여러 도구가 유용합니다:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 주어진 domains와 subdomains로 permutations를 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 주어진 도메인과 서브도메인으로 permutations를 생성합니다.
- [**여기**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 goaltdns permutations **wordlist**를 얻을 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 도메인과 서브도메인이 주어지면 permutations를 생성합니다. permutations 파일이 지정되지 않으면 gotator는 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): 서브도메인 permutation을 생성하는 것 외에도 이를 resolve하려고 시도할 수 있습니다(하지만 앞에서 언급한 도구들을 사용하는 것이 더 좋습니다).
- [**altdns**] permutation **wordlist**는 [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 얻을 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 서브도메인에 대해 permutations, mutations 및 alteration을 수행하는 또 다른 도구입니다. 이 도구는 결과를 brute force합니다(dns wild card를 지원하지 않습니다).
- [**dmut** permutations wordlist는 [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 받을 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로, 지정된 패턴에 따라 **새로운 잠재적 서브도메인 이름을 생성**하여 더 많은 서브도메인을 발견하려고 시도합니다.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 자세한 내용은 이 [**post**](https://cramppet.github.io/regulator/index.html)를 읽어보세요. 기본적으로 **발견된 서브도메인**에서 **주요 부분**을 가져와 서로 조합해 더 많은 서브도메인을 찾습니다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_는 매우 단순하지만 효과적인 DNS 응답 기반 알고리즘과 결합된 subdomain brute-force fuzzer이다. 이는 맞춤형 wordlist나 과거 DNS/TLS records 같은 제공된 입력 데이터를 활용해, 더 많은 대응 domain name을 정확하게 합성하고 DNS scan 중 수집된 정보를 바탕으로 이를 반복적으로 더 확장한다.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows**를 사용하여 도메인에서 **subdomain discovery**를 자동화하는 방법에 대해 제가 쓴 이 블로그 पोस्ट를 확인해보세요. 이렇게 하면 컴퓨터에서 수많은 도구를 수동으로 실행할 필요가 없습니다:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

하나 또는 여러 개의 웹 페이지를 포함하고 있고 subdomains에 속한 IP address를 찾았다면, 해당 IP의 **OSINT sources**에서 도메인을 찾아보거나 그 IP에서 **VHost domain names를 brute-forcing** 해서 **그 IP에 있는 다른 subdomains**를 찾아볼 수 있습니다.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 다른 APIs**를 사용해 **IPs에서 VHosts**를 찾을 수 있습니다.

**Brute Force**

어떤 subdomain이 웹 서버 안에 숨겨져 있다고 의심된다면 brute force를 시도해볼 수 있습니다:

**IP가 hostname으로 리디렉션될 때**(name-based vhosts), `Host` header를 직접 fuzz하고 ffuf가 **auto-calibrate**하도록 해서 기본 vhost와 다른 응답을 강조 표시하게 하세요:
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
> 이 기법을 사용하면 내부/숨겨진 endpoint에 접근할 수도 있습니다.

### **CORS Brute Force**

때때로 _**Origin**_ 헤더에 유효한 도메인/subdomain이 설정된 경우에만 _**Access-Control-Allow-Origin**_ 헤더를 반환하는 페이지를 찾을 수 있습니다. 이런 시나리오에서는 이 동작을 악용해 새로운 **subdomain**을 **discover**할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains**을 살펴보면서 어떤 종류의 **bucket**을 가리키는지 확인하고, 그런 경우 [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
또한 이 시점이면 범위 내의 모든 도메인을 알게 되었을 테니, 가능한 bucket 이름을 [**brute force**하고 **check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)해 보세요.

### **Monitorization**

도메인의 **new subdomains**가 생성되는지 **Certificate Transparency** Logs를 모니터링하여 확인할 수 있습니다. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)가 이를 수행합니다.

### **Looking for vulnerabilities**

가능한 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
**subdomain**이 어떤 **S3 bucket**을 가리키고 있다면, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)하세요.

발견한 assets discovery에서 이미 찾은 것들과 **IP가 다른 subdomain**이 있으면, **basic vulnerability scan**(Nessus 또는 OpenVAS 사용)과 함께 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 **nmap/masscan/shodan**으로 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 그 서비스를 "attack"하는 몇 가지 trick**을 찾을 수 있습니다.\
_참고로, 때때로 subdomain은 client가 통제하지 않는 IP 내부에서 호스팅되므로 scope에 포함되지 않을 수 있으니 주의하세요._

## IPs

초기 단계에서 **some IP ranges, domains and subdomains**를 발견했을 수 있습니다.\
이제 해당 범위의 **모든 IP를 수집**하고, **domains/subdomains**에 대해서도 수집할 차례입니다(DNS queries).

다음 **free apis**를 사용하는 서비스들을 통해 도메인과 subdomain이 과거에 사용했던 **previous IPs**도 찾을 수 있습니다. 이러한 IP는 여전히 client가 소유하고 있을 수 있으며, [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾는 데 도움이 될 수 있습니다)

- [**https://securitytrails.com/**](https://securitytrails.com/)

또한 [**hakip2host**](https://github.com/hakluke/hakip2host) 도구를 사용해 특정 IP address를 가리키는 도메인도 확인할 수 있습니다.

### **Looking for vulnerabilities**

CDN에 속하지 않는 **모든 IP에 대해 Port scan**을 수행하세요(그 안에서는 흥미로운 것을 찾지 못할 가능성이 매우 높기 때문입니다). 발견된 실행 중인 서비스에서 **vulnerabilities**를 찾을 수 있을지도 모릅니다.

**호스트를 scan하는 방법에 대한** [**guide**](../pentesting-network/index.html)를 **찾아보세요.**

## Web servers hunting

> 우리는 모든 회사와 그 assets를 찾았고, scope 안의 IP ranges, domains and subdomains도 알고 있습니다. 이제 web servers를 찾을 차례입니다.

이전 단계에서 이미 발견한 IP와 도메인에 대해 일부 **recon**을 수행했을 가능성이 높으므로, 이미 **가능한 모든 web servers**를 찾았을 수도 있습니다. 하지만 그렇지 않다면, 이제 scope 안에서 **web servers를 찾는 빠른 trick** 몇 가지를 살펴보겠습니다.

이 내용은 **web apps discovery**에 초점을 맞추고 있으므로, **vulnerability** 및 **port scanning**도 (**scope에서 허용된다면**) 수행해야 합니다.

[**masscan**을 사용해 **web** servers와 관련된 **열린 port**를 찾는 빠른 방법은 여기에서 확인할 수 있습니다](../pentesting-network/index.html#http-port-discovery).\
web servers를 찾는 또 다른 유용한 도구는 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe), 그리고 [**httpx**](https://github.com/projectdiscovery/httpx)입니다. 도메인 목록을 넘기면 port 80(http)과 443(https)에 연결을 시도합니다. 추가로 다른 port도 시도하도록 지정할 수 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

이제 범위 안에 존재하는 **모든 web servers**를 발견했으니(회사 **IPs**와 모든 **domains** 및 **subdomains** 포함) 아마도 **어디서 시작해야 할지 모를** 것입니다. 그러니 간단하게, 우선 전부 **screenshots**를 찍어봅시다. **메인 페이지**를 **보기만 해도** 더 **취약할 가능성**이 높은 **이상한** endpoints를 찾을 수 있습니다.

제안한 아이디어를 수행하려면 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** 를 사용할 수 있습니다.

또한 [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용해 모든 **screenshots**를 훑어보며 **무엇이 취약점을 포함할 가능성이 높은지**, 그리고 무엇이 아닌지를 알려주게 할 수 있습니다.

## Public Cloud Assets

회사에 속한 잠재적인 cloud assets를 찾으려면, 먼저 **그 회사를 식별하는 키워드 목록**으로 시작해야 합니다. 예를 들어, crypto 회사라면 `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` 같은 단어를 사용할 수 있습니다.

또한 **buckets**에서 흔히 사용되는 단어들의 wordlists도 필요합니다:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그 다음, 그 단어들로 **permutations**를 생성해야 합니다(자세한 내용은 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)를 참고).

생성된 wordlists로 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **또는** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** 같은 도구를 사용할 수 있습니다.

Cloud Assets를 찾을 때는 **AWS의 buckets만 찾으면 안 된다**는 점을 기억하세요.

### **Looking for vulnerabilities**

**open buckets**나 **cloud functions exposed** 같은 것을 찾았다면, **직접 접근**해서 무엇을 제공하는지 확인하고 악용할 수 있는지 시도해 보세요.

## Emails

범위 안의 **domains**와 **subdomains**가 있으면, 기본적으로 이메일을 찾기 시작하는 데 필요한 모든 것을 갖춘 것입니다. 아래는 제가 회사의 이메일을 찾는 데 가장 잘 작동했던 **APIs**와 **tools**입니다:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

이메일은 나중에 **web logins and auth services**(예: SSH)을 **brute-force**할 때 유용합니다. 또한 **phishings**에도 필요합니다. 더불어, 이러한 APIs는 이메일 뒤의 **사람에 대한 더 많은 info**를 제공하므로, phishing campaign에 유용합니다.

## Credential Leaks

**domains,** **subdomains**, 그리고 **emails**가 있으면, 과거에 유출된 해당 이메일들의 credentials를 찾기 시작할 수 있습니다:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**유효한 유출** credentials를 찾는다면, 이것은 매우 쉬운 성과입니다.

## Secrets Leaks

Credential leaks는 **민감한 정보가 유출되어 판매된** 회사 해킹과 관련이 있습니다. 하지만 회사는 이러한 데이터베이스에 없는 **다른 leak**의 영향을 받을 수도 있습니다:

### Github Leaks

Credentials와 APIs는 **회사**의 **public repositories** 또는 그 github 회사에서 일하는 **users**의 저장소에 유출될 수 있습니다.\
**tool** [**Leakos**](https://github.com/carlospolop/Leakos)를 사용해 **organization**과 그 **developers**의 모든 **public repos**를 **download**하고, 자동으로 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 실행할 수 있습니다.

**Leakos**는 제공된 모든 **text**와 **URLs passed**에 대해 **gitleaks**를 실행하는 데도 사용할 수 있는데, 때때로 **web pages also contains secrets**이기 때문입니다.

#### Github Dorks

공격 중인 organization에서 검색할 수 있는 잠재적인 **github dorks**에 대해서도 이 **page**를 확인하세요:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

때때로 공격자나 단순히 직원들이 **paste site**에 회사 콘텐츠를 게시하기도 합니다. 여기에는 **민감한 정보**가 포함될 수도 있고 아닐 수도 있지만, 검색해 볼 가치는 매우 큽니다.\
**tool** [**Pastos**](https://github.com/carlospolop/Pastos)를 사용하면 80개가 넘는 paste sites를 동시에 검색할 수 있습니다.

### Google Dorks

오래됐지만 여전히 좋은 google dorks는 **거기에 있어서는 안 될 노출된 정보**를 찾는 데 항상 유용합니다. 유일한 문제는 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에 수천 개의 가능한 queries가 있어 수동으로 전부 실행할 수 없다는 점입니다. 그래서 가장 좋아하는 10개만 고르거나, 아니면 [**Gorks**](https://github.com/carlospolop/Gorks) 같은 **tool을 사용해** 전부 실행할 수 있습니다.

_정규 Google browser를 사용해 데이터베이스 전체를 실행하도록 기대하는 tools는 결코 끝나지 않을 것입니다. Google이 매우 빨리 차단할 것이기 때문입니다._

### **Looking for vulnerabilities**

**유효한 유출** credentials나 API tokens를 찾는다면, 이것은 매우 쉬운 성과입니다.

## Public Code Vulnerabilities

회사가 **open-source code**를 보유하고 있다면, 이를 **분석**하고 그 안의 **vulnerabilities**를 찾을 수 있습니다.

**언어에 따라** 사용할 수 있는 **tools**는 다릅니다:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

공개 repositories를 **scan**할 수 있는 무료 서비스도 있으며, 예를 들면:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**bug hunters**가 발견하는 **vulnerabilities의 대부분**은 **web applications** 안에 있으므로, 여기서는 **web application testing methodology**에 대해 이야기하고자 합니다. 관련 정보는 [**여기**](../../network-services-pentesting/pentesting-web/index.html)에서 확인할 수 있습니다.

또한 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 섹션도 특별히 언급하고 싶습니다. 이 도구들이 매우 민감한 vulnerabilities를 찾아줄 것이라 기대해서는 안 되지만, **workflows**에 넣어 초기 web 정보를 얻는 데 매우 유용합니다.

## Recapitulation

> 축하합니다! 이 시점에서 이미 **모든 기본 enumeration**을 수행했습니다. 네, 기본인 이유는 훨씬 더 많은 enumeration을 할 수 있기 때문입니다(더 많은 트릭은 나중에 보게 될 것입니다).

따라서 이미 다음을 수행한 것입니다:

1. 범위 안의 모든 **companies**를 찾음
2. 회사에 속한 모든 **assets**를 찾음(범위 안이라면 vuln scan도 수행)
3. 회사에 속한 모든 **domains**를 찾음
4. domains의 모든 **subdomains**를 찾음(subdomain takeover?)
5. 범위 안의 모든 **IPs**(CDNs **from and not from**)를 찾음.
6. 모든 **web servers**를 찾고 그 **screenshot**을 찍음(더 깊게 볼 만한 이상한 것이 있는가?)
7. 회사에 속한 모든 **potential public cloud assets**를 찾음.
8. 쉽게 큰 성과를 낼 수 있는 **Emails**, **credentials leaks**, **secret leaks**.
9. 찾은 모든 web에 대해 **Pentesting**

## **Full Recon Automatic Tools**

주어진 범위에 대해 제안한 작업의 일부를 수행하는 여러 도구가 있습니다.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 조금 오래되었고 업데이트되지 않음

## **References**

- [**@Jhaddix**](https://twitter.com/Jhaddix)의 모든 무료 코스, 예를 들면 [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
