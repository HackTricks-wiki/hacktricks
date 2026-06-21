# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> 그래서 어떤 회사에 속한 모든 것이 scope 안에 있다고 들었고, 이 회사가 실제로 무엇을 소유하는지 알아내고 싶다는 거군요.

이 단계의 목표는 메인 회사가 소유한 모든 **companies**를 찾은 다음, 이들 회사의 모든 **assets**를 찾는 것입니다. 이를 위해 다음을 수행합니다:

1. 메인 회사의 acquisitions를 찾습니다. 그러면 scope 안의 회사들을 알 수 있습니다.
2. 각 회사의 ASN(있다면)을 찾습니다. 그러면 각 회사가 소유한 IP ranges를 알 수 있습니다.
3. reverse whois lookups를 사용해 첫 번째 결과와 관련된 다른 항목들(organization names, domains...)을 찾습니다. 이것은 재귀적으로 수행할 수 있습니다.
4. shodan `org`및 `ssl`filters 같은 다른 기법을 사용해 다른 assets를 찾습니다(`ssl` trick도 재귀적으로 수행할 수 있습니다).

### **Acquisitions**

우선, 메인 company가 어떤 **other companies**를 소유하고 있는지 알아야 합니다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com)을 방문해 **main company**를 **search**한 뒤 "**acquisitions**"를 **click**하는 것입니다. 그러면 메인 회사가 인수한 다른 회사들을 볼 수 있습니다.\
다른 방법은 메인 회사의 **Wikipedia** 페이지를 방문해 **acquisitions**를 검색하는 것입니다.\
공개 회사의 경우, **SEC/EDGAR filings**, **investor relations** 페이지, 또는 지역 기업 등록부(예: 영국의 **Companies House**)를 확인하세요.\
글로벌 기업 구조와 자회사를 보려면 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/))와 **GLEIF LEI** 데이터베이스([https://www.gleif.org/](https://www.gleif.org/))를 시도해 보세요.

> 좋습니다, 이제 scope 안의 모든 회사를 알아야 합니다. 이제 이들의 assets를 찾는 방법을 알아봅시다.

### **ASNs**

autonomous system number(**ASN**)은 **Internet Assigned Numbers Authority (IANA)**가 **autonomous system**(AS)에 할당하는 **unique number**입니다.\
**AS**는 외부 네트워크에 접근하기 위한 정책이 명확히 정의된 **IP addresses**의 **blocks**로 구성되며, 단일 organisation이 관리하지만 여러 operator로 구성될 수도 있습니다.

회사가 할당받은 **ASN**이 있는지 찾아 **IP ranges**를 알아내는 것이 흥미롭습니다. scope 안의 모든 **hosts**에 대해 **vulnerability test**를 수행하고 이 IP들 안에서 **domains**를 찾아보는 것이 좋습니다.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **또는** [**https://ipinfo.io/**](https://ipinfo.io/)에서 회사 **name**, **IP** 또는 **domain**으로 **search**할 수 있습니다.\
**회사의 지역에 따라 더 많은 데이터를 수집하는 데 유용할 수 있는 링크들:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). 어쨌든, 아마도 모든 유용한 정보**(IP ranges and Whois)**는 이미 첫 번째 링크에 나타납니다.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한 [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration은 스캔이 끝날 때 ASN을 자동으로 집계하고 요약합니다.
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
조직의 IP 범위는 [http://asnlookup.com/](http://asnlookup.com)에서도 찾을 수 있습니다(무료 API가 있습니다).\
도메인의 IP와 ASN은 [http://ipv4info.com/](http://ipv4info.com)에서 찾을 수 있습니다.

### **취약점 찾기**

이 시점에서는 **범위 내의 모든 자산을 알고 있으므로**, 허용된다면 모든 호스트에 대해 **취약점 스캐너**(Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei))를 실행할 수 있습니다.\
또한 일부 [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) 을 실행하거나 Shodan, Censys, ZoomEye 같은 서비스를 **사용해** 열린 포트를 **찾을 수 있으며,** 무엇을 찾느냐에 따라 이 책에서 실행 중인 여러 서비스에 대해 pentest하는 방법을 살펴봐야 합니다.\
**또한, 기본 username**과 **password** 목록을 준비한 뒤 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)로 서비스에 대해 bruteforce를 시도해볼 수도 있습니다.

## 도메인

> 우리는 범위 내의 모든 회사와 그 자산을 알고 있습니다. 이제 범위 내의 도메인을 찾을 차례입니다.

_참고로, 아래의 제시된 기법들에서는 서브도메인도 찾을 수 있으며 그 정보는 과소평가해서는 안 됩니다._

먼저 각 회사의 **주 도메인**을 찾아야 합니다. 예를 들어, _Tesla Inc._의 경우 _tesla.com_이 됩니다.

### **Reverse DNS**

도메인의 모든 IP 범위를 찾았다면, 그 **IP**들에 대해 **reverse dns lookup**을 수행하여 **범위 내의 더 많은 도메인**을 찾을 수 있습니다. 피해자의 DNS 서버나 널리 알려진 DNS 서버(1.1.1.1, 8.8.8.8)를 사용해 보세요.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
이 기능이 작동하려면 관리자가 PTR를 수동으로 활성화해야 합니다.\
이 정보는 온라인 도구도 사용할 수 있습니다: [http://ptrarchive.com/](http://ptrarchive.com).\
큰 범위의 경우 [**massdns**](https://github.com/blechschmidt/massdns)와 [**dnsx**](https://github.com/projectdiscovery/dnsx) 같은 도구가 reverse lookups와 enrichment를 자동화하는 데 유용합니다.

### **Reverse Whois (loop)**

**whois** 안에서 **organisation name**, **address**, **emails**, 전화번호 같은 많은 흥미로운 **information**을 찾을 수 있습니다. 하지만 더 흥미로운 점은 이러한 필드 중 하나를 기준으로 **reverse whois lookups**를 수행하면 **회사와 관련된 더 많은 assets**를 찾을 수 있다는 것입니다(예: 같은 이메일이 나타나는 다른 whois registries).\
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
[amass](https://github.com/OWASP/Amass)를 사용해서 일부 자동 reverse whois discovery도 수행할 수 있습니다: `amass intel -d tesla.com -whois`

**이 기법을 사용하면 새 domain을 찾을 때마다 더 많은 domain name을 발견할 수 있다는 점에 유의하세요.**

### **Trackers**

서로 다른 2개 페이지에서 **같은 tracker의 같은 ID**를 찾으면 **두 페이지가 같은 팀에 의해 관리된다**고 추정할 수 있습니다.\
예를 들어 여러 페이지에서 같은 **Google Analytics ID** 또는 같은 **Adsense ID**를 볼 수 있습니다.

이러한 tracker와 그 밖의 정보를 기준으로 검색할 수 있게 해주는 페이지와 도구가 있습니다:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (공유 analytics/trackers를 통해 관련 사이트를 찾음)

### **Favicon**

같은 favicon icon hash를 보면 대상과 관련된 domain과 subdomain을 찾을 수 있다는 사실을 알고 있었나요? 바로 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 도구가 [@m4ll0k2](https://twitter.com/m4ll0k2)에 의해 이 기능을 수행합니다. 사용 방법은 다음과 같습니다:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 동일한 favicon 아이콘 해시를 가진 도메인 발견](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash는 대상과 동일한 favicon 아이콘 해시를 가진 도메인들을 발견할 수 있게 해줍니다.

또한, [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)에서 설명하듯 favicon 해시를 사용해 기술을 검색할 수도 있습니다. 즉, **취약한 버전의 웹 기술 favicon 해시**를 알고 있다면 shodan에서 검색해 **더 많은 취약한 장소를 찾을 수 있습니다**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
이것이 웹의 **favicon hash**를 계산하는 방법입니다:
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
[**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`)를 사용해 대규모로 favicon 해시를 얻은 다음 Shodan/Censys에서 pivot할 수도 있습니다.

### **Copyright / Uniq string**

웹 페이지 내부에서 **같은 조직의 다른 웹들 간에 공유될 수 있는 문자열**을 검색하세요. **copyright string**은 좋은 예가 될 수 있습니다. 그런 다음 그 문자열을 **google**, 다른 **browsers** 또는 심지어 **shodan**에서 검색하세요: `shodan search http.html:"Copyright string"`

### **CRT Time**

다음과 같은 cron job이 있는 것은 흔합니다
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

많은 subdomains를 가장 빠르게 얻는 방법은 external sources에서 search하는 것입니다. 가장 많이 사용되는 **tools**는 다음과 같습니다(API keys를 configure하면 더 좋은 결과를 얻을 수 있습니다):

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
다음과 같은 **다른 흥미로운 tools/APIs**도 있습니다. 비록 subdomains를 찾는 데 직접 특화되지는 않았더라도 subdomains를 찾는 데 유용할 수 있습니다:

- [**IP.THC.ORG**](https://ip.thc.org) 무료 API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io)를 사용하여 subdomains를 얻습니다
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) 무료 API
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
- [**gau**](https://github.com/lc/gau)**:** 주어진 도메인에 대해 AlienVault의 Open Threat Exchange, Wayback Machine, 그리고 Common Crawl에서 알려진 URL을 가져옵니다.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 이들은 웹을 스크랩하여 JS 파일을 찾고, 그 안에서 subdomains를 추출합니다.
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
- [**securitytrails.com**](https://securitytrails.com/)은 서브도메인과 IP 이력을 검색할 수 있는 무료 API를 제공합니다
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

이 프로젝트는 **bug-bounty 프로그램과 관련된 모든 서브도메인**을 **무료로** 제공합니다. 이 데이터는 [chaospy](https://github.com/dr-0x0x/chaospy)를 사용해서도 접근할 수 있고, 이 프로젝트가 사용하는 scope도 [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)에서 확인할 수 있습니다

여기에서 이들 도구의 **비교**를 볼 수 있습니다: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

가능한 서브도메인 이름을 이용해 DNS 서버를 brute-forcing하여 새로운 **subdomains**를 찾아봅시다.

이 작업을 위해서는 다음과 같은 **일반적인 subdomains wordlists**가 필요합니다:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

그리고 좋은 DNS resolvers의 IP도 필요합니다. 신뢰할 수 있는 DNS resolvers 목록을 생성하려면 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)에서 resolvers를 다운로드한 뒤 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용해 필터링할 수 있습니다. 또는 다음을 사용할 수도 있습니다: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force에 가장 추천되는 도구는 다음과 같습니다:

- [**massdns**](https://github.com/blechschmidt/massdns): 이는 효과적인 DNS brute-force를 수행한 최초의 도구였습니다. 매우 빠르지만 false positives가 발생하기 쉽습니다.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 이것은 제 생각에 resolver 1개만 사용하는 것 같습니다
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is a wrapper around `massdns`, written in go, that allows you to enumerate valid subdomains using active bruteforce, as well as resolve subdomains with wildcard handling and easy input-output support.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 이것도 `massdns`를 사용합니다.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용하여 도메인 이름을 비동기적으로 브루트 포스합니다.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Second DNS Brute-Force Round

오픈 소스와 brute-forcing을 사용해 subdomains를 찾은 뒤, 발견한 subdomains의 변형을 생성하여 더 많은 subdomains를 찾아볼 수 있습니다. 이 목적에는 다음 도구들이 유용합니다:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 주어진 domains와 subdomains로 permutations를 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 주어진 도메인과 서브도메인으로 permutations를 생성합니다.
- goaltdns permutations **wordlist**는 [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 얻을 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 도메인과 서브도메인이 주어지면 permutations를 생성합니다. permutation 파일이 지정되지 않으면 gotator는 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): 서브도메인 permutation을 생성하는 것 외에도 이를 resolve하려고 시도할 수 있습니다(하지만 이전에 언급한 도구들을 사용하는 것이 더 좋습니다).
- [**altdns** permutations **wordlist**는 [**여기**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 얻을 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 서브도메인의 permutations, mutations 및 alteration을 수행하는 또 다른 도구입니다. 이 도구는 결과를 brute force합니다 (dns wild card를 지원하지 않습니다).
- [**dmut** permutations wordlist는 [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 받을 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로, 표시된 패턴에 따라 **새로운 잠재적 subdomains 이름**을 생성하여 더 많은 subdomains를 발견하려고 시도한다.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 자세한 내용은 이 [**post**](https://cramppet.github.io/regulator/index.html)를 참고하라. 기본적으로 **발견된 subdomains**에서 **주요 부분**을 가져와 이를 조합해 더 많은 subdomains를 찾는다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_는 매우 단순하지만 효과적인 DNS 응답 기반 알고리즘과 결합된 subdomain brute-force fuzzer이다. 이는 맞춤형 wordlist나 과거의 DNS/TLS records 같은 제공된 입력 데이터 집합을 활용해, DNS scan 중 수집한 정보를 바탕으로 더 많은 대응 domain name을 정확하게 합성하고, 이를 루프 방식으로 더 확장한다.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows**를 사용해서 도메인에서 **subdomain discovery**를 자동화하는 방법에 대해 내가 쓴 이 블로그 글을 확인해보세요. 이렇게 하면 컴퓨터에서 여러 도구를 수동으로 실행할 필요가 없습니다:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

하나 이상의 웹 페이지를 포함하고 있고 subdomain에 속하는 IP address를 찾았다면, **OSINT sources**에서 그 IP의 domains를 찾아서 또는 그 IP에서 **VHost domain names를 brute-force**해서, 그 IP에 있는 다른 subdomain을 **찾아볼 수 있습니다**.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 다른 APIs를 사용해서** IP들에서 일부 **VHosts를 찾을 수 있습니다**.

**Brute Force**

어떤 subdomain이 web server 안에 숨겨져 있다고 의심된다면, brute force를 시도해볼 수 있습니다:

**IP가 hostname으로 redirect될 때**(name-based vhosts), `Host` header를 직접 fuzz하고 ffuf가 **auto-calibrate**하도록 해서 default vhost와 다른 responses를 강조 표시하게 하세요:
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
> 이 기법을 사용하면 internal/hidden endpoint에까지 접근할 수 있을 수도 있습니다.

### **CORS Brute Force**

때때로 _**Origin**_ 헤더에 유효한 domain/subdomain이 설정된 경우에만 _**Access-Control-Allow-Origin**_ 헤더를 반환하는 페이지를 발견할 수 있습니다. 이런 시나리오에서는 이 동작을 악용해 새로운 **subdomain**을 **discover**할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**서브도메인**을 살펴보면서 그것이 어떤 유형의 **bucket**을 가리키는지 확인하고, 그런 경우 [**permissions를 확인**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
또한, 이 시점에서는 scope 안의 모든 domains를 알게 되었으므로, [**가능한 bucket 이름을 brute force하고 permissions를 확인**](../../network-services-pentesting/pentesting-web/buckets/index.html)해 보세요.

### **Monitorization**

도메인의 **새로운 subdomains**가 생성되는지 **Certificate Transparency** Logs를 모니터링하여 확인할 수 있습니다. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)가 이를 수행합니다.

### **Looking for vulnerabilities**

가능한 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
**subdomain**이 어떤 **S3 bucket**을 가리키고 있다면, [**permissions를 확인**](../../network-services-pentesting/pentesting-web/buckets/index.html)하세요.

이미 assets discovery에서 찾은 것들과 **IP가 다른 subdomain**을 발견했다면, **basic vulnerability scan**(Nessus 또는 OpenVAS 사용)과 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 **nmap/masscan/shodan**으로 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 그것들을 "공격"하는 몇 가지 트릭**을 찾을 수 있습니다.\
_때때로 subdomain은 client가 제어하지 않는 IP 안에서 호스팅되므로 scope 밖일 수 있습니다. 주의하세요._

## IPs

초기 단계에서 **일부 IP ranges, domains, subdomains**를 **찾았을** 수 있습니다.\
이제 그 ranges에 속한 **모든 IP를 다시 수집**하고, **domains/subdomains에 대한 DNS queries**도 수행할 차례입니다.

다음 **free apis**의 서비스를 사용하면 **domains와 subdomains가 과거에 사용했던 IP**도 찾을 수 있습니다. 이 IP들은 아직 client가 소유하고 있을 수 있으며, [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾는 데 도움이 될 수 있습니다.

- [**https://securitytrails.com/**](https://securitytrails.com/)

또한 [**hakip2host**](https://github.com/hakluke/hakip2host) 도구를 사용해 특정 IP address를 가리키는 domains를 확인할 수 있습니다.

### **Looking for vulnerabilities**

**CDN에 속하지 않는 모든 IP에 port scan**을 수행하세요(그곳에서는 흥미로운 것을 찾지 못할 가능성이 매우 높습니다). 발견한 실행 중인 서비스에서 **vulnerabilities**를 찾을 수 있습니다.

호스트를 스캔하는 방법에 대한 [**guide**](../pentesting-network/index.html)를 **찾아보세요.**

## Web servers hunting

> 우리는 모든 companies와 그 assets를 찾았고, scope 안의 IP ranges, domains, subdomains도 알고 있습니다. 이제 web servers를 찾을 차례입니다.

이전 단계에서 이미 발견한 IP와 domains에 대한 일부 **recon**을 수행했을 가능성이 높으므로, **가능한 모든 web servers를 이미 찾았을** 수도 있습니다. 그러나 아직 찾지 못했다면, 이제 scope 안에서 web servers를 찾는 몇 가지 **빠른 트릭**을 살펴보겠습니다.

이 작업은 **web apps discovery**에 맞춰져 있으므로, **vulnerability**와 **port scanning**도 해야 합니다(**scope에서 허용되는 경우**).

[**masscan**을 사용해 web servers 관련 **열린 ports**를 찾는 빠른 방법은 여기**에서**](../pentesting-network/index.html#http-port-discovery) 확인할 수 있습니다.\
웹 servers를 찾는 또 다른 유용한 도구는 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 및 [**httpx**](https://github.com/projectdiscovery/httpx)입니다. domains 목록을 넘기면 port 80 (http)와 443 (https)에 연결을 시도합니다. 추가로, 다른 ports도 시도하도록 지정할 수 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

이제 범위 내에 존재하는 **모든 web servers**를 찾았으니 (회사의 **IPs**와 모든 **domains** 및 **subdomains**를 포함해서) 아마도 **어디서 시작해야 할지 모를 것**입니다. 그러니 단순하게, 우선 이들 모두의 screenshot을 찍어봅시다. **메인 페이지**를 **한번 보기만 해도** 더 **취약할 가능성**이 높은 **이상한** endpoints를 찾을 수 있습니다.

제안한 아이디어를 수행하려면 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**를 사용할 수 있습니다.

또한 [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용해 모든 **screenshots**를 검사하여 **무엇이 취약점을 포함할 가능성이 높은지**, 그리고 무엇이 아닌지를 알려줄 수 있습니다.

## Public Cloud Assets

회사에 속한 잠재적인 cloud assets를 찾으려면 먼저 **그 회사를 식별하는 키워드 목록**부터 시작해야 합니다. 예를 들어 crypto 회사라면 `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` 같은 단어들을 사용할 수 있습니다.

또한 buckets에서 흔히 사용되는 단어들의 wordlists도 필요합니다:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그다음, 그 단어들로 **permutations**를 생성해야 합니다(자세한 내용은 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)를 확인하세요).

이렇게 만든 wordlists로 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **또는** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** 같은 도구를 사용할 수 있습니다.

Cloud Assets를 찾을 때는 **AWS의 buckets만 찾으면 안 된다는 점**을 기억하세요.

### **Looking for vulnerabilities**

**open buckets**나 **exposed된 cloud functions** 같은 것을 찾았다면, 그것들에 **접속해** 무엇을 제공하는지 확인하고 악용할 수 있는지 시도해야 합니다.

## Emails

범위 안의 **domains**와 **subdomains**가 있다면, 이메일을 찾기 시작하는 데 필요한 것은 사실상 모두 갖춘 셈입니다. 회사의 이메일을 찾는 데 가장 잘 작동했던 **APIs**와 **tools**는 다음과 같습니다:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

이메일은 나중에 **web logins and auth services**(예: SSH)를 **brute-force**할 때 유용합니다. 또한 **phishings**에도 필요합니다. 더불어 이들 API는 이메일 뒤에 있는 **사람에 대한 더 많은 info**도 제공하므로 phishing campaign에 유용합니다.

## Credential Leaks

**domains,** **subdomains**, 그리고 **emails**가 있으면, 과거에 그 이메일들과 관련해 유출된 credentials를 찾기 시작할 수 있습니다:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**valid leaked** credentials를 찾았다면, 이것은 매우 쉬운 성과입니다.

## Secrets Leaks

Credential leaks는 **민감한 정보가 유출되어 판매된** 회사 해킹과 관련이 있습니다. 하지만 회사는 이런 데이터베이스에 없는 **다른 leaks**의 영향을 받을 수도 있습니다:

### Github Leaks

Credentials와 APIs는 **회사**의 **public repositories**나, 그 github 회사에서 일하는 **users**의 저장소에 유출될 수 있습니다.\
[**Leakos**](https://github.com/carlospolop/Leakos) **tool**을 사용하면 조직의 **public repos**와 그 **developers**의 저장소를 모두 **download**한 뒤, 자동으로 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 실행할 수 있습니다.

**Leakos**는 전달된 **text**가 포함된 모든 **URLs passed**에 대해 **gitleaks**를 실행하는 데에도 사용할 수 있는데, 때때로 **web pages also contains secrets**이기 때문입니다.

#### Github Dorks

공격 중인 조직에서 검색해볼 수 있는 잠재적인 **github dorks**에 대해서도 이 **page**를 확인하세요:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

때때로 공격자나 일반 사용자들이 **paste site**에 회사 콘텐츠를 게시하기도 합니다. 여기에 **민감한 정보**가 포함될 수도 있고 아닐 수도 있지만, 검색해볼 가치가 매우 큽니다.\
[**Pastos**](https://github.com/carlospolop/Pastos) tool을 사용하면 한 번에 80개 이상의 paste sites에서 검색할 수 있습니다.

### Google Dorks

오래되었지만 여전히 유용한 google dorks는 **그곳에 있으면 안 되는 노출된 정보**를 찾는 데 항상 유용합니다. 유일한 문제는 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에 수천 개의 가능한 쿼리가 있어서 수동으로 모두 실행할 수 없다는 점입니다. 따라서 마음에 드는 10개만 골라 쓰거나, [**Gorks**](https://github.com/carlospolop/Gorks) **같은 tool**을 사용해 전부 실행할 수 있습니다.

_정규 Google browser를 사용해 데이터베이스 전체를 실행하도록 되어 있는 tools는 Google이 아주 빨리 차단할 것이므로 끝까지 돌지 못한다는 점에 유의하세요._

### **Looking for vulnerabilities**

**valid leaked** credentials나 API tokens를 찾았다면, 이것은 매우 쉬운 성과입니다.

## Public Code Vulnerabilities

회사가 **open-source code**를 가지고 있다면, 이를 **analyse**하고 그 안에서 **vulnerabilities**를 찾을 수 있습니다.

**언어에 따라** 사용할 수 있는 **tools**가 다릅니다:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

또한 public repositories를 **scan**할 수 있게 해주는 무료 서비스도 있습니다. 예를 들면:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters가 찾는 **majority of the vulnerabilities**는 **web applications** 안에 있으므로, 이 시점에서는 **web application testing methodology**에 대해 이야기하고 싶습니다. 관련 정보는 [**여기**](../../network-services-pentesting/pentesting-web/index.html)에서 찾을 수 있습니다.

또한 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 섹션도 특별히 언급하고 싶습니다. 이들은 매우 민감한 취약점을 찾아줄 것이라고 기대해서는 안 되지만, **workflows**에 넣어 초기 web information을 얻는 데 유용합니다.

## Recapitulation

> 축하합니다! 이 시점에서 여러분은 이미 **모든 basic enumeration**을 수행했습니다. 네, basic입니다. 더 많은 enumeration이 가능하기 때문입니다(나중에 더 많은 tricks를 보게 될 것입니다).

따라서 여러분은 이미 다음을 수행했습니다:

1. 범위 내의 모든 **companies**를 찾음
2. 회사에 속한 모든 **assets**를 찾음(범위에 포함된다면 vuln scan도 수행)
3. 회사에 속한 모든 **domains**를 찾음
4. domains의 모든 **subdomains**를 찾음(subdomain takeover가 있는가?)
5. 범위 내의 모든 **IPs**(CDNs **from and not from** 포함)를 찾음.
6. 모든 **web servers**를 찾고 그들의 **screenshot**을 찍음(더 깊게 살펴볼 만한 이상한 것이 있는가?)
7. 회사에 속한 모든 **potential public cloud assets**를 찾음.
8. 매우 쉽게 큰 성과를 낼 수 있는 **Emails**, **credentials leaks**, 그리고 **secret leaks**.
9. 찾은 모든 웹에 대해 **Pentesting** 수행

## **Full Recon Automatic Tools**

제안한 작업의 일부를 특정 범위에 대해 수행해 주는 도구들이 몇 가지 있습니다.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 조금 오래되었고 업데이트되지 않음

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
