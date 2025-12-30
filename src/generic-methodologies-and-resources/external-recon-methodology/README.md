# 외부 Recon 방법론

{{#include ../../banners/hacktricks-training.md}}

## 자산 발견

> 어떤 회사에 속한 모든 것이 범위 내에 있다고 알려졌고, 그 회사가 실제로 무엇을 소유하고 있는지 파악하려는 상황입니다.

이 단계의 목표는 주회사가 소유한 모든 **회사들**을 찾아내고, 그 다음 이 회사들의 모든 **자산**을 확보하는 것입니다. 이를 위해 우리는 다음을 수행합니다:

1. 주회사의 **acquisitions**를 찾아 범위에 속한 회사를 확인합니다.
2. 각 회사의 **ASN**(있다면)을 찾아 각 회사가 소유한 **IP 범위**를 확인합니다.
3. **reverse whois lookups**를 사용하여 최초 항목과 관련된 다른 엔트리(조직 이름, 도메인 등)를 검색합니다(재귀적으로 수행 가능).
4. shodan `org`and `ssl`filters와 같은 다른 기법을 사용하여 다른 자산을 검색합니다(`ssl` 트릭은 재귀적으로 수행할 수 있음).

### **인수**

무엇보다 먼저, 주회사가 소유한 **다른 회사들**이 무엇인지 알아야 합니다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com)에서 **주회사를 검색**하고 "**acquisitions**"를 클릭하는 것입니다. 거기에서 주회사가 인수한 다른 회사를 확인할 수 있습니다.\
또 다른 방법은 주회사의 **Wikipedia** 페이지를 방문해 **acquisitions**를 찾아보는 것입니다.\
상장 기업의 경우 **SEC/EDGAR filings**, **investor relations** 페이지 또는 지역 법인 등기소(예: 영국의 **Companies House**)를 확인하세요.\
글로벌 기업 구조와 자회사를 파악하려면 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/))와 **GLEIF LEI** 데이터베이스 ([https://www.gleif.org/](https://www.gleif.org/))를 확인해 보세요.

> 좋습니다. 이 시점에서 범위에 포함된 모든 회사를 파악했을 것입니다. 이제 이들의 자산을 찾는 방법을 알아봅시다.

### **ASNs**

**autonomous system number**(**ASN**)은 **Internet Assigned Numbers Authority (IANA)**가 **autonomous system**(AS)에 할당하는 **고유 번호**입니다.\
**AS**는 외부 네트워크 접근에 대해 명확히 정의된 정책을 가진 **IP 주소 블록들**로 구성되며, 하나의 조직에서 관리하지만 여러 운영자들로 구성될 수 있습니다.

회사가 **ASN을 할당받았는지** 확인하면 **IP 범위**를 찾을 수 있으므로 흥미로운 정보가 됩니다. 범위 내의 모든 **호스트**에 대해 **vulnerability test**를 수행하고 이러한 IP들 안에서 **도메인**을 찾아보는 것이 유용합니다.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **또는** [**https://ipinfo.io/**](https://ipinfo.io/)에서 회사 **이름**, **IP** 또는 **도메인**으로 검색할 수 있습니다.\
**회사 지역에 따라 이 링크들이 추가 정보를 수집하는 데 유용할 수 있습니다:** [**AFRINIC**](https://www.afrinic.net) **(아프리카),** [**Arin**](https://www.arin.net/about/welcome/region/)**(북미),** [**APNIC**](https://www.apnic.net) **(아시아),** [**LACNIC**](https://www.lacnic.net) **(라틴아메리카),** [**RIPE NCC**](https://www.ripe.net) **(유럽). 어쨌든, 아마도 첫 번째 링크에서 이미 모든 **유용한 정보**(**IP 범위와 Whois**)를 확인할 수 있을 것입니다.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration은 스캔이 끝날 때 ASNs를 자동으로 집계하고 요약합니다.
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

### **취약점 찾기**

이 시점에서는 **스코프 내의 모든 자산**을 파악했으므로, 허용된다면 모든 호스트에 대해 **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei))를 실행할 수 있습니다.\
또는 [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)를 수행하거나 Shodan, Censys, 또는 ZoomEye 같은 서비스를 사용해 열린 포트를 찾아볼 수 있으며, 발견 내용에 따라 이 책에서 어떻게 여러 실행 중인 서비스를 pentest할지 확인해야 합니다.\
**또한, 언급할 가치가 있는 점은** 기본적인 default username **및** passwords **리스트를 준비하고** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)를 사용해 서비스를 bruteforce해 볼 수 있다는 것입니다.

## Domains

> We know all the companies inside the scope and their assets, it's time to find the domains inside the scope.

_참고: 아래에 제시된 기법들로 subdomains도 찾을 수 있으며, 해당 정보는 과소평가되어서는 안 됩니다._

우선 각 회사의 **main domain**(들)을 찾아야 합니다. 예를 들어, _Tesla Inc._의 경우 _tesla.com_이 됩니다.

### **Reverse DNS**

이미 도메인의 모든 IP ranges를 찾았다면, 해당 **IPs에 대해 reverse dns lookups를 수행하여 스코프 내 더 많은 도메인을 찾는 것**을 시도해볼 수 있습니다. 피해자(victim)의 dns server나 잘 알려진 dns server(1.1.1.1, 8.8.8.8)를 사용해 보세요.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
이 작업이 작동하려면, 관리자가 수동으로 PTR을 활성화해야 합니다.\
이 정보를 위해 다음 온라인 도구를 사용할 수도 있습니다: [http://ptrarchive.com/](http://ptrarchive.com).\
대규모 범위의 경우 [**massdns**](https://github.com/blechschmidt/massdns) 및 [**dnsx**](https://github.com/projectdiscovery/dnsx) 같은 도구가 reverse lookups 및 enrichment를 자동화하는 데 유용합니다.

### **Reverse Whois (loop)**

**whois** 내부에는 **정보**(organisation name, address, emails, 전화번호 등)를 많이 찾을 수 있습니다. 하지만 더 흥미로운 점은 이러한 필드 중 하나로 **reverse whois lookups**를 수행하면 **회사와 관련된 더 많은 자산**을 찾을 수 있다는 것입니다(예: 동일한 이메일이 나타나는 다른 whois 레지스트리).\
다음과 같은 온라인 도구를 사용할 수 있습니다:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **무료**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **웹은 무료**, API는 유료.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 유료
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 유료 (단, **100회 무료** 검색 제공)
- [https://www.domainiq.com/](https://www.domainiq.com) - 유료
- [https://securitytrails.com/](https://securitytrails.com/) - 유료 (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 유료 (API)

이 작업은 [**DomLink** ](https://github.com/vysecurity/DomLink)(whoxy API 키 필요)를 사용해 자동화할 수 있습니다.\
또한 [amass](https://github.com/OWASP/Amass)를 사용해 일부 자동 reverse whois 검색을 수행할 수 있습니다: `amass intel -d tesla.com -whois`

**새 도메인을 찾을 때마다 이 기법을 사용해 더 많은 도메인 이름을 발견할 수 있다는 점에 유의하세요.**

### **Trackers**

서로 다른 2개의 페이지에서 **같은 트래커의 같은 ID**를 발견하면, **두 페이지 모두 같은 팀에 의해 관리되는 것**으로 추정할 수 있습니다.\
예를 들어 여러 페이지에서 동일한 **Google Analytics ID**나 동일한 **Adsense ID**를 보는 경우입니다.

이러한 트래커로 검색할 수 있는 페이지와 도구들이 있습니다:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (공유된 analytics/trackers로 관련 사이트를 찾음)

### **Favicon**

동일한 favicon 아이콘 해시를 찾아 대상과 관련된 도메인 및 서브도메인을 찾을 수 있다는 것을 알고 계셨나요? 이것이 바로 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 도구가 [@m4ll0k2](https://twitter.com/m4ll0k2)에 의해 수행하는 작업입니다. 사용 방법은 다음과 같습니다:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash는 대상과 동일한 favicon 아이콘의 hash를 가진 도메인을 발견할 수 있게 해줍니다.

Moreover, you can also search technologies using the favicon hash as explained in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). 즉, **취약한 버전의 웹 기술의 favicon hash**를 알고 있다면 shodan에서 검색해 **더 많은 취약한 장소를 찾을 수 있습니다**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
웹사이트의 **favicon hash**를 계산하는 방법은 다음과 같습니다:
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

### **저작권 / 고유 문자열**

웹 페이지 내에서 동일 조직의 서로 다른 웹에 걸쳐 공유될 수 있는 문자열을 검색하세요. **copyright string**이 좋은 예가 될 수 있습니다. 그런 다음 해당 문자열을 **google**, 다른 **browsers** 또는 심지어 **shodan**에서 검색하세요: `shodan search http.html:"Copyright string"`

### **CRT Time**

흔히 다음과 같은 cron job이 있습니다:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
서버에서 모든 도메인 인증서를 갱신하기 위해서입니다. 이는 이 작업에 사용된 CA가 Validity 시간에 생성 시간을 설정하지 않더라도, **certificate transparency 로그에서 동일 회사에 속한 도메인들을 찾을 수 있다**는 뜻입니다.\
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

일반적으로 사람들은 서브도메인을 클라우드 제공자의 IP에 할당해 놓고 어느 시점에 그 IP 주소를 **잃지만 DNS 레코드를 삭제하는 것을 잊어버리는** 경우가 흔합니다. 따라서 (Digital Ocean과 같은) 클라우드에 단순히 **spawning a VM** 하면 실제로 일부 서브도메인을 **taking over some subdomains(s)** 하게 될 수 있습니다.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

이미 IP 공간을 소유한 조직의 이름을 알고 있다면, shodan에서 다음과 같이 검색할 수 있습니다: `org:"Tesla, Inc."` 찾은 호스트들의 TLS certificate에서 예상치 못한 새로운 도메인이 있는지 확인하세요.

메인 웹 페이지의 **TLS certificate**에 접근해 **Organisation name**을 얻고, 그 이름으로 **shodan**이 알고 있는 모든 웹 페이지의 **TLS certificates**에서 다음 필터로 검색할 수 있습니다: `ssl:"Tesla Motors"` 또는 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 같은 도구를 사용하세요.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)은 메인 도메인과 관련된 **도메인** 및 그 **서브도메인**을 찾는 도구입니다. 꽤 유용합니다.

**Passive DNS / Historical DNS**

Passive DNS 데이터는 여전히 해석되는 또는 takeover할 수 있는 **오래되고 잊힌 레코드**를 찾는 데 아주 유용합니다. 다음을 확인하세요:

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

이제 발견된 각 도메인의 가능한 모든 서브도메인을 찾을 시간입니다.

> [!TIP]
> 도메인을 찾는 일부 도구와 기법은 서브도메인 찾기에도 도움이 될 수 있다는 점을 유의하세요

### **DNS**

DNS 레코드에서 **서브도메인**을 가져와 보겠습니다. 또한 **Zone Transfer**도 시도해 봐야 합니다 (취약한 경우 보고해야 합니다).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

많은 서브도메인을 확보하는 가장 빠른 방법은 외부 소스에서 검색하는 것입니다. 가장 많이 사용되는 **도구**는 다음과 같습니다 (더 나은 결과를 위해 API 키를 설정하세요):

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
다음은 직접적으로 subdomains 찾기에 특화되어 있지 않더라도 subdomains 찾는 데 유용할 수 있는 **기타 흥미로운 tools/APIs**입니다:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** [https://sonar.omnisint.io](https://sonar.omnisint.io) API를 사용해 subdomains을 얻습니다
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC 무료 API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** 주어진 도메인에 대해 AlienVault's Open Threat Exchange, the Wayback Machine 및 Common Crawl에서 알려진 URL을 가져옵니다.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 이들은 웹을 스크랩해 JS 파일을 찾아 그곳에서 서브도메인을 추출합니다.
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
- [**securitytrails.com**](https://securitytrails.com/) 는 subdomains와 IP history를 검색할 수 있는 무료 API를 제공합니다
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

This project offers for **free all the subdomains related to bug-bounty programs**. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

You can find a **비교** of many of these tools here: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

가능한 subdomain 이름들을 사용해 DNS servers를 brute-force하여 새로운 **subdomains**를 찾아봅시다.

For this action you will need some **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

And also IPs of good DNS resolvers. In order to generate a list of trusted DNS resolvers you can download the resolvers from [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) and use [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) to filter them. Or you could use: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

- [**massdns**](https://github.com/blechschmidt/massdns): This was the first tool that performed an effective DNS brute-force. It's very fast however it's prone to false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 제 생각에는 이건 1개의 resolver만 사용하는 것 같습니다.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 는 `massdns`를 래핑하는 go로 작성된 도구로, active bruteforce를 사용해 valid subdomains를 enumerate할 수 있으며, wildcard handling과 쉬운 input-output 지원으로 subdomains를 resolve할 수 있게 해줍니다.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 또한 `massdns`도 사용합니다.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용하여 도메인 이름을 비동기적으로 brute force합니다.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 두 번째 DNS Brute-Force 라운드

오픈 소스와 brute-forcing을 사용해 서브도메인을 찾은 후, 발견한 서브도메인의 변형을 생성하여 더 많은 것을 찾을 수 있습니다. 이 목적에 유용한 도구가 몇 가지 있습니다:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 도메인과 서브도메인이 주어지면 변형을 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 도메인과 서브도메인으로부터 permutations를 생성합니다.
- goaltdns permutations **wordlist**는 [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 얻을 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** domains와 subdomains를 받아 permutations를 생성합니다. permutations 파일이 지정되지 않으면 gotator은 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations을 생성하는 것 외에도, 이를 resolve하려 시도할 수 있습니다 (하지만 앞서 언급한 도구들을 사용하는 것이 더 좋습니다).
- altdns permutations **wordlist**는 [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 얻을 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 서브도메인의 permutations, mutations 및 alteration을 수행하는 또 다른 도구입니다. 이 도구는 결과를 brute force합니다 (dns wild card는 지원하지 않습니다).
- dmut permutations wordlist는 [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 얻을 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로 지정된 패턴에 따라 더 많은 서브도메인을 찾기 위해 **새로운 잠재적 서브도메인 이름을 생성합니다**.

#### 스마트 순열 생성

- [**regulator**](https://github.com/cramppet/regulator): 자세한 내용은 이 [**post**](https://cramppet.github.io/regulator/index.html)를 읽어보세요. 하지만 기본적으로 **발견된 서브도메인**에서 **주요 부분**을 추출한 다음 이를 섞어 더 많은 서브도메인을 찾아냅니다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_는 매우 단순하지만 효과적인 DNS response-guided 알고리즘과 결합된 subdomain brute-force fuzzer입니다. 제공된 입력 데이터(맞춤 wordlist 또는 과거 DNS/TLS 기록 등)를 사용하여 더 많은 대응되는 도메인 이름을 정확히 합성하고, DNS scan 중 수집된 정보를 기반으로 루프를 돌며 이를 더 확장합니다.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

제가 쓴 블로그 포스트를 확인하세요. 이 글은 도메인에서 **automate the subdomain discovery** 하기 위해 **Trickest workflows** 를 사용하는 방법에 대해 설명하며, 그래서 제 컴퓨터에서 여러 도구를 수동으로 실행할 필요가 없습니다:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

만약 서브도메인에 속한 **one or several web pages** 를 포함하는 IP 주소를 찾았다면, 해당 IP에서 웹이 있는 다른 서브도메인을 찾기 위해 **OSINT sources** 에서 그 IP의 도메인을 찾아보거나 **brute-forcing VHost domain names in that IP** 를 시도할 수 있습니다.

#### OSINT

일부 **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs** 를 통해 찾을 수 있습니다.

**Brute Force**

어떤 subdomain이 web server에 숨겨져 있다고 의심되면, 이를 brute force해볼 수 있습니다:
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
> 이 기술을 사용하면 내부/숨겨진 endpoints에 접근할 수도 있습니다.

### **CORS Brute Force**

때때로 유효한 domain/subdomain이 _**Origin**_ 헤더에 설정되어 있을 때에만 _**Access-Control-Allow-Origin**_ 헤더를 반환하는 페이지를 발견할 수 있습니다. 이런 경우 이 동작을 악용하여 새로운 **subdomains**를 발견할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

While looking for **subdomains** 찾는 동안 해당 **subdomains**가 어떤 유형의 **bucket**을 **pointing** 하는지 주의하고, 그런 경우 [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
또한 이 시점에는 scope 내의 모든 도메인을 알게 되므로, 가능한 [**bucket 이름을 brute force하고 권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

도메인에 새로운 **subdomains**가 생성되는지 확인하려면 **Certificate Transparency** Logs를 모니터링하는 [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)와 같은 도구를 사용할 수 있습니다.

### **Looking for vulnerabilities**

가능한 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
만약 **subdomain**이 어떤 **S3 bucket**을 가리키고 있다면, [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

자산 검색에서 이미 찾은 것들과 다른 IP를 가진 **subdomain**을 발견하면, **기본 취약점 스캔**(Nessus 또는 OpenVAS 사용)과 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 **nmap/masscan/shodan**으로 수행해야 합니다. 어떤 서비스가 실행 중인지에 따라 이 책에서 그것들을 "공격"하기 위한 몇 가지 트릭을 찾을 수 있습니다.\
_참고: 때때로 subdomain은 클라이언트가 제어하지 않는 IP에 호스팅되어 있어 scope에 포함되지 않을 수 있으니 주의하세요._

## IPs

초기 단계에서 일부 IP 범위, 도메인 및 **subdomains**를 발견했을 수 있습니다.\
이제 해당 범위에서 모든 IP를 수집하고 도메인/ **subdomains**(DNS 쿼리)로부터도 수집할 시간입니다.

다음의 **무료 apis** 서비스를 이용하면 도메인 및 **subdomains**가 이전에 사용했던 **이전 IP들**도 찾아낼 수 있습니다. 이 IP들은 여전히 클라이언트 소유일 수 있으며(그리고 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾는 데 도움이 될 수 있습니다)

- [**https://securitytrails.com/**](https://securitytrails.com/)

특정 IP를 가리키는 도메인을 확인하려면 [**hakip2host**](https://github.com/hakluke/hakip2host) 도구를 사용할 수도 있습니다.

### **Looking for vulnerabilities**

**CDNs에 속하지 않는 모든 IP에 대해 Port scan을 수행하세요** (거기서는 흥미로운 것을 거의 찾지 못할 가능성이 큽니다). 발견된 실행 중인 서비스에서 **취약점을 찾을 수 있을** 것입니다.

**호스트 스캔 방법에 대한** [**가이드**](../pentesting-network/index.html)를 확인하세요.

## Web servers hunting

> 우리는 모든 회사와 그들의 자산을 찾았고, scope 내의 IP 범위, 도메인 및 **subdomains**를 알고 있습니다. 이제 웹 서버를 검색할 시간입니다.

이전 단계에서 이미 발견한 IP와 도메인에 대해 어느 정도 **recon**을 수행했을 가능성이 있으므로, 이미 가능한 모든 웹 서버를 찾았을 수 있습니다. 그러나 아직 찾지 못했다면, 이제 범위 내에서 웹 서버를 검색하는 몇 가지 **빠른 트릭**을 보겠습니다.

참고: 이것은 **web apps discovery**에 초점이 맞춰져 있으므로, (scope에서 허용한다면) **취약점 스캔**과 **port scanning**도 수행해야 합니다.

웹 서버와 관련된 **열린 포트**를 빠르게 찾는 방법으로 [**masscan** 사용법은 여기](../pentesting-network/index.html#http-port-discovery)에서 찾을 수 있습니다.\
웹 서버를 찾기 위한 또 다른 유용한 도구로는 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 및 [**httpx**](https://github.com/projectdiscovery/httpx)가 있습니다. 도메인 목록을 전달하면 포트 80(http)과 443(https)에 연결을 시도합니다. 추가로 다른 포트도 시도하도록 지정할 수 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Now that you have discovered **all the web servers** present in the scope (among the **IPs** of the company and all the **domains** and **subdomains**) you probably **don't know where to start**. So, let's make it simple and start just taking screenshots of all of them. Just by **taking a look** at the **main page** you can find **weird** endpoints that are more **prone** to be **vulnerable**.

To perform the proposed idea you can use [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) or [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Moreover, you could then use [**eyeballer**](https://github.com/BishopFox/eyeballer) to run over all the **screenshots** to tell you **what's likely to contain vulnerabilities**, and what isn't.

## Public Cloud Assets

In order to find potential cloud assets belonging to a company you should **start with a list of keywords that identify that company**. For example, a crypto for a crypto company you might use words such as: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

You will also need wordlists of **common words used in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Then, with those words you should generate **permutations** (check the [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) for more info).

With the resulting wordlists you could use tools such as [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **or** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Remember that when looking for Cloud Assets you should l**ook for more than just buckets in AWS**.

### **Looking for vulnerabilities**

If you find things such as **open buckets or cloud functions exposed** you should **access them** and try to see what they offer you and if you can abuse them.

## Emails

With the **domains** and **subdomains** inside the scope you basically have all what you **need to start searching for emails**. These are the **APIs** and **tools** that have worked the best for me to find emails of a company:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails will come handy later to **brute-force web logins and auth services** (such as SSH). Also, they are needed for **phishings**. Moreover, these APIs will give you even more **info about the person** behind the email, which is useful for the phishing campaign.

## Credential Leaks

With the **domains,** **subdomains**, and **emails** you can start looking for credentials leaked in the past belonging to those emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

If you find **valid leaked** credentials, this is a very easy win.

## Secrets Leaks

Credential leaks are related to hacks of companies where **sensitive information was leaked and sold**. However, companies might be affected for **other leaks** whose info isn't in those databases:

### Github Leaks

Credentials and APIs might be leaked in the **public repositories** of the **company** or of the **users** working by that github company.\
You can use the **tool** [**Leakos**](https://github.com/carlospolop/Leakos) to **download** all the **public repos** of an **organization** and of its **developers** and run [**gitleaks**](https://github.com/zricethezav/gitleaks) over them automatically.

**Leakos** can also be used to run **gitleaks** agains all the **text** provided **URLs passed** to it as sometimes **web pages also contains secrets**.

#### Github Dorks

Check also this **page** for potential **github dorks** you could also search for in the organization you are attacking:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Sometimes attackers or just workers will **publish company content in a paste site**. This might or might not contain **sensitive information**, but it's very interesting to search for it.\
You can use the tool [**Pastos**](https://github.com/carlospolop/Pastos) to search in more that 80 paste sites at the same time.

### Google Dorks

Old but gold google dorks are always useful to find **exposed information that shouldn't be there**. The only problem is that the [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contains several **thousands** of possible queries that you cannot run manually. So, you can get your favourite 10 ones or you could use a **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

If you find **valid leaked** credentials or API tokens, this is a very easy win.

## Public Code Vulnerabilities

If you found that the company has **open-source code** you can **analyse** it and search for **vulnerabilities** on it.

**Depending on the language** there are different **tools** you can use:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

There are also free services that allow you to **scan public repositories**, such as:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

The **majority of the vulnerabilities** found by bug hunters resides inside **web applications**, so at this point I would like to talk about a **web application testing methodology**, and you can [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

I also want to do a special mention to the section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), as, if you shouldn't expect them to find you very sensitive vulnerabilities, they come handy to implement them on **workflows to have some initial web information.**

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

So you have already:

1. Found all the **companies** inside the scope
2. Found all the **assets** belonging to the companies (and perform some vuln scan if in scope)
3. Found all the **domains** belonging to the companies
4. Found all the **subdomains** of the domains (any subdomain takeover?)
5. Found all the **IPs** (from and **not from CDNs**) inside the scope.
6. Found all the **web servers** and took a **screenshot** of them (anything weird worth a deeper look?)
7. Found all the **potential public cloud assets** belonging to the company.
8. **Emails**, **credentials leaks**, and **secret leaks** that could give you a **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

There are several tools out there that will perform part of the proposed actions against a given scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
