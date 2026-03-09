# 외부 정찰 방법론

{{#include ../../banners/hacktricks-training.md}}

## 자산 발견

> 누군가가 어떤 회사에 속한 모든 것이 범위(scope) 안에 있다고 말했고, 이 회사가 실제로 무엇을 소유하고 있는지 파악하고 싶다고 합시다.

이 단계의 목표는 메인 회사가 소유한 모든 **companies**를 확보한 다음, 이들 회사의 모든 **assets**를 파악하는 것입니다. 이를 위해 우리는 다음을 수행합니다:

1. 메인 회사의 인수(acquisitions)를 찾아 범위 내의 회사들을 파악합니다.
2. 각 회사의 ASN(있는 경우)을 찾아 각 회사가 소유한 IP ranges를 확인합니다.
3. 초기 항목과 관련된 다른 항목(조직명, 도메인 등)을 찾기 위해 reverse whois lookups를 사용합니다(이 작업은 재귀적으로 수행할 수 있습니다).
4. shodan `org`and `ssl`filters 같은 다른 기법을 사용해 다른 자산을 검색합니다(`ssl` 트릭은 재귀적으로 수행할 수 있습니다).

### **Acquisitions**

우선, 어떤 **other companies are owned by the main company**인지 알아야 합니다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com) 에 접속해 **메인 회사**를 **검색**하고 "**acquisitions**"를 **클릭**하는 것입니다. 거기서 메인 회사가 인수한 다른 회사들을 볼 수 있습니다.\
또 다른 방법은 메인 회사의 **Wikipedia** 페이지를 방문해 **acquisitions**를 찾아보는 것입니다.\
상장 회사의 경우 **SEC/EDGAR filings**, **investor relations** 페이지, 또는 지역 법인 등기부(예: 영국의 **Companies House**)를 확인하십시오.\
전세계 기업 구조와 자회사를 파악하려면 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 및 **GLEIF LEI** 데이터베이스 ([https://www.gleif.org/](https://www.gleif.org/))를 시도해 보십시오.

> 자, 이 시점에서 범위 내의 모든 회사를 알아냈을 것입니다. 이제 그들의 자산을 찾는 방법을 살펴봅시다.

### **ASNs**

autonomous system number (**ASN**)은 **Internet Assigned Numbers Authority (IANA)**가 autonomous system(AS)에 할당하는 **고유 번호**입니다.\
**AS**는 외부 네트워크에 접근하는 정책이 명확히 정의된 **IP 주소** 블록으로 구성되며, 단일 조직에 의해 관리되지만 여러 운영자로 구성될 수 있습니다.

회사가 ASN을 할당받았는지 확인하면 IP ranges를 파악하는 데 유용합니다. 범위(scope) 내 모든 hosts에 대해 vulnerability test를 수행하고 해당 IP들에서 domains를 찾아보는 것이 좋습니다.\
다음 사이트들에서 회사 **name**, **IP** 또는 **domain**으로 **검색**할 수 있습니다: [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **또는** [**https://ipinfo.io/**](https://ipinfo.io/).\
**회사 소재 지역에 따라 추가 데이터를 수집하는 데 유용한 링크들:** [**AFRINIC**](https://www.afrinic.net) **(아프리카),** [**Arin**](https://www.arin.net/about/welcome/region/)**(북미),** [**APNIC**](https://www.apnic.net) **(아시아),** [**LACNIC**](https://www.lacnic.net) **(라틴 아메리카),** [**RIPE NCC**](https://www.ripe.net) **(유럽). 어쨌든 아마도 모든 유용한 정보(IP ranges 및 Whois)는 이미 첫 번째 링크에 나타날 것입니다.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration은 scan이 끝날 때 ASNs를 자동으로 집계하고 요약합니다.
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

이 시점에서는 **범위 내의 모든 자산**을 알고 있으므로, 허가가 있다면 모든 호스트에 대해 **취약점 스캐너** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei))를 실행할 수 있습니다.\
또한, [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **또는 Shodan, Censys, 또는 ZoomEye와 같은 서비스를 사용하여** **찾기 위해** 열린 포트를 찾아볼 수 있으며 **찾은 내용에 따라** 이 책에서 실행 중인 여러 가능한 서비스를 pentest하는 방법을 확인해야 합니다.\
**또한, 미리 준비해두면 좋다는 점을 언급할 만합니다** default username **및** passwords **리스트를 준비하고 시도해보세요** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

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
이 기능이 작동하려면 관리자가 PTR을 수동으로 활성화해야 합니다.\
이 정보를 위해 온라인 도구를 사용할 수도 있습니다: [http://ptrarchive.com/](http://ptrarchive.com).\
대규모 범위의 경우 reverse lookups 및 enrichment를 자동화하기 위해 [**massdns**](https://github.com/blechschmidt/massdns) 및 [**dnsx**](https://github.com/projectdiscovery/dnsx) 같은 도구가 유용합니다.

### **Reverse Whois (loop)**

한 **whois** 기록 안에는 **organisation name**, **address**, **emails**, 전화번호 등 많은 흥미로운 **information**가 포함되어 있을 수 있습니다. 하지만 더 흥미로운 점은 이러한 필드들로 **reverse whois lookups**를 수행하면 회사와 관련된 **더 많은 자산**을 찾을 수 있다는 것입니다(예: 동일한 이메일이 나타나는 다른 whois 레지스트리).\
다음과 같은 온라인 도구를 사용할 수 있습니다:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **무료**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **무료** 웹, API는 유료.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 유료
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 유료 (단, **100회 무료** 검색 제공)
- [https://www.domainiq.com/](https://www.domainiq.com) - 유료
- [https://securitytrails.com/](https://securitytrails.com/) - 유료 (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 유료 (API)

이 작업을 자동화하려면 [**DomLink** ](https://github.com/vysecurity/DomLink)(whoxy API 키 필요)를 사용할 수 있습니다.\
또한 [amass](https://github.com/OWASP/Amass)를 사용해 일부 자동 reverse whois 디스커버리를 수행할 수 있습니다: `amass intel -d tesla.com -whois`

**새로운 도메인을 찾을 때마다 이 기술을 사용해 더 많은 도메인 이름을 발견할 수 있다는 점을 기억하세요.**

### **Trackers**

서로 다른 두 페이지에서 **same ID of the same tracker**를 발견하면, **both pages**가 **같은 팀에 의해 관리되는 것으로 추정**할 수 있습니다.\
예를 들어 여러 페이지에서 같은 **Google Analytics ID**나 같은 **Adsense ID**를 보면 동일한 관리 주체일 가능성이 높습니다.

다음은 이러한 trackers로 검색하거나 관련 사이트를 찾을 수 있는 사이트 및 도구들입니다:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (공유된 analytics/trackers로 관련 사이트를 찾음)

### **Favicon**

같은 favicon 아이콘 해시를 찾아봄으로써 대상과 관련된 도메인 및 서브도메인을 찾을 수 있다는 것을 알고 있었나요? 바로 이것이 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 도구(작성자 [@m4ll0k2](https://twitter.com/m4ll0k2))가 하는 일입니다. 사용 방법은 다음과 같습니다:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash는 대상과 동일한 favicon icon hash를 가진 도메인을 발견할 수 있게 해준다.

또한, [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)에서 설명한 것처럼 favicon hash를 사용해 기술을 검색할 수도 있다. 즉, **hash of the favicon of a vulnerable version of a web tech**를 알고 있다면 shodan에서 검색해 **find more vulnerable places**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
웹의 **favicon hash**를 계산하는 방법은 다음과 같습니다:
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

웹 페이지 내부에서 **같은 조직 내의 여러 웹에서 공유될 수 있는 문자열**을 검색하세요. **저작권 문자열**이 좋은 예가 될 수 있습니다. 그런 다음 해당 문자열을 **google**, 다른 **browsers** 또는 심지어 **shodan**에서 검색하세요: `shodan search http.html:"Copyright string"`

### **CRT Time**

다음과 같은 cron job을 실행하는 경우가 흔합니다
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
서버의 모든 도메인 인증서를 갱신하기 위해. 이는 이 작업에 사용된 CA가 Validity 시간에 생성 시각을 설정하지 않더라도, **같은 회사에 속한 도메인들을 certificate transparency logs에서 찾을 수 있다**는 것을 의미한다.\
자세한 내용은 이 [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)를 확인하라.

또한 **certificate transparency** logs를 직접 사용하라:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC 정보

다음과 같은 웹사이트 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 또는 다음과 같은 도구 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)를 사용하여 **같은 dmarc 정보를 공유하는 도메인과 서브도메인**을 찾을 수 있다.\
다른 유용한 도구로는 [**spoofcheck**](https://github.com/BishopFox/spoofcheck)와 [**dmarcian**](https://dmarcian.com/)이 있다.

### **Passive Takeover**

사람들이 subdomains를 클라우드 제공자의 IP에 할당했다가 해당 IP 주소를 잃었지만 DNS 레코드를 제거하는 것을 잊어버리는 경우가 흔하다. 따라서 Digital Ocean 같은 클라우드에서 단순히 VM을 스폰하면 실제로 **taking over some subdomains(s)** 하게 될 수 있다.

[**This post**](https://kmsec.uk/blog/passive-takeover/)는 그 사례를 설명하고 **DigitalOcean에서 VM을 스폰**하고, 새 머신의 **IPv4**를 **가져와(Virustotal에서)** 해당 IP를 가리키는 서브도메인 레코드를 검색하는 스크립트를 제안한다.

### **Other ways**

**새로운 도메인을 찾을 때마다 이 기법을 사용해 더 많은 도메인 이름을 찾을 수 있다는 점을 기억하라.**

**Shodan**

이미 IP 공간을 소유한 조직의 이름을 알고 있다면, shodan에서 다음과 같이 검색할 수 있다: `org:"Tesla, Inc."` 발견된 호스트의 TLS certificate에서 예상치 못한 새로운 도메인이 있는지 확인하라.

메인 웹페이지의 **TLS certificate**에 접근해 **Organisation name**을 얻은 후, 해당 이름으로 **shodan**이 알고 있는 모든 웹페이지의 **TLS certificates** 안에서 필터 `ssl:"Tesla Motors"`를 사용해 검색하거나 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 같은 도구를 사용하라.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)는 메인 도메인과 관련된 **domains** 및 그 **서브도메인**을 찾아주는 도구로 아주 유용하다.

**Passive DNS / Historical DNS**

Passive DNS 데이터는 여전히 해석되거나 takeover할 수 있는 **오래된 잊혀진 레코드**를 찾기에 훌륭하다. 다음을 확인하라:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

다음의 [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)를 확인하라. 어떤 회사가 도메인을 사용하고 있었지만 소유권을 잃었을 수 있다. 비용이 충분히 저렴하다면 해당 도메인을 등록하고 회사에 알려라.

이미 자산 탐색에서 찾은 것들과 다른 IP를 가진 **도메인**을 발견하면, **basic vulnerability scan**(Nessus 또는 OpenVAS 사용)과 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 **nmap/masscan/shodan**으로 수행하라. 어떤 서비스가 실행 중인지에 따라 이 책에서 제공하는 몇몇 트릭으로 그것들을 "attack"할 수 있다.\
_때로는 도메인이 클라이언트가 제어하지 않는 IP 내에 호스팅되어 있어 범위(scope)에 포함되지 않을 수 있으니 주의하라._

## Subdomains

> 우리는 scope 내의 모든 회사, 각 회사의 모든 자산 및 회사와 관련된 모든 도메인을 알고 있다.

이제 발견한 각 도메인의 가능한 모든 서브도메인을 찾아야 할 때다.

> [!TIP]
> 도메인을 찾기 위한 일부 도구와 기법은 서브도메인을 찾는 데에도 도움이 될 수 있다는 점을 기억하라

### **DNS**

DNS 레코드에서 **서브도메인**을 얻어보자. 또한 **Zone Transfer**도 시도해 보아야 한다 (취약하면 보고해야 한다).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

많은 서브도메인을 얻는 가장 빠른 방법은 외부 소스를 검색하는 것입니다. 가장 많이 사용되는 **도구**는 다음과 같습니다 (더 나은 결과를 위해 API 키를 구성하세요):

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
직접적으로 서브도메인 찾기에 특화되어 있지 않더라도 서브도메인을 찾는 데 유용할 수 있는 **다른 흥미로운 도구/APIs**가 있습니다. 예:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io)을 사용하여 서브도메인을 얻습니다
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
- [**gau**](https://github.com/lc/gau)**:** 주어진 도메인에 대해 AlienVault's Open Threat Exchange, the Wayback Machine, 그리고 Common Crawl에서 알려진 URL을 가져옵니다.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 웹에서 JS 파일을 찾아 그로부터 서브도메인을 추출합니다.
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
- [**securitytrails.com**](https://securitytrails.com/) 는 서브도메인과 IP 히스토리를 검색할 수 있는 무료 API를 제공합니다
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

이 프로젝트는 **free all the subdomains related to bug-bounty programs**. 이 데이터는 [chaospy](https://github.com/dr-0x0x/chaospy)를 사용해서도 접근할 수 있으며, 이 프로젝트에서 사용한 scope에도 접근할 수 있습니다 [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

You can find a **comparison** of many of these tools here: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

가능한 서브도메인 이름을 사용해 DNS 서버를 brute-forcing하여 새로운 **subdomains**를 찾아봅시다.

For this action you will need some **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

또한 좋은 DNS resolvers의 IP도 필요합니다. 신뢰할 수 있는 DNS resolvers 목록을 생성하려면 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)에서 resolvers를 다운로드하고 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)로 필터링하세요. 또는 다음을 사용할 수 있습니다: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

- [**massdns**](https://github.com/blechschmidt/massdns): This was the first tool that performed an effective DNS brute-force. It's very fast however it's prone to false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 이건 제가 보기엔 resolver를 1개만 사용하는 것 같습니다
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns)은 `massdns`의 래퍼로 go로 작성되었으며, active bruteforce를 사용해 유효한 서브도메인을 열거하고, wildcard 처리와 간편한 입출력 지원으로 서브도메인을 resolve할 수 있게 해줍니다.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 또한 `massdns`를 사용합니다.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용하여 도메인 이름을 비동기적으로 brute force합니다.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 두 번째 DNS Brute-Force 라운드

오픈 소스와 brute-forcing을 사용해 subdomains를 찾은 후, 발견한 subdomains의 변형을 생성해 더 찾아볼 수 있습니다. 이 목적에는 여러 도구가 유용합니다:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domains와 subdomains로부터 순열을 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 도메인과 서브도메인으로부터 변형을 생성합니다.
- goaltdns 변형 **wordlist**는 [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 얻을 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 주어진 domains와 subdomains로부터 permutations를 생성합니다. permutations 파일이 지정되지 않으면 gotator는 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations을 생성하는 것 외에도, 그것들을 resolve하려고 시도할 수 있습니다 (하지만 이전에 언급된 도구들을 사용하는 것이 더 낫습니다).
- altdns permutations **wordlist**는 [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 얻을 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 서브도메인의 permutations, mutations 및 alteration을 수행하는 또 다른 도구입니다. 이 도구는 결과를 brute force합니다 (dns wild card를 지원하지 않습니다).
- dmut permutations wordlist는 [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 얻을 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로 지정된 패턴에 따라 더 많은 서브도메인을 찾기 위해 **새로운 잠재적 서브도메인 이름을 생성합니다**.

#### 스마트 순열 생성

- [**regulator**](https://github.com/cramppet/regulator): 자세한 내용은 이 [**post**](https://cramppet.github.io/regulator/index.html) 를 읽어보세요. 기본적으로 **발견된 서브도메인들**에서 **주요 부분들**을 추출해 섞어서 더 많은 서브도메인을 찾아냅니다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_은 매우 단순하지만 효과적인 DNS response-guided 알고리즘과 결합된 subdomain brute-force fuzzer입니다. 제공된 입력 데이터(맞춤 wordlist나 과거 DNS/TLS 기록 등)를 활용하여 더 많은 대응 도메인을 정확히 합성하고, DNS scan 중 수집된 정보를 바탕으로 루프를 돌며 이를 계속 확장합니다.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

제가 쓴 이 블로그 글을 확인하세요. 도메인에서 **automate the subdomain discovery**를 **Trickest workflows**로 자동화하여 제 컴퓨터에서 여러 도구를 수동으로 실행할 필요가 없게 한 방법입니다:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

서브도메인에 속하는 **one or several web pages**가 포함된 IP 주소를 찾았다면, 해당 IP에서 **find other subdomains with webs in that IP**를 찾기 위해 **OSINT sources**에서 IP의 도메인을 조회하거나, 해당 IP에서 **brute-forcing VHost domain names in that IP**을 시도할 수 있습니다.

#### OSINT

몇몇 **VHosts in IPs using**는 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**로 찾을 수 있습니다.

**Brute Force**

어떤 서브도메인이 웹 서버에 숨겨져 있을 수 있다고 의심되면, 이를 brute force로 찾아볼 수 있습니다:

When the **IP redirects to a hostname** (name-based vhosts), `Host` header를 직접 fuzz하고 ffuf **auto-calibrate**를 이용해 기본 vhost와 다른 응답을 강조하도록 하세요:
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
> 이 기술을 사용하면 내부/숨겨진 endpoints에까지 접근할 수 있을 수도 있습니다.

### **CORS Brute Force**

경우에 따라 유효한 domain/subdomain이 _**Origin**_ 헤더에 설정되어 있을 때만 _**Access-Control-Allow-Origin**_ 헤더를 반환하는 페이지를 발견할 수 있습니다. 이러한 상황에서는 이 동작을 악용하여 새로운 **subdomains**를 **발견**할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains**를 찾는 동안 해당 항목이 어떤 유형의 **bucket**을 **pointing**하는지 주의해서 보세요. 그런 경우 [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
또한 이 시점에서는 스코프 내 모든 domains를 알고 있을 것이므로, [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)를 시도해 보세요.

### **Monitorization**

도메인의 **new subdomains** 생성 여부는 **Certificate Transparency** Logs를 모니터링함으로써 확인할 수 있으며, [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)가 이를 수행합니다.

### **Looking for vulnerabilities**

가능한 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
만약 **subdomain**이 어떤 **S3 bucket**을 가리키고 있다면, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)를 확인하세요.

만약 자산 탐색에서 이미 찾은 것들과 다른 IP를 가진 **subdomain**을 발견하면, **basic vulnerability scan**(Nessus 또는 OpenVAS 사용)과 **nmap/masscan/shodan**을 이용한 일부 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 수행해야 합니다. 어떤 서비스가 실행 중인지에 따라 이 책에서 해당 서비스를 "attack"하기 위한 몇몇 트릭을 찾을 수 있습니다.\
_때로는 subdomain이 클라이언트가 제어하지 않는 IP에 호스팅되어 있어 스코프에 속하지 않을 수 있으니 주의하세요._

## IPs

초기 단계에서 **found some IP ranges, domains and subdomains**을 발견했을 수 있습니다.\
이제 해당 범위들로부터 모든 IP들을 **recollect all the IPs from those ranges**하고, 도메인/서브도메인(DNS 쿼리)에 대해서도 IP를 수집할 차례입니다.

다음의 **free apis** 서비스를 사용하면 도메인 및 subdomains가 이전에 사용했던 **previous IPs used by domains and subdomains**도 찾을 수 있습니다. 이 IP들은 여전히 클라이언트 소유일 수 있으며(그리고 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾는 데 도움이 될 수 있습니다)

- [**https://securitytrails.com/**](https://securitytrails.com/)

특정 IP 주소를 가리키는 도메인을 확인하려면 [**hakip2host**](https://github.com/hakluke/hakip2host) 도구를 사용할 수 있습니다.

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs**(CDNs에 속하지 않는 모든 IP를 포트 스캔하세요) — CDN 내에서는 흥미로운 결과를 찾기 어려울 가능성이 높습니다. 발견된 실행 중인 서비스들에서 **able to find vulnerabilities**할 수 있습니다.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

이전 단계에서 이미 발견된 IP들과 도메인들에 대해 어느 정도 **recon of the IPs and domains discovered**을 수행했을 가능성이 있으므로, 이미 가능한 모든 웹 서버를 발견했을 수도 있습니다. 그러나 아직 발견하지 못했다면, 이제 스코프 내에서 웹 서버를 빠르게 찾는 몇 가지 트릭을 살펴보겠습니다.

참고로, 이 내용은 **oriented for web apps discovery**하므로, 스코프에서 허용된다면 취약점 및 포트 스캐닝도 반드시 수행해야 합니다.

웹 관련 포트들이 열려 있는지를 빠르게 발견하는 **fast method**는 [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery)에서 확인할 수 있습니다.\
웹 서버를 찾기 위한 친숙한 도구로는 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 및 [**httpx**](https://github.com/projectdiscovery/httpx)가 있습니다. 도메인 리스트를 넘기면 포트 80(http)과 443(https)에 접속을 시도합니다. 추가로 다른 포트들을 시도하도록 지정할 수도 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **스크린샷**

이제 scope 내에 존재하는 **all the web servers**(회사 **IPs** 및 모든 **domains**와 **subdomains** 포함)를 모두 발견했으니, 아마 **어디서 시작할지 모를** 것입니다. 간단히 하기 위해 일단 모든 것들의 스크린샷을 찍는 것부터 시작하세요. **main page**를 한 번 보는 것만으로도 더 **vulnerable**할 가능성이 높은 **weird endpoints**를 발견할 수 있습니다.

제안한 작업을 수행하기 위해 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**을** 사용할 수 있습니다.

또한 모든 **screenshots**를 대상으로 [**eyeballer**](https://github.com/BishopFox/eyeballer)를 실행하여 **what's likely to contain vulnerabilities**인지, 무엇이 아닌지를 판별하게 할 수도 있습니다.

## Public Cloud Assets

회사의 잠재적 cloud assets를 찾기 위해서는 **그 회사를 식별할 수 있는 키워드 리스트**부터 시작해야 합니다. 예를 들어, crypto 회사라면 `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` 같은 단어들을 사용할 수 있습니다.

버킷에서 자주 사용되는 **common words**의 wordlists도 필요합니다:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그 단어들을 가지고 **permutations**를 생성하세요(자세한 내용은 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) 참조).

생성된 wordlists로 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **또는** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** 같은 도구를 사용할 수 있습니다.**

Cloud Assets를 찾을 때는 **AWS의 buckets**뿐만 아니라 더 많은 것을 찾아야 한다는 점을 기억하세요.

### **Looking for vulnerabilities**

만약 **open buckets**나 **cloud functions exposed** 같은 것을 찾으면, **접근해서** 그들이 제공하는 것을 살펴보고 남용할 수 있는지가 있는지 확인하세요.

## Emails

scope 내의 **domains**와 **subdomains**가 있다면, 기본적으로 **emails**을 찾기 시작하는 데 필요한 모든 것이 있습니다. 제가 회사의 이메일을 찾는 데 가장 잘 작동했던 **APIs**와 **도구들**은 다음과 같습니다:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails는 나중에 **web logins and auth services**(예: SSH) brute-force에 유용합니다. 또한 **phishings**에 필요합니다. 더불어, 이 API들은 해당 이메일 소유자에 대한 추가 **정보**를 제공해줘서 phishing 캠페인에 유용합니다.

## Credential Leaks

**domains,** **subdomains**, 그리고 **emails**로 해당 이메일들에 속한 과거에 leaked된 credential을 찾기 시작할 수 있습니다:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

만약 **valid leaked** credentials를 찾는다면, 이는 매우 쉬운 승리입니다.

## Secrets Leaks

Credential leaks는 회사의 해킹으로 인해 **sensitive information**이 leaked되고 판매된 경우와 관련이 있습니다. 그러나 회사는 데이터베이스에 나타나지 않는 다른 형태의 leaks로도 영향을 받을 수 있습니다:

### Github Leaks

Credentials와 APIs는 회사의 **public repositories**나 그 회사에서 일하는 **users**의 public repositories에 leaked될 수 있습니다. **Leakos** 도구([**Leakos**](https://github.com/carlospolop/Leakos))를 사용하여 조직 및 그 개발자들의 모든 **public repos**를 다운로드하고 자동으로 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 실행할 수 있습니다.

**Leakos**는 또한 제공된 URL들에 대해 **gitleaks**를 실행할 수 있는데, 때때로 **web pages**도 secrets를 포함하고 있기 때문입니다.

#### Github Dorks

공격 대상 조직에서 검색할 수 있는 잠재적 **github dorks**에 대해서도 다음 **페이지**를 확인하세요:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

때때로 공격자나 단순 직원들이 paste 사이트에 회사 콘텐츠를 **publish**합니다. 이는 민감한 정보를 포함할 수도 있고 아닐 수도 있지만, 찾아볼 만한 가치가 큽니다. 여러 paste 사이트를 동시에 검색할 수 있는 도구 [**Pastos**](https://github.com/carlospolop/Pastos)를 사용할 수 있습니다.

### Google Dorks

오래됐지만 유용한 google dorks는 항상 **노출되어선 안 되는 정보**를 찾는 데 유용합니다. 문제는 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에 수천 개의 쿼리가 있어 수동으로 실행할 수 없다는 점입니다. 그래서 좋아하는 10개 정도를 선택하거나 [**Gorks**](https://github.com/carlospolop/Gorks) 같은 **도구**를 사용해 모두 실행할 수 있습니다.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

만약 **valid leaked** credentials나 API tokens를 찾는다면, 이는 매우 쉬운 승리입니다.

## Public Code Vulnerabilities

회사가 **open-source code**를 가지고 있다면, 이를 **analyse**하고 그 안에서 **vulnerabilities**를 찾아보세요.

**언어에 따라** 사용할 수 있는 다양한 **도구**들이 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

또한 public repositories를 스캔할 수 있는 무료 서비스들도 있습니다. 예를 들어:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

버그 헌터들이 발견하는 **majority of the vulnerabilities**는 web applications 내부에 있으므로, 이 시점에서 **web application testing methodology**에 대해 말하고 싶습니다. 이 정보는 [**여기**](../../network-services-pentesting/pentesting-web/index.html)에서 확인할 수 있습니다.

또한 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 섹션을 특별히 언급하고 싶습니다. 이 도구들이 아주 민감한 취약점을 찾아줄 것으로 기대하긴 어렵지만, 초기 웹 정보를 얻기 위한 **workflows**에 통합하면 유용합니다.

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

따라서 지금까지 이미 다음을 수행했습니다:

1. Scope 내의 모든 **companies**를 찾음  
2. 회사에 속한 모든 **assets**를 찾음(범위 내라면 일부 vuln scan 수행)  
3. 회사에 속한 모든 **domains**를 찾음  
4. domains의 모든 **subdomains**를 찾음(**any subdomain takeover?**)  
5. Scope 내의 모든 **IPs**(CDNs에서 온 것과 아닌 것 모두)를 찾음  
6. 모든 **web servers**를 찾아 **screenshot**을 찍음(**deeper look**할 만한 이상한 점이 있는가?)  
7. 회사에 속한 모든 **potential public cloud assets**를 찾음  
8. **Emails**, **credentials leaks**, 그리고 **secret leaks** — 이것들은 매우 쉬운 큰 승리를 가져다줄 수 있음  
9. 찾은 모든 웹에 대한 **Pentesting**

## **Full Recon Automatic Tools**

주어진 scope에 대해 제안된 작업의 일부를 수행하는 도구들이 여러 개 있습니다.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
