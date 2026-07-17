# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> 따라서 어떤 회사에 속한 모든 것이 scope 안에 있다고 들었고, 이 회사가 실제로 무엇을 소유하고 있는지 파악하려고 합니다.

이 단계의 목표는 **main company가 소유한 모든 회사**를 확인한 다음, 해당 회사들의 모든 **assets**를 확인하는 것입니다. 이를 위해 다음을 수행합니다:

1. main company의 acquisitions를 찾습니다. 이를 통해 scope 안에 있는 회사들을 확인할 수 있습니다.
2. 각 회사의 ASN(있는 경우)을 찾습니다. 이를 통해 각 회사가 소유한 IP ranges를 확인할 수 있습니다.
3. reverse whois lookups를 사용하여 첫 번째 항목과 관련된 다른 항목(organisation names, domains...)을 검색합니다(이 작업은 recursive하게 수행할 수 있습니다).
4. 다른 assets를 검색하기 위해 shodan의 `org` 및 `ssl` filters와 같은 다른 techniques를 사용합니다(`ssl` trick은 recursive하게 수행할 수 있습니다).

### **Acquisitions**

먼저 **main company가 소유한 다른 회사**가 무엇인지 알아야 합니다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com)를 방문하여 **main company**를 **search**한 다음 "**acquisitions**"를 **click**하는 것입니다. 여기에서 main company가 인수한 다른 회사들을 확인할 수 있습니다.\
또 다른 방법은 main company의 **Wikipedia** 페이지를 방문하여 **acquisitions**를 검색하는 것입니다.\
Public companies의 경우 **SEC/EDGAR filings**, **investor relations** 페이지 또는 현지 corporate registries(예: 영국의 **Companies House**)를 확인합니다.\
Global corporate trees 및 subsidiaries의 경우 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 및 **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/))를 사용해 보세요.

> 이제 scope 안에 있는 모든 회사를 파악했을 것입니다. 이들의 assets를 찾는 방법을 알아봅시다.

### **ASNs**

autonomous system number(**ASN**)는 **Internet Assigned Numbers Authority (IANA)**가 **autonomous system**(AS)에 할당하는 **unique number**입니다.\
**AS**는 외부 networks에 접근하기 위한 명확하게 정의된 policy를 보유하고 단일 organisation이 관리하는 **IP addresses**의 **blocks**로 구성되지만, 여러 operators로 이루어질 수도 있습니다.

**company에 ASN이 할당되어 있는지** 확인하면 해당 company의 **IP ranges**를 찾는 데 유용합니다. **scope** 안의 모든 **hosts**를 대상으로 **vulnerability test**를 수행하고 이 IP들 내부의 **domains**를 **look for**하는 것도 유용합니다.\
[**https://bgp.he.net/**](https://bgp.he.net), [**https://bgpview.io/**](https://bgpview.io/) **또는** [**https://ipinfo.io/**](https://ipinfo.io/)에서 company **name**, **IP** 또는 **domain**으로 **search**할 수 있습니다.\
**company의 region에 따라 더 많은 data를 수집하는 데 유용한 links:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe).** 어쨌든 유용한 **information**(**IP ranges** 및 **Whois**)은 아마도 첫 번째 link에 이미 모두 나와 있을 것입니다.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**의** enumeration은 스캔 종료 시 ASN을 자동으로 집계하고 요약합니다.
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
기관의 IP 범위는 [http://asnlookup.com/](http://asnlookup.com)를 사용해서도 확인할 수 있습니다(free API를 제공합니다).\
도메인의 IP와 ASN은 [http://ipv4info.com/](http://ipv4info.com)를 사용해서 확인할 수 있습니다.

### **취약점 찾기**

이 시점에는 **scope 내부의 모든 asset**을 알고 있으므로, 허용된다면 모든 host에 대해 **vulnerability scanner**(Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei))를 실행할 수 있습니다.\
또한 [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)를 실행하거나 Shodan, Censys 또는 ZoomEye와 같은 **services를 사용하여** 열린 port를 **찾을 수 있으며, 찾은 항목에 따라** 실행 중인 여러 서비스에 대한 pentest 방법을 이 책에서 확인해야 합니다.\
**또한 일부** 기본 username **및** passwords **lists를 준비한 후** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)를 사용해 services를 **bruteforce**해 보는 것도 좋습니다.

## Domains

> scope 내부의 모든 company와 해당 asset을 파악했으므로, 이제 scope 내부의 domain을 찾아야 합니다.

_다음에 설명할 기법을 사용하면 subdomain도 찾을 수 있으며, 이러한 정보는 과소평가해서는 안 됩니다._

먼저 각 company의 **main domain**(들)을 찾아야 합니다. 예를 들어 _Tesla Inc._의 경우 _tesla.com_입니다.

### **Reverse DNS**

domain의 모든 IP range를 찾았다면 해당 **IP에서 reverse dns lookups**를 수행하여 **scope 내부의 더 많은 domain을 찾을 수 있습니다**. 대상의 dns server 또는 잘 알려진 dns server(1.1.1.1, 8.8.8.8)를 사용해 보세요.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
이 기능이 작동하려면 관리자가 PTR을 수동으로 활성화해야 합니다.\
이 정보를 확인하기 위해 online tool을 사용할 수도 있습니다: [http://ptrarchive.com/](http://ptrarchive.com).\
대규모 범위에서는 [**massdns**](https://github.com/blechschmidt/massdns) 및 [**dnsx**](https://github.com/projectdiscovery/dnsx)와 같은 도구를 사용하여 reverse lookup 및 enrichment를 자동화할 수 있습니다.

### **Reverse Whois (loop)**

**whois**에서는 **조직 이름**, **주소**, **이메일**, 전화번호 등 흥미로운 **정보**를 많이 찾을 수 있습니다. 하지만 더 흥미로운 점은 이러한 필드 중 하나를 사용해 **reverse whois lookup**을 수행하면 **회사와 관련된 더 많은 asset**을 찾을 수 있다는 것입니다(예: 동일한 이메일이 나타나는 다른 whois registry).\
다음과 같은 online tool을 사용할 수 있습니다:

- [https://ip.thc.org/](https://ip.thc.org/) - **무료** (Web 및 API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **무료**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web은 **무료**, API는 무료가 아님.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 무료가 아님
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 무료가 아님 (**100회 무료** 검색만 제공)
- [https://www.domainiq.com/](https://www.domainiq.com) - 무료가 아님
- [https://securitytrails.com/](https://securitytrails.com/) - 무료가 아님 (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 무료가 아님 (API)

[**DomLink** ](https://github.com/vysecurity/DomLink)를 사용하여 이 작업을 자동화할 수 있습니다(who​xy API key 필요).\
[amass](https://github.com/OWASP/Amass)를 사용하여 일부 automatic reverse whois discovery를 수행할 수도 있습니다: `amass intel -d tesla.com -whois`

**새로운 domain을 찾을 때마다 이 technique을 사용하여 더 많은 domain name을 발견할 수 있다는 점에 유의하세요.**

### **Trackers**

서로 다른 2개의 페이지에서 **동일한 tracker의 동일한 ID**를 찾는다면 **두 페이지**가 **동일한 team에 의해 관리된다**고 추정할 수 있습니다.\
예를 들어 여러 페이지에서 동일한 **Google Analytics ID** 또는 동일한 **Adsense ID**가 보이는 경우입니다.

이러한 tracker 및 기타 항목으로 검색할 수 있는 일부 페이지와 도구가 있습니다:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (공유된 analytics/trackers를 기반으로 관련 site를 찾음)

### **Favicon**

동일한 favicon icon hash를 검색하여 target과 관련된 domain 및 subdomain을 찾을 수 있다는 사실을 알고 계셨나요? 이것이 바로 [@m4ll0k2](https://twitter.com/m4ll0k2)가 제작한 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool이 수행하는 작업입니다. 사용 방법은 다음과 같습니다:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 동일한 favicon icon hash를 사용하는 도메인 검색](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash를 사용하면 대상과 동일한 favicon icon hash를 사용하는 도메인을 검색할 수 있습니다.

또한 [**이 블로그 게시물**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)에 설명된 것처럼 favicon hash를 사용해 technologies를 검색할 수도 있습니다. 즉, **취약한 버전의 web tech favicon hash**를 알고 있다면 Shodan에서 검색하여 **더 많은 취약한 대상**을 찾을 수 있습니다:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
웹의 **favicon hash를 계산**하는 방법입니다( **base64-encoded** favicon 바이트에 대한 MMH3):
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
[**httpx**](https://github.com/projectdiscovery/httpx)(`httpx -l targets.txt -favicon`)를 사용하면 favicon hash를 대규모로 수집한 다음 Shodan/Censys에서 pivot할 수도 있습니다.

favicon fingerprint를 사용할 때 기억해 둘 유용한 사항:

- **hash를 증거가 아닌 지표로 취급하세요**: MMH3는 compact하며 collision이 발생할 수 있습니다. 또한 operator가 favicon을 교체하거나 의도적으로 오해를 유도하는 icon을 재사용할 수도 있습니다.
- **`/favicon.ico` 이상을 probe하세요**: 많은 제품은 framework/build path 또는 `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URL, HTML `<link rel="icon">` tag를 통해 icon을 노출합니다. path 자체가 product family를 fingerprint할 수도 있습니다.
- **app에 접근할 수 없어도 static file에는 접근할 수 있는 경우가 많습니다**: WAF/SSO/IdP control이 dynamic route를 보호하더라도 static icon은 노출될 수 있습니다. 항상 favicon을 직접 request하고 `ETag`, `Last-Modified`, redirect 및 cache header를 검토하여 약한 version/build hint를 확인하세요.
- **주변 signal로 match를 검증하세요**: favicon이 product를 식별한다고 결론 내리기 전에 title, HTML/body hash, header, TLS certificate subject/SAN, Shodan/Censys component 및 exposed port를 비교하세요.
- **대규모로 pivot할 때 HTML/body hash로 cluster를 구성하세요**: favicon을 공유하는 대부분의 host가 하나의 page template으로 모이면 fingerprint는 더 강력합니다. 같은 hash가 서로 관련 없는 여러 template으로 나뉜다면 product label보다 "generic/shared/honeypot"을 우선하세요.
- **Honeypot heuristic**: 동일한 favicon hash가 서로 관련 없는 여러 HTML signature, random port 및 상충하는 product에서 나타난다면 실제 product fingerprint가 아니라 probable honeypot 또는 generic placeholder로 취급하세요.
- **모호한 target에는 404 probe를 사용하세요**: browser에서 실제 page와 `/_favicon_probe_<8-hex>`와 같은 존재하지 않는 path를 fetch하세요. 일치하는 hosting-provider/parking response는 실제 product overlap보다 shared favicon을 더 잘 설명할 수 있습니다.
- **Detection rule에서 mapping을 bootstrap하세요**: Nuclei template 및 public favicon dataset은 알려진 `favicon` ↔ `product` ↔ `CPE` mapping을 제공할 수 있으며, CVE disclosure 이후 rapid triage에 유용합니다.
- **Coverage caveat**: Shodan 스타일의 dataset은 IP-centric입니다. CDN-fronted, SNI-routed, anycast 및 domain-only surface는 실제보다 적게 집계될 수 있으므로 hit count가 낮다고 해서 **실제 환경에서의 deployment가 적다는 의미는 아닙니다**.

### **Copyright / Uniq string**

웹 페이지 내부에서 **동일한 organisation의 서로 다른 web에서 공유될 수 있는 string**을 검색하세요. **copyright string**이 좋은 예가 될 수 있습니다. 그런 다음 **google**, 다른 **browser**, 또는 **shodan**에서 해당 string을 검색하세요: `shodan search http.html:"Copyright string"`

### **CRT Time**

다음과 같은 cron job을 설정하는 것은 일반적입니다.
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
서버의 모든 domain certificate를 갱신합니다. 이는 이를 위해 사용되는 CA가 Validity time에 생성된 시간을 설정하지 않더라도, **certificate transparency logs에서 동일한 회사에 속한 domain을 찾을 수 있음**을 의미합니다.\
자세한 내용은 [**이 writeup을 참고하세요**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

또한 **certificate transparency** logs를 직접 사용하세요:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC 정보

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)과 같은 web 또는 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)와 같은 tool을 사용하여 **동일한 dmarc 정보를 공유하는 domain 및 subdomain**을 찾을 수 있습니다.\
그 외 유용한 tool로는 [**spoofcheck**](https://github.com/BishopFox/spoofcheck)와 [**dmarcian**](https://dmarcian.com/)이 있습니다.

### **Passive Takeover**

사람들이 subdomain을 cloud provider에 속한 IP에 할당한 후 어느 시점에 **해당 IP 주소를 잃어버리고 DNS record 제거를 잊는** 경우가 흔한 것으로 보입니다. 따라서 cloud(Digital Ocean 등)에 **VM을 생성하기만 해도** 실제로 **일부 subdomain을 takeover**할 수 있습니다.

[**이 post**](https://kmsec.uk/blog/passive-takeover/)에서는 이에 관한 사례를 설명하고 **DigitalOcean에 VM을 생성**하고 새 machine의 **IPv4**를 **가져온 다음**, 해당 IP를 가리키는 subdomain record를 Virustotal에서 **검색**하는 script를 제안합니다.

### **기타 방법**

**새로운 domain을 발견할 때마다 이 technique을 사용하여 더 많은 domain name을 찾을 수 있다는 점에 유의하세요.**

**Shodan**

이미 해당 IP space를 소유한 organisation의 이름을 알고 있습니다. 다음을 사용하여 shodan에서 해당 데이터로 검색할 수 있습니다: `org:"Tesla, Inc."` 검색된 host에서 TLS certificate에 있는 새롭고 예상하지 못한 domain을 확인하세요.

main web page의 **TLS certificate**에 접근하여 **Organisation name**을 얻은 다음, **shodan**이 알고 있는 모든 web page의 **TLS certificate** 안에서 해당 이름을 다음 filter로 검색할 수 있습니다: `ssl:"Tesla Motors"` 또는 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch)와 같은 tool을 사용할 수 있습니다.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)는 main domain과 관련된 **domain** 및 해당 domain의 **subdomain**을 찾는 tool로, 매우 훌륭합니다.

**Passive DNS / Historical DNS**

Passive DNS data는 여전히 resolve되거나 takeover할 수 있는 **오래되고 잊힌 record**를 찾는 데 매우 유용합니다. 다음을 확인하세요:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **취약점 찾기**

일부 [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)를 확인하세요. 회사가 **어떤 domain을 사용하고 있지만** **소유권을 잃었을** 수 있습니다. 해당 domain을 등록하고(충분히 저렴한 경우) 회사에 알려주세요.

이미 asset discovery에서 찾은 IP와 **다른 IP를 가진 domain**을 발견했다면 **basic vulnerability scan**(Nessus 또는 OpenVAS 사용)과 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 **nmap/masscan/shodan**으로 수행해야 합니다. 실행 중인 service에 따라 **이 책에서 해당 service를 "attack"하는 몇 가지 trick을 찾을 수 있습니다**.\
_때때로 domain이 client가 control하지 않는 IP 내부에 hosted되어 scope에 포함되지 않을 수 있으므로 주의하세요._

## Subdomains

> scope 내의 모든 회사, 각 회사의 모든 asset, 그리고 회사와 관련된 모든 domain을 알고 있습니다.

이제 발견된 각 domain의 가능한 모든 subdomain을 찾아야 합니다.

> [!TIP]
> domain을 찾는 일부 tool과 technique은 subdomain을 찾는 데에도 도움이 될 수 있습니다.

### **DNS**

**DNS** record에서 **subdomain**을 가져와 보겠습니다. **Zone Transfer**도 시도해야 합니다(취약한 경우 report해야 합니다).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

많은 서브도메인을 확보하는 가장 빠른 방법은 외부 소스를 검색하는 것입니다. 가장 많이 사용되는 **tools**는 다음과 같습니다(더 나은 결과를 위해 API keys를 구성하세요):

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
**다른 흥미로운 tools/APIs**도 있습니다. 이러한 tools/APIs는 subdomain 찾기에 직접 특화된 것은 아니지만 subdomain을 찾는 데 유용할 수 있습니다.

- [**IP.THC.ORG**](https://ip.thc.org) 무료 API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io)를 사용하여 서브도메인을 가져옵니다
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
- [**gau**](https://github.com/lc/gau)**:** 주어진 도메인에 대해 AlienVault의 Open Threat Exchange, Wayback Machine 및 Common Crawl에서 알려진 URL을 가져옵니다.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **및** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 웹을 크롤링하며 JS 파일을 찾고, 해당 파일에서 subdomain을 추출합니다.
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
- [**securitytrails.com**](https://securitytrails.com/)에는 subdomains 및 IP history를 검색할 수 있는 무료 API가 있습니다.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

이 project는 **bug-bounty programs와 관련된 모든 subdomains**를 **무료로** 제공합니다. [chaospy](https://github.com/dr-0x0x/chaospy)를 사용하여 이 데이터에 액세스하거나, 이 project에서 사용하는 scope에도 액세스할 수 있습니다: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

다음에서 이러한 여러 tools의 **comparison**을 확인할 수 있습니다: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

가능한 subdomain 이름을 사용해 DNS servers를 brute-force하여 새로운 **subdomains**를 찾아보겠습니다.

이 작업을 위해 다음과 같은 **일반적인 subdomains wordlists가** 필요합니다:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

또한 우수한 DNS resolvers의 IPs도 필요합니다. 신뢰할 수 있는 DNS resolvers 목록을 생성하려면 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt)에서 resolvers를 다운로드하고 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용하여 필터링할 수 있습니다. 또는 다음을 사용할 수도 있습니다: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force에 가장 권장되는 tools는 다음과 같습니다:

- [**massdns**](https://github.com/blechschmidt/massdns): 효과적인 DNS brute-force를 수행한 최초의 tool입니다. 매우 빠르지만 false positives가 발생하기 쉽습니다.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 이 도구는 1개의 resolver만 사용하는 것 같습니다.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns)는 go로 작성된 `massdns` wrapper로, active bruteforce를 사용해 유효한 subdomain을 열거하고, wildcard 처리를 지원하며 간편한 input-output을 통해 subdomain을 resolve할 수 있습니다.
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
### Second DNS Brute-Force Round

After having found subdomains using open sources and brute-forcing, you could generate alterations of the subdomains found to try to find even more. Several tools are useful for this purpose:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domains와 subdomains를 입력하면 permutation을 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 도메인과 subdomain이 주어지면 permutations를 생성합니다.
- [**여기**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 goaltdns permutations **wordlist**를 가져올 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 도메인과 subdomain이 주어지면 permutations를 생성합니다. permutations 파일이 지정되지 않으면 gotator 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations을 생성하는 것 외에도 이를 resolve할 수 있습니다(하지만 이전에 주석 처리된 도구를 사용하는 것이 더 좋습니다).
- [**여기**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 altdns permutations **wordlist**를 가져올 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomain의 permutations, mutations 및 alteration을 수행하는 또 다른 tool입니다. 이 tool은 결과를 brute force합니다(DNS wildcard를 지원하지 않음).
- dmut permutations wordlist는 [**여기**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 가져올 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로 지정된 패턴에 따라 **새로운 잠재적 서브도메인 이름을 생성**하여 더 많은 서브도메인을 발견할 수 있도록 합니다.

#### Smart permutations 생성

- [**regulator**](https://github.com/cramppet/regulator): 자세한 정보는 이 [**post**](https://cramppet.github.io/regulator/index.html)를 참고하세요. 기본적으로 **discovered subdomains**에서 **주요 부분**을 가져와 조합하여 더 많은 서브도메인을 찾습니다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_은 매우 단순하지만 효과적인 DNS response-guided algorithm이 결합된 subdomain brute-force fuzzer입니다. 맞춤형 wordlist 또는 과거의 DNS/TLS 레코드와 같은 입력 데이터 세트를 활용하여, DNS scan 중 수집된 정보를 기반으로 더 많은 관련 도메인 이름을 정확하게 생성하고 loop에서 이를 더욱 확장합니다.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows**를 사용하여 domain에서 **subdomain discovery를 자동화**하는 방법에 대해 작성한 이 blog post를 확인하세요. 따라서 컴퓨터에서 여러 도구를 수동으로 실행할 필요가 없습니다:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

subdomains에 속하는 **하나 이상의 web pages**가 포함된 IP address를 발견했다면, IP의 domains를 **OSINT sources**에서 검색하거나 해당 IP에서 **VHost domain names를 brute-forcing**하여 **그 IP의 web을 사용하는 다른 subdomains를 찾을 수 있습니다**.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 다른 APIs를 사용하여 IPs에서 일부 VHosts를 찾을 수 있습니다**.

**Brute Force**

일부 subdomain이 web server에 숨겨져 있다고 의심된다면 brute force를 시도할 수 있습니다:

**IP가 hostname으로 redirect되는 경우**(name-based vhosts), `Host` header를 직접 fuzz하고 ffuf가 **auto-calibrate**하도록 하여 기본 vhost와 다른 responses를 강조 표시합니다:
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
> 이 technique를 사용하면 internal/hidden endpoints에 access할 수도 있습니다.

### **CORS Brute Force**

때때로 _**Origin**_ header에 유효한 domain/subdomain이 설정된 경우에만 _**Access-Control-Allow-Origin**_ header를 반환하는 페이지를 발견할 수 있습니다. 이러한 상황에서는 이 동작을 악용하여 새로운 **subdomains**를 **discover**할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains**를 찾는 동안 **bucket** 유형을 가리키고 있는지 확인하고, 그런 경우 [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
또한 이 시점에는 scope 내부의 모든 domain을 알고 있으므로, [**가능한 bucket 이름을 brute force하고 권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

**Certificate Transparency** Logs를 모니터링하여 domain의 **새 subdomains**가 생성되는지 **모니터링**할 수 있습니다. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)가 이를 수행합니다.

### **Looking for vulnerabilities**

가능한 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
**subdomain**이 일부 **S3 bucket**을 가리키고 있다면, [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

자산 탐색에서 이미 발견한 IP와 **다른 IP를 사용하는 subdomain**을 발견했다면, **기본 vulnerability scan**(Nessus 또는 OpenVAS 사용)과 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 **nmap/masscan/shodan**으로 수행해야 합니다. 실행 중인 service에 따라 **이 책에서 해당 service를 "공격"하는 몇 가지 기법을 찾을 수 있습니다**.\
_때때로 subdomain이 client가 제어하지 않는 IP 내부에서 hosting되므로 scope에 포함되지 않을 수 있습니다. 주의하세요._

## IPs

초기 단계에서 **일부 IP range, domain 및 subdomain을 발견했을 수 있습니다**.\
이제 해당 range에서 **모든 IP를 수집**하고 **domain/subdomain에 대해 DNS query를 수행할** 시간입니다.

다음 **free api**의 service를 사용하면 **domain 및 subdomain이 과거에 사용했던 IP**도 찾을 수 있습니다. 이러한 IP는 여전히 client가 소유하고 있을 수 있으며, [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾을 수 있게 해줄 수도 있습니다.

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) tool을 사용하여 특정 IP address를 가리키는 domain도 확인할 수 있습니다.

### **Looking for vulnerabilities**

**CDN에 속하지 않는 모든 IP를 port scan하세요**(그곳에서는 흥미로운 것을 찾을 가능성이 매우 낮기 때문입니다). 발견된 실행 중인 service에서 **vulnerability를 찾을 수 있을** 가능성이 있습니다.

**host를 scan하는 방법에 대한** [**guide**](../pentesting-network/index.html) **를 확인하세요.**

## Web servers hunting

> 모든 company와 해당 asset을 찾았고 scope 내부의 IP range, domain 및 subdomain을 알고 있습니다. 이제 web server를 검색할 시간입니다.

이전 단계에서 이미 **발견한 IP와 domain에 대한 recon**을 수행했을 가능성이 높으므로, **가능한 모든 web server를 이미 찾았을** 수도 있습니다. 하지만 그렇지 않다면 이제 scope 내부에서 web server를 검색하는 **빠른 기법 몇 가지를 살펴보겠습니다**.

이 과정은 **web app discovery를 중심으로** 하므로, scope에서 **허용하는 경우** vulnerability 및 **port scanning**도 **수행해야 한다는 점에** 유의하세요.

[**masscan**을 사용하여 web server와 관련된 **open port**를 발견하는 **빠른 방법은 여기에서 확인할 수 있습니다**](../pentesting-network/index.html#http-port-discovery).\
web server를 찾는 데 사용할 수 있는 또 다른 편리한 tool은 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 및 [**httpx**](https://github.com/projectdiscovery/httpx)입니다. domain 목록을 전달하면 port 80(http) 및 443(https)에 연결을 시도합니다. 추가로 다른 port도 시도하도록 지정할 수 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **스크린샷**

이제 범위 내에 존재하는 **모든 웹 서버**(회사의 **IP**와 모든 **도메인**, **서브도메인**)를 찾았지만, 아마 **어디서 시작해야 할지 모를 것**입니다. 그러니 간단하게 모든 서버의 스크린샷을 찍는 것부터 시작해 봅시다. **메인 페이지**를 **살펴보는 것**만으로도 더 **취약할 가능성이 높은** **이상한** endpoint를 찾을 수 있습니다.

제안한 작업을 수행하려면 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**을** 사용할 수 있습니다.

또한 [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용해 모든 **스크린샷**을 분석하고 **취약점을 포함할 가능성이 높은 항목**과 그렇지 않은 항목을 알려주도록 할 수도 있습니다.

## Public Cloud Assets

회사에 속한 잠재적인 cloud asset을 찾으려면 **회사를 식별할 수 있는 keyword 목록부터 시작해야 합니다**. 예를 들어 crypto 회사를 대상으로 한다면 `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`와 같은 단어를 사용할 수 있습니다.

또한 bucket에서 일반적으로 사용되는 **common word**의 wordlist도 필요합니다.

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그런 다음 해당 단어로 **permutation**을 생성해야 합니다(자세한 내용은 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)를 참고하세요).

생성된 wordlist로 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **또는** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**와 같은** 도구를 사용할 수 있습니다.

Cloud Asset을 찾을 때는 **AWS의 bucket만 찾지 않도록** 주의하세요.

### **취약점 찾기**

**공개된 bucket이나 노출된 cloud function** 등을 발견했다면 **접근하여** 어떤 기능을 제공하는지, 그리고 이를 악용할 수 있는지 확인해야 합니다.

## Emails

범위 내에 있는 **도메인**과 **서브도메인**만으로도 **email 검색을 시작하는 데 필요한 것**을 거의 모두 갖춘 셈입니다. 다음은 회사의 email을 찾는 데 가장 효과적이었던 **API**와 **도구**입니다.

- [**theHarvester**](https://github.com/laramies/theHarvester) - API 사용
- [**https://hunter.io/**](https://hunter.io/)의 API (무료 버전)
- [**https://app.snov.io/**](https://app.snov.io/)의 API (무료 버전)
- [**https://minelead.io/**](https://minelead.io/)의 API (무료 버전)

### **취약점 찾기**

Email은 나중에 **web login과 auth service**(예: SSH)를 **brute-force**하는 데 유용합니다. 또한 **phishing**에도 필요합니다. 더 나아가 이러한 API는 email의 **배후에 있는 사람에 대한 추가 정보**까지 제공하므로 phishing campaign에 유용합니다.

## Credential Leaks

**도메인**, **서브도메인**, **email**을 사용하여 해당 email과 관련된 과거의 credential leak을 검색할 수 있습니다.

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **취약점 찾기**

**유효한 leaked** credential을 발견한다면 매우 쉽게 성공할 수 있습니다.

## Secrets Leaks

Credential leak은 **민감한 정보가 leak되고 판매된** 회사 해킹과 관련이 있습니다. 그러나 회사는 해당 database에 정보가 없는 **다른 leak**의 영향을 받을 수도 있습니다.

### Github Leaks

Credential과 API가 **회사의** **public repository** 또는 해당 회사에서 근무하는 **user**의 repository에 leak되었을 수 있습니다.\
[**Leakos**](https://github.com/carlospolop/Leakos) **tool**을 사용하면 **organization**과 그 **developer**의 모든 **public repo**를 **download**한 후 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 자동으로 실행할 수 있습니다.

**Leakos**는 전달된 **URL**이 가리키는 모든 **text**에 대해 **gitleaks**를 실행하는 데에도 사용할 수 있습니다. 때로는 **web page에도 secret이 포함**되어 있기 때문입니다.

#### Github Dorks

잠재적인 **github dork**를 확인하려면 이 **page**도 살펴보세요. 공격 중인 organization에서 해당 dork를 검색할 수도 있습니다.


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

때때로 공격자나 단순히 직원이 paste site에 **회사 content를 publish**합니다. 여기에 **민감한 정보가 포함되어 있을 수도 있고 아닐 수도** 있지만, 검색해 볼 가치가 충분합니다.\
[**Pastos**](https://github.com/carlospolop/Pastos)를 사용하면 80개가 넘는 paste site를 동시에 검색할 수 있습니다.

### Google Dorks

오래되었지만 여전히 유용한 Google dork는 **노출되어서는 안 되는 정보를 찾는 데** 항상 도움이 됩니다. 유일한 문제는 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에 수천 개의 검색 query가 있어 이를 수동으로 실행할 수 없다는 점입니다. 따라서 마음에 드는 10개를 선택하거나 [**Gorks**](https://github.com/carlospolop/Gorks) **와 같은 tool을 사용해 모두 실행**할 수 있습니다.

_일반 Google browser를 사용해 전체 database를 실행하려는 도구는 Google이 매우 빠르게 차단하기 때문에 절대 종료되지 않는다는 점에 유의하세요._

### **취약점 찾기**

**유효한 leaked** credential 또는 API token을 발견한다면 매우 쉽게 성공할 수 있습니다.

## Public Code Vulnerabilities

회사에 **open-source code**가 있다는 것을 확인했다면 이를 **분석**하고 **취약점**을 찾을 수 있습니다.

**언어에 따라** 사용할 수 있는 **tool**이 다릅니다.


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

다음과 같이 **public repository를 scan**할 수 있는 무료 service도 있습니다.

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunter가 발견하는 **취약점의 대부분**은 **web application** 내부에 존재합니다. 따라서 이 시점에서는 **web application testing methodology**에 대해 설명하고자 하며, [**여기에서 해당 정보를 확인할 수 있습니다**](../../network-services-pentesting/pentesting-web/index.html).

또한 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) section도 특별히 언급하고 싶습니다. 이 도구들이 매우 민감한 취약점을 찾아낼 것이라고 기대해서는 안 되지만, **workflow에 적용하여 초기 web 정보를 얻는 데** 유용합니다.

## Recapitulation

> 축하합니다! 이 시점에서 이미 **모든 기본 enumeration**을 수행했습니다. 물론 더 많은 enumeration을 수행할 수 있으므로 기본적인 수준에 불과합니다(나중에 더 많은 trick을 살펴보겠습니다).

이제 다음을 수행했습니다.

1. 범위 내의 모든 **회사**를 찾았습니다.
2. 회사에 속한 모든 **asset**을 찾았습니다(범위에 포함되어 있다면 vuln scan도 수행).
3. 회사에 속한 모든 **도메인**을 찾았습니다.
4. 도메인의 모든 **서브도메인**을 찾았습니다(subdomain takeover 가능성은 없는가?).
5. 범위 내의 모든 **IP**(CDN에서 제공되는 것과 **CDN에서 제공되지 않는 것**)를 찾았습니다.
6. 모든 **web server**를 찾고 스크린샷을 찍었습니다(더 자세히 살펴볼 만한 이상한 점은 없는가?).
7. 회사에 속한 **잠재적인 public cloud asset**을 모두 찾았습니다.
8. 매우 쉽게 **큰 성공을 안겨줄 수 있는** **email**, **credential leak**, **secret leak**을 찾았습니다.
9. 찾은 모든 web을 **Pentesting**했습니다.

## **Full Recon Automatic Tools**

주어진 범위에 대해 제안된 작업의 일부를 수행하는 여러 도구가 있습니다.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 조금 오래되었고 update되지 않음

## **References**

- [**@Jhaddix**](https://twitter.com/Jhaddix)의 모든 무료 course. 예: [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
