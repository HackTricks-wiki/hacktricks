# 외부 정찰 방법론

{{#include ../../banners/hacktricks-training.md}}

## 자산 탐색

> 회사에 속한 모든 것이 스코프에 포함된다고 들었고, 이 회사가 실제로 소유한 것이 무엇인지 파악하고 싶다고 가정해 봅시다.

이 단계의 목표는 **모회사가 소유한 모든 회사**를 파악한 다음, 각 회사의 **자산**을 모두 찾는 것입니다. 이를 위해 다음을 수행합니다:<sup>[[1]](#references)</sup>

1. 모회사의 인수 내역을 찾습니다. 이를 통해 스코프에 포함된 회사를 파악할 수 있습니다.
2. 각 회사의 ASN이 있는지 확인합니다. 이를 통해 각 회사가 소유한 IP 범위를 파악할 수 있습니다.
3. reverse whois 조회를 사용해 첫 번째 항목과 관련된 다른 항목(조직 이름, 도메인 등)을 검색합니다(재귀적으로 수행 가능).
4. shodan의 `org` 및 `ssl` 필터 같은 다른 기법으로 추가 자산을 검색합니다(`ssl` 기법은 재귀적으로 수행 가능).

### **인수**

먼저, **모회사가 소유한 다른 회사**를 파악해야 합니다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com)에 접속해 **모회사를 검색**한 다음 "**acquisitions**"를 **클릭**하는 것입니다. 그러면 모회사가 인수한 다른 회사를 확인할 수 있습니다.\
또 다른 방법은 모회사의 **Wikipedia** 페이지에 접속해 **acquisitions**를 검색하는 것입니다.\
상장 기업의 경우 **SEC/EDGAR 공시**, **투자자 관계** 페이지 또는 현지 기업 등록부(예: 영국의 **Companies House**)를 확인하세요.\
전 세계 기업 구조와 자회사를 확인하려면 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/))와 **GLEIF LEI** 데이터베이스 ([https://www.gleif.org/](https://www.gleif.org/))를 이용해 보세요.

> 이제 스코프에 포함된 회사를 모두 파악했을 것입니다. 자산을 찾는 방법을 알아보겠습니다.

### **ASN**

자율 시스템 번호(**ASN**)는 **자율 시스템**(AS)에 **Internet Assigned Numbers Authority (IANA)**가 할당하는 **고유 번호**입니다.\
**AS**는 외부 네트워크에 접근하기 위한 정책이 명확히 정의된 **IP 주소 블록**으로 구성됩니다. 단일 조직이 관리하지만 여러 사업자로 이루어질 수도 있습니다.

회사가 **ASN을 할당받았는지** 확인하면 **IP 범위**를 찾을 수 있으므로 유용합니다. **스코프** 내에 있는 **모든 호스트**를 대상으로 **취약점 테스트**를 수행하고, 해당 IP에서 **도메인을 찾는 것**도 유용합니다.\
회사 **이름**, **IP** 또는 **도메인**으로 [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **또는** [**https://ipinfo.io/**](https://ipinfo.io/)에서 **검색**할 수 있습니다.\
**회사 지역에 따라 다음 링크에서 더 많은 정보를 수집할 수 있습니다:** [**AFRINIC**](https://www.afrinic.net) **(아프리카),** [**Arin**](https://www.arin.net/about/welcome/region/)**(북미),** [**APNIC**](https://www.apnic.net) **(아시아),** [**LACNIC**](https://www.lacnic.net) **(라틴 아메리카),** [**RIPE NCC**](https://www.ripe.net) **(유럽).** 어쨌든 유용한 정보(**IP 범위 및 Whois**)는 대부분 첫 번째 링크에서 이미 확인할 수 있습니다.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

또한 [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration은 스캔 종료 시 ASN을 자동으로 집계하고 요약합니다.

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

조직의 IP 범위는 [http://asnlookup.com/](http://asnlookup.com)(무료 API 제공)에서도 확인할 수 있습니다.\
도메인의 IP와 ASN은 [http://ipv4info.com/](http://ipv4info.com)에서 확인할 수 있습니다.

### **취약점 찾기**

이제 **범위에 포함된 모든 자산을 알고 있으므로**, 허용된다면 모든 호스트에서 **취약점 스캐너**(Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei))를 실행할 수 있습니다.\
또한 [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)를 실행하거나 Shodan, Censys, ZoomEye 같은 서비스를 이용해 열린 **포트를 찾을 수도 있습니다.** 발견한 내용에 따라 이 책에서 해당 서비스의 pentest 방법을 살펴보세요.\
**또한 기본 사용자 이름과 비밀번호 목록을 준비하고 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)를 사용해 서비스에** bruteforce **공격을 시도해 볼 수도 있습니다.**

## 도메인

> 범위에 포함된 모든 회사와 자산을 파악했으니, 이제 범위 내 도메인을 찾아볼 차례입니다.

_아래에 제시된 기법으로 subdomain도 찾을 수 있으며, 해당 정보를 과소평가해서는 안 된다는 점에 유의하세요._

먼저 각 회사의 **주 도메인**을 찾아야 합니다. 예를 들어 _Tesla Inc._의 경우 _tesla.com_입니다.

### **Reverse DNS**

도메인의 모든 IP 범위를 찾았으므로 해당 **IP에서 reverse DNS 조회를 수행해 범위 내 도메인을 더 찾을 수 있습니다.** 피해자의 DNS 서버나 잘 알려진 DNS 서버(1.1.1.1, 8.8.8.8)를 사용해 보세요.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

이 기능이 작동하려면 관리자가 PTR을 수동으로 활성화해야 합니다.\
이 정보는 다음 온라인 도구로도 확인할 수 있습니다: [http://ptrarchive.com/](http://ptrarchive.com).\
대규모 범위에서는 [**massdns**](https://github.com/blechschmidt/massdns), [**dnsx**](https://github.com/projectdiscovery/dnsx) 같은 도구를 사용해 reverse lookup과 정보 보강을 자동화할 수 있습니다.

### **Reverse Whois (loop)**

**whois**에서는 **조직명**, **주소**, **이메일**, 전화번호 등 흥미로운 **정보**를 많이 찾을 수 있습니다. 하지만 더욱 흥미로운 점은 이러한 필드 중 하나를 사용해 **reverse whois lookup**을 수행하면 **회사와 관련된 자산을 더 많이** 찾을 수 있다는 것입니다(예: 같은 이메일이 나오는 다른 whois 레지스트리).\
다음과 같은 온라인 도구를 사용할 수 있습니다:

- [https://ip.thc.org/](https://ip.thc.org/) - **무료** (Web 및 API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **무료**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web은 **무료**, API는 유료입니다.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 유료
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 유료 (**100회 검색만 무료**)
- [https://www.domainiq.com/](https://www.domainiq.com) - 유료
- [https://securitytrails.com/](https://securitytrails.com/) - 유료 (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 유료 (API)

[**DomLink** ](https://github.com/vysecurity/DomLink)를 사용해 이 작업을 자동화할 수 있습니다(whoху API 키 필요).\
[amass](https://github.com/OWASP/Amass)를 사용해 reverse whois 탐색을 자동으로 수행할 수도 있습니다: `amass intel -d tesla.com -whois`

**새 도메인을 찾을 때마다 이 기법으로 도메인 이름을 더 발견할 수 있습니다.**

### **Trackers**

두 페이지에서 **동일한 tracker의 ID가 같은 것**을 발견하면 **두 페이지가 같은 팀에서 관리**한다고 추정할 수 있습니다.\
예를 들어 여러 페이지에서 같은 **Google Analytics ID** 또는 같은 **Adsense ID**를 발견한 경우입니다.

이러한 tracker 등을 검색할 수 있는 페이지와 도구가 있습니다:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (공유 analytics/trackers를 기준으로 관련 사이트를 찾음)
- [**StackScan**](https://www.stackscan.com) - **무료 요금제** (Web 및 API). tracker ID뿐 아니라 제공되는 모든 asset을 기준으로 검색할 수 있습니다. 예를 들어 script 경로, 자체 호스팅 bundle 이름, asset을 불러오는 호스트를 기준으로 검색해 해당 asset을 포함하는 모든 사이트를 반환합니다.

API는 단일 도메인의 stack을 반환하며, 이를 통해 후보 asset이 같은 estate에 속하는지 확인할 수 있습니다:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

감지된 각 기술을 해당 카테고리와 함께 반환합니다. Asset pivoting은 현재 웹에서만 지원되며, API는 도메인별 조회를 제공합니다.

### **Favicon**

같은 favicon 아이콘 hash를 찾아 타깃과 관련된 도메인 및 서브도메인을 찾을 수 있다는 사실을 알고 계셨나요? [@m4ll0k2](https://twitter.com/m4ll0k2)가 만든 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 도구가 바로 이런 기능을 합니다. 사용 방법은 다음과 같습니다:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash를 사용하면 대상과 동일한 favicon hash를 가진 도메인을 찾을 수 있습니다.

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

알려진 favicon hash를 Shodan 또는 FOFA의 pivot으로 사용해 동일한 기술을 사용하는 다른 노출된 인스턴스를 찾으세요.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

웹사이트의 **favicon hash**(**base64-encoded** favicon 바이트에 대한 MMH3)를 **계산하는 방법**은 다음과 같습니다:

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

[**httpx**](https://github.com/projectdiscovery/httpx)(`httpx -l targets.txt -favicon`)를 사용하면 favicon hash를 대량으로 수집한 뒤 Shodan/Censys에서 pivot할 수도 있습니다.

favicon fingerprint는 단서로 취급하고 주변 신호를 통해 검증하세요.<sup>[[3]](#references)[[4]](#references)</sup>

- **hash를 증거가 아닌 지표로 취급하세요**: MMH3는 간결하며, 충돌, 아이콘 재사용, 의도적인 스푸핑이 발생할 수 있습니다.
- **`/favicon.ico` 외에도 탐색하세요**: 프레임워크/빌드 경로, manifest 파일, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, 인라인 data URL, HTML `<link rel="icon">` 태그를 확인하세요.
- **WAF/SSO/IdP 제어 뒤에서도 정적 asset에 접근할 수 있습니다**: 아이콘을 직접 요청하고 `ETag`, `Last-Modified`, 리디렉션, cache header를 검토하세요.
- **주변 신호로 일치 여부를 검증하세요**: title, HTML/body hash, header, TLS 인증서 subject/SAN, 제품 구성 요소, 노출된 port를 비교하세요.
- **HTML/body hash로 그룹화하세요**: 일관된 template은 fingerprint의 신뢰도를 높이며, template이 섞여 있으면 범용 또는 공유 아이콘일 수 있습니다.
- **서로 무관한 signature, port, 제품에서 같은 hash가 나타나면 honeypot 또는 placeholder일 가능성을 고려하세요.**
- **대상이 모호하면 실제 페이지와 존재하지 않는 경로**(예: `/_favicon_probe_<8-hex>`) **를 비교하세요**. 동일한 호스팅 또는 파킹 응답이 아이콘 공유의 원인일 수 있습니다.
- **favicon hash를 제품 및 CPE에 매핑하는 Nuclei detection rule이나 공개 dataset으로 초기 분류를 진행하세요.**
- **IP 중심 수집의 범위 한계를 기억하세요**: CDN을 경유하거나, SNI로 라우팅되거나, anycast를 사용하거나, 도메인만으로 접근할 수 있는 대상은 Shodan과 유사한 dataset에서 누락될 수 있습니다.

### **저작권 / 고유 문자열**

웹 페이지에서 **같은 조직의 여러 웹사이트에 공통으로 나타날 수 있는 문자열**을 검색하세요. **저작권 문자열**이 좋은 예입니다. 그런 다음 **Google**, 다른 **브라우저**, 또는 **Shodan**에서 해당 문자열을 검색하세요: `shodan search http.html:"Copyright string"`

### **CRT 시간**

다음과 같은 cron job이 있는 경우가 흔합니다.

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

서버의 모든 인증서를 동시에 갱신하기 위해. 인증서 타임스탬프 또는 certificate-transparency 로그 위치를 연관 지으면 관련 도메인을 알아낼 수 있습니다.<sup>[[6]](#references)</sup>

**certificate transparency** 로그를 직접 사용하는 방법도 있습니다:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### 메일 DMARC 정보

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 같은 웹사이트나 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 같은 도구를 사용하면 **같은 DMARC 정보를 공유하는 도메인 및 서브도메인**을 찾을 수 있습니다.\
그 밖에 유용한 도구로는 [**spoofcheck**](https://github.com/BishopFox/spoofcheck)과 [**dmarcian**](https://dmarcian.com/)이 있습니다.

### **Passive Takeover**

버려진 A 레코드는 cloud provider가 IP를 재할당할 때 접근 가능한 상태가 될 수 있습니다. 참고된 연구는 인스턴스를 생성하고 해당 주소를 passive DNS 데이터와 연관 짓는 기회주의적 워크플로를 보여 줍니다. takeover 시나리오는 승인된 범위 내에서만 테스트하세요.<sup>[[7]](#references)</sup>

### **기타 방법**

새 도메인을 찾을 때마다 적용 가능한 discovery pivot을 반복하세요. 각 결과에서 원래 시작점만으로는 확인할 수 없었던 추가 인증서 이름, passive-DNS 관계, favicon 일치 항목, 조직 식별자가 드러날 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP 공간을 소유한 조직의 이름은 이미 알고 있습니다. Shodan에서 다음과 같이 해당 정보로 검색할 수 있습니다: `org:"Tesla, Inc."` 검색된 호스트의 TLS 인증서에서 예상치 못한 새 도메인이 있는지 확인하세요.

메인 웹 페이지의 **TLS certificate**에 접근해 **Organisation name**을 확인한 다음, **shodan**에 알려진 모든 웹 페이지의 **TLS certificates**에서 해당 이름을 필터 `ssl:"Tesla Motors"`로 검색할 수도 있습니다. 또는 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 같은 도구를 사용하세요.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)는 메인 도메인과 **관련된 도메인** 및 해당 도메인의 **서브도메인**을 찾는 도구로, 꽤 훌륭합니다.

**Passive DNS / Historical DNS**

Passive DNS 데이터는 여전히 해석되거나 takeover될 수 있는 **오래된 잊힌 레코드**를 찾는 데 유용합니다. 다음을 확인하세요:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **취약점 찾기**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)가 가능한지 확인하세요. 어떤 회사가 **도메인을 사용하고 있지만** **소유권을 잃었을** 수도 있습니다. (충분히 저렴하다면) 도메인을 등록하고 회사에 알리세요.

자산 탐색 중에 이미 찾은 IP와 **다른 IP를 사용하는 도메인**을 발견하면 Nessus 또는 OpenVAS를 사용해 **기본 취약점 스캔**을 수행하고, **nmap/masscan/shodan**으로 [**포트 스캔**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 하세요. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 몇 가지 방법**을 찾을 수 있습니다.\
_도메인이 클라이언트가 제어하지 않는 IP에 호스팅된 경우가 있어 범위에 포함되지 않을 수 있으니 주의하세요._

## 서브도메인

> 범위에 포함된 모든 회사, 각 회사의 모든 자산, 그리고 회사와 관련된 모든 도메인을 알고 있습니다.

이제 발견한 각 도메인에서 가능한 모든 서브도메인을 찾을 차례입니다.

> [!TIP]
> 도메인을 찾는 데 사용하는 도구와 기법 중 일부는 서브도메인을 찾는 데도 도움이 될 수 있습니다.

### **DNS**

**DNS** 레코드에서 **서브도메인**을 찾아보겠습니다. **Zone Transfer**도 시도해야 합니다(취약한 경우 보고하세요).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

하위 도메인 탐색 외에 인프라, 평판, 침해 기록 및 보강 정보를 다루는 API와 플랫폼은 [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)를 참조하세요.

많은 하위 도메인을 가장 빠르게 찾는 방법은 외부 소스를 검색하는 것입니다. 가장 많이 사용되는 **도구**는 다음과 같습니다(API 키를 설정하면 더 나은 결과를 얻을 수 있습니다).


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

서브도메인 찾기에 직접 특화된 것은 아니지만, 서브도메인을 찾는 데 유용할 수 있는 **다른 흥미로운 도구/API**도 있습니다.

- [**IP.THC.ORG**](https://ip.thc.org) 무료 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 서브도메인을 얻기 위해 API [https://sonar.omnisint.io](https://sonar.omnisint.io)를 사용합니다.

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

- [**gau**](https://github.com/lc/gau)**:** 주어진 도메인에 대해 AlienVault's Open Threat Exchange, Wayback Machine, Common Crawl에서 알려진 URL을 가져옵니다.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 웹을 스크래핑해 JS 파일을 찾고, 해당 파일에서 서브도메인을 추출합니다.

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

- [**Censys 하위 도메인 검색기**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**securitytrails.com**](https://securitytrails.com/)에는 서브도메인과 IP 이력을 검색할 수 있는 무료 API가 있습니다.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

이 프로젝트는 **버그 바운티 프로그램과 관련된 모든 서브도메인을 무료로** 제공합니다. [chaospy](https://github.com/dr-0x0x/chaospy)를 사용해 이 데이터에 액세스하거나, 이 프로젝트에서 사용하는 scope([https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list))에 액세스할 수도 있습니다.

이러한 도구의 **비교**는 여기에서 확인할 수 있습니다: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

가능한 서브도메인 이름을 사용해 DNS 서버를 brute-force하여 새로운 **서브도메인**을 찾아보겠습니다.

이 작업에는 다음과 같은 **일반적인 서브도메인 wordlist가 필요합니다**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

신뢰할 수 있는 DNS resolver의 IP도 필요합니다. 신뢰할 수 있는 DNS resolver 목록을 만들려면 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt)에서 resolver를 다운로드하고 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용해 필터링하면 됩니다. 또는 [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)를 사용할 수도 있습니다.

DNS brute-force에 가장 권장되는 도구는 다음과 같습니다.

- [**massdns**](https://github.com/blechschmidt/massdns): 효과적인 DNS brute-force를 수행한 최초의 도구입니다. 매우 빠르지만 false positive가 발생하기 쉽습니다.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): 이 도구는 resolver를 하나만 사용하는 것 같습니다.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns)는 go로 작성된 `massdns` 래퍼로, active bruteforce를 사용해 유효한 서브도메인을 열거하고 와일드카드 처리를 통해 서브도메인을 확인하며 간편한 입력·출력 기능을 제공합니다.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns`도 사용합니다.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용해 도메인 이름을 비동기적으로 brute force합니다.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### 두 번째 DNS Brute-Force 라운드

오픈 소스와 brute-force를 사용해 하위 도메인을 찾은 후에는, 찾은 하위 도메인을 변형하여 더 많은 하위 도메인을 찾아볼 수 있습니다. 이 작업에 유용한 도구는 다음과 같습니다.

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 도메인과 하위 도메인을 입력하면 순열을 생성합니다.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): 도메인과 서브도메인을 기반으로 permutation을 생성합니다.
  - [**여기**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 goaltdns용 permutation **wordlist**를 받을 수 있습니다.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** 도메인과 서브도메인이 주어지면 순열을 생성합니다. 순열 파일을 지정하지 않으면 gotator 자체 파일을 사용합니다.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): 서브도메인 변형을 생성하는 것 외에도 해당 서브도메인을 resolve할 수 있습니다(하지만 앞서 언급한 도구를 사용하는 편이 더 좋습니다).
  - altdns 변형용 **wordlist**는 [**여기**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 받을 수 있습니다.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): 서브도메인의 permutation, mutation 및 변형을 수행하는 또 다른 도구입니다. 결과를 brute force합니다(DNS wildcard는 지원하지 않습니다).
  - [**여기**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 dmut permutation wordlist를 가져올 수 있습니다.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로 지정된 패턴에 따라 새 하위 도메인 후보 이름을 생성해 더 많은 하위 도메인을 찾습니다.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 발견된 하위 도메인에서 regex와 유사한 패턴을 학습하고, 확인할 후보 이름을 생성합니다.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_는 매우 단순하지만 효과적인 DNS 응답 기반 알고리즘을 결합한 서브도메인 brute-force fuzzer입니다. 맞춤형 wordlist나 과거 DNS/TLS 레코드와 같은 입력 데이터 집합을 사용해 관련 도메인 이름을 정확하게 합성하고, DNS 스캔 중 수집한 정보를 바탕으로 반복적으로 더 확장합니다.

```
echo www | subzuf facebook.com
```

### **서브도메인 탐색 워크플로**

Trickest 워크플로 예시는 반복 가능한 서브도메인 열거를 위해 OSINT, DNS brute force, permutation 단계를 결합합니다.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

서브도메인에 속한 **하나 이상의 웹 페이지**가 있는 IP 주소를 찾았다면, **OSINT 소스**에서 해당 IP의 도메인을 찾아보거나 해당 IP의 **VHost 도메인 이름을 brute force**하여 **같은 IP에 웹사이트를 둔 다른 서브도메인을 찾을** 수 있습니다.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 다른 API를 사용해 IP의 VHosts를 찾을 수 있습니다.**

**Brute Force**

일부 서브도메인이 웹 서버에 숨겨져 있을 가능성이 있다고 판단되면 brute force를 시도할 수 있습니다.

이름 기반 vhost의 경우 `Host` 헤더를 fuzzing하고 ffuf의 자동 보정을 사용해 기본 응답을 필터링합니다.<sup>[[2]](#references)</sup>

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

유효한 도메인/하위 도메인을 _**Origin**_ 헤더에 설정했을 때만 _**Access-Control-Allow-Origin**_ 헤더를 반환하는 페이지를 발견할 수 있습니다. 이런 상황에서는 이 동작을 악용해 새로운 **하위 도메인**을 **발견**할 수 있습니다.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains**를 찾을 때는 **bucket**을 가리키는지 살펴보고, 그런 경우 [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
이 시점에는 scope에 포함된 모든 도메인을 알고 있을 것이므로, [**가능한 bucket 이름을 brute force하고 권한을 확인해 보세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **모니터링**

[sublert ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)가 하는 것처럼 **Certificate Transparency** Logs를 모니터링하여 도메인의 **새 subdomain**이 생성되는지 **모니터링**할 수 있습니다.

### **취약점 찾기**

가능한 [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
**subdomain**이 **S3 bucket**을 가리키는 경우, [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

자산 탐색에서 이미 발견한 IP와 **다른 IP를 사용하는 subdomain**을 찾았다면, **기본 취약점 스캔**(Nessus 또는 OpenVAS 사용)과 **nmap/masscan/shodan**을 이용한 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 몇 가지 기법을 찾을 수 있습니다**.\
_때로는 subdomain이 클라이언트가 제어하지 않는 IP에서 호스팅되어 scope에 포함되지 않을 수 있으니 주의하세요._

## IP

초기 단계에서 **IP range, domain, subdomain을 발견했을 수 있습니다**.\
이제 해당 range와 **domain/subdomain(DNS 쿼리)**에서 IP를 **모두 수집할** 차례입니다.

다음 **무료 API** 서비스를 이용하면 **domain과 subdomain이 과거에 사용한 IP**도 찾을 수 있습니다. 이 IP는 여전히 클라이언트 소유일 수 있으며 [**CloudFlare 우회**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾는 데 도움이 될 수 있습니다.

- [**https://securitytrails.com/**](https://securitytrails.com/)

도구 [**hakip2host**](https://github.com/hakluke/hakip2host)를 사용해 특정 IP 주소를 가리키는 domain도 확인할 수 있습니다.

### **취약점 찾기**

CDN에 속하지 않는 모든 IP를 대상으로 **port scan을 수행하세요**(CDN에서는 흥미로운 것을 찾을 가능성이 매우 낮습니다). 발견한 실행 중인 서비스에서 **취약점을 찾을 수 있습니다**.

호스트 스캔 방법은 [**가이드**](../pentesting-network/index.html)**를 참고하세요.**

## 웹 서버 탐색

> 모든 회사와 자산을 찾았으며 scope 내의 IP range, domain, subdomain을 파악했습니다. 이제 웹 서버를 찾아볼 차례입니다.

이전 단계에서 이미 발견한 IP와 domain을 대상으로 **recon을 수행했을 가능성이 높으므로**, 가능한 **웹 서버를 이미 모두 찾았을 수도 있습니다**. 그렇지 않다면 scope 내의 웹 서버를 찾는 **빠른 기법**을 살펴보겠습니다.

이 방법은 **웹 앱 탐색에 초점을 둡니다**. 따라서 scope에서 **허용하는 경우**, **취약점 스캔**과 **port scan**도 수행해야 합니다.

[masscan을 사용해 웹 서버와 관련된 열린 port를 빠르게 찾는 방법은 여기에서 확인할 수 있습니다](../pentesting-network/index.html#http-port-discovery).\
웹 서버를 찾는 또 다른 편리한 도구는 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe), [**httpx**](https://github.com/projectdiscovery/httpx)입니다. domain 목록을 전달하면 port 80(http)과 443(https)에 연결을 시도합니다. 다른 port도 시도하도록 지정할 수도 있습니다:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

이제 범위 내의 **모든 웹 서버**(회사의 **IP**와 모든 **도메인**, **서브도메인**)를 발견했지만, 어디서 시작해야 할지 **모를 수도 있습니다**. 간단하게 시작해 모든 서버의 스크린샷을 찍어 봅시다. **메인 페이지**를 **살펴보는 것만으로도** **취약할 가능성이 더 높은** **이상한** 엔드포인트를 찾을 수 있습니다.

제안한 작업을 수행하려면 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**을** 사용할 수 있습니다.

또한 [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용해 모든 **스크린샷**을 분석하고, **취약점이 있을 가능성이 높은** 곳과 그렇지 않은 곳을 파악할 수 있습니다.

## Public Cloud Assets

회사에 속한 잠재적인 cloud assets를 찾으려면 먼저 해당 회사를 식별하는 **키워드 목록을 준비해야 합니다**. 예를 들어, crypto 회사라면 `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` 같은 단어를 사용할 수 있습니다.

또한 **버킷에서 흔히 사용되는 단어**의 wordlist도 필요합니다.

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그런 다음 이 단어들로 **permutations**를 생성합니다(자세한 내용은 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)를 참고하세요).

생성한 wordlist로 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **또는** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**와 같은 도구를 사용할 수 있습니다.**

Cloud Assets를 찾을 때 **AWS 버킷만 살펴보는 것이 아니라는 점을 기억하세요**.

### **취약점 찾기**

**공개된 버킷이나 노출된 cloud function** 같은 것을 발견하면 **접근해서** 어떤 기능을 제공하는지, 악용할 수 있는지 확인해야 합니다.

## Emails

범위에 포함된 **도메인**과 **서브도메인**이 있다면 **이메일 검색을 시작하는 데 필요한 것**은 거의 모두 갖춘 셈입니다. 회사 이메일을 찾는 데 가장 효과적이었던 **API**와 **도구**는 다음과 같습니다.

- [**theHarvester**](https://github.com/laramies/theHarvester) - API 사용
- [**https://hunter.io/**](https://hunter.io/)의 API (무료 버전)
- [**https://app.snov.io/**](https://app.snov.io/)의 API (무료 버전)
- [**https://minelead.io/**](https://minelead.io/)의 API (무료 버전)

### **취약점 찾기**

이메일은 나중에 **웹 로그인과 auth service(예: SSH)를 brute-force**하거나 **phishing**을 수행할 때 유용합니다. 또한 이 API들은 이메일 소유자에 대한 **추가 정보**도 제공하므로 phishing campaign에 활용할 수 있습니다.

## Credential Leaks

**도메인**, **서브도메인**, **이메일**을 이용해 해당 이메일과 관련된 과거 credential leak을 검색할 수 있습니다.

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **취약점 찾기**

**유효한 leaked** credential을 발견한다면 아주 쉽게 성과를 얻을 수 있습니다.

## Secrets Leaks

Credential leak은 기업이 해킹당해 **민감한 정보가 유출되고 판매된** 사례와 관련이 있습니다. 하지만 기업은 해당 데이터베이스에 정보가 없는 **다른 leak**의 영향을 받았을 수도 있습니다.

### Github Leaks

회사의 **공개 저장소**나 해당 회사에서 일하는 **사용자**의 공개 저장소에서 credential과 API가 leaked될 수 있습니다.\
[**Leakos**](https://github.com/carlospolop/Leakos) **도구**를 사용해 **조직**과 개발자의 **공개 저장소**를 모두 **다운로드**한 다음, 그 저장소에서 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 자동으로 실행할 수 있습니다.

**Leakos**는 제공된 모든 **텍스트 URL**에 대해 **gitleaks**를 실행하는 데도 사용할 수 있습니다. **웹 페이지에도 때때로 secret이 포함되기 때문입니다**.

#### Github Dorks

조직에서 검색할 만한 **GitHub dorks**는 [GitHub dorks and leaks 페이지](github-leaked-secrets.md)를 확인하세요.

### Pastes Leaks

공격자나 직원이 회사 콘텐츠를 **paste site에 공개**하는 경우가 있습니다. 여기에 **민감한 정보**가 포함될 수도, 그렇지 않을 수도 있지만 검색해 볼 가치가 충분합니다.\
[**Pastos**](https://github.com/carlospolop/Pastos) 도구를 사용하면 80개가 넘는 paste site를 한 번에 검색할 수 있습니다.

### Google Dorks

오래됐지만 여전히 유용한 Google dorks는 **노출되어서는 안 되는 정보**를 찾는 데 도움이 됩니다. 다만 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에는 수천 개의 검색 쿼리가 있어 수동으로 실행하기 어렵습니다. 따라서 마음에 드는 10개를 골라 사용하거나 [**Gorks**](https://github.com/carlospolop/Gorks) **같은 도구로 전부 실행**할 수 있습니다.

_Note: 일반 Google 브라우저를 사용해 데이터베이스 전체를 실행하려는 도구는 Google이 곧 차단하므로 작업을 끝내지 못합니다._

### **취약점 찾기**

**유효한 leaked** credential이나 API token을 발견한다면 아주 쉽게 성과를 얻을 수 있습니다.

## Public Code Vulnerabilities

회사의 **오픈소스 코드**를 찾았다면 이를 **분석**하고 **취약점**을 검색할 수 있습니다.

**언어에 따라** 사용할 수 있는 **도구**가 다릅니다. [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) 목록을 확인하세요.

다음과 같이 **공개 저장소를 scan**할 수 있는 무료 서비스도 있습니다.

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunter가 발견하는 **대부분의 취약점**은 **웹 애플리케이션**에 있으므로, 여기서는 **웹 애플리케이션 테스트 방법론**을 소개하겠습니다. [**이 정보는 여기에서 확인할 수 있습니다**](../../network-services-pentesting/pentesting-web/index.html).

[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 섹션도 특별히 언급하고 싶습니다. 매우 민감한 취약점을 찾아낼 것이라고 기대해서는 안 되지만, **초기 웹 정보를 얻기 위한 workflow에 도입하기 좋습니다**.

## Recapitulation

> 축하합니다! 이제 **기본적인 열거 작업**을 모두 마쳤습니다. 물론 기본 단계일 뿐입니다. 훨씬 더 많은 열거 작업을 수행할 수 있으며, 뒤에서 더 많은 기법을 살펴보겠습니다.

지금까지 다음 작업을 완료했습니다.

1. 범위 내의 모든 **회사**를 찾았습니다.
2. 회사에 속한 모든 **자산**을 찾았습니다(범위에 포함된다면 vuln scan도 수행했습니다).
3. 회사에 속한 모든 **도메인**을 찾았습니다.
4. 도메인의 모든 **서브도메인**을 찾았습니다(subdomain takeover 가능성도 확인했나요?).
5. 범위에 포함된 모든 **IP**를 찾았습니다(**CDN에서 제공되는 IP와 그렇지 않은 IP** 모두).
6. 모든 **웹 서버**를 찾고 스크린샷을 찍었습니다(자세히 살펴볼 만한 이상한 점이 있었나요?).
7. 회사에 속한 모든 **잠재적 public cloud asset**을 찾았습니다.
8. **Emails**, **credential leaks**, **secret leaks**를 찾아 손쉽게 **큰 성과를 얻을 기회**를 확보했습니다.
9. 찾은 모든 웹을 **pentesting**했습니다.

## **Full Recon Automatic Tools**

주어진 범위를 대상으로 제안한 작업의 일부를 수행하는 도구가 여러 가지 있습니다.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 다소 오래됐고 업데이트되지 않음

## References

- [1] [Jason Haddix – 버그 헌터 방법론 v4.0: Recon 에디션](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon 살펴보기: 브라우저 아이콘에서 공격 표면 인텔리전스까지](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug Bounties, OSINT 등을 위한 favicon.ico 무기화](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency의 시간 상관관계 공격을 통한 도메인 발견](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: 비용이 많이 드는 subdomain takeover campaign의 발견 및 모방](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: 독특한 subdomain 열거 방법](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – 전체 subdomain 발견 workflow, 1부](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 자동화된 Trickest workflow를 사용한 전체 subdomain brute-force 발견, 2부](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash 출력 스크린샷](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
