# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## 자산 탐색

> 회사에 속한 모든 것이 scope에 포함된다고 들었고, 이 회사가 실제로 무엇을 소유하고 있는지 알아내고 싶다고 해봅시다.

이 단계의 목표는 **주요 회사가 소유한 모든 회사**를 파악한 다음, 해당 회사들의 **모든 자산**을 찾는 것입니다. 이를 위해 다음을 수행합니다:<sup>[[1]](#references)</sup>

1. 주요 회사의 인수를 찾아 scope에 포함되는 회사를 파악합니다.
2. 각 회사의 ASN(있는 경우)을 찾아 회사별 소유 IP 범위를 파악합니다.
3. reverse whois 조회를 사용해 첫 번째 항목과 관련된 다른 항목(조직 이름, 도메인 등)을 검색합니다(이 작업은 재귀적으로 수행할 수 있습니다).
4. Shodan의 `org` 및 `ssl` 필터 같은 다른 기법을 사용해 추가 자산을 검색합니다(`ssl` 트릭은 재귀적으로 수행할 수 있습니다).

해석된 하위 도메인에서 HTTP crawling 및 포트 탐색으로 단계적으로 인계하는 방법은 [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline)를 참조하세요.

### **인수**

먼저 **주요 회사가 소유한 다른 회사**가 무엇인지 알아야 합니다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com)에 방문해 **주요 회사를 검색**한 다음 "**acquisitions**"를 **클릭**하는 것입니다. 여기서 해당 회사가 인수한 다른 회사를 확인할 수 있습니다.\
또 다른 방법은 주요 회사의 **Wikipedia** 페이지를 방문해 **acquisitions**를 검색하는 것입니다.\
상장 기업의 경우 **SEC/EDGAR filings**, **investor relations** 페이지 또는 현지 기업 등기부(예: 영국의 **Companies House**)를 확인하세요.\
글로벌 기업 구조와 자회사를 확인하려면 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 및 **GLEIF LEI** 데이터베이스 ([https://www.gleif.org/](https://www.gleif.org/))를 이용해 보세요.

> 좋습니다. 이제 scope에 포함되는 모든 회사를 파악했을 것입니다. 이 회사들의 자산을 찾는 방법을 알아보겠습니다.

### **ASN**

자율 시스템 번호(**ASN**)는 **Internet Assigned Numbers Authority (IANA)**가 **자율 시스템**(AS)에 할당하는 **고유 번호**입니다.\
**AS**는 **외부 네트워크에 액세스하는 정책이 명확히 정의된 IP 주소 블록**으로 구성됩니다. 하나의 조직이 관리하지만 여러 운영자로 이루어질 수 있습니다.

**회사가 ASN을 할당받았는지** 확인하면 **IP 범위**를 찾는 데 유용합니다. **scope** 내 모든 **호스트**에 대해 **취약점 테스트**를 수행하고 해당 IP 내의 **도메인을 찾는** 것도 유용합니다.\
[**https://bgp.he.net/**](https://bgp.he.net) **또는** [**https://ipinfo.io/**](https://ipinfo.io/)에서 회사 **이름**, **IP** 또는 **도메인**으로 **검색**할 수 있습니다.\
**회사 지역에 따라 다음 링크에서 추가 데이터를 얻을 수 있습니다:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). 어쨌든, 유용한 정보**(IP 범위와 Whois)**는 아마 첫 번째 링크에 이미 모두 나와 있을 것입니다.**

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

조직의 IP 대역은 제한된 무료 API 요금제를 제공하는 [ASNLookup](https://asnlookup.com/)을 통해서도 찾을 수 있습니다.

### **취약점 찾기**

이제 **scope 내의 모든 자산을 알고 있으므로**, 허용된다면 모든 호스트에 **취약점 스캐너**(Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei))를 실행할 수 있습니다.\
또한 [**포트 스캔**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 실행하거나 Shodan, Censys, ZoomEye 같은 서비스를 사용해 열린 포트를 **찾을 수 있습니다. 발견한 내용에 따라** 이 책에서 실행 중인 여러 서비스의 pentest 방법을 **살펴보세요.**\
**또한 기본 사용자 이름과 비밀번호 목록을 준비하고** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)를 사용해 서비스에 **bruteforce를 시도해볼 수도 있습니다.**

## 도메인

> scope 내의 모든 회사와 자산을 파악했으니, 이제 scope 내의 도메인을 찾을 차례입니다.

_다음에 소개하는 기법으로 subdomain도 찾을 수 있으니, 이 정보를 가볍게 여겨서는 안 됩니다._

먼저 각 회사의 **기본 도메인**을 찾아야 합니다. 예를 들어 _Tesla Inc._의 기본 도메인은 _tesla.com_입니다.

### **Reverse DNS**

도메인의 모든 IP 대역을 찾았다면, 해당 **IP에서 reverse DNS 조회를 수행해 scope 내의 도메인을 더 찾아볼 수 있습니다.** 피해자의 DNS 서버나 잘 알려진 DNS 서버(1.1.1.1, 8.8.8.8)를 사용해 보세요.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

이 작업을 수행하려면 관리자가 PTR을 수동으로 활성화해야 합니다.\
이 정보는 [SecurityTrails](https://securitytrails.com/)에서도 확인할 수 있지만, 과거 DNS 데이터는 유료 플랜이 필요합니다.\
대규모 범위에서는 [**massdns**](https://github.com/blechschmidt/massdns) 및 [**dnsx**](https://github.com/projectdiscovery/dnsx) 같은 도구를 사용하면 역방향 조회와 정보 보강을 자동화할 수 있습니다.

### **Reverse Whois (loop)**

**whois**에서는 **조직 이름**, **주소**, **이메일**, 전화번호 등 흥미로운 **정보**를 많이 찾을 수 있습니다. 더 흥미로운 점은 해당 필드 중 하나를 사용해 **reverse whois lookups**를 수행하면 **회사와 관련된 추가 자산**을 찾을 수 있다는 것입니다(예: 동일한 이메일이 표시되는 다른 whois 레지스트리).\
다음과 같은 온라인 도구를 사용할 수 있습니다.

- [https://ip.thc.org/](https://ip.thc.org/) - **무료** (Web 및 API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
- [https://www.whoxy.com/](https://www.whoxy.com) - **무료** 웹 인터페이스, API는 유료.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 유료
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 무료 아님 (**무료 검색 100회**만 제공)
- [https://www.domainiq.com/](https://www.domainiq.com) - 무료 아님
- [https://securitytrails.com/](https://securitytrails.com/) - 현재 DNS/하위 도메인에 대해 제한된 무료 API 액세스를 제공하며, 과거 데이터 및 reverse lookup은 유료 플랜이 필요합니다.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 가입 시 무료 API 크레딧 500개 제공, 이후 유료.

[**DomLink** ](https://github.com/vysecurity/DomLink)(whoxy API 키 필요)를 사용해 이 작업을 자동화할 수 있습니다.\
[amass](https://github.com/owasp-amass/amass)를 사용해 자동으로 reverse whois 검색을 수행할 수도 있습니다: `amass intel -d tesla.com -whois`

**새 도메인을 찾을 때마다 이 기법을 사용해 더 많은 도메인 이름을 찾을 수 있다는 점에 유의하세요.**

### **Trackers**

서로 다른 두 페이지에서 **동일한 tracker의 동일한 ID**를 찾으면 **두 페이지 모두** **같은 팀이 관리한다고** 추정할 수 있습니다.\
예를 들어 여러 페이지에서 동일한 **Google Analytics ID** 또는 동일한 **Adsense ID**를 발견한 경우입니다.

이러한 tracker 등을 검색할 수 있는 페이지와 도구가 있습니다.

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **유료** 웹 및 API 서비스 ([가격](https://www.stackscan.com/pricing)); 현재 무료 플랜은 안내되어 있지 않습니다. tracker ID뿐 아니라 제공되는 모든 자산을 기준으로 검색 범위를 넓혀 보세요. 스크립트 경로, 자체 호스팅 번들 이름 또는 자산을 불러오는 호스트를 기준으로 검색하면 해당 자산이 포함된 모든 사이트를 확인할 수 있습니다.

API는 단일 도메인의 기술 스택을 반환하며, 이를 통해 후보 자산이 동일한 인프라에 속하는지 확인할 수 있습니다:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

감지된 각 기술과 해당 카테고리를 반환합니다. Asset pivoting은 현재 웹에서만 지원되며, API는 도메인별 조회를 지원합니다.

### **Favicon**

같은 favicon 아이콘 해시를 찾아 대상과 관련된 도메인 및 서브도메인을 발견할 수 있다는 사실을 알고 계셨나요? [@m4ll0k2](https://twitter.com/m4ll0k2)가 만든 [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) 도구가 바로 이 기능을 합니다. 사용 방법은 다음과 같습니다:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash 결과를 사용해 favicon hash를 공유하는 도메인 찾기](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash를 사용하면 대상과 동일한 favicon hash를 가진 도메인을 찾을 수 있습니다.

![favihash 출력을 사용해 동일한 favicon hash를 가진 도메인 찾기](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

알려진 favicon hash를 Shodan 또는 FOFA에서 피벗으로 사용해 동일한 기술의 다른 노출된 인스턴스를 찾으세요.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

웹사이트의 **favicon hash를 계산하는 방법**은 다음과 같습니다 (favicon bytes를 **base64-encoded**한 값에 대한 MMH3):

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

규모에 맞게 [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`)를 사용해 favicon hash를 수집한 다음 Shodan/Censys에서 관련 정보를 찾아볼 수도 있습니다.

favicon fingerprint는 단서로 취급하고 주변 신호를 통해 검증하세요.<sup>[[3]](#references)[[4]](#references)</sup>

- **hash는 증거가 아니라 지표로 취급하세요**: MMH3는 간결하므로 충돌, 아이콘 재사용, 의도적인 스푸핑이 발생할 수 있습니다.
- **`/favicon.ico` 외에도 조사하세요**: framework/build 경로, manifest 파일, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, 인라인 data URL, HTML `<link rel="icon">` 태그를 확인하세요.
- **WAF/SSO/IdP 제어 뒤에서도 정적 asset에 접근할 수 있습니다**: 아이콘을 직접 요청하고 `ETag`, `Last-Modified`, redirect, cache header를 확인하세요.
- **주변 신호를 통해 일치 항목을 검증하세요**: 제목, HTML/body hash, header, TLS 인증서 subject/SAN, 제품 구성 요소, 노출된 port를 비교하세요.
- **HTML/body hash를 기준으로 클러스터링하세요**: 일관된 template은 fingerprint의 신뢰도를 높이며, 서로 다른 template은 범용 또는 공유 아이콘일 가능성을 시사합니다.
- **서로 관련 없는 signature, port, 제품에서 동일한 hash가 나타나면 잠재적인 honeypot 또는 placeholder로 취급하세요.**
- **대상이 모호하다면 실제 페이지와 존재하지 않는 경로**(예: `/_favicon_probe_<8-hex>`)를 비교하세요. hosting 또는 parking 응답이 같다면 아이콘이 공유되는 이유를 설명할 수 있습니다.
- **favicon hash를 제품 및 CPE에 매핑하는 Nuclei 탐지 규칙이나 공개 데이터셋**을 초기 triage에 활용하세요.
- **IP 중심 탐지 범위의 한계를 기억하세요**: CDN을 통해 제공되거나, SNI 라우팅 또는 anycast를 사용하는 표면과 도메인으로만 식별되는 표면은 Shodan과 유사한 데이터셋에서 누락될 수 있습니다.

### **저작권 / 고유 문자열**

웹 페이지에서 **같은 조직의 여러 웹사이트에서 공유될 수 있는 문자열**을 검색하세요. **저작권 문자열**이 좋은 예가 될 수 있습니다. 그런 다음 **google**, 다른 **브라우저** 또는 **shodan**에서 해당 문자열을 검색하세요: `shodan search http.html:"Copyright string"`

### **CRT 시간**

다음과 같은 cron job이 흔히 있습니다.

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

서버의 모든 인증서를 동시에 갱신하기 위해서입니다. 인증서 타임스탬프나 Certificate Transparency 로그의 위치를 대조하면 관련 도메인을 알아낼 수 있습니다.<sup>[[6]](#references)</sup>

**Certificate Transparency** 로그를 직접 사용하는 방법도 있습니다.

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### 메일 DMARC 정보

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 같은 웹사이트나 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 같은 도구를 사용하면 **같은 DMARC 정보를 공유하는 도메인 및 서브도메인**을 찾을 수 있습니다.\
또 다른 유용한 서비스로 [**dmarcian**](https://dmarcian.com/)이 있습니다.

### **Passive Takeover**

방치된 A 레코드는 cloud provider가 IP를 재할당할 때 다시 접속 가능해질 수 있습니다. 참고한 연구에서는 인스턴스를 생성하고 해당 주소를 passive DNS 데이터와 대조하는 기회주의적 워크플로를 보여 줍니다. Takeover 시나리오는 승인된 범위 내에서만 테스트하세요.<sup>[[7]](#references)</sup>

### **그 외 방법**

새 도메인을 찾을 때마다 해당하는 발견 방법을 반복하세요. 각 결과를 통해 최초 seed에서는 보이지 않았던 추가 인증서 이름, passive DNS 관계, favicon 일치 항목, 조직 식별자를 찾을 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP 대역을 소유한 조직의 이름은 이미 알고 있습니다. 다음과 같이 Shodan에서 해당 정보로 검색할 수 있습니다. `org:"Tesla, Inc."` 검색된 호스트의 TLS 인증서에서 예상치 못한 새 도메인이 있는지 확인하세요.

주 웹 페이지의 **TLS 인증서**에 접근해 **조직 이름**을 확인한 다음, **Shodan**이 알고 있는 모든 웹 페이지의 **TLS 인증서**에서 다음 필터를 사용해 해당 이름을 검색할 수 있습니다: `ssl:"Tesla Motors"`. 또는 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 같은 도구를 사용하세요.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)는 주 도메인과 **관련된 도메인** 및 해당 도메인의 **서브도메인**을 찾는 도구로, 매우 유용합니다.

**Passive DNS / Historical DNS**

Passive DNS 데이터는 여전히 확인되거나 takeover 가능한 **오래되고 잊힌 레코드**를 찾는 데 유용합니다. 다음을 확인하세요.

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **취약점 찾기**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)가 가능한지 확인하세요. 어떤 회사가 **도메인을 사용하고 있지만** **소유권을 잃었을** 수도 있습니다. (가격이 충분히 저렴하다면) 해당 도메인을 등록한 뒤 회사에 알려 주세요.

자산 검색에서 이미 찾은 IP와 **다른 IP를 가리키는 도메인**을 발견하면 **기본 취약점 검사**(Nessus 또는 OpenVAS 사용)와 **nmap/masscan/shodan**을 이용한 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 몇 가지 기법을** 찾을 수 있습니다.\
_때로는 클라이언트가 제어하지 않는 IP에서 도메인이 호스팅되기도 하므로 범위에 포함되지 않을 수 있습니다. 주의하세요._

## 서브도메인

> 범위에 포함된 모든 회사와 각 회사의 모든 자산, 그리고 회사와 관련된 모든 도메인을 파악했습니다.

이제 찾은 각 도메인에서 가능한 모든 서브도메인을 찾아볼 차례입니다.

> [!TIP]
> 도메인을 찾는 일부 도구와 기법은 서브도메인을 찾는 데도 도움이 될 수 있습니다.

### **DNS**

**DNS** 레코드에서 **서브도메인**을 찾아보겠습니다. **Zone Transfer**도 시도해야 합니다(취약하다면 보고해야 합니다).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

인프라, 평판, 유출 기록, 서브도메인 탐색을 넘어서는 정보 보강을 다루는 API 및 플랫폼은 [정찰 및 Threat-Intelligence API 카탈로그](reconnaissance-and-threat-intelligence-apis.md)를 참조하세요.

많은 서브도메인을 가장 빠르게 얻는 방법은 외부 소스를 검색하는 것입니다. 가장 많이 사용되는 **도구**는 다음과 같습니다(API 키를 설정하면 더 나은 결과를 얻을 수 있습니다):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

서브도메인을 찾는 데 직접 특화되어 있지는 않더라도, 서브도메인을 찾는 데 유용할 수 있는 **다른 흥미로운 도구/API**도 있습니다.

- [**IP.THC.ORG**](https://ip.thc.org) 무료 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB 무료 API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** 주어진 도메인에 대해 AlienVault의 Open Threat Exchange, Wayback Machine, Common Crawl에서 알려진 URL을 가져옵니다.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 웹을 크롤링해 JS 파일을 찾고, 여기서 서브도메인을 추출합니다.

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

- [**Censys 서브도메인 검색기**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/)은 현재 DNS 및 subdomain 데이터에 대해 제한된 무료 API 액세스를 제공하며, 과거 DNS/IP 데이터는 유료 플랜이 필요합니다.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

이 프로젝트는 **bug-bounty 프로그램과 관련된 모든 subdomain을 무료로** 제공합니다. [chaospy](https://github.com/Moaaz-0x/chaospy)를 사용해 이 데이터에 액세스하거나, 이 프로젝트에서 사용하는 scope를 [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)에서 확인할 수도 있습니다.

이러한 도구 중 다수를 [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)에서 **비교**해 볼 수 있습니다.

### **DNS Brute force**

가능한 subdomain 이름으로 DNS 서버를 brute-force하여 새로운 **subdomain**을 찾아보겠습니다.

이 작업에는 다음과 같은 **일반적인 subdomain wordlist가 필요합니다**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

그리고 신뢰할 수 있는 DNS resolver의 IP도 필요합니다. 신뢰할 수 있는 DNS resolver 목록을 만들려면 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt)에서 resolver를 다운로드한 다음 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용해 필터링할 수 있습니다. 또는 다음 목록을 사용할 수도 있습니다: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

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

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns)는 go로 작성된 `massdns` 래퍼로, active bruteforce를 사용해 유효한 하위 도메인을 열거하고 와일드카드 처리 및 간편한 입출력 지원을 통해 하위 도메인을 resolve할 수 있습니다.

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

오픈 소스를 검색하고 brute-force를 수행해 서브도메인을 찾은 후, 발견한 서브도메인을 변형해 더 많은 서브도메인을 찾을 수 있습니다. 이 작업에 유용한 도구는 다음과 같습니다.

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** 도메인과 서브도메인을 입력하면 여러 변형을 생성합니다.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): 도메인과 서브도메인을 입력하면 permutations를 생성합니다.
  - [**여기**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 goaltdns permutations **wordlist**를 받을 수 있습니다.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** 도메인과 서브도메인이 주어지면 변형을 생성합니다. permutations 파일을 지정하지 않으면 gotator가 자체 파일을 사용합니다.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): 서브도메인 permutation을 생성하는 것 외에도 이를 resolve할 수 있습니다(하지만 앞서 언급한 도구를 사용하는 것이 더 좋습니다).
  - [**여기**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 altdns permutation **wordlist**를 가져올 수 있습니다.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): 서브도메인의 순열, 변형 및 변경을 수행하는 또 다른 도구입니다. 이 도구는 결과를 brute force합니다(DNS wildcard는 지원하지 않습니다).
  - [**여기**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 dmut 순열 wordlist를 받을 수 있습니다.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 도메인을 기반으로 지정된 패턴에 따라 **새로운 잠재적 서브도메인 이름을 생성**하여 더 많은 서브도메인을 찾으려고 합니다.

#### 스마트 순열 생성

- [**regulator**](https://github.com/cramppet/regulator): 발견된 서브도메인에서 정규식과 유사한 패턴을 학습하고 확인할 후보 이름을 생성합니다.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_는 매우 단순하지만 효과적인 DNS 응답 기반 알고리즘을 결합한 서브도메인 brute-force fuzzer입니다. 맞춤형 wordlist나 과거 DNS/TLS 레코드와 같은 입력 데이터를 사용해 관련 도메인 이름을 정확하게 생성하고, DNS 스캔 중 수집한 정보를 바탕으로 반복적으로 더 많은 도메인 이름을 찾아냅니다.

```
echo www | subzuf facebook.com
```

### **서브도메인 발견 워크플로**

Trickest 워크플로 예시는 OSINT, DNS brute force, permutation 단계를 결합해 반복 가능한 서브도메인 열거를 수행합니다.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

서브도메인에 속한 **웹 페이지가 하나 이상 있는 IP 주소**를 찾았다면, **OSINT 소스**에서 해당 IP의 도메인을 찾거나 해당 IP에서 **VHost 도메인 이름을 brute force**해 **같은 IP에서 다른 서브도메인을 찾을 수 있습니다**.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 다른 API를 사용해 IP에서 일부 VHosts를 찾을 수 있습니다**.

**Brute Force**

웹 서버에 일부 서브도메인이 숨겨져 있을 수 있다고 생각한다면 brute force를 시도해 볼 수 있습니다.

이름 기반 vhost의 경우 `Host` 헤더를 fuzz하고 ffuf의 자동 보정 기능을 사용해 기본 응답을 필터링하세요.<sup>[[2]](#references)</sup>

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

유효한 도메인/서브도메인을 _**Origin**_ 헤더에 설정했을 때만 _**Access-Control-Allow-Origin**_ 헤더를 반환하는 페이지를 발견할 수 있습니다. 이런 경우, 이 동작을 악용해 새로운 **서브도메인**을 **발견**할 수 있습니다.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains**를 찾는 동안 어떤 종류의 **bucket**을 **가리키고 있는지** 확인하고, 그런 경우 [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
또한 이 시점에는 스코프에 포함된 모든 도메인을 알고 있을 테니, 가능한 **bucket 이름을 brute force하고 권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **모니터링**

[sublert ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)가 하는 것처럼 **Certificate Transparency** 로그를 모니터링하여 도메인의 **새 subdomain**이 생성되는지 확인할 수 있습니다.

### **취약점 탐색**

가능한 [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
**subdomain**이 **S3 bucket**을 가리키고 있다면 [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/index.html).

자산 탐색에서 이미 찾은 IP와 **다른 IP를 사용하는 subdomain**을 발견하면 **기본 취약점 스캔**(Nessus 또는 OpenVAS 사용)과 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)을 **nmap/masscan/shodan**으로 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 해당 서비스를 "공격"하는 몇 가지 기법을 찾을 수 있습니다**.\
_때때로 subdomain이 고객이 제어하지 않는 IP에서 호스팅되므로 스코프에 포함되지 않을 수 있습니다. 주의하세요._

## IPs

초기 단계에서 **일부 IP 대역, 도메인, subdomain을 발견했을 수 있습니다**.\
이제 해당 대역의 모든 IP와 **도메인/subdomain의 IP(DNS 쿼리)**를 **수집할 차례입니다**.

다음과 같은 서비스를 사용하면 **도메인과 subdomain이 과거에 사용했던 IP**도 찾을 수 있습니다. 이 IP는 여전히 고객 소유일 수 있으며 [**CloudFlare 우회**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾는 데 도움이 될 수도 있습니다.

- [**SecurityTrails**](https://securitytrails.com/) (과거 DNS/IP 데이터는 유료 플랜에서 제공)

도구 [**hakip2host**](https://github.com/hakluke/hakip2host)를 사용하면 특정 IP 주소를 가리키는 도메인도 확인할 수 있습니다.

### **취약점 탐색**

**CDN에 속하지 않는 모든 IP를 port scan하세요**(CDN에서는 흥미로운 것을 찾을 가능성이 매우 낮기 때문입니다). 발견한 실행 중인 서비스에서 **취약점을 찾을 수 있을지도 모릅니다**.

호스트를 스캔하는 방법에 대한 [**가이드**](../pentesting-network/index.html)를 **확인하세요**.

## 웹 서버 탐색

> 회사와 자산을 모두 찾아냈고, 스코프에 포함된 IP 대역, 도메인, subdomain을 파악했습니다. 이제 웹 서버를 찾아볼 차례입니다.

이전 단계에서 이미 발견한 IP와 도메인을 **정찰**했을 가능성이 높으므로, 가능한 웹 서버를 **이미 모두 찾았을 수도 있습니다**. 그렇지 않은 경우, 이제 스코프 내 웹 서버를 찾는 몇 가지 **빠른 기법**을 살펴보겠습니다.

이 과정은 **웹 앱 탐색에 초점을 둡니다**. 따라서 스코프에서 허용하는 경우 **취약점 스캔**과 **port scan**도 수행해야 합니다.

[**masscan**을 사용해 웹 서버와 관련된 열린 포트를 빠르게 탐색하는 방법은 여기에서 확인할 수 있습니다](../pentesting-network/index.html#http-port-discovery).\
웹 서버를 찾는 데 유용한 다른 도구로는 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe), [**httpx**](https://github.com/projectdiscovery/httpx)가 있습니다. 도메인 목록을 전달하면 80번 포트(http)와 443번 포트(https)에 연결을 시도합니다. 다른 포트도 시도하도록 지정할 수도 있습니다:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **스크린샷**

범위 내에 있는 **모든 웹 서버**(회사의 **IP**와 모든 **도메인**, **서브도메인**)를 찾았지만, 어디서부터 시작해야 할지 **모를 수 있습니다**. 그러니 간단하게, 우선 모든 서버의 스크린샷을 찍어 보겠습니다. **메인 페이지**를 **살펴보는 것만으로도** 취약할 **가능성이 더 높은** **이상한** 엔드포인트를 찾을 수 있습니다.

제안한 작업을 수행하려면 [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**을 사용할 수 있습니다.

그런 다음 [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용해 모든 **스크린샷**을 분석하면, 어떤 항목에 **취약점이 있을 가능성이 높은지**, 어떤 항목은 그렇지 않은지 확인할 수 있습니다.

## 퍼블릭 클라우드 자산

회사에 속한 잠재적인 클라우드 자산을 찾으려면 우선 해당 회사를 식별하는 키워드 목록을 만들어야 합니다. 예를 들어, 암호화폐 회사라면 `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` 같은 단어를 사용할 수 있습니다.

또한 버킷에서 **자주 사용되는 단어**의 wordlist도 필요합니다.

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그런 다음 해당 단어를 사용해 **순열**을 생성해야 합니다(자세한 내용은 [**두 번째 DNS Brute-Force 라운드**](#second-dns-bruteforce-round)를 확인하세요).

생성한 wordlist를 사용해 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **또는** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** 같은 도구를 실행할 수 있습니다.

Cloud Assets를 찾을 때는 **AWS 버킷만 찾아서는 안 된다는 점**을 기억하세요.

### **취약점 찾기**

**공개된 버킷이나 노출된 cloud functions** 같은 것을 찾으면 **접속해서** 어떤 기능을 제공하는지, 악용할 수 있는지 확인해야 합니다.

## 이메일

범위 내에 있는 **도메인**과 **서브도메인**만 있으면 이메일을 검색하는 데 필요한 정보를 거의 모두 갖춘 셈입니다. 회사 이메일을 찾는 데 가장 효과적이었던 **API**와 **도구**는 다음과 같습니다.

- API를 사용하는 [**theHarvester**](https://github.com/laramies/theHarvester)
- [**https://hunter.io/**](https://hunter.io/)의 API (무료 버전)
- [**https://app.snov.io/**](https://app.snov.io/)의 API (무료 버전)
- [**https://minelead.io/**](https://minelead.io/)의 API (무료 버전)

### **취약점 찾기**

나중에 이메일은 **웹 로그인과 인증 서비스(예: SSH)를 brute-force**할 때 유용합니다. 또한 **피싱**에도 필요합니다. 더불어 이러한 API는 이메일을 사용하는 **사람에 대한 정보**도 더 많이 제공하므로 피싱 캠페인에 유용합니다.

## 자격 증명 유출

**도메인**, **서브도메인**, **이메일**을 확보했다면 해당 이메일과 관련해 과거에 유출된 자격 증명을 찾을 수 있습니다.

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **취약점 찾기**

**유효한 유출** 자격 증명을 찾았다면 아주 쉽게 성과를 거둘 수 있습니다.

## 비밀 정보 유출

자격 증명 유출은 **민감한 정보가 유출되어 판매된** 회사 해킹 사건과 관련이 있습니다. 하지만 회사는 해당 데이터베이스에 정보가 없는 **다른 유출 사건**의 영향을 받았을 수도 있습니다.

### Github 유출

회사의 **공개 저장소**나 해당 회사에서 일하는 **사용자**의 **공개 저장소**에서 자격 증명이나 API가 유출되었을 수 있습니다.\
[**Leakos**](https://github.com/carlospolop/Leakos) **도구**를 사용하면 **조직**과 개발자의 **공개 저장소**를 모두 **다운로드**한 다음 [**gitleaks**](https://github.com/gitleaks/gitleaks)를 자동으로 실행할 수 있습니다.

**Leakos**는 전달된 **URL**의 모든 **텍스트**에 대해 **gitleaks**를 실행하는 데도 사용할 수 있습니다. **웹 페이지에도 비밀 정보가 포함될 수 있기 때문입니다**.

#### Github Dorks

조직에서 검색할 만한 **GitHub dorks**는 [GitHub dorks 및 유출 페이지](github-leaked-secrets.md)를 확인하세요.

### Pastes 유출

때로는 공격자나 직원이 paste 사이트에 회사 콘텐츠를 **게시**하기도 합니다. 여기에 **민감한 정보**가 들어 있을 수도, 없을 수도 있지만 검색해 볼 가치는 충분합니다.\
[**Pastos**](https://github.com/carlospolop/Pastos) 도구를 사용하면 80개가 넘는 paste 사이트를 한 번에 검색할 수 있습니다.

### Google Dorks

오래됐지만 여전히 유용한 google dorks는 **노출되면 안 되는 정보**를 찾을 때 항상 도움이 됩니다. 다만 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)에는 수천 개의 검색어가 있어 수동으로 실행할 수 없다는 문제가 있습니다. 따라서 마음에 드는 검색어 10개를 골라 사용하거나, [**Gorks**](https://github.com/carlospolop/Gorks) **같은 도구를 사용해 모두 실행할 수 있습니다**.

_일반 Google 브라우저를 사용해 데이터베이스 전체를 실행하는 도구는 Google이 매우 빠르게 차단하기 때문에 끝까지 실행되지 않는다는 점에 유의하세요._

### **취약점 찾기**

**유효한 유출** 자격 증명이나 API 토큰을 찾았다면 아주 쉽게 성과를 거둘 수 있습니다.

## 공개 코드 취약점

회사가 **오픈소스 코드**를 보유한 것으로 확인되면 해당 코드를 **분석**해 **취약점**을 찾을 수 있습니다.

**언어에 따라** 사용할 수 있는 **도구**가 다릅니다. [소스 코드 리뷰 도구](../../network-services-pentesting/pentesting-web/code-review-tools.md) 목록을 확인하세요.

또한 다음과 같이 **공개 저장소를 스캔**할 수 있는 무료 서비스도 있습니다.

- [**Snyk**](https://app.snyk.io/)

## [**웹 Pentesting 방법론**](../../network-services-pentesting/pentesting-web/index.html)

bug hunter가 발견하는 **취약점 대부분**은 **웹 애플리케이션**에 있으므로, 여기서는 **웹 애플리케이션 테스트 방법론**을 소개하겠습니다. [**여기에서 자세한 정보를 확인할 수 있습니다**](../../network-services-pentesting/pentesting-web/index.html).

[**오픈소스 Web Automated Scanners 도구**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 섹션도 꼭 살펴보세요. 매우 민감한 취약점을 찾아낼 것으로 기대해서는 안 되지만, 초기 웹 정보를 얻기 위해 **워크플로에 포함하면 유용합니다.**

## 정리

> 축하합니다! 이제 기본적인 **열거 작업**을 모두 마쳤습니다. 물론 이건 기본 단계입니다. 훨씬 더 많은 열거 작업을 할 수 있으며, 뒤에서 더 많은 기술을 살펴보겠습니다.

지금까지 완료한 작업은 다음과 같습니다.

1. 범위 내에 있는 모든 **회사**를 찾았습니다.
2. 회사에 속한 모든 **자산**을 찾았습니다(범위에 포함된다면 취약점 스캔도 수행).
3. 회사에 속한 모든 **도메인**을 찾았습니다.
4. 도메인의 모든 **서브도메인**을 찾았습니다(서브도메인 takeover 가능성은 없나요?).
5. 범위 내의 모든 **IP**를 찾았습니다(**CDN** 소속 여부와 관계없이).
6. 모든 **웹 서버**를 찾아 스크린샷을 찍었습니다(더 자세히 살펴볼 만한 이상한 점은 없나요?).
7. 회사에 속한 잠재적인 **퍼블릭 클라우드 자산**을 모두 찾았습니다.
8. 쉽게 **큰 성과를 거둘 수 있는** **이메일**, **자격 증명 유출**, **비밀 정보 유출**을 확인했습니다.
9. 찾은 모든 웹사이트를 **Pentesting**했습니다.

## **전체 Recon 자동화 도구**

주어진 범위에서 제안한 작업의 일부를 수행해 주는 도구가 여러 가지 있습니다.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 다소 오래되어 업데이트되지 않았습니다



## References

- [1] [Jason Haddix – Bug Hunter의 방법론 v4.0: Recon 편](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon에 대하여: 브라우저 아이콘에서 Attack Surface Intelligence까지](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug Bounty, OSINT 등을 위해 favicon.ico를 무기화하기](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency에 대한 시간 상관관계 공격으로 도메인 찾기](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: 비용이 많이 드는 Subdomain Takeover 캠페인 발견 및 에뮬레이션](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: 독특한 Subdomain 열거 기법](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – 전체 서브도메인 검색 워크플로, 1부](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 자동화된 Trickest 워크플로로 전체 서브도메인 Brute Force 검색, 2부](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash 출력 스크린샷](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
