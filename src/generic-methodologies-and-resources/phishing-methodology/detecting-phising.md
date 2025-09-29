# 피싱 탐지

{{#include ../../banners/hacktricks-training.md}}

## 소개

피싱 시도를 탐지하려면 **오늘날 사용되는 피싱 기술들을 이해하는 것**이 중요합니다. 이 게시물의 상위 페이지에서 해당 정보를 찾을 수 있으므로, 현재 어떤 기술이 사용되는지 모른다면 상위 페이지로 가서 적어도 그 섹션을 읽어보시길 권합니다.

이 게시물은 **공격자가 피해자의 도메인 이름을 어떻게든 모방하거나 사용할 것**이라는 아이디어에 기반합니다. 만약 여러분의 도메인이 `example.com`이고 공격자가 어떤 이유로 완전히 다른 도메인 이름(`youwonthelottery.com`)을 사용해 피싱을 시도했다면, 아래 기술들은 이를 밝혀내지 못할 수 있습니다.

## 도메인 이름 변형

이메일 내부에서 **유사한 도메인**을 사용하는 피싱 시도는 찾아내기 **상당히 쉽습니다**.\
공격자가 사용할 가능성이 높은 피싱 이름들의 목록을 **생성**하고, 해당 도메인이 **등록되어 있는지** 또는 어떤 **IP**에 사용되고 있는지 확인하면 됩니다.

### 의심스러운 도메인 찾기

이를 위해 다음 도구들 중 하나를 사용할 수 있습니다. 이 도구들은 도메인에 할당된 IP가 있는지 확인하기 위해 자동으로 DNS 요청도 수행합니다:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

팁: 후보 목록을 생성했다면 DNS 리졸버 로그에 투입하여 조직 내부에서의 **NXDOMAIN lookups**(사용자가 공격자가 실제로 등록하기 전에 오타 도메인에 접속을 시도함)을 탐지하세요. 정책이 허용한다면 이러한 도메인을 Sinkhole 또는 사전 차단하세요.

### Bitflipping

**이 기술에 대한 짧은 설명은 상위 페이지에서 확인할 수 있습니다. 또는 원본 연구를 읽어보세요:** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

예를 들어, 도메인 microsoft.com에서 1비트만 변경하면 _windnws.com._으로 변할 수 있습니다.\
**공격자들은 피해자와 관련된 가능한 한 많은 bit-flipping 도메인을 등록하여 정당한 사용자를 자신의 인프라로 리디렉션할 수 있습니다.**

**모든 가능한 bit-flipping 도메인 이름도 모니터링해야 합니다.**

동일문자(예: Latin/Cyrillic 혼합) 기반의 homoglyph/IDN lookalikes도 고려해야 한다면, 다음을 확인하세요:

{{#ref}}
homograph-attacks.md
{{#endref}}

### 기본 검사

잠재적으로 의심스러운 도메인 목록을 확보했다면 해당 도메인들을 **확인**해야 합니다(주로 HTTP 및 HTTPS 포트). 이는 해당 도메인들이 피해자 도메인의 로그인 폼과 **유사한 로그인 폼을 사용하고 있는지** 확인하기 위함입니다.\
포트 3333이 열려 있고 `gophish` 인스턴스가 실행 중인지도 확인할 수 있습니다.\
발견된 의심 도메인들이 **언제 생성되었는지(등록 연월)** 아는 것도 흥미로운데, 생성일이 최신일수록 위험이 큽니다.\
의심스러운 HTTP 및/또는 HTTPS 웹페이지의 **스크린샷**을 받아 보고 의심스러우면 **접속하여 더 자세히 조사**하세요.

### 고급 검사

한 단계 더 나아가려면 의심스러운 도메인들을 주기적으로(매일?) **모니터링하고 추가로 검색**할 것을 권합니다(소요 시간은 몇 초/분에 불과합니다). 관련 IP의 열린 **포트**를 확인하고 `gophish` 또는 유사 도구의 인스턴스 존재 여부를 **검색**하세요(네, 공격자들도 실수를 합니다). 또한 의심 도메인 및 서브도메인의 HTTP 및 HTTPS 웹페이지를 모니터링하여 피해자의 웹페이지에서 복제한 로그인 폼이 있는지 확인하세요.\
이를 **자동화**하려면 피해자 도메인의 로그인 폼 목록을 보유하고, 의심스러운 웹페이지를 크롤링하여 발견된 각 로그인 폼을 `ssdeep` 같은 도구로 피해자 도메인의 각 로그인 폼과 비교하는 방식을 권장합니다.\
의심 도메인의 로그인 폼을 찾았다면, **임의의(쓸데없는) 자격증명(junk credentials)을 전송**해 보고 **피해자 도메인으로 리디렉션되는지** 확인할 수 있습니다.

---

### favicon 및 웹 지문으로 헌팅하기 (Shodan/ZoomEye/Censys)

많은 피싱 키트는 사칭하는 브랜드의 favicon을 재사용합니다. 인터넷 전체 스캐너는 base64로 인코딩된 favicon의 MurmurHash3를 계산합니다. 해시를 생성하고 이를 기반으로 피벗할 수 있습니다:

Python 예제 (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan 쿼리: `http.favicon.hash:309020573`
- 도구 사용: favfreak 같은 커뮤니티 도구를 확인하여 Shodan/ZoomEye/Censys용 hashes 및 dorks를 생성하세요.

Notes
- Favicons은 재사용됩니다; 일치 항목을 단서로 취급하고 조치하기 전에 콘텐츠와 certs를 검증하세요.
- 더 높은 정확도를 위해 domain-age 및 keyword heuristics와 결합하세요.

### URL 텔레메트리 헌팅 (urlscan.io)

`urlscan.io`는 제출된 URL의 과거 스크린샷, DOM, 요청 및 TLS 메타데이터를 저장합니다. 브랜드 남용 및 클론을 찾아낼 수 있습니다:

Example queries (UI or API):
- 정식 도메인을 제외한 유사 사이트 찾기: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 자산을 hotlinking하는 사이트 찾기: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 최근 결과로 제한: `AND date:>now-7d`를 덧붙이세요

API 예시:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON에서 pivot할 항목:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` — 유사 도메인 탐지를 위해 매우 새로 발급된 인증서를 찾아보세요
- `task.source` 값(예: `certstream-suspicious`) — 발견을 CT 모니터링과 연계하는 데 사용

### RDAP로 도메인 연령 확인 (스크립트 가능)

RDAP는 기계 판독 가능한 생성 이벤트를 반환합니다. **새로 등록된 도메인 (NRDs)** 를 표시하는 데 유용합니다.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
파이프라인을 보강하려면 도메인을 등록 연령 구간(예: <7 days, <30 days)으로 태그하고 트리아지 우선순위를 조정하세요.

### TLS/JAx fingerprints로 AiTM 인프라 탐지

Modern credential-phishing은 세션 토큰 탈취를 위해 **Adversary-in-the-Middle (AiTM)** 리버스 프록시(예: Evilginx)를 점점 더 많이 사용합니다. 네트워크 측 탐지를 추가할 수 있습니다:

- Egress에서 TLS/HTTP 지문(JA3/JA4/JA4S/JA4H)을 로그하세요. 일부 Evilginx 빌드에서는 안정적인 JA4 클라이언트/서버 값이 관찰되었습니다. 알려진 악성 지문에 대해서만 약한 신호로 경보를 설정하고 항상 콘텐츠 및 domain intel로 확인하세요.
- CT 또는 urlscan을 통해 발견된 유사 호스트에 대해 TLS certificate metadata(issuer, SAN count, wildcard 사용 여부, validity)를 선제적으로 기록하고 DNS age 및 지리적 위치와 상관관계를 분석하세요.

> Note: 지문을 enrichment로 취급하고 단독 차단 근거로 보지 마세요; 프레임워크는 진화하며 무작위화하거나 난독화할 수 있습니다.

### Domain names using keywords

상위 페이지는 또한 **victim's domain name inside a bigger domain** 기법을 언급합니다(예: paypal-financial.com은 paypal.com을 겨냥).

#### Certificate Transparency

이전의 "Brute-Force" 접근법은 불가능할 수 있지만, Certificate Transparency 덕분에 이러한 피싱 시도를 찾아내는 것이 실제로 가능합니다. CA가 인증서를 발행할 때마다 세부 정보가 공개됩니다. 즉, certificate transparency를 읽거나 모니터링하면 이름 안에 키워드를 포함한 도메인을 찾아낼 수 있습니다. 예를 들어 공격자가 [https://paypal-financial.com](https://paypal-financial.com)의 인증서를 생성하면, 인증서를 통해 "paypal"이라는 키워드를 찾아 의심스러운 사용을 확인할 수 있습니다.

게시물 [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)은 Censys를 사용해 특정 키워드가 포함된 인증서를 검색하고 날짜(신규 인증서만)와 CA 발급자("Let's Encrypt")로 필터링할 수 있다고 제안합니다:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

그러나 무료 웹 **crt.sh**를 사용해도 "동일한" 작업을 수행할 수 있습니다. 키워드를 검색하고 원하면 결과를 날짜와 CA로 필터링할 수 있습니다.

![](<../../images/image (519).png>)

이 마지막 옵션을 사용하면 Matching Identities 필드를 이용해 실제 도메인의 어떤 identity가 의심 도메인과 일치하는지 확인할 수 있습니다(의심 도메인은 false positive일 수 있음에 유의).

**Another alternative**는 [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)이라는 훌륭한 프로젝트입니다. CertStream은 새로 생성된 인증서의 실시간 스트림을 제공하며, 이를 이용해 지정한 키워드를 (거의) 실시간으로 탐지할 수 있습니다. 실제로 [**phishing_catcher**](https://github.com/x0rz/phishing_catcher)라는 프로젝트가 바로 이를 수행합니다.

실용 팁: CT 히트를 트리아지할 때는 NRDs, 신뢰되지 않거나 알 수 없는 레지스트라, privacy-proxy WHOIS, `NotBefore` 시간이 매우 최근인 인증서를 우선순위로 두세요. 소음을 줄이려면 소유한 도메인/브랜드의 allowlist를 유지하세요.

#### **New domains**

**One last alternative**는 일부 TLD에 대해 **newly registered domains** 목록을 수집하는 것입니다([Whoxy](https://www.whoxy.com/newly-registered-domains/)가 이런 서비스를 제공합니다) 그리고 이러한 도메인에서 키워드를 확인하세요. 다만, 긴 도메인은 보통 하나 이상의 서브도메인을 사용하므로 키워드가 FLD 안에 나타나지 않아 피싱 서브도메인을 찾지 못할 수 있습니다.

추가 휴리스틱: 특정 **file-extension TLDs**(예: `.zip`, `.mov`)는 경보 시 추가 의심 대상으로 처리하세요. 이는 미끼에서 파일명으로 혼동되는 경우가 많으므로 TLD 신호를 브랜드 키워드 및 NRD age와 결합하면 정확도를 높일 수 있습니다.

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
