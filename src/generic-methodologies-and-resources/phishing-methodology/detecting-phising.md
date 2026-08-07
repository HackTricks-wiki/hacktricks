# Phishing 감지

{{#include ../../banners/hacktricks-training.md}}

## 소개

Phishing 시도를 감지하려면 **현재 사용되고 있는 phishing 기법을 이해하는 것**이 중요합니다. 이 게시물의 상위 페이지에서 관련 정보를 확인할 수 있으므로, 현재 어떤 기법이 사용되는지 잘 모른다면 상위 페이지로 이동하여 적어도 해당 섹션을 읽어보는 것을 권장합니다.

이 게시물은 **공격자가 어떤 방식으로든 피해자의 도메인 이름을 모방하거나 사용하려 한다**는 아이디어를 기반으로 합니다. 도메인이 `example.com`인데 어떤 이유로 `youwonthelottery.com`과 같이 완전히 다른 도메인 이름을 사용한 phishing을 당했다면, 이러한 기법으로는 이를 발견할 수 없습니다.

## 도메인 이름 변형

이메일 내부에서 **유사한 도메인** 이름을 사용하는 **phishing** 시도는 **발견하기가** 꽤 **쉽습니다**.\
공격자가 사용할 가능성이 가장 높은 phishing 이름의 목록을 **생성**한 다음, 해당 이름이 **등록되어 있는지 확인**하거나 이를 사용하는 **IP**가 있는지만 확인하면 충분합니다.

### 의심스러운 도메인 찾기

이 목적을 위해 다음 도구 중 하나를 사용할 수 있습니다. 이러한 도구는 도메인에 할당된 IP가 있는지 확인하기 위해 DNS 요청도 자동으로 수행한다는 점에 유의하세요.

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

팁: 후보 목록을 생성했다면 DNS resolver 로그에도 입력하여 **조직 내부에서 발생하는 NXDOMAIN 조회**(공격자가 실제로 해당 도메인을 등록하기 전에 사용자가 오타가 난 도메인에 접속하려는 시도)를 감지하세요. 정책에서 허용한다면 이러한 도메인을 Sinkhole 처리하거나 사전에 차단하세요.

### Bitflipping

**이 기법에 대한 간단한 설명은 상위 페이지에서 확인할 수 있습니다. 또는 원본 연구는** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>**에서 읽을 수 있습니다.**

예를 들어, microsoft.com 도메인에서 1비트를 수정하면 _windnws.com._으로 변환될 수 있습니다.\
**공격자는 합법적인 사용자를 자신의 인프라로 리디렉션하기 위해 피해자와 관련된 가능한 한 많은 bit-flipping 도메인을 등록할 수 있습니다**.<sup>[[1]](#references)</sup>

**가능한 모든 bit-flipping 도메인 이름도 모니터링해야 합니다.**

homoglyph/IDN lookalike(예: Latin/Cyrillic 문자 혼합)도 고려해야 한다면 다음을 확인하세요.

{{#ref}}
homograph-attacks.md
{{#endref}}

### 기본 확인

잠재적으로 의심스러운 도메인 이름 목록을 확보했다면 해당 도메인을 **확인**하여(주로 HTTP 및 HTTPS 포트) 피해자 도메인의 로그인 양식과 유사한 **로그인 양식을 사용하고 있는지 확인**해야 합니다.\
포트 3333이 열려 있고 `gophish` 인스턴스를 실행 중인지 확인할 수도 있습니다.\
**발견된 각 의심스러운 도메인이 얼마나 오래되었는지** 확인하는 것도 유용합니다. 도메인이 새것일수록 위험성이 높습니다.\
의심스러운 HTTP 및/또는 HTTPS 웹 페이지의 **스크린샷**을 가져와 의심스러운지 확인하고, 그런 경우 **접속하여 더 자세히 살펴볼** 수도 있습니다.

### 고급 확인

한 단계 더 나아가고 싶다면 **이러한 의심스러운 도메인을 모니터링하고 가끔씩 더 많은 도메인을 검색**하는 것을 권장합니다(매일? 몇 초/몇 분밖에 걸리지 않습니다). 또한 관련 IP의 열린 **포트**를 **확인**하고 **`gophish` 또는 유사한 도구의 인스턴스를 검색**해야 합니다(예, 공격자도 실수합니다). 그리고 **의심스러운 도메인 및 서브도메인의 HTTP 및 HTTPS 웹 페이지를 모니터링**하여 피해자의 웹 페이지에서 로그인 양식을 복사했는지 확인해야 합니다.\
이를 **자동화**하려면 피해자 도메인의 로그인 양식 목록을 준비하고, 의심스러운 웹 페이지를 spider한 다음, `ssdeep`과 같은 도구를 사용하여 의심스러운 도메인에서 발견된 각 로그인 양식을 피해자 도메인의 각 로그인 양식과 비교하는 것을 권장합니다.\
의심스러운 도메인의 로그인 양식을 찾았다면 **임의의 자격 증명을 전송**하고 **피해자 도메인으로 리디렉션되는지 확인**해 볼 수 있습니다.

---

### favicon 및 웹 fingerprint를 사용한 Hunting (Shodan/ZoomEye/Censys)

많은 phishing kit은 사칭하는 브랜드의 favicon을 재사용합니다. Internet-wide scanner는 base64로 인코딩된 favicon의 MurmurHash3를 계산합니다. hash를 생성하고 이를 기준으로 pivot할 수 있습니다.

Python 예제(mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan 쿼리: `http.favicon.hash:309020573`
- Tooling 사용: favfreak와 같은 community tools를 사용해 Shodan/ZoomEye/Censys용 hashes와 dorks를 생성합니다.

Notes
- Favicons는 재사용됩니다. 일치 결과를 단서로 취급하고, 조치를 취하기 전에 콘텐츠와 certs를 검증하세요.
- 더 높은 precision을 위해 domain-age 및 keyword heuristics와 결합하세요.

### URL telemetry hunting (urlscan.io)

`urlscan.io`는 제출된 URL의 과거 screenshots, DOM, requests 및 TLS metadata를 저장합니다. 이를 사용해 brand abuse와 clones를 hunting할 수 있습니다:<sup>[[2]](#references)</sup>

Example queries (UI 또는 API):
- 합법적인 domains를 제외한 lookalikes 찾기: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- assets를 hotlink하는 sites 찾기: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 최근 results로 제한하기: `AND date:>now-7d` 추가

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON에서 다음 항목을 기준으로 피벗합니다:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`를 사용해 유사 도메인에 사용된 매우 최근 인증서를 식별합니다.
- `certstream-suspicious`와 같은 `task.source` 값을 사용해 결과를 CT monitoring과 연결합니다.

### RDAP를 통한 도메인 연령 확인 (스크립트로 처리 가능)

RDAP는 기계가 읽을 수 있는 생성 이벤트를 반환합니다. **최근 등록된 도메인(newly registered domains, NRDs)**을 식별하는 데 유용합니다.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
파이프라인을 개선하려면 도메인을 등록 기간별 구간(예: <7일, <30일)으로 태깅하고 그에 따라 triage 우선순위를 지정하세요.

### AiTM 인프라를 식별하기 위한 TLS/JAx fingerprints

Modern credential-phishing increasingly uses **Adversary-in-the-Middle (AiTM)** reverse proxies (예: Evilginx)를 사용해 session token을 탈취합니다. 다음과 같은 네트워크 측 탐지 기능을 추가할 수 있습니다.

- egress에서 TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H)를 기록하세요. 일부 Evilginx 빌드에서는 안정적인 JA4 client/server 값이 관찰되었습니다. 알려진 악성 fingerprint에 대해서만 약한 신호로 alert를 생성하고, 항상 content 및 domain intel로 확인하세요.<sup>[[3]](#references)</sup>
- CT 또는 urlscan에서 발견된 lookalike host에 대해 TLS certificate metadata (issuer, SAN count, wildcard 사용 여부, validity)를 사전에 기록하고 DNS age 및 geolocation과 상관 분석하세요.

> 참고: fingerprint는 단독 차단 기준이 아니라 enrichment로 취급하세요. framework는 발전하며 fingerprint를 randomise하거나 obfuscate할 수 있습니다.

### 키워드를 사용하는 도메인 이름

상위 페이지에서는 **victim의 domain name을 더 큰 domain 안에 넣는** domain name variation technique도 언급합니다(예: paypal.com에 대한 paypal-financial.com).

#### Certificate Transparency

이전의 "Brute-Force" 접근 방식을 사용할 수는 없지만, Certificate Transparency 덕분에 이러한 phishing 시도를 **찾아내는 것이 실제로 가능합니다**. CA가 certificate를 발급할 때마다 세부 정보가 공개됩니다. 즉, Certificate Transparency를 읽거나 모니터링하면 **이름에 특정 keyword를 사용하는 domain을 찾을 수 있습니다**. 예를 들어 attacker가 [https://paypal-financial.com](https://paypal-financial.com)의 certificate를 생성하면 certificate를 확인하여 "paypal" keyword를 찾고 해당 suspicious email이 사용되고 있음을 알 수 있습니다.

[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) 게시물에서는 Censys를 사용해 특정 keyword에 영향을 받는 certificate를 검색하고 날짜(“new” certificate만) 및 CA issuer “Let's Encrypt”로 필터링할 수 있다고 설명합니다:<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

하지만 무료 웹 서비스인 [**crt.sh**](https://crt.sh)를 사용해 "동일한" 작업을 수행할 수 있습니다. **keyword를 검색**하고 원하는 경우 결과를 **날짜 및 CA별로 필터링**할 수 있습니다.

![키워드를 사용하는 도메인 이름 - Certificate Transparency: 하지만 무료 웹 서비스인 crt.sh를 사용해 "동일한" 작업을 수행할 수 있습니다. keyword를 검색하고 결과를 날짜 및...](<../../images/image (519).png>)

이 마지막 옵션을 사용하면 Matching Identities 필드에서 실제 domain의 identity가 suspicious domain과 일치하는지 확인할 수도 있습니다(suspicious domain이 false positive일 수 있다는 점에 유의하세요).

**또 다른 대안**은 [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)이라는 훌륭한 project입니다. CertStream은 새로 생성된 certificate의 real-time stream을 제공하며, 이를 사용해 (거의) real-time으로 지정된 keyword가 포함된 certificate를 탐지할 수 있습니다. 실제로 이를 수행하는 [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) project가 있습니다.

실용적인 팁: CT hit를 triage할 때 NRD, 신뢰할 수 없거나 알려지지 않은 registrar, privacy-proxy WHOIS, 그리고 매우 최근의 `NotBefore` 시간을 가진 cert를 우선 처리하세요. noise를 줄이기 위해 소유한 domain/brand의 allowlist를 유지하세요.

#### **새로운 도메인**

**마지막 대안**은 일부 TLD의 **새로 등록된 domain 목록**을 수집하고([Whoxy](https://www.whoxy.com/newly-registered-domains/)에서 이러한 서비스를 제공함) **해당 domain의 keyword를 확인**하는 것입니다. 하지만 긴 domain은 일반적으로 하나 이상의 subdomain을 사용하므로 keyword가 FLD 내부에 나타나지 않고 phishing subdomain을 찾을 수 없습니다.

추가 heuristic: 특정 **file-extension TLD**(예: `.zip`, `.mov`)는 alerting 시 더욱 의심스럽게 처리하세요. 이러한 TLD는 lure에서 filename으로 혼동되는 경우가 많으므로, 더 높은 정밀도를 위해 TLD signal을 brand keyword 및 NRD age와 결합하세요.

## 참고 자료

- [1] [bitflipping을 사용하여 Microsoft의 windows.com traffic hijacking](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io - Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog - JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Phishing 찾기: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
