# 피싱 탐지

{{#include ../../banners/hacktricks-training.md}}

## 소개

피싱 시도를 탐지하려면 **요즘 사용되는 피싱 기법을 이해하는 것이 중요합니다**. 이 글의 상위 페이지에서 관련 정보를 확인할 수 있습니다. 오늘날 어떤 기법이 사용되는지 잘 모른다면 상위 페이지로 이동해 적어도 해당 섹션을 읽어보시기 바랍니다.

이 글은 **공격자가 어떻게든 피해자의 도메인 이름을 흉내 내거나 사용하려 한다**는 생각을 바탕으로 합니다. 여러분의 도메인이 `example.com`인데, 어떤 이유로 `youwonthelottery.com`처럼 완전히 다른 도메인 이름을 사용하는 피싱을 당했다면 이 기법으로는 찾아낼 수 없습니다.

## 도메인 이름 변형

이메일에서 **유사한 도메인** 이름을 사용하는 **피싱** 시도는 **찾아내기**가 꽤 **쉽습니다**.\
공격자가 사용할 가능성이 가장 높은 피싱 이름 목록을 **생성**한 다음, 해당 이름이 **등록**되어 있는지 확인하거나 이를 사용하는 **IP**가 있는지만 확인하면 됩니다.

### 의심스러운 도메인 찾기

이 목적에는 다음 도구 중 하나를 사용할 수 있습니다. 두 도구 모두 후보 도메인을 조회해 실제로 사용 중인지 확인합니다.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

팁: 후보 목록을 생성했다면 DNS resolver 로그에도 대조해 **조직 내부에서 발생하는 NXDOMAIN 조회**(공격자가 도메인을 실제로 등록하기 전에 사용자가 오타가 포함된 주소로 접속하려는 시도)를 탐지하세요. 정책에서 허용한다면 해당 도메인을 sinkhole 처리하거나 사전에 차단하세요.

### 비트 플리핑

**간단한 설명은 상위 페이지를 참고하세요. Windows.com bit squatting에 관한 1차 연구는 [Remy Hax의 글](https://remyhax.xyz/posts/bitsquatting-windows/)과 [BleepingComputer의 보도](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)를 참고하세요**.<sup>[[1]](#references)[[2]](#references)</sup>

예를 들어, microsoft.com에서 비트 하나를 변경하면 _windnws.com._으로 바뀔 수 있습니다.\
**공격자는 피해자와 관련된 비트 플리핑 도메인을 가능한 한 많이 등록해 정상 사용자를 자신들의 인프라로 리디렉션할 수 있습니다**.<sup>[[1]](#references)[[2]](#references)</sup>

**가능한 모든 비트 플리핑 도메인 이름도 모니터링해야 합니다.**

혼동하기 쉬운 동형 문자/homoglyph 또는 IDN 도메인(예: 라틴 문자와 키릴 문자의 혼용)도 고려해야 한다면 다음을 확인하세요.

{{#ref}}
homograph-attacks.md
{{#endref}}

### 기본 검사

의심스러운 도메인 후보 목록을 확보했다면 해당 도메인을 검사해(주로 HTTP 및 HTTPS 포트) 피해자 도메인의 로그인 양식과 유사한 양식을 사용하는지 **확인해야 합니다**.\
또한 포트 3333이 열려 있고 `gophish` 인스턴스가 실행 중인지 확인할 수도 있습니다.\
발견된 의심 도메인이 얼마나 오래되었는지 알아보는 것도 유용합니다. 도메인이 새것일수록 위험성이 높습니다.\
HTTP 및/또는 HTTPS의 의심스러운 웹 페이지를 **스크린샷**으로 남겨 의심스러운지 확인할 수도 있습니다. 의심스러운 경우에는 **접속해 더 자세히 살펴보세요**.

### 고급 검사

한 단계 더 나아가려면 의심스러운 도메인을 **모니터링하고 주기적으로 새로운 도메인을 찾는 것**을 권장합니다(매일 확인해도 좋습니다. 몇 초 또는 몇 분이면 충분합니다). 관련 IP의 열린 **포트**도 **확인**하고, **`gophish` 또는 유사 도구의 인스턴스를 찾으세요**(네, 공격자도 실수합니다). 또한 의심스러운 도메인 및 하위 도메인의 HTTP 및 HTTPS 웹 페이지를 **모니터링해 피해자의 웹 페이지에서 로그인 양식을 복사했는지 확인하세요**.\
이를 **자동화**하려면 피해자 도메인의 로그인 양식 목록을 준비하고, 의심스러운 웹 페이지를 spider한 다음, 의심스러운 도메인에서 발견된 각 로그인 양식을 피해자 도메인의 각 로그인 양식과 `ssdeep` 같은 도구로 비교하는 방법을 권장합니다.\
의심스러운 도메인의 로그인 양식을 찾았다면 **가짜 자격 증명을 전송**하고 **피해자 도메인으로 리디렉션되는지 확인**할 수 있습니다.

---

### favicon 및 웹 지문을 이용한 탐색 (Shodan/Censys)

많은 피싱 키트가 사칭하는 브랜드의 favicon을 재사용합니다. Shodan은 base64로 인코딩된 favicon 데이터를 MurmurHash3로 해시하며, Censys는 자체 favicon 해시 필드를 제공합니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan과 호환되는 해시를 생성해 이를 기준으로 검색 범위를 좁힐 수 있습니다.

Python 예제 (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Shodan에서 검색: `http.favicon.hash:309020573`
- 도구 사용: 해시를 계산하고 Shodan dorks를 생성하려면 favfreak 같은 커뮤니티 도구를 살펴보세요.<sup>[[16]](#references)</sup>

참고
- 파비콘은 재사용되므로 일치 항목은 단서로만 취급하고, 조치를 취하기 전에 콘텐츠와 인증서를 검증하세요.
- 정확도를 높이려면 도메인 생성 시점 및 키워드 휴리스틱과 결합하세요.

### URL 텔레메트리 헌팅 (urlscan.io)

`urlscan.io`는 제출된 URL의 과거 스크린샷, DOM, 요청 및 TLS 메타데이터를 저장합니다. 브랜드 도용 및 복제 사이트를 헌팅할 수 있습니다:<sup>[[8]](#references)</sup>

쿼리 예시 (UI 또는 API):
- 합법적인 도메인을 제외하고 유사 도메인 찾기: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 에셋을 핫링크하는 사이트 찾기: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 최근 결과로 제한하기: `AND date:>now-7d` 추가

API 예시:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

JSON에서 다음 항목을 기준으로 살펴봅니다.
- lookalike에 사용된 지 얼마 안 된 인증서를 찾으려면 `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`
- CT monitoring 결과와 연결하려면 `certstream-suspicious` 같은 `task.source` 값

### RDAP를 통한 도메인 생성 시기 확인 (스크립트 사용 가능)

RDAP는 기계가 읽을 수 있는 등록 이벤트를 반환합니다. **신규 등록 도메인(NRD)**을 표시하는 데 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

등록 연령 구간(예: <7일, <30일)을 기준으로 도메인에 태그를 지정해 파이프라인을 보강하고, 이에 따라 트리아지 우선순위를 정하세요.

### AiTM 인프라를 찾기 위한 TLS/JAx fingerprints

자격 증명 피싱은 세션 토큰을 탈취하기 위해 **Adversary-in-the-Middle (AiTM)** reverse proxy(예: Evilginx)를 사용할 수 있습니다.<sup>[[11]](#references)</sup> 네트워크 측 탐지를 추가할 수 있습니다.

- 송신 트래픽의 TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H)를 기록하세요. 일부 Evilginx 빌드에서는 안정적인 JA4 클라이언트/서버 값이 관찰된 바 있습니다. 알려진 악성 fingerprints만 약한 신호로 간주해 경고하고, 항상 콘텐츠 및 도메인 인텔리전스로 확인하세요.<sup>[[12]](#references)</sup>
- CT 또는 urlscan에서 발견한 유사 도메인 호스트의 TLS certificate metadata(issuer, SAN 개수, wildcard 사용 여부, 유효 기간)를 사전에 기록하고 DNS age 및 geolocation과 연관 분석하세요.

> 참고: fingerprints는 차단의 유일한 기준이 아니라 보강 정보로 취급하세요. 프레임워크는 진화하며 fingerprint를 무작위화하거나 난독화할 수 있습니다.

### 키워드를 사용하는 도메인 이름

상위 페이지에서는 **피해자 도메인 이름을 더 큰 도메인 안에 넣는** 도메인 이름 변형 기법도 언급합니다(예: paypal.com을 사칭하는 paypal-financial.com).

#### Certificate Transparency

Certificate Transparency (CT) 로그에는 인증서 식별 정보가 노출되므로, Subject 또는 SAN 이름에서 브랜드 키워드를 검색하면 유사 도메인을 찾을 수 있습니다(예를 들어 `paypal-financial.com` 인증서에는 `paypal` 키워드가 표시됩니다). 필요하면 발급 날짜와 CA로 결과를 필터링하고, 키워드 일치는 오탐일 수 있으므로 후보를 검증하세요.<sup>[[13]](#references)</sup>

Patrik Hudak의 원본 [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/)에서는 Censys에서 인증서 날짜 및 Let's Encrypt와 같은 issuer 필터를 사용해 이 워크플로를 보여줍니다.<sup>[[13]](#references)</sup>

![유사 도메인을 식별하는 데 사용된 Censys 인증서 검색 결과](<../../images/image (1115).png>)

무료 서비스인 [**crt.sh**](https://crt.sh)에서도 키워드를 검색하고 날짜 및 CA로 결과를 필터링할 수 있습니다.<sup>[[13]](#references)</sup>

![의심스러운 인증서 식별 정보를 검색하는 crt.sh 키워드 검색](<../../images/image (519).png>)

Matching Identities 필드를 사용하면 실제 도메인과 의심 도메인의 식별 정보를 비교할 수 있지만, 일치 결과는 증거가 아니라 추가 조사 단서로 취급하세요.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)은 CT 업데이트를 거의 실시간으로 스트리밍하며, [*phishing_catcher*](https://github.com/x0rz/phishing_catcher)는 해당 스트림을 사용해 의심스러운 인증서 이름에 점수를 매깁니다.<sup>[[14]](#references)[[15]](#references)</sup>

실용적인 팁: CT 결과를 트리아지할 때 NRD, 신뢰할 수 없거나 알려지지 않은 registrar, privacy-proxy WHOIS, 그리고 `NotBefore` 시간이 매우 최근인 인증서를 우선 처리하세요. 오탐을 줄이기 위해 소유한 도메인/브랜드의 allowlist를 유지하세요.

#### **새 도메인**

두 번째 방법은 TLD별로 새로 등록된 도메인을 수집한 다음(예: [Whoxy](https://www.whoxy.com/newly-registered-domains/) 이용) 브랜드 키워드로 필터링하는 것입니다. 등록 도메인에 키워드가 없으면 하위 도메인에서 호스팅되는 피싱을 놓칠 수 있습니다.<sup>[[13]](#references)</sup>

추가 휴리스틱: 특정 **파일 확장자 형태의 TLD**(예: `.zip`, `.mov`)는 경고 시 더욱 의심스럽게 취급하세요. 이러한 TLD는 피싱 유도 문구에서 파일 이름으로 흔히 오인됩니다. 정확도를 높이려면 TLD 신호를 브랜드 키워드 및 NRD age와 함께 사용하세요.

## References

- [1] [Remy Hax – Windows.com 비트스쿼팅](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [비트 플리핑으로 Microsoft의 windows.com 트래픽 하이재킹하기](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [심층 분석: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 문서](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API 참조](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol 도움말](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol용 JSON 응답](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [토큰 전술: cloud token theft를 예방, 탐지 및 대응하는 방법](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ 네트워크 fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – 피싱 찾기: 도구와 기법](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream 소개](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
