# Phishing 탐지

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Phishing 시도를 탐지하려면 **오늘날 사용되는 Phishing 기법을 이해하는 것**이 중요합니다. 이 게시물의 상위 페이지에서 관련 정보를 확인할 수 있으므로, 현재 사용되는 기법을 잘 모른다면 상위 페이지로 이동하여 최소한 해당 섹션을 읽어보는 것을 권장합니다.

이 게시물은 **공격자가 어떤 방식으로든 피해자의 도메인 이름을 모방하거나 사용하려고 한다**는 전제를 기반으로 합니다. 도메인이 `example.com`인데 어떤 이유로 `youwonthelottery.com`과 같이 완전히 다른 도메인 이름을 사용한 Phishing을 당한 경우에는 이러한 기법으로 발견할 수 없습니다.

## 도메인 이름 변형

이메일 내부에서 **유사한 도메인** 이름을 사용하는 **Phishing** 시도를 **발견**하는 것은 꽤 **쉽습니다**.\
공격자가 사용할 가능성이 가장 높은 **Phishing 이름 목록을 생성**한 다음, 해당 이름이 **등록되어 있는지 확인**하거나 이를 사용하는 **IP**가 있는지 확인하면 충분합니다.

### 의심스러운 도메인 찾기

이 목적을 위해 다음 도구 중 하나를 사용할 수 있습니다. 두 도구 모두 후보 도메인을 resolve하여 사용 중인지 확인합니다.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

팁: 후보 목록을 생성했다면 이를 DNS resolver 로그에도 입력하여 **조직 내부에서 발생하는 NXDOMAIN 조회**(공격자가 실제로 등록하기 전에 사용자가 오타가 난 도메인에 접속하려는 시도)를 탐지하세요. 정책이 허용한다면 이러한 도메인을 Sinkhole 처리하거나 사전에 차단하세요.

### Bitflipping

**간단한 설명은 상위 페이지를 참조하고, Windows.com을 대상으로 한 주요 bitsquatting 연구는 [Remy Hax의 write-up](https://remyhax.xyz/posts/bitsquatting-windows/)과 [BleepingComputer의 보고서](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)를 참조하세요**.<sup>[[1]](#references)[[2]](#references)</sup>

예를 들어 도메인 microsoft.com에서 1 bit를 수정하면 _windnws.com._으로 변환할 수 있습니다.\
**공격자는 합법적인 사용자를 자신의 infrastructure로 redirect하기 위해 피해자와 관련된 가능한 많은 bit-flipping 도메인을 등록할 수 있습니다**.<sup>[[1]](#references)[[2]](#references)</sup>

**가능한 모든 bit-flipping 도메인 이름도 모니터링해야 합니다.**

homoglyph/IDN lookalike도 고려해야 한다면(예: Latin/Cyrillic 문자 혼합) 다음을 확인하세요.

{{#ref}}
homograph-attacks.md
{{#endref}}

### 기본 확인

잠재적으로 의심스러운 도메인 이름 목록을 확보했다면 해당 도메인(주로 HTTP 및 HTTPS 포트)을 **확인**하여 피해자 도메인의 로그인 form과 **유사한 로그인 form을 사용하는지 확인**해야 합니다.\
포트 3333이 열려 있고 `gophish` 인스턴스가 실행 중인지 확인할 수도 있습니다.\
**발견된 각각의 의심스러운 도메인이 얼마나 오래되었는지** 확인하는 것도 중요합니다. 생성된 지 얼마 되지 않은 도메인일수록 위험성이 높습니다.\
의심스러운 HTTP 및/또는 HTTPS 웹 페이지의 **스크린샷**을 가져와 의심스러운지 확인하고, 의심스러운 경우 **접속하여 더 자세히 살펴볼** 수도 있습니다.

### 고급 확인

한 단계 더 나아가려면 **해당 의심스러운 도메인을 모니터링하고 주기적으로 더 많은 도메인을 검색**하는 것을 권장합니다(매일? 몇 초 또는 몇 분밖에 걸리지 않습니다). 또한 관련 IP의 열린 **포트**를 **확인**하고 **`gophish` 또는 유사한 도구의 인스턴스를 검색**해야 합니다(공격자도 실수하기 때문입니다). 그리고 **의심스러운 도메인 및 subdomain의 HTTP 및 HTTPS 웹 페이지를 모니터링**하여 피해자의 웹 페이지에서 로그인 form을 복사했는지 확인해야 합니다.\
이를 **자동화**하려면 피해자 도메인의 로그인 form 목록을 보유하고, 의심스러운 웹 페이지를 spidering한 다음, `ssdeep`과 같은 도구를 사용하여 의심스러운 도메인 내부에서 발견된 각 로그인 form을 피해자 도메인의 각 로그인 form과 비교하는 것을 권장합니다.\
의심스러운 도메인의 로그인 form을 찾았다면 **임의의 credentials를 전송**하고 **피해자 도메인으로 redirect되는지 확인**해 볼 수 있습니다.

---

### favicon 및 web fingerprint를 사용한 Hunting (Shodan/Censys)

많은 Phishing kit은 사칭하는 브랜드의 favicon을 재사용합니다. Shodan은 base64로 인코딩된 favicon 데이터를 MurmurHash3로 hash하는 반면, Censys는 자체 favicon hash field를 노출합니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan 호환 hash를 생성하고 이를 기준으로 pivot할 수 있습니다.

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan 쿼리: `http.favicon.hash:309020573`
- Tooling 사용: favfreak와 같은 community tools를 확인하여 해시를 계산하고 Shodan dorks를 생성합니다.<sup>[[16]](#references)</sup>

참고
- Favicon은 재사용되므로, 일치 결과를 단서로 취급하고 조치하기 전에 콘텐츠와 인증서를 검증합니다.
- 더 높은 정밀도를 위해 도메인 생성 시점 및 키워드 heuristics와 결합합니다.

### URL 텔레메트리 헌팅 (urlscan.io)

`urlscan.io`는 제출된 URL의 과거 스크린샷, DOM, 요청 및 TLS metadata를 저장합니다. 이를 사용하여 brand abuse와 clone을 헌팅할 수 있습니다:<sup>[[8]](#references)</sup>

예시 쿼리 (UI 또는 API):
- 합법적인 도메인을 제외하고 lookalike 찾기: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 사용자의 asset을 hotlink하는 사이트 찾기: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 최근 결과로 제한: `AND date:>now-7d` 추가

API 예시:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON에서 다음 항목을 기준으로 분석을 확장합니다:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`를 기준으로 매우 최근에 발급된 인증서를 찾아 lookalike 도메인을 식별합니다.
- `task.source`에서 `certstream-suspicious`와 같은 값을 확인하여 발견 사항을 CT monitoring과 연결합니다.

### RDAP를 통한 도메인 생성 시점 확인 (스크립트화 가능)

RDAP는 기계가 읽을 수 있는 등록 이벤트를 반환합니다. **최근 등록된 도메인(NRD)** 을 식별하는 데 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
파이프라인을 강화하려면 도메인에 등록 기간 버킷(예: <7일, <30일)을 태그하고 그에 따라 triage 우선순위를 지정하세요.

### AiTM infrastructure를 탐지하기 위한 TLS/JAx fingerprints

Credential-phishing은 **Adversary-in-the-Middle (AiTM)** reverse proxy(예: Evilginx)를 사용하여 session token을 탈취할 수 있습니다.<sup>[[11]](#references)</sup> 네트워크 측 탐지를 추가할 수 있습니다.

- egress에서 TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H)를 기록합니다. 일부 Evilginx 빌드는 안정적인 JA4 client/server 값을 사용하는 것으로 관찰되었습니다. 알려진 악성 fingerprints에 대해서는 약한 신호로만 alert를 생성하고, 항상 content 및 domain intel로 확인하세요.<sup>[[12]](#references)</sup>
- CT 또는 urlscan을 통해 발견된 lookalike host의 TLS certificate metadata(issuer, SAN count, wildcard 사용 여부, validity)를 사전에 기록하고 DNS age 및 geolocation과 상관 분석합니다.

> 참고: fingerprints는 단독 차단 기준이 아니라 enrichment로 취급하세요. framework는 발전하며 randomise하거나 obfuscate할 수 있습니다.

### keywords를 사용하는 도메인 이름

상위 페이지에서는 **victim의 domain name을 더 큰 domain 내부에 넣는** domain name variation 기법도 언급합니다(예: paypal.com에 대한 paypal-financial.com).

#### Certificate Transparency

Certificate Transparency (CT) logs는 certificate identity를 노출하므로, Subject 또는 SAN name에서 brand keyword를 검색하면 lookalike domain을 찾을 수 있습니다(예를 들어 `paypal-financial.com`에 대한 certificate는 `paypal` keyword를 노출합니다). 필요한 경우 issuance date 및 CA로 결과를 filter하고, keyword match는 false positive일 수 있으므로 후보를 검증하세요.<sup>[[13]](#references)</sup>

Patrik Hudak의 원본 [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/)은 Censys에서 이 workflow를 수행하는 방법을 보여 주며, Let's Encrypt와 같은 certificate date 및 issuer에 대한 filter를 포함합니다.<sup>[[13]](#references)</sup>

![lookalike domain을 식별하는 데 사용되는 Censys certificate search 결과](<../../images/image (1115).png>)

무료 [**crt.sh**](https://crt.sh) service를 사용하여 keyword를 검색하고 date 및 CA로 결과를 filter할 수도 있습니다.<sup>[[13]](#references)</sup>

![의심스러운 certificate identity를 검색하는 crt.sh keyword 검색](<../../images/image (519).png>)

Matching Identities field는 real domain의 identity와 의심스러운 domain의 identity를 비교하는 데 도움이 될 수 있지만, match를 증거가 아닌 조사 단서로 취급하세요.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)은 CT update를 거의 real time으로 stream하며, [*phishing_catcher*](https://github.com/x0rz/phishing_catcher)는 해당 stream을 사용하여 의심스러운 certificate name을 scoring합니다.<sup>[[14]](#references)[[15]](#references)</sup>

실무 팁: CT hit를 triage할 때 NRD, 신뢰할 수 없거나 알려지지 않은 registrar, privacy-proxy WHOIS, 그리고 매우 최근의 `NotBefore` time을 가진 cert를 우선 처리하세요. noise를 줄이기 위해 소유한 domain/brand의 allowlist를 유지하세요.

#### **새 도메인**

두 번째 방법은 TLD별로 새로 등록된 domain을 수집한 다음(예: [Whoxy](https://www.whoxy.com/newly-registered-domains/)를 통해) brand keyword로 filter하는 것입니다. registered domain에 keyword가 없을 경우 subdomain에 호스팅된 phishing을 놓칠 수 있습니다.<sup>[[13]](#references)</sup>

추가 heuristic: 특정 **file-extension TLD**(예: `.zip`, `.mov`)는 alerting에서 더욱 의심스럽게 취급하세요. 이러한 TLD는 lure에서 filename으로 자주 혼동되므로, 더 높은 precision을 위해 TLD signal을 brand keyword 및 NRD age와 결합하세요.

## References

- [1] [Remy Hax – Windows.com 비트스쿼팅](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [bitflipping을 사용한 Microsoft windows.com 트래픽 hijacking](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [심층 분석: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol을 위한 JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: cloud token theft를 예방, 탐지 및 대응하는 방법](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing 찾기: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream 소개](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
