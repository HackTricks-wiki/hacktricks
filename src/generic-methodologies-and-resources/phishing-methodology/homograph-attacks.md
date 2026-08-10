# Phishing에서의 Homograph / Homoglyph Attacks

## 개요

homograph(일명 homoglyph) attack은 많은 **비라틴 script의 Unicode code point가 ASCII 문자와 시각적으로 동일하거나 매우 유사하다는 사실**을 악용합니다. 하나 이상의 라틴 문자를 비슷하게 생긴 문자로 대체하면 공격자는 다음과 같은 것을 만들 수 있습니다.

* 사람의 눈에는 정상적으로 보이지만 keyword 기반 탐지를 우회하는 표시 이름, 제목 또는 메시지 본문
* 피해자가 신뢰할 수 있는 사이트를 방문한다고 믿게 만드는 domain, sub-domain 또는 URL 경로<sup>[[1]](#references)</sup>

모든 glyph는 내부적으로 **Unicode code point**로 식별되므로, 문자 하나만 치환해도 단순한 문자열 비교를 무력화할 수 있습니다(예: `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## 일반적인 Phishing Workflow

1. **메시지 콘텐츠 작성** – 사칭하려는 brand / keyword의 특정 라틴 문자를 다른 script(그리스어, 키릴 문자, 아르메니아어, Cherokee 등)의 시각적으로 구별하기 어려운 문자로 대체합니다.
2. **지원 인프라 등록** – 선택적으로 homoglyph domain을 등록하고 TLS certificate를 발급받습니다(대부분의 CA는 시각적 유사성 검사를 수행하지 않습니다).
3. **email / SMS 전송** – 메시지에는 다음 위치 중 하나 이상에 homoglyph가 포함됩니다.
* 발신자 표시 이름(예: `Ηеlрdеѕk`)
* 제목(`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink 텍스트 또는 fully qualified domain name
4. **Redirect chain** – 피해자는 자격 증명을 수집하거나 malware를 전달하는 악성 host에 도달하기 전에 겉보기에는 정상적인 website 또는 URL shortener를 거치게 됩니다.<sup>[[1]](#references)</sup>

## 흔히 악용되는 Unicode 범위

다음은 script 간 look-alike를 만드는 데 흔히 사용되는 문자를 포함하는 Unicode block의 예입니다.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | 범위 | 예시 glyph | 다음 문자처럼 보임 |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Unicode code chart를 사용하여 block과 code point를 확인하세요.

## Detection Techniques

### 1. Mixed-Script Inspection

영어 사용 organisation을 대상으로 하는 Phishing email에서 여러 script의 문자를 혼합하는 경우는 드뭅니다. 간단하지만 효과적인 heuristic은 다음과 같습니다.

1. 검사할 문자열의 각 문자를 순회합니다.
2. code point를 script 이름 또는 Unicode block에 매핑합니다.
3. 둘 이상의 script가 존재하거나 **예상되지 않은 위치(표시 이름, domain, 제목, URL 등)에 비라틴 script가 나타나면** alert를 발생시킵니다.<sup>[[3]](#references)</sup>

Python proof-of-concept:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Punycode 정규화 (도메인)

국제화 도메인 이름(IDN)은 Unicode 형식과 `xn--`이 앞에 붙는 ASCII 호환 **Punycode** 형식을 가집니다. 허용 목록에 추가하거나 비교하기 전에 호스트 이름을 IDNA/Punycode 형식으로 변환하고, 표시할 때는 Unicode 형식을 유지하세요.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph 사전 / Algorithms

**dnstwist** (`--fuzzers homoglyph`) 또는 **urlcrazy**와 같은 Tools는 시각적으로 유사한 도메인 변형을 열거할 수 있으며, 사전 예방적 takedown / monitoring에 유용합니다.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* 엄격한 DMARC/DKIM/SPF 정책을 적용하여 승인되지 않은 도메인에서의 spoofing을 방지합니다.
* 위의 detection logic을 **Secure Email Gateways** 및 **SIEM/XSOAR** playbook에 구현합니다.
* display name domain ≠ sender domain인 메시지를 flag하거나 quarantine합니다.
* 사용자 교육: 의심스러운 텍스트를 Unicode inspector에 복사하여 붙여넣고, 링크에 마우스를 올려 확인하며, URL shortener를 절대 신뢰하지 않도록 합니다.

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA로 보호되는 `mlcorsftpsswddprotcct.approaches.it.com`의 fake Microsoft login.
* Spotify impersonation: `redirects.ca` 뒤에 링크를 숨긴 `Sρօtifս` sender.

이 샘플은 Unit 42 research(July 2025)에서 가져온 것으로, homograph abuse가 URL redirection 및 CAPTCHA evasion과 결합되어 automated analysis를 우회하는 방식을 보여 줍니다.<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: 모든 것이 보이는 그대로는 아니다](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Code Charts](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [4] [dnstwist – 도메인 변형 engine](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – 도메인 typo 및 variation generator](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
