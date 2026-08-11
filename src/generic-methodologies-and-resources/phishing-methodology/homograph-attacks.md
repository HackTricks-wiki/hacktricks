# Phishing에서의 Homograph / Homoglyph Attacks

{{#include ../../banners/hacktricks-training.md}}

## 개요

Homograph(또는 homoglyph) attack은 많은 **비라틴 스크립트의 Unicode code point가 ASCII 문자와 시각적으로 동일하거나 매우 유사하다**는 점을 악용합니다. 하나 이상의 라틴 문자를 비슷하게 생긴 문자로 바꾸면 공격자는 다음과 같은 작업을 수행할 수 있습니다.

* 사람의 눈에는 정상적으로 보이지만 keyword 기반 탐지를 우회하는 Display name, 제목 또는 메시지 본문을 작성합니다.
* 피해자가 신뢰할 수 있는 사이트를 방문한다고 믿게 만드는 도메인, 하위 도메인 또는 URL 경로를 생성합니다.<sup>[[1]](#references)</sup>

각 glyph는 내부적으로 **Unicode code point**로 식별되므로, 단 하나의 문자를 바꾸는 것만으로도 단순한 문자열 비교를 무력화할 수 있습니다(예: `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## 일반적인 Phishing Workflow

1. **메시지 콘텐츠 작성** – 사칭할 브랜드 / keyword의 특정 라틴 문자를 다른 스크립트(그리스어, 키릴 문자, 아르메니아어, 체로키어 등)의 시각적으로 구분하기 어려운 문자로 바꿉니다.
2. **지원 인프라 등록** – 선택적으로 homoglyph 도메인을 등록하고 TLS certificate를 발급받습니다(대부분의 CA는 시각적 유사성을 검사하지 않습니다).
3. **email / SMS 전송** – 메시지의 다음 위치 중 하나 이상에 homoglyph를 포함합니다.
* Sender display name (예: `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text 또는 fully qualified domain name
4. **Redirect chain** – 피해자를 악성 host로 이동시켜 credentials를 수집하거나 malware를 전달하기 전에, 겉보기에는 무해한 웹사이트 또는 URL shortener를 여러 단계 거치게 합니다.<sup>[[1]](#references)</sup>

## 자주 악용되는 Unicode 범위

다음은 cross-script look-alike를 생성하는 데 자주 사용되는 문자를 포함하는 Unicode block의 예입니다.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Unicode code chart를 사용해 block과 code point를 확인할 수 있습니다.

## Detection Techniques

### 1. Mixed-Script Inspection

영어 사용 조직을 대상으로 하는 Phishing email은 여러 스크립트의 문자를 혼합하는 경우가 드뭅니다. 간단하지만 효과적인 heuristic은 다음과 같습니다.

1. 검사할 문자열의 각 문자를 순회합니다.
2. code point를 해당 script name 또는 Unicode block에 매핑합니다.
3. 둘 이상의 script가 존재하거나 **예상되지 않는 위치(표시 이름, 도메인, 제목, URL 등)에 비라틴 script가 나타나는 경우** alert를 발생시킵니다.<sup>[[3]](#references)</sup>

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
### 2. Punycode 정규화 (Domains)

Internationalised Domain Names(IDN)은 Unicode 형식과 `xn--`이 앞에 붙는 ASCII 호환 **Punycode** 형식을 가집니다. allow-listing하거나 비교하기 전에 호스트 이름을 IDNA/Punycode 형식으로 변환하고, 표시할 때는 Unicode 형식을 유지하세요.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph Dictionaries / Algorithms

**dnstwist** (`--fuzzers homoglyph`) 또는 **urlcrazy** 같은 도구는 시각적으로 유사한 도메인 변형을 열거할 수 있으며, 사전 예방적 takedown / 모니터링에 유용합니다.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* 엄격한 DMARC/DKIM/SPF 정책을 적용하여 승인되지 않은 도메인에서의 spoofing을 방지합니다.
* 위의 탐지 로직을 **Secure Email Gateways** 및 **SIEM/XSOAR** playbook에 구현합니다.
* 표시 이름의 도메인 ≠ 발신자 도메인인 메시지를 표시하거나 격리합니다.
* 사용자를 교육합니다: 의심스러운 텍스트를 Unicode inspector에 복사하여 붙여넣고, 링크에 마우스를 올려 확인하며, URL shortener를 절대 신뢰하지 않도록 합니다.

## Real-World Examples

* 표시 이름: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* 도메인 chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA로 보호되는 `mlcorsftpsswddprotcct.approaches.it.com`의 가짜 Microsoft login.
* Spotify impersonation: `redirects.ca` 뒤에 링크가 숨겨진 `Sρօtifս` sender.

이 샘플은 Unit 42 research (2025년 7월)에서 비롯되었으며, homograph abuse가 URL redirection 및 CAPTCHA evasion과 결합되어 automated analysis를 우회하는 방식을 보여 줍니다.<sup>[[1]](#references)</sup>

## References

- [1] [Homograph Illusion: 모든 것이 보이는 그대로는 아니다](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Code Charts](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [4] [dnstwist – 도메인 permutation engine](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – 도메인 typo 및 variation generator](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
