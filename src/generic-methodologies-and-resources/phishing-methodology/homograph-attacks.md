# Phishing에서의 Homograph / Homoglyph Attacks

{{#include ../../banners/hacktricks-training.md}}

## 개요

Homograph(일명 homoglyph) attack은 많은 **Latin이 아닌 script의 Unicode code point가 ASCII 문자와 시각적으로 동일하거나 매우 유사하다**는 점을 악용합니다. 하나 이상의 Latin 문자를 비슷하게 생긴 문자로 대체하면 공격자는 다음과 같은 것을 만들 수 있습니다.

* 사람의 눈에는 정상적으로 보이지만 keyword 기반 탐지를 우회하는 표시 이름, 제목 또는 메시지 본문
* 피해자가 신뢰할 수 있는 사이트를 방문한다고 믿게 만드는 도메인, 서브도메인 또는 URL 경로

각 glyph는 내부적으로 **Unicode code point**로 식별되므로, 문자 하나만 치환해도 단순한 문자열 비교를 무력화할 수 있습니다(예: `"Παypal.com"` vs. `"Paypal.com"`).

## 일반적인 Phishing Workflow

1. **메시지 콘텐츠 구성** – 사칭하는 브랜드 / keyword의 특정 Latin 문자를 다른 script( Greek, Cyrillic, Armenian, Cherokee 등)의 시각적으로 구별하기 어려운 문자로 대체합니다.
2. **지원 인프라 등록** – 선택적으로 homoglyph 도메인을 등록하고 TLS certificate를 발급받습니다(대부분의 CA는 시각적 유사성 검사를 수행하지 않습니다).
3. **이메일 / SMS 전송** – 메시지의 다음 위치 중 하나 이상에 homoglyph가 포함됩니다.
* 발신자 표시 이름(예: `Ηеlрdеѕk`)
* 제목(`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink 텍스트 또는 fully qualified domain name
4. **Redirect chain** – 피해자는 자격 증명을 수집하거나 malware를 전달하는 악성 host에 도달하기 전에 겉보기에는 무해한 웹사이트 또는 URL shortener를 거칩니다.

## 일반적으로 악용되는 Unicode 범위

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: 전체 Unicode chart는 [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>에서 확인할 수 있습니다.

## 탐지 기법

### 1. Mixed-Script 검사

English-speaking organisation을 대상으로 하는 Phishing 이메일에서 여러 script의 문자가 혼합되는 경우는 드뭅니다. 간단하면서도 효과적인 heuristic은 다음과 같습니다.

1. 검사할 문자열의 각 문자를 순회합니다.
2. code point를 해당 Unicode block에 매핑합니다.
3. 둘 이상의 script가 존재하거나 **또는** 예상되지 않은 위치(표시 이름, 도메인, 제목, URL 등)에 non-Latin script가 나타나면 alert를 발생시킵니다.

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

국제화 도메인 이름(IDN)은 **punycode** (`xn--`)로 인코딩됩니다. 모든 hostname을 punycode로 변환한 다음 다시 Unicode로 변환하면, 문자열이 정규화된 **후** whitelist와 대조하거나 유사성 검사(예: Levenshtein distance)를 수행할 수 있습니다.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Dictionaries / Algorithms

**dnstwist** (`--homoglyph`) 또는 **urlcrazy**와 같은 도구는 시각적으로 유사한 도메인 변형을 열거할 수 있으며, 사전 예방적 takedown / monitoring에 유용합니다.<sup>[[3]](#references)</sup>

## Prevention & Mitigation

* 엄격한 DMARC/DKIM/SPF 정책을 적용하여 인증되지 않은 도메인에서의 spoofing을 방지합니다.
* 위의 detection logic을 **Secure Email Gateways** 및 **SIEM/XSOAR** playbooks에 구현합니다.
* display name domain ≠ sender domain인 메시지를 flag하거나 quarantine합니다.
* 사용자를 교육합니다. 의심스러운 텍스트를 Unicode inspector에 copy-paste하고, 링크 위에 마우스를 올려 확인하며, URL shortener를 절대 신뢰하지 않도록 합니다.

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA로 보호되는 `mlcorsftpsswddprotcct.approaches.it.com`의 가짜 Microsoft login.
* Spotify impersonation: `redirects.ca` 뒤에 링크를 숨긴 `Sρօtifս` sender.

이 샘플들은 Unit 42 research (July 2025)에서 비롯되었으며, homograph abuse가 URL redirection 및 CAPTCHA evasion과 결합되어 automated analysis를 우회하는 방식을 보여줍니다.<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
