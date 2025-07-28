# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## 개요

하모그래프(또는 호모글리프) 공격은 많은 **비라틴 스크립트의 유니코드 코드 포인트가 ASCII 문자와 시각적으로 동일하거나 매우 유사하다는 사실을 악용합니다**. 하나 이상의 라틴 문자를 그들의 유사한 문자로 대체함으로써 공격자는 다음을 만들 수 있습니다:

* 인간의 눈에는 합법적으로 보이지만 키워드 기반 탐지를 우회하는 표시 이름, 주제 또는 메시지 본문.
* 피해자가 신뢰할 수 있는 사이트를 방문하고 있다고 믿게 만드는 도메인, 서브 도메인 또는 URL 경로.

모든 글리프는 **유니코드 코드 포인트**로 내부적으로 식별되기 때문에, 단일 대체 문자가 순진한 문자열 비교를 무너뜨리기에 충분합니다 (예: `"Παypal.com"` vs. `"Paypal.com"`).

## 전형적인 피싱 워크플로우

1. **메시지 내용 작성** – impersonated 브랜드 / 키워드의 특정 라틴 문자를 다른 스크립트(그리스어, 키릴 문자, 아르메니아어, 체로키어 등)에서 시각적으로 구별할 수 없는 문자로 대체합니다.
2. **지원 인프라 등록** – 선택적으로 호모글리프 도메인을 등록하고 TLS 인증서를 얻습니다(대부분의 CA는 시각적 유사성 검사를 수행하지 않습니다).
3. **이메일 / SMS 전송** – 메시지에는 다음 위치 중 하나 이상에 호모글리프가 포함되어 있습니다:
* 발신자 표시 이름 (예: `Ηеlрdеѕk`)
* 제목 줄 (`Urgеnt Аctіon Rеquіrеd`)
* 하이퍼링크 텍스트 또는 완전한 도메인 이름
4. **리디렉션 체인** – 피해자는 자격 증명을 수집하거나 악성 코드를 전달하는 악성 호스트에 도착하기 전에 겉보기에는 무해한 웹사이트나 URL 단축기를 통해 이동합니다.

## 일반적으로 악용되는 유니코드 범위

| 스크립트 | 범위 | 예시 글리프 | 유사 문자 |
|--------|-------|---------------|------------|
| 그리스어  | U+0370-03FF | `Η` (U+0397) | 라틴 `H` |
| 그리스어  | U+0370-03FF | `ρ` (U+03C1) | 라틴 `p` |
| 키릴 문자 | U+0400-04FF | `а` (U+0430) | 라틴 `a` |
| 키릴 문자 | U+0400-04FF | `е` (U+0435) | 라틴 `e` |
| 아르메니아어 | U+0530-058F | `օ` (U+0585) | 라틴 `o` |
| 체로키어 | U+13A0-13FF | `Ꭲ` (U+13A2) | 라틴 `T` |

> 팁: 전체 유니코드 차트는 [unicode.org](https://home.unicode.org/)에서 확인할 수 있습니다.

## 탐지 기술

### 1. 혼합 스크립트 검사

영어를 사용하는 조직을 목표로 하는 피싱 이메일은 여러 스크립트의 문자를 혼합하는 경우가 드뭅니다. 간단하지만 효과적인 휴리스틱은 다음과 같습니다:

1. 검사하는 문자열의 각 문자를 반복합니다.
2. 코드 포인트를 해당 유니코드 블록에 매핑합니다.
3. 하나 이상의 스크립트가 존재하거나 비라틴 스크립트가 예상치 못한 곳(표시 이름, 도메인, 주제, URL 등)에 나타나면 경고를 발생시킵니다.

Python 개념 증명:
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

국제화 도메인 이름 (IDN)은 **punycode** (`xn--`)로 인코딩됩니다. 모든 호스트 이름을 punycode로 변환한 다음 다시 유니코드로 변환하면 화이트리스트와 일치시키거나 유사성 검사를 수행할 수 있습니다 (예: Levenshtein 거리) **문자열이 정규화된 후**.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. 동형 문자 사전 / 알고리즘

**dnstwist** (`--homoglyph`) 또는 **urlcrazy**와 같은 도구는 시각적으로 유사한 도메인 변형을 나열할 수 있으며, 사전적 차단 / 모니터링에 유용합니다.

## 예방 및 완화

* 엄격한 DMARC/DKIM/SPF 정책을 시행하여 무단 도메인에서의 스푸핑을 방지합니다.
* **Secure Email Gateways** 및 **SIEM/XSOAR** 플레이북에 위의 탐지 로직을 구현합니다.
* 표시 이름 도메인 ≠ 발신자 도메인인 메시지를 플래그하거나 격리합니다.
* 사용자 교육: 의심스러운 텍스트를 유니코드 검사기에 복사-붙여넣기하고, 링크에 마우스를 올리며, URL 단축기를 절대 신뢰하지 마십시오.

## 실제 사례

* 표시 이름: `Сonfidеntiаl Ꭲiꮯkеt` (키릴 문자 `С`, `е`, `а`; 체로키 `Ꭲ`; 라틴 소문자 대문자 `ꮯ`).
* 도메인 체인: `bestseoservices.com` ➜ municipal `/templates` 디렉토리 ➜ `kig.skyvaulyt.ru` ➜ 커스텀 OTP CAPTCHA로 보호된 가짜 Microsoft 로그인 `mlcorsftpsswddprotcct.approaches.it.com`.
* Spotify 사칭: 링크가 `redirects.ca` 뒤에 숨겨진 `Sρօtifŭ` 발신자.

이 샘플은 Unit 42 연구(2025년 7월)에서 유래되었으며, 동형 문자 남용이 URL 리디렉션 및 CAPTCHA 회피와 결합되어 자동 분석을 우회하는 방법을 보여줍니다.

## 참고 문헌

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
