# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

찾아볼 항목:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## 실용적 절차

평문(plain text)이 예기치 않게 동작하면 코드포인트를 검사하고 신중히 정규화하세요(증거를 훼손하지 마세요).

### 기법

Text stego는 동일하게(또는 보이지 않게) 렌더링되는 문자에 자주 의존합니다:

- Homoglyphs: 서로 같아 보이는 다른 Unicode codepoints (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

추가로 신호가 높은 사례:

- Bidirectional override/control characters (텍스트를 시각적으로 재정렬할 수 있음)
- Variation selectors and combining characters used as a covert channel

### 디코딩 도구

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### 코드포인트 검사
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` 채널

`@font-face` 규칙은 `unicode-range: U+..` 항목에 바이트를 인코딩할 수 있습니다. 코드포인트를 추출하여 16진수를 이어붙이고 디코드하세요:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
ranges에 선언당 여러 bytes가 포함되어 있으면, 먼저 쉼표로 분리하고 정규화하세요 (`tr ',+' '\n'`). 포맷이 일관되지 않으면 bytes를 파싱하고 출력하는 작업은 Python으로 쉽게 할 수 있습니다.

## 참조

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
