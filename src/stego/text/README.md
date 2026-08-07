# 텍스트 Steganography

{{#include ../../banners/hacktricks-training.md}}

다음을 확인하세요:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## 실용적인 방법

일반 텍스트가 예상과 다르게 동작한다면 codepoints를 검사하고 신중하게 normalize하세요 (evidence를 훼손하지 마세요).

### Technique

Text stego는 동일하게 렌더링되는 (또는 보이지 않는) characters에 의존하는 경우가 많습니다:

- Homoglyphs: 동일하게 보이는 서로 다른 Unicode codepoints (Latin `a`와 Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces와 tabs, trailing spaces, line-length patterns<sup>[[1]](#references)</sup>

추가적인 high-signal 사례:

- Bidirectional override/control characters (텍스트를 시각적으로 재배열할 수 있음)
- covert channel로 사용되는 Variation selectors 및 combining characters

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### codepoints 검사
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

`@font-face` 규칙은 `unicode-range: U+..` 항목에 바이트를 인코딩할 수 있습니다. 코드 포인트를 추출하고 16진수를 연결한 다음 디코딩합니다:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
범위에 선언당 여러 바이트가 포함되어 있다면 먼저 쉼표를 기준으로 분할하고 normalize하세요 (`tr ',+' '\n'`). Python을 사용하면 형식이 일관되지 않아도 바이트를 쉽게 파싱하고 출력할 수 있습니다.<sup>[[1]](#references)</sup>

## 참고 문헌

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
