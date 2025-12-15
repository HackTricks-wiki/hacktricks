# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

찾아볼 것:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## 실무 경로

일반 텍스트가 예기치 않게 동작하면, 코드포인트를 검사하고 신중하게 정규화하세요(증거를 훼손하지 마세요).

### 기법

Text stego는 동일하게(또는 보이지 않게) 렌더링되는 문자에 자주 의존합니다:

- Homoglyphs: 겉모습이 같은 서로 다른 Unicode codepoints (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

추가로 주목할 사례:

- Bidirectional override/control characters (텍스트를 시각적으로 재배열할 수 있음)
- Variation selectors and combining characters (은밀한 채널로 사용될 수 있음)

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
{{#include ../../banners/hacktricks-training.md}}
