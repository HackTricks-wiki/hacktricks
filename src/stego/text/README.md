# 텍스트 Steganography

{{#include ../../banners/hacktricks-training.md}}

## 실용적인 접근

일반 텍스트가 예상과 다르게 동작하면 원본 증거를 보존하고, 해당 텍스트의 codepoint를 검사한 후 사본만 정규화하세요.

### 기법

텍스트 Steganography는 렌더링 결과가 동일하거나 보이지 않는 문자를 자주 이용합니다:

- Homoglyphs: 서로 다른 Unicode codepoint이지만 비슷하게 보이는 문자(예: Latin `a`와 Cyrillic `а`)<sup>[[1]](#references)</sup>
- Zero-width 문자: joiner, non-joiner 및 zero-width space<sup>[[2]](#references)</sup>
- Whitespace 인코딩: space와 tab의 차이, 줄 끝 공백 패턴 및 의도적인 줄 길이 패턴<sup>[[3]](#references)[[4]](#references)</sup>

추가적인 고신호 사례:

- Bidirectional control은 텍스트를 시각적으로 재배열할 수 있습니다<sup>[[1]](#references)</sup>
- Variation selector와 combining character는 표시되는 텍스트를 거의 변경하지 않고 숨겨진 상태를 전달할 수 있습니다<sup>[[1]](#references)</sup>

### Decode helper

- [Unicode Homoglyph 및 zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### codepoint 검사
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

`@font-face` 규칙을 악용하여 `unicode-range: U+..` 항목에 바이트를 인코딩할 수 있습니다. 코드포인트를 추출하고 16진수 값을 연결한 다음 디코딩합니다:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
범위에 선언당 여러 값이 포함되어 있으면 먼저 쉼표를 기준으로 분할한 다음 정규화하세요 (`tr ',+' '\n'`). 형식이 일관되지 않을 때는 Python으로 바이트를 파싱하고 출력할 수 있습니다.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode 기술 보고서 #36: Unicode 보안 고려 사항](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Zero-Width Characters 및 Homoglyphs를 사용한 Unicode Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa's Wishlist](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian 매뉴얼: `stegsnow` 공백 Steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
