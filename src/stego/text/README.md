# 텍스트 스테가노그래피

{{#include ../../banners/hacktricks-training.md}}

## 실전 경로

일반 텍스트가 예상과 다르게 동작하면 원본 증거를 보존하고, 코드 포인트를 검사한 다음 복사본만 정규화합니다.

### 기법

텍스트 스테가노그래피는 흔히 동일하게 보이거나 눈에 보이지 않는 문자에 의존합니다.

- 동형문자: 서로 다른 Unicode 코드 포인트지만 비슷하게 보이는 문자(예: 라틴 문자 `a`와 키릴 문자 `а`)<sup>[[1]](#references)</sup>
- 폭 없는 문자: 조이너, 논조이너, 폭 없는 공백<sup>[[2]](#references)</sup>
- 공백 인코딩: 공백과 탭의 차이, 줄 끝 공백 패턴, 의도적인 줄 길이 패턴<sup>[[3]](#references)[[4]](#references)</sup>

추가로 주의 깊게 살펴볼 사례:

- 텍스트를 시각적으로 재배열할 수 있는 양방향 제어 문자<sup>[[1]](#references)</sup>
- 표시되는 텍스트를 거의 바꾸지 않으면서 숨겨진 상태를 담을 수 있는 변형 선택자와 결합 문자<sup>[[1]](#references)</sup>

### 디코딩 도구

- [Unicode 동형문자 및 폭 없는 문자 인코더/디코더](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### 코드 포인트 검사하기

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

`@font-face` 규칙을 악용해 `unicode-range: U+..` 항목에 바이트를 인코딩할 수 있습니다. 코드 포인트를 추출하고 16진수 값을 이어 붙인 다음 디코딩합니다:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

선언에 여러 값이 포함된 범위는 먼저 쉼표로 분리한 다음 정규화하세요 (`tr ',+' '\n'`). 형식이 일관되지 않을 때는 Python으로 바이트를 파싱하고 출력할 수 있습니다.<sup>[[3]](#references)</sup>

## References

- [1] [유니코드 기술 보고서 #36: 유니코드 보안 고려 사항](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Zero-Width 문자와 Homoglyph를 이용한 유니코드 Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa의 위시리스트](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian 매뉴얼: `stegsnow` 공백 Steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
