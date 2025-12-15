# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

確認ポイント:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## 実践的な手順

プレーンテキストが予期せぬ挙動を示す場合は、コードポイントを確認し、慎重に正規化してください（証拠を破壊しないでください）。

### 手法

Text stego はしばしば見た目が同じ（または見えない）文字に依存します:

- Homoglyphs: 見た目が同じ異なる Unicode コードポイント (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

追加で検出に有効なケース:

- Bidirectional override/control characters (視覚的にテキストの並びを入れ替えることがある)
- Variation selectors and combining characters used as a covert channel

### 復号補助

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### コードポイントの検査
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
