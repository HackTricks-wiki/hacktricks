# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

確認項目:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## 実践的な手順

プレーンテキストが予期せぬ振る舞いをする場合は、コードポイントを確認して正規化を慎重に行う（証拠を破壊しないこと）。

### 手法

Text stegoは、同じように表示される（あるいは不可視の）文字にしばしば依存します:

- Homoglyphs: 見た目が同じ異なるUnicodeコードポイント（Latin `a` vs Cyrillic `а`）
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

追加で注目すべきケース:

- Bidirectional override/control characters (視覚的にテキストの順序を入れ替えることがある)
- Variation selectors and combining characters used as a covert channel

### デコード補助

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### コードポイントを検査する
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` チャネル

`@font-face` ルールは `unicode-range: U+..` エントリ内にバイトをエンコードできます。コードポイントを抽出し、16進数を連結してデコードします:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
範囲の宣言に複数 bytes が含まれる場合は、まずカンマで分割し、正規化してください (`tr ',+' '\n'`)。Python を使うと、フォーマットが不一致でも bytes の解析と出力が簡単になります。

## References

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
