# テキスト Steganography

{{#include ../../banners/hacktricks-training.md}}

確認する項目:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces と tabs)

## 実践的な手順

プレーンテキストが予期せぬ動作をする場合は、codepointsを調査し、慎重にnormalizeする（証拠を破壊しないこと）。

### Technique

Text stegoでは、同じように表示される（または見えない）文字が頻繁に利用されます:

- Homoglyphs: 同じに見える異なるUnicode codepoints（Latinの `a` とCyrillicの `а`）
- Zero-width characters: joiners、non-joiners、zero-width spaces
- Whitespace encodings: spaces と tabs、末尾のspaces、行長のパターン<sup>[[1]](#references)</sup>

その他のhigh-signalなケース:

- Bidirectional override/control characters（テキストを視覚的に並べ替えられる）
- Variation selectors と combining characters をcovert channelとして使用する

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### codepointsを調査する
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

`@font-face` ルールでは、`unicode-range: U+..` エントリにバイトをエンコードできます。コードポイントを抽出し、16進数を連結してデコードします：
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
複数の bytes が 1 つの declaration に含まれている場合は、まずカンマで分割し、正規化します（`tr ',+' '\n'`）。Python を使うと、formatting に一貫性がない場合でも bytes の parse と emit を簡単に行えます。<sup>[[1]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
