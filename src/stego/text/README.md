# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

## 実践的な手順

プレーンテキストが予期せず動作する場合は、元の証拠を保持し、その codepoints を調べ、コピーに対してのみ正規化を行います。

### Technique

Text Steganography は、同じように表示される、または表示されない文字に依存することがよくあります。

- Homoglyphs: 似て見える異なる Unicode codepoints（例: Latin の `a` と Cyrillic の `а`）<sup>[[1]](#references)</sup>
- Zero-width characters: joiners、non-joiners、zero-width spaces<sup>[[2]](#references)</sup>
- Whitespace encodings: spaces と tabs の違い、末尾の空白パターン、意図的な行長パターン<sup>[[3]](#references)[[4]](#references)</sup>

その他の signal が強いケース:

- Bidirectional controls: テキストの見た目上の順序を変更できます<sup>[[1]](#references)</sup>
- Variation selectors と combining characters: 表示されるテキストをほぼ変更せずに、hidden state を保持できます<sup>[[1]](#references)</sup>

### Decode helpers

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### codepoints を調べる
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` channels

`@font-face` ルールを悪用して、`unicode-range: U+..` エントリにバイトをエンコードできます。コードポイントを抽出し、16進数値を連結してデコードします。<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
宣言ごとに複数の値が含まれている場合は、まずカンマで分割して正規化します（`tr ',+' '\n'`）。フォーマットに一貫性がない場合でも、Pythonでバイト列を解析して出力できます。<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Unicodeのセキュリティに関する考慮事項](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Zero-Width CharactersとHomoglyphsによるUnicode Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa's Wishlist](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian manual: `stegsnow` whitespace steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
