# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

以下を探します:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Practical path

プレーンテキストが予期せず動作する場合は、codepointsを調査し、慎重に正規化します（証拠を破壊しないでください）。

### Technique

Text stegoは、同じように表示される（または表示されない）文字に依存することがよくあります:

- Homoglyphs: 同じように見える異なるUnicode codepoints（Latin `a` と Cyrillic `а`）
- Zero-width characters: joiners、non-joiners、zero-width spaces
- Whitespace encodings: spaces と tabs、末尾のspaces、行長のパターン<sup>[[1]](#references)</sup>

その他のhigh-signalなケース:

- Bidirectional override/control characters（テキストの表示順序を視覚的に変更できる）
- Variation selectorsおよびcombining charactersをcovert channelとして使用する

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspect codepoints
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

`@font-face` ルールは、`unicode-range: U+..` エントリにバイトをエンコードできます。コードポイントを抽出し、16進数を連結してデコードします。
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
1つの宣言に複数のバイトが含まれている場合は、まずカンマで分割し、正規化します（`tr ',+' '\n'`）。Pythonを使うと、形式が一貫していない場合でもバイトの解析と出力を簡単に行えます。

## 参考資料

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
