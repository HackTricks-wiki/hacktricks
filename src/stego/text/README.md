# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

## 实践路径

如果纯文本的行为异常，请保留原始证据，检查其 codepoints，并仅对副本进行规范化。

### 技术

Text steganography 经常依赖于显示效果相同或不可见的字符：

- Homoglyphs：看起来相似但 Unicode codepoints 不同的字符（例如 Latin `a` 和 Cyrillic `а`）<sup>[[1]](#references)</sup>
- Zero-width characters：连接符、非连接符和零宽空格<sup>[[2]](#references)</sup>
- Whitespace encodings：空格与制表符、行尾空格模式，以及有意设置的行长度模式<sup>[[3]](#references)[[4]](#references)</sup>

其他高信号案例：

- 双向控制字符，可以在视觉上重新排列文本<sup>[[1]](#references)</sup>
- Variation selectors 和 combining characters，可以在几乎不改变可见文本的情况下携带隐藏状态<sup>[[1]](#references)</sup>

### Decode helpers

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### 检查 codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` 通道

`@font-face` 规则可被滥用，通过 `unicode-range: U+..` 条目编码字节。提取 codepoints，连接十六进制值，然后进行解码：<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
如果每个声明中的范围包含多个值，请先按逗号拆分并进行规范化（`tr ',+' '\n'`）。当格式不一致时，Python 可以解析并输出这些字节。<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36：Unicode 安全注意事项](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek：使用零宽字符和 Homoglyphs 进行 Unicode Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf：Flagvent 2025（Medium）——Santa's Wishlist](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian 手册：`stegsnow` 空白 Steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
