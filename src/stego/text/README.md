# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

查找：

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## 实用流程

如果纯文本表现异常，请检查码位并小心进行归一化（不要破坏证据）。

### 技巧

Text stego 通常依赖于呈现相同（或不可见）的字符：

- Homoglyphs: 不同的 Unicode 码位，但外观相同 (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

其他高信号情况：

- Bidirectional override/control characters (可在视觉上重新排序文本)
- Variation selectors and combining characters 可用作隐蔽通道

### 解码辅助

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### 检查码位
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

`@font-face` 规则可以在 `unicode-range: U+..` 条目中编码字节。提取码点，拼接十六进制，然后解码：
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
如果范围在每个声明中包含多个字节，先按逗号分割并归一化（`tr ',+' '\n'`）。当格式不一致时，Python 可更容易地解析并输出字节。

## 参考资料

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
