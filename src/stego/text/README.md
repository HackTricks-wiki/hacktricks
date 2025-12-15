# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

查找：

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## 实用路径

如果纯文本表现异常，检查码位并谨慎归一化（不要破坏证据）。

### 技术

Text stego 经常依赖于外观相同（或不可见）的字符：

- Homoglyphs: 不同的 Unicode 码位但看起来相同 (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

其他高信号情况：

- Bidirectional override/control characters (可在视觉上重新排序文本)
- Variation selectors and combining characters 可被用作隐蔽通道

### Decode helpers

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
{{#include ../../banners/hacktricks-training.md}}
