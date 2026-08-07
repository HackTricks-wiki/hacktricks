# 文本隐写术

{{#include ../../banners/hacktricks-training.md}}

关注：

- Unicode homoglyphs
- Zero-width characters
- 空白模式（空格与制表符）

## 实践路径

如果纯文本的行为异常，请检查代码点并谨慎进行规范化（不要破坏证据）。

### 技术

Text stego 经常依赖渲染结果相同（或不可见）的字符：

- Homoglyphs：看起来相同但 Unicode codepoint 不同的字符（拉丁字母 `a` 与西里尔字母 `а`）
- Zero-width characters：连接符、非连接符、零宽空格
- 空白编码：空格与制表符、尾随空格、行长度模式<sup>[[1]](#references)</sup>

其他高信号案例：

- 双向覆盖/控制字符（可能在视觉上重新排列文本）
- 用作 covert channel 的变体选择符和组合字符

### 解码辅助工具

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### 检查代码点
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

`@font-face` 规则可以在 `unicode-range: U+..` 条目中编码字节。提取 codepoints，拼接十六进制值，然后进行解码：
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
如果 ranges 中每个 declaration 包含多个 bytes，请先按逗号拆分并进行规范化（`tr ',+' '\n'`）。如果格式不一致，Python 可以轻松解析并输出 bytes。<sup>[[1]](#references)</sup>

## 参考资料

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
