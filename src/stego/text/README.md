# 文本隐写

{{#include ../../banners/hacktricks-training.md}}

查找：

- Unicode 同形异义字符
- 零宽字符
- 空白模式（空格与制表符）

## 实践路径

如果纯文本的行为异常，请检查 codepoints 并谨慎执行规范化（不要破坏证据）。

### 技术

文本隐写经常依赖渲染结果相同（或不可见）的字符：

- 同形异义字符：看起来相同但 Unicode codepoints 不同的字符（拉丁字母 `a` 与西里尔字母 `а`）
- 零宽字符：连接符、非连接符、零宽空格
- 空白编码：空格与制表符、行尾空格、行长度模式<sup>[[1]](#references)</sup>

其他高信号案例：

- 双向覆盖/控制字符（可以在视觉上重新排列文本）
- 将变体选择符和组合字符用作 covert channel

### 解码辅助工具

- Unicode 同形异义字符/零宽字符 playground：https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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
## CSS `unicode-range` channels

`@font-face` 规则可以在 `unicode-range: U+..` 条目中编码字节。提取 codepoint，拼接十六进制值，然后进行解码：
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
如果每个声明中的范围包含多个字节，请先按逗号拆分，然后进行规范化（`tr ',+' '\n'`）。当格式不一致时，Python 可以轻松解析并输出字节。

## 参考资料

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
