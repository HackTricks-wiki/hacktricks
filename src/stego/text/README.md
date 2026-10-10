# 文本隐写术

{{#include ../../banners/hacktricks-training.md}}

## 实用路径

如果纯文本表现异常，请保留原始证据，检查其码位，并且只对副本进行规范化。

### 技术

文本隐写术通常依赖渲染效果相同或不可见的字符：

- 同形异义字符：外观相似但 Unicode 码位不同的字符（例如，拉丁字母 `a` 和西里尔字母 `а`）<sup>[[1]](#references)</sup>
- 零宽字符：连接符、非连接符和零宽空格<sup>[[2]](#references)</sup>
- 空白编码：空格与制表符的区别、行尾空格模式，以及刻意设计的行长模式<sup>[[3]](#references)[[4]](#references)</sup>

其他高信号特征：

- 双向控制符，可在视觉上重排文本<sup>[[1]](#references)</sup>
- 变体选择符和组合字符，可在几乎不改变可见文本的情况下携带隐藏状态<sup>[[1]](#references)</sup>

### 解码工具

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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

`@font-face` 规则可被滥用，通过 `unicode-range: U+..` 条目编码字节。提取码点，拼接十六进制值，然后解码：<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

如果每个声明中的范围包含多个值，请先按逗号拆分并规范化（`tr ',+' '\n'`）。如果格式不一致，可以用 Python 解析并输出字节。<sup>[[3]](#references)</sup>

## References

- [1] [Unicode 技术报告 #36：Unicode 安全注意事项](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek：使用零宽字符和同形异义字进行 Unicode 隐写](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf：Flagvent 2025（Medium）— Santa 的愿望清单](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian 手册：`stegsnow` 空白字符隐写](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
