# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

大多数 stego 问题通过系统化的 triage 解决得更快，而不是随机尝试工具。

## 核心流程

### Quick triage checklist

目标是高效回答两个问题：

1. 真正的 container/format 是什么？
2. payload 位于 metadata、追加的字节、嵌入的文件，还是 content-level stego 中？

#### 1) Identify the container
```bash
file target
ls -lah target
```
如果 `file` 与扩展名不一致，请检查文件签名，而不要相信后缀。`file` 同样是启发式工具，可能会被格式错误的输入或 polyglot 文件误导。在适当情况下，应将常见格式视为容器（例如，OOXML 文档就是 ZIP 包）。<sup>[[2]](#references)</sup>

#### 2) 查找元数据和明显的字符串
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
尝试多种编码：
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) 检查附加数据 / 嵌入文件
```bash
binwalk target
binwalk -e target
```
如果提取失败但报告了 signatures，使用 `dd` 手动 carve offsets，然后对 carve 区域重新运行 `file`。

#### 4) 如果是图像

- 检查异常：`magick identify -verbose file`
- 如果是 PNG/BMP，枚举 bit-planes/LSB：`zsteg -a file.png`
- 验证 PNG 结构：`pngcheck -v file.png`
- 当内容可能通过 channel/plane 变换显现时，使用 visual filters（Stegsolve / StegoVeritas）

#### 5) 如果是音频

- 首先生成 Spectrogram（Sonic Visualiser）
- Decode/inspect streams：`ffmpeg -v info -i file -f null -`
- 如果音频类似结构化音调，测试 DTMF decoding

### 常用工具

这些工具可以发现高频的 container-level cases：metadata payloads、appended bytes，以及伪装扩展名的 embedded files。<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
项目仓库：`korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### 文件 / 字符串
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### 容器、追加数据和 polyglot 技巧

许多 steganography 挑战的内容是有效文件之后的额外字节，或是通过扩展名伪装的嵌入式 archive。

#### 追加的 payload

许多格式会忽略末尾字节。可以将 ZIP/PDF/script 追加到 image/audio 容器中。

快速检查：
```bash
binwalk file
tail -c 200 file | xxd
```
如果你知道偏移量，请使用 `dd` 进行 carve：
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

当 `file` 无法判断时，使用 `xxd` 查找 Magic bytes，并与已知签名进行比较：
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

即使文件扩展名没有表明它是 zip，也可以尝试使用 `7z` 和 `unzip`：
```bash
7z l file
unzip -l file
```
### 与 stego 相邻的异常现象

经常出现在 stego 附近的模式的快速链接（从二进制生成 QR、盲文等）。

#### 从二进制生成 QR codes

如果 blob 长度是一个完全平方数，它可能是图像/QR 的原始像素。
```python
import math
math.isqrt(2500)  # 50
```
二进制图像辅助工具：

- dCode 二进制图像辅助工具。<sup>[[5]](#references)</sup>

#### 盲文

- Branah 盲文翻译器。<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 捆绑最常用 steganography 工具的 Docker 镜像](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston 等人 — ECMA-376 开放打包约定](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — 二进制图像](https://www.dcode.fr/binary-image)
- [6] [Branah — 盲文翻译器](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
