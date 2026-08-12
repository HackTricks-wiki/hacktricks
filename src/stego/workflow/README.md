# Stego 工作流程

{{#include ../../banners/hacktricks-training.md}}

大多数 Stego 问题，通过系统化的 triage 解决得更快，而不是随机尝试各种工具。

## 核心流程

### Quick triage checklist

目标是高效回答两个问题：

1. 真正的容器/格式是什么？
2. payload 位于 metadata、追加的字节、嵌入的文件中，还是 content-level stego 中？

#### 1) 识别容器
```bash
file target
ls -lah target
```
如果 `file` 的判断结果与扩展名不一致，请检查文件签名，而不是盲目信任后缀。`file` 同样是启发式工具，可能会被格式错误的输入或 polyglot input 混淆。适当时，将常见格式视为容器（例如，OOXML 文档是 ZIP packages）。<sup>[[2]](#references)</sup>

#### 2) 查找 metadata 和明显的字符串
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
如果提取失败但报告了 signatures，使用 `dd` 手动 carve offsets，然后在 carve 后的区域上重新运行 `file`。

#### 4) 如果是图像

- 检查异常：`magick identify -verbose file`
- 如果是 PNG/BMP，枚举 bit-planes/LSB：`zsteg -a file.png`
- 验证 PNG 结构：`pngcheck -v file.png`
- 当内容可能通过 channel/plane transforms 显现时，使用 visual filters（Stegsolve / StegoVeritas）

#### 5) 如果是音频

- 首先生成 Spectrogram（Sonic Visualiser）
- Decode/inspect streams：`ffmpeg -v info -i file -f null -`
- 如果音频类似结构化 tones，测试 DTMF decoding

### 常用工具

这些工具可以捕获高频的 container-level cases：metadata payloads、appended bytes，以及伪装成其他扩展名的 embedded files。<sup>[[1]](#references)[[3]](#references)</sup>

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
项目 repository：`korczis/foremost`。<sup>[[4]](#references)</sup>

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
### Containers、appended data 和 polyglot tricks

许多 steganography challenges 是有效文件后的额外字节，或是通过扩展名伪装的 embedded archives。

#### Appended payloads

许多格式会忽略 trailing bytes。可以将 ZIP/PDF/script appended 到 image/audio container 中。

快速检查：
```bash
binwalk file
tail -c 200 file | xxd
```
如果你知道偏移量，可使用 `dd` 执行 carve：
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

当 `file` 无法判断时，使用 `xxd` 查找 magic bytes，并与已知签名进行比较：
```bash
xxd -g 1 -l 32 file
```
#### 伪装的 Zip

即使文件扩展名不是 zip，也可以尝试使用 `7z` 和 `unzip`：
```bash
7z l file
unzip -l file
```
### Near-stego 异常现象

经常与 stego 一起出现的模式的快速链接（从 binary 生成 QR、盲文等）。

#### 从 binary 生成 QR codes

如果 blob 长度是完全平方数，它可能是图像/QR 的原始像素。
```python
import math
math.isqrt(2500)  # 50
```
二进制到图像辅助工具：

- dCode 二进制图像辅助工具。<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator。<sup>[[6]](#references)</sup>

如需更广泛的 steganography utilities 和特定技术资源集合，请参阅随附的 stego-toolkit 和 0xRick 的精选列表。<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 集成最常用 steganography tools 的 Docker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston 等 — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — 二进制图像](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Translator](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography Resources](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
