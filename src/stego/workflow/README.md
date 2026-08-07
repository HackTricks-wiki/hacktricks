# Stego 工作流程

{{#include ../../banners/hacktricks-training.md}}

大多数 stego 问题，通过系统化 triage 解决的速度比随机尝试工具更快。

## 核心流程

### 快速 triage 清单

目标是高效回答两个问题：

1. 真正的容器/格式是什么？
2. payload 位于 metadata、追加的字节、嵌入的文件，还是内容级 stego 中？

#### 1) 识别容器
```bash
file target
ls -lah target
```
如果 `file` 和扩展名不一致，以 `file` 的结果为准。适当时，将常见格式视为容器（例如，OOXML 文档是 ZIP 文件）。

#### 2) 查找 metadata 和明显字符串
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
#### 3) 检查追加数据 / 嵌入文件
```bash
binwalk target
binwalk -e target
```
如果提取失败但报告了 signatures，使用 `dd` 手动 carve offsets，然后对 carve 出的区域重新运行 `file`。

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

这些工具可以捕获高频的 container-level cases：metadata payloads、appended bytes，以及伪装成其他扩展名的 embedded files。<sup>[[1]](#references)</sup>

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
仓库：https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### file / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### 容器、附加数据和 polyglot 技巧

许多 steganography challenges 是有效文件之后存在额外字节，或是通过扩展名伪装的 embedded archives。

#### 附加 payload

许多格式会忽略尾部字节。可以将 ZIP/PDF/script 附加到 image/audio container 中。

快速检查：
```bash
binwalk file
tail -c 200 file | xxd
```
如果你知道偏移量，可以使用 `dd` 进行 carve：
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

当 `file` 无法判断时，使用 `xxd` 查找 magic bytes，并与已知签名进行比较：
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

即使扩展名没有表明它是 zip，也要尝试使用 `7z` 和 `unzip`：
```bash
7z l file
unzip -l file
```
### Near-stego 异常

用于查看经常出现在 stego 附近的模式的快速链接（从 binary 生成 QR codes、盲文等）。

#### 从 binary 生成 QR codes

如果 blob 长度是完全平方数，它可能是某个图像/QR 的原始像素。
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## 参考资料

- [1] [DominicBreuker/stego-toolkit - 集成了最常用 steganography tools 的 Docker image](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
