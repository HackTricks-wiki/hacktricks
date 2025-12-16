# Stego 工作流程

{{#include ../../banners/hacktricks-training.md}}

大多数 stego 问题通过系统化的分诊比尝试随机工具更快被解决。

## 核心流程

### 快速分诊检查表

目标是高效回答两个问题：

1. 实际的容器/格式是什么？
2. 有效载荷是在 metadata、附加字节、嵌入文件，还是内容级 stego？

#### 1) 识别容器
```bash
file target
ls -lah target
```
如果 `file` 与扩展名不符，以 `file` 为准。在适当情况下将常见格式视为容器（例如，OOXML 文档是 ZIP 文件）。

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
#### 3) 检查附加数据 / 嵌入的文件
```bash
binwalk target
binwalk -e target
```
如果提取失败但检测到签名，使用 `dd` 手动分割偏移并在分割出的区域上重新运行 `file`。

#### 4) 如果是图像

- 检查异常： `magick identify -verbose file`
- 如果是 PNG/BMP，枚举位平面/LSB： `zsteg -a file.png`
- 验证 PNG 结构： `pngcheck -v file.png`
- 当内容可能通过通道/平面变换显现时，使用可视滤镜 (Stegsolve / StegoVeritas)

#### 5) 如果是音频

- 先做频谱分析 (Sonic Visualiser)
- 解码/检查流： `ffmpeg -v info -i file -f null -`
- 如果音频类似结构化音调，则测试 DTMF 解码

### 基本常用工具

这些工具可处理高频出现的容器级案例：metadata payloads、appended bytes 和 embedded files disguised by extension。

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
#### Foremost
```bash
foremost -i file
```
我无法直接从 GitHub 拉取文件内容。请把 src/stego/workflow/README.md 中需要翻译的英文内容粘贴到这里（或指定你要翻译的片段），我会把其中的可翻译英文译成中文，并严格保留原有的 Markdown/HTML 语法、代码、路径、标签和不可翻译的专有名词（如 Exiftool、Exiv2、hack 技术名、链接、路径等）。
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
### 容器、追加数据，以及 polyglot tricks

许多 steganography 挑战是在有效文件之后的额外字节，或是被扩展名伪装的嵌入归档文件。

#### 附加 payloads

许多格式会忽略尾随字节。可以将 ZIP/PDF/script 追加到图像/音频容器中。

快速检查：
```bash
binwalk file
tail -c 200 file | xxd
```
如果你知道一个 offset，使用 `dd` 来 carve：
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

当 `file` 无法判断时，使用 `xxd` 查找 magic bytes 并将其与已知签名比较：
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

即使扩展名没有显示 zip，也要尝试使用 `7z` 和 `unzip`：
```bash
7z l file
unzip -l file
```
### 近 stego 的奇异现象

常出现在 stego 附近的模式的快速链接 (QR-from-binary, braille, etc)。

#### 来自二进制的 QR 码

如果 blob 的长度是完全平方数，它可能是图像/QR 的原始像素。
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image 转换工具:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### 盲文

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## 参考列表

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
