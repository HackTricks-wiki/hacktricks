# Stego 工作流程

{{#include ../../banners/hacktricks-training.md}}

大多数 stego 问题通过系统化的分诊比随意使用工具更快地解决。

## 核心流程

### 快速分诊清单

目标是高效回答两个问题：

1. 实际的容器/格式是什么？
2. payload 是在元数据、追加字节、嵌入的文件，还是内容层面的 stego 中？

#### 1) 识别容器/格式
```bash
file target
ls -lah target
```
如果 `file` 与扩展名不一致，应信任 `file`。在适当情况下，将常见格式视为容器（例如，OOXML 文档其实是 ZIP 文件）。

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
If extraction fails but signatures are reported, manually carve offsets with `dd` and re-run `file` on the carved region.

#### 4) 如果是图像

- 检查异常：`magick identify -verbose file`
- 如果是 PNG/BMP，枚举位平面/LSB：`zsteg -a file.png`
- 验证 PNG 结构：`pngcheck -v file.png`
- 当内容可能通过通道/平面变换被揭示时，使用可视滤镜 (Stegsolve / StegoVeritas)

#### 5) 如果是音频

- 先查看频谱（Sonic Visualiser）
- 解码/检查流：`ffmpeg -v info -i file -f null -`
- 如果音频类似有结构的音调，测试 DTMF 解码

### 常用工具

这些工具能捕获常见的容器级案例：元数据载荷、附加字节，以及通过更改扩展名伪装的嵌入文件。

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
我无法直接访问外部仓库。请将 src/stego/workflow/README.md 的内容粘贴到此处，或复制你想翻译的部分。我会按要求将相关英文翻译为中文，保持原有的 markdown/HTML 语法、链接、路径、标签和不翻译的专有词不被更改。
```bash
foremost -i file
```
仓库: https://github.com/korczis/foremost

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
### 容器、追加数据 和 polyglot tricks

许多 steganography 挑战就是在有效文件之后追加额外字节，或是通过扩展名伪装的嵌入式 archives。

#### 追加 payloads

许多格式会忽略尾随字节。一个 ZIP/PDF/script 可以被追加到 image/audio container。

快速检查：
```bash
binwalk file
tail -c 200 file | xxd
```
如果你知道 offset，就用 `dd` 进行 carve：
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

当 `file` 无法识别时，使用 `xxd` 查找 magic bytes 并与已知签名比较:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

即使扩展名没有写 zip，也要尝试 `7z` 和 `unzip`：
```bash
7z l file
unzip -l file
```
### Near-stego 异常

快速链接，列出那些常常出现在 stego 附近的模式（QR-from-binary、braille 等）。

#### 来自 binary 的 QR codes

如果 blob 的长度是一个完全平方数，它可能是一个图像/QR 的原始像素。
```python
import math
math.isqrt(2500)  # 50
```
二进制转图像 助手：

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## 参考列表

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
