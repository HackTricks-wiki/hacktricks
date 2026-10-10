# 隐写工作流

{{#include ../../banners/hacktricks-training.md}}

大多数隐写问题，通过系统化排查比随机尝试工具更快解决。

## 核心流程

### 快速排查清单

目标是高效回答两个问题：

1. 实际的容器/格式是什么？
2. payload 位于元数据、追加的字节、嵌入的文件中，还是内容级隐写中？

#### 1) 识别容器

```bash
file target
ls -lah target
```

如果 `file` 的判断结果与扩展名不一致，请检查文件签名，而不要相信后缀。`file` 也采用启发式判断，可能会被格式错误或多格式混合的输入所迷惑。适当情况下，将常见格式视为容器（例如，OOXML 文档是 ZIP 软件包）。<sup>[[2]](#references)</sup>

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

#### 3) 检查追加数据 / 嵌入文件

```bash
binwalk target
binwalk -e target
```

如果提取失败但检测到了签名，请使用 `dd` 手动截取偏移处的数据，然后对截取出的区域重新运行 `file`。

#### 4) 如果是图像

- 检查异常：`magick identify -verbose file`
- 如果是 PNG/BMP，枚举位平面/LSB：`zsteg -a file.png`
- 验证 PNG 结构：`pngcheck -v file.png`
- 如果内容可能通过通道/平面变换显现，使用视觉滤镜（Stegsolve / StegoVeritas）

#### 5) 如果是音频

- 先查看频谱图（Sonic Visualiser）
- 解码/检查流：`ffmpeg -v info -i file -f null -`
- 如果音频类似结构化音调，尝试 DTMF 解码

### 常用工具

这些工具可以检测高频出现的容器级情况：元数据载荷、附加字节，以及扩展名伪装的嵌入文件。<sup>[[1]](#references)[[3]](#references)</sup>

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

项目仓库：`korczis/foremost`。<sup>[[4]](#references)</sup>

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

许多隐写术挑战涉及有效文件末尾的额外字节，或伪装成其他文件扩展名的嵌入式压缩包。

#### 附加的 payload

许多格式会忽略尾随字节。ZIP/PDF/script 可以附加到图片/音频容器中。

快速检查：

```bash
binwalk file
tail -c 200 file | xxd
```

如果你知道偏移量，可以使用 `dd` 提取数据：

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### 魔数

当 `file` 无法判断时，使用 `xxd` 查找魔数字节，并与已知签名进行比较：

```bash
xxd -g 1 -l 32 file
```

#### 伪装成其他格式的 Zip

即使扩展名看起来不像 zip，也可以尝试使用 `7z` 和 `unzip`：

```bash
7z l file
unzip -l file
```

### stego 附近的异常情况

指向经常出现在 stego 附近的模式的快速链接（从二进制数据生成 QR、盲文等）。

#### 从二进制数据生成 QR 码

如果 blob 的长度是完全平方数，它可能是图像/QR 码的原始像素数据。

```python
import math
math.isqrt(2500)  # 50
```

二进制转图像工具：

- dCode 二进制图像工具。<sup>[[5]](#references)</sup>

#### 盲文

- Branah 盲文翻译器。<sup>[[6]](#references)</sup>

如需了解更全面的 steganography 工具合集和特定技术资源，请参阅随附的 stego-toolkit 和 0xRick 精选列表。<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 集成了最常用 steganography 工具的 Docker 镜像](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston 等 — ECMA-376 开放打包约定](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — 二进制图像](https://www.dcode.fr/binary-image)
- [6] [Branah — 盲文翻译器](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography 资源](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
