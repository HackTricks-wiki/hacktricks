# 图像隐写

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF 图像隐写题都属于以下几类：

- LSB/位平面（PNG/BMP）
- 元数据/注释载荷
- PNG 块异常 / 损坏修复
- JPEG DCT 域工具（OutGuess 等）
- 基于帧的隐写（GIF/APNG）

## 快速初步检查

在深入分析内容前，优先检查容器层面的证据。有关文件识别和 carving 的步骤，请参阅[通用隐写工作流](../workflow/)。

- 验证文件并检查结构：`file`、`magick identify -verbose`、格式验证工具（例如 `pngcheck`）。
- 提取元数据和可见字符串：`exiftool -a -u -g1`、`strings`。
- 检查嵌入或附加的内容：`binwalk` 和文件末尾检查（`tail | xxd`）。
- 按容器类型进一步检查：
  - PNG/BMP：位平面/LSB 和块级异常。
  - JPEG：元数据 + DCT 域工具（OutGuess/F5 类工具）。
  - GIF/APNG：帧提取、帧差分、调色板技巧。

## 位平面 / LSB

### 技术

PNG/BMP 在 CTF 中很常见，因为它们以便于**位级操作**的方式存储像素。经典的隐藏/提取机制如下：

- 每个像素通道（R/G/B/A）包含多位数据。
- 每个通道的**最低有效位**（LSB）变化对图像的影响很小。
- 攻击者会在这些低位中隐藏数据，有时还会使用步长、置换或按通道选择。

题目中可能遇到的情况：

- 载荷只在一个通道中（例如 `R` 的 LSB）。
- 载荷在 alpha 通道中。
- 提取后，载荷经过压缩/编码。
- 消息分布在多个平面中，或通过平面间的 XOR 隐藏。

你可能遇到的其他类型（取决于具体实现）：

- **LSB matching**（不只是翻转位，而是通过 +/-1 调整来匹配目标位）
- **基于调色板/索引的隐藏**（索引色 PNG/GIF：载荷藏在颜色索引中，而非原始 RGB 值中）
- **仅 alpha 载荷**（在 RGB 视图中完全不可见）

### 索引色调色板索引

索引色 PNG 或 GIF 为每个像素存储的是调色板**索引**，而非 RGB 三元组。多个索引可能映射到相同的可见颜色，因此在分析前转换为 RGB 可能会抹去隐藏差异。检查重复或近似重复的调色板条目，然后为使用每个可疑索引的像素生成二值掩码。近期的 GIF 题目中，有人通过此方法发现了隐藏文本和 QR 码变化。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

对于单帧索引色 PNG（或 GIF 的**第一帧**），请保留 Pillow 的 `P` 模式，并将 `target` 改为脚本报告的可疑索引。选择索引时，除了 RGB，也要检查透明度（`tRNS` 或 GIF 透明索引）。<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

对于动画 GIF，请分别检查各帧。Pillow 在合成时通常会将后续帧转换为 RGB/RGBA；`GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` 仅在调色板未发生变化时保留 `P` 模式。如果某帧使用了局部调色板或已被合成，请检查其原始索引帧数据，而不要将 RGB 转换后的像素视为索引。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### 工具

#### zsteg

`zsteg` 可枚举 PNG/BMP 的多种 LSB/位平面提取模式：

```bash
zsteg -a file.png
```

仓库: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`：运行一系列变换（元数据、图像变换、暴力尝试各种 LSB 变体）。
- `stegsolve`：手动视觉滤镜（通道隔离、平面检查、XOR 等）。

Stegsolve 下载地址：https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### 基于 FFT 的可见性技巧

FFT 不是 LSB 提取；它适用于内容被刻意隐藏在频域或细微图案中的情况。

- EPFL 演示：http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF 中常用的网页端初步分析工具：

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG 内部结构：数据块、损坏和隐藏数据

### 技术

PNG 是一种由数据块组成的格式。在许多挑战中，载荷存储在容器/数据块层，而非像素值中：

- **`IEND` 后的额外字节**（许多查看器会忽略尾随字节）
- **承载载荷的非标准辅助数据块**；参见 [PNG 数据块遍历与数据雕刻工作流](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads)。
- **损坏的文件头**，它们会隐藏图像尺寸或导致解析器无法处理，直到修复为止

需要检查的高价值数据块位置：

- `tEXt` / `iTXt` / `zTXt`（文本元数据，有时经过压缩）
- `iCCP`（ICC 配置文件）及其他用作载体的辅助数据块
- `eXIf`（PNG 中的 EXIF 数据）

### PNG 扫描线滤波器字节作为载体

PNG 在解压后的 `IDAT` 数据流中，每条扫描线前会存储一个滤波器类型字节（0–4）。这些字节不是像素值；解码后的 RGB 像素不会保留原始滤波器选择，重新编码也可能改变它们。编码器可以合理地改变滤波器，但刻意设计的模式能够编码短消息；近期有一道挑战使用滤波器值 1–4 作为双比特符号。检查**原始文件**，并在解压前拼接所有 `IDAT` 数据。对于以下非交错、8 位 RGB/RGBA 的情况，扫描线步长为宽度乘以通道数；Adam7 图像需要使用各遍的扫描线宽度。<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>列出 PNG 扫描线滤波器字节，不重新编码</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

运行 `python3 filters.py suspect.png`。检查滤镜序列本身是否符合合理的符号映射，而不是检查解码后的像素。映射方式因挑战而异；仅凭变化并不能证明存在隐写术。<sup>[[3]](#references)[[7]](#references)</sup>

### 初步分析命令

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

需要检查的内容：

- 异常的宽度/高度/位深/颜色类型组合
- CRC/chunk 错误（pngcheck 通常会指出确切偏移量）
- 关于 `IEND` 之后存在额外数据的警告

如果需要更深入地查看 chunk：

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Useful references:

- PNG 规范（结构、chunks）：https://www.w3.org/TR/PNG/
- 文件格式技巧（PNG/JPEG/GIF 边界情况）：https://github.com/corkami/docs

## JPEG：metadata、DCT 域工具和 ELA 的局限

### Technique

JPEG 并非以原始像素形式存储，而是在 DCT 域中压缩。因此，JPEG stego 工具与 PNG LSB 工具不同：

- Metadata/comment payload 位于文件级别（信号明显，检查快速）
- DCT 域 stego 工具将比特嵌入频率系数中

实际操作中，将 JPEG 视为：

- metadata segments 的容器（信号明显，检查快速）
- 压缩信号域（DCT 系数），专业 stego 工具会在其中操作

### 快速检查

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

高信号位置：

- EXIF/XMP/IPTC 元数据
- JPEG 注释段（`COM`）
- 应用程序段（`APP1` 用于 EXIF，`APPn` 用于厂商数据）

### 常用工具

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

如果你要处理 JPEG 中的 steghide payload，可以考虑使用 `stegseek`（比旧脚本的暴力破解速度更快）：

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA 会突出显示不同的重新压缩伪影；它可以帮助你定位经过编辑的区域，但本身并不是 stego 检测器：

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 动画图像

### 技术

对于动画图像，假设消息：

- 位于单个帧中（简单）
- 分散在多个帧中（顺序很重要）
- 只有在对连续帧进行 diff 时才可见

### 提取帧

```bash
ffmpeg -i anim.gif frame_%04d.png
```

然后像处理普通 PNG 一样处理帧：`zsteg`、`pngcheck`、通道隔离。

其他工具：

- `gifsicle --explode anim.gif`（快速提取帧）
- `imagemagick`/`magick` 用于逐帧变换

帧差分通常能起到决定性作用：

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG 像素计数编码

- 检测 APNG 容器：`exiftool -a -G1 file.png | grep -i animation` 或 `file`。
- 提取帧且不重新定时：`ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- 恢复编码为每帧像素计数的载荷：

```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
    counts = Image.open(f).getcolors()
    target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
    out.append(target or 0)
print(bytes(out).decode('latin1'))
```

动画挑战可能会将每个字节编码为每帧中特定颜色的数量；将这些数量串联起来即可还原消息。<sup>[[1]](#references)</sup>

## 受密码保护的嵌入

如果你怀疑嵌入内容是通过密码短语保护的，而非通过像素级操作实现的，这通常是最快的途径。

### steghide

支持 `JPEG, BMP, WAV, AU`，可嵌入/提取加密载荷。

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

支持 PNG/BMP/GIF/WebP/WAV。

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — 粉色、Santa 的愿望清单、圣诞元数据、捕获的噪声](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 write-up — 扭曲的颜色](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [便携式网络图形（PNG）规范，第三版](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — 深处的水中藏着什么](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow 图像文件格式 — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a 规范](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [余像协议 — CTF write-up](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
