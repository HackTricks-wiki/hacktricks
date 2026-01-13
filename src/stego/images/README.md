# 图像隐写术

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF image stego 问题可归为以下几类：

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## 快速初步诊断

在深入分析内容之前，优先检查容器层级的证据：

- 验证文件并检查结构：`file`, `magick identify -verbose`, format validators (e.g., `pngcheck`)。
- 提取元数据和可见字符串：`exiftool -a -u -g1`, `strings`。
- 检查嵌入/追加内容：`binwalk` 和 文件末尾检查（`tail | xxd`）。
- 按容器类型分支：
- PNG/BMP：bit-planes/LSB 和 chunk-level 异常。
- JPEG：metadata + DCT-domain 工具（OutGuess/F5-style 家族）。
- GIF/APNG：帧提取、帧差分、调色板技巧。

## Bit-planes / LSB

### 技术

PNG/BMP 在 CTF 中很受欢迎，因为它们以便于 **位级操作** 的方式存储像素。经典的隐藏/提取机制是：

- 每个像素通道 (R/G/B/A) 都有多个位。
- 每个通道的 **least significant bit** (LSB) 对图像影响很小。
- 攻击者将数据隐藏在这些低位，有时会使用步幅、置换或按通道选择。

在题目中可能遇到：

- 有效载荷仅在一个通道（例如 `R` 的 LSB）。
- 有效载荷在 alpha 通道。
- 提取后 payload 被压缩/编码。
- 消息分布在多个 plane 或通过 plane 之间的 XOR 隐藏。

你可能遇到的其他变体（依赖实现）：

- **LSB matching**（不仅仅是翻转位，而是通过 +/-1 调整以匹配目标位）
- **Palette/index-based hiding**（indexed PNG/GIF：payload 存在于颜色索引而非原始 RGB）
- **Alpha-only payloads**（在 RGB 视图中完全不可见）

### 工具

#### zsteg

`zsteg` 列举了许多针对 PNG/BMP 的 LSB/bit-plane 提取模式：
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: 运行一系列变换（元数据、图像变换，brute forcing LSB variants）。
- `stegsolve`: 手动视觉滤镜（channel isolation, plane inspection, XOR 等）。

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT 不是 LSB 提取；它用于内容被有意隐藏在频率域或细微模式中的情况。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG 是一种分块（chunked）格式。在许多挑战中，payload 存储在容器/chunk 级别，而不是像素值中：

- **Extra bytes after `IEND`**（许多查看器会忽略尾随字节）
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** 会隐藏图像尺寸或在修复前导致解析器失败

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt`（文本元数据，有时经过压缩）
- `iCCP`（ICC profile）以及其他可作为载体的 ancillary chunks
- `eXIf`（PNG 中的 EXIF 数据）

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
要注意的事项：

- 奇怪的宽度/高度/位深/颜色类型组合
- CRC/chunk 错误（pngcheck 通常会指出确切的偏移）
- 关于 `IEND` 之后存在额外数据的警告

如果需要更深入的 chunk 视图：
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
有用的参考：

- PNG 规范（结构、块）：https://www.w3.org/TR/PNG/
- 文件格式技巧（PNG/JPEG/GIF 特殊情况）：https://github.com/corkami/docs

## JPEG：元数据、DCT-domain 工具和 ELA 限制

### 技术

JPEG 不以原始像素的形式存储；它在 DCT domain 被压缩。这就是为什么 JPEG stego 工具与 PNG LSB 工具不同：

- 元数据/注释 的负载是文件级别的（高信号且可快速检查）
- DCT-domain stego 工具将比特嵌入频率系数中

在操作上，将 JPEG 视为：

- 一个用于元数据段的容器（高信号、可快速检查）
- 一个压缩的信号域（DCT 系数），专门的 stego 工具在该处运行

### 快速检查
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
高信号位置：

- EXIF/XMP/IPTC metadata
- JPEG 注释段 (`COM`)
- 应用段 (`APP1` for EXIF, `APPn` for vendor data)

### 常用工具

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

如果你在 JPEG 中遇到 steghide payloads，考虑使用 `stegseek`（faster bruteforce than older scripts）：

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA 会突出显示不同的再压缩伪影；它可以指示被编辑的区域，但它本身并不是 stego detector：

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 动画图像

### 方法

对于动画图像，假设隐藏信息：

- 位于单帧中（简单），或
- 跨帧分布（顺序很重要），或
- 只有在对相邻帧进行 diff 时可见

### 提取帧
```bash
ffmpeg -i anim.gif frame_%04d.png
```
然后把帧当作普通的 PNG 处理：`zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (快速帧提取)
- `imagemagick`/`magick` 用于逐帧变换

Frame differencing 常常具有决定性作用:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- 检测 APNG 容器： `exiftool -a -G1 file.png | grep -i animation` 或 `file`.
- 提取帧（不重新定时）： `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- 恢复以每帧像素计数编码的 payload：
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
动画挑战可能将每个字节编码为每帧中特定颜色的计数；将这些计数串联即可重构消息。

## 密码保护的嵌入

如果你怀疑嵌入是由口令保护而不是像素级操作，这通常是最快的路径。

### steghide

支持 `JPEG, BMP, WAV, AU`，并且可以 embed/extract encrypted payloads。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
### StegCracker

StegCracker 是一个使用字典对 steghide 密码进行暴力破解的工具。它通过尝试 wordlist 中的密码来提取被 steghide 隐写的内容，适用于在已知或猜测密码可能来源于常见密码列表的场景。

安装
```
pip install stegcracker
```

用法
```
stegcracker [options] <file> <wordlist>
```

示例
```
stegcracker image.jpg wordlist.txt
```

特性
- 使用 wordlist 进行暴力破解
- 支持并行处理以加速尝试
- 支持从上次中断处恢复（断点续传）
```bash
stegcracker file.jpg wordlist.txt
```
仓库: https://github.com/Paradoxis/StegCracker

### stegpy

支持 PNG/BMP/GIF/WebP/WAV.

仓库: https://github.com/dhsdshdhk/stegpy

## 参考资料

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
