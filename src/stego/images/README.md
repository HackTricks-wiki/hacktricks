# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF 图像 stego 通常归为以下几类：

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

在深入内容分析之前，优先检查容器层面的证据：

- 验证文件并检查结构：`file`, `magick identify -verbose`, format validators (e.g., `pngcheck`)。
- 提取元数据和可见字符串：`exiftool -a -u -g1`, `strings`。
- 检查嵌入/追加内容：`binwalk` 和 文件末尾检查（`tail | xxd`）。
- 按容器类型分支：
- PNG/BMP：bit-planes/LSB 和 chunk-level 异常。
- JPEG：元数据 + DCT-domain 工具（OutGuess/F5-style 系列）。
- GIF/APNG：帧提取、帧差分、调色板技巧。

## Bit-planes / LSB

### 技术

PNG/BMP 在 CTF 中很受欢迎，因为它们以便于进行**位级操作**的方式存储像素。典型的隐藏/提取机制是：

- 每个像素通道（R/G/B/A）由多个位组成。
- 每个通道的**最低有效位** (LSB) 对图像的影响很小。
- 攻击者会将数据隐藏在这些低位，有时会用步长、置换或按通道选择的方式。

在挑战中可能遇到的情况：

- payload 仅存在于单一通道（例如 `R` LSB）。
- payload 存在于 alpha 通道。
- payload 在提取后可能被压缩/编码。
- 消息可能分布在多个位面或通过位面间的 XOR 隐藏。

你可能遇到的其他变体（依赖于实现）：

- **LSB matching**（不仅仅是翻转位，而是通过 +/-1 调整来匹配目标位）
- **Palette/index-based hiding**（indexed PNG/GIF：payload 存在于颜色索引而不是原始 RGB）
- **Alpha-only payloads**（在 RGB 视图中完全不可见）

### 工具

#### zsteg

`zsteg` 列举了许多针对 PNG/BMP 的 LSB/bit-plane 提取模式：
```bash
zsteg -a file.png
```
仓库： https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 运行一系列变换（metadata、image transforms、brute forcing LSB variants）。
- `stegsolve`: 手动视觉滤镜（channel isolation、plane inspection、XOR 等）。

Stegsolve 下载: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### 基于 FFT 的可视化技巧

FFT 不是 LSB 提取；它用于内容被故意隐藏在频率域或细微模式中的情况。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF 中常用的基于 Web 的初步分析工具：

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG 内部结构：chunks、损坏和隐藏数据

### 技术

PNG 是分块格式。在许多挑战中，payload 存储在容器/chunk 级别，而不是在像素值中：

- **Extra bytes after `IEND`**（许多查看器会忽略尾随字节）
- **Non-standard ancillary chunks** 携带 payloads
- **Corrupted headers** 会隐藏尺寸或使解析器在修复前出错

应重点检查的高信号 chunk 位置：

- `tEXt` / `iTXt` / `zTXt`（文本元数据，有时被压缩）
- `iCCP`（ICC profile）以及其他用作载体的 ancillary chunks
- `eXIf`（PNG 中的 EXIF 数据）

### 初步分析命令
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
需要查找的内容：

- 奇怪的宽度/高度/位深/颜色类型组合
- CRC/chunk 错误（pngcheck 通常会指向确切的偏移）
- 关于在 `IEND` 之后存在额外数据的警告

如果你需要更深入的 chunk 视图：
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
有用的参考：

- PNG specification（结构、chunks）：https://www.w3.org/TR/PNG/
- 文件格式技巧（PNG/JPEG/GIF corner cases）：https://github.com/corkami/docs

## JPEG：metadata、DCT-domain tools 与 ELA 限制

### 技术

JPEG 不是以原始像素存储；它在 DCT 域被压缩。这就是 JPEG stego 工具与 PNG LSB 工具不同的原因：

- Metadata/comment payloads 是文件级别的（高信号且可快速检查）
- DCT-domain stego 工具将比特嵌入到频率系数中

在操作上，应将 JPEG 视为：

- 一个用于 metadata 段的容器（高信号，易快速检查）
- 一个压缩的信号域（DCT coefficients），专门的 stego 工具在此工作

### 快速检查
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC 元数据
- JPEG 注释段 (`COM`)
- 应用段 (`APP1` for EXIF, `APPn` for vendor数据)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA highlights different recompression artifacts; it can point you to regions that were edited, but it’s not a stego detector by itself:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

For animated images, assume the message is:

- In a single frame (easy), or
- Spread across frames (ordering matters), or
- Only visible when you diff consecutive frames

### Extract frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
然后将帧视为普通的 PNG: `zsteg`, `pngcheck`, channel isolation.

替代工具:

- `gifsicle --explode anim.gif` (快速提取帧)
- `imagemagick`/`magick` 用于每帧的转换

Frame differencing 通常能起决定性作用:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## 受密码保护的嵌入

如果你怀疑嵌入是由密码短语保护而不是像素级修改，这通常是最快的路径。

### steghide

支持 `JPEG, BMP, WAV, AU`，并且可以 embed/extract encrypted payloads。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
我无法直接访问外部仓库。请把 src/stego/images/README.md 的内容（或你要翻译的部分）粘贴到这里，我会按你要求将其中的英文翻译成中文，并保持原有的 Markdown/HTML 语法与不翻译的项不变。
```bash
stegcracker file.jpg wordlist.txt
```
仓库: https://github.com/Paradoxis/StegCracker

### stegpy

支持 PNG/BMP/GIF/WebP/WAV。

仓库: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
