# 图像隐写术

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF 图像 stego 都可以归入以下类别之一：

- LSB/位平面（PNG/BMP）
- Metadata/comment payloads
- PNG chunk 异常 / 损坏修复
- JPEG DCT-domain tools（OutGuess 等）
- 基于帧（GIF/APNG）

## 快速分流

在深入分析内容之前，优先检查容器级证据：

- 验证文件并检查结构：`file`、`magick identify -verbose`、格式验证工具（例如 `pngcheck`）。
- 提取 metadata 和可见字符串：`exiftool -a -u -g1`、`strings`。
- 检查嵌入/追加的内容：`binwalk` 和文件末尾检查（`tail | xxd`）。
- 根据容器类型选择分析方向：
- PNG/BMP：位平面/LSB 和 chunk 级异常。
- JPEG：metadata + DCT-domain tooling（OutGuess/F5-style families）。
- GIF/APNG：帧提取、帧差分、palette 技巧。

## 位平面 / LSB

### Technique

PNG/BMP 在 CTF 中很常见，因为它们以便于进行**位级操作**的方式存储像素。经典的隐藏/提取机制如下：

- 每个像素通道（R/G/B/A）包含多个 bit。
- 每个通道的**最低有效位**（LSB）对图像的影响极小。
- 攻击者会将数据隐藏在这些低位中，有时还会使用 stride、排列或按通道选择。

在 challenges 中需要关注：

- payload 仅位于一个通道中（例如 `R` LSB）。
- payload 位于 alpha 通道中。
- 提取后 payload 经过压缩/编码。
- 消息分散在多个平面中，或通过平面之间的 XOR 隐藏。

你可能遇到的其他 family（取决于具体实现）：

- **LSB matching**（不只是翻转 bit，而是通过 +/-1 调整来匹配目标 bit）
- **基于 palette/index 的隐藏**（indexed PNG/GIF：payload 位于 color indices 中，而不是原始 RGB 中）
- **仅 alpha 的 payload**（在 RGB 视图中完全不可见）

### Tooling

#### zsteg

`zsteg` 会枚举 PNG/BMP 中多种 LSB/位平面提取模式：
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`：运行一系列 transforms（metadata、image transforms、brute forcing LSB variants）。
- `stegsolve`：手动 visual filters（channel isolation、plane inspection、XOR 等）。

Stegsolve 下载地址：https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### 基于 FFT 的可见性技巧

FFT 不是 LSB extraction；它适用于内容被有意隐藏在频率空间或细微模式中的情况。

- EPFL demo：http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier：https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic：https://github.com/0xcomposure/FFTStegPic

基于 Web 的 triage 通常用于 CTFs：

- Aperi’Solve：https://aperisolve.com/
- StegOnline：https://stegonline.georgeom.net/

## PNG internals：chunks、corruption 和 hidden data

### 技术

PNG 是一种基于 chunk 的格式。在许多 challenges 中，payload 存储在 container/chunk 层，而不是 pixel values 中：

- **`IEND` 后的额外字节**（许多 viewers 会忽略 trailing bytes）
- **携带 payload 的非标准 ancillary chunks**
- **隐藏 dimensions 或导致 parsers 失效的 corrupted headers，直到修复为止**

建议重点检查的 chunk 位置：

- `tEXt` / `iTXt` / `zTXt`（text metadata，有时经过压缩）
- `iCCP`（ICC profile）以及其他用作 carrier 的 ancillary chunks
- `eXIf`（PNG 中的 EXIF data）

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
需要检查的内容：

- 异常的宽度/高度/位深度/颜色类型组合
- CRC/chunk 错误（pngcheck 通常会指出确切的偏移量）
- 关于 `IEND` 后存在额外数据的警告

如果需要更深入的 chunk 视图：
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Useful references:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG：metadata、DCT-domain tools 和 ELA limitations

### Technique

JPEG 不是以 raw pixels 的形式存储的；它在 DCT domain 中经过压缩。这就是 JPEG stego tools 与 PNG LSB tools 不同的原因：

- Metadata/comment payloads 位于文件级别（high-signal，且可快速检查）
- DCT-domain stego tools 将 bits 嵌入 frequency coefficients

在实际操作中，应将 JPEG 视为：

- 用于存放 metadata segments 的 container（high-signal，可快速检查）
- 一个压缩 signal domain（DCT coefficients），specialized stego tools 在其中运行

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
高信号位置：

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments（`APP1` 用于 EXIF，`APPn` 用于 vendor data）

### 常用 tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

如果你遇到的是 JPEG 中的 steghide payload，可以考虑使用 `stegseek`（比旧版 scripts 更快地进行 bruteforce）：

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA 会突出显示不同的 recompression artifacts；它可以帮助你定位被编辑过的区域，但本身不是 stego detector：

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 动画图像

### Technique

对于动画图像，假设 message：

- 位于单个 frame 中（简单），或
- 分布在多个 frame 中（ordering 很重要），或
- 只有在对连续 frame 进行 diff 时才可见

### 提取 frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
然后将 frames 当作普通 PNG 处理：`zsteg`、`pngcheck`、channel isolation。

Alternative tooling：

- `gifsicle --explode anim.gif`（快速提取 frames）
- 使用 `imagemagick`/`magick` 进行 per-frame transforms

Frame differencing 通常是决定性的：
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG 像素计数编码

- 检测 APNG 容器：`exiftool -a -G1 file.png | grep -i animation` 或使用 `file`。
- 提取帧且不重新计时：`ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- 恢复按每帧像素数量编码的 payloads：
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
动画 challenges 可能会将每个 byte 编码为每一帧中特定颜色的数量；将这些数量连接起来即可还原消息。<sup>[[1]](#references)</sup>

## 受密码保护的嵌入

如果你怀疑嵌入内容是通过 passphrase 保护的，而不是通过像素级操作实现的，通常这是最快的路径。

### steghide

支持 `JPEG, BMP, WAV, AU`，并可以嵌入/提取加密 payload。
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

## 参考资料

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
