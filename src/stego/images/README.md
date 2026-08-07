# 图像隐写术

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF 图像 stego 都可以归入以下类别之一：

- LSB/bit-planes（PNG/BMP）
- Metadata/comment payloads
- PNG chunk 异常 / corruption repair
- JPEG DCT-domain tools（OutGuess 等）
- 基于帧的技术（GIF/APNG）

## 快速初筛

在进行深度内容分析之前，优先检查容器级证据：

- 验证文件并检查结构：`file`、`magick identify -verbose`、格式验证工具（例如 `pngcheck`）。
- 提取 metadata 和可见字符串：`exiftool -a -u -g1`、`strings`。
- 检查嵌入/追加的内容：`binwalk` 以及文件末尾检查（`tail | xxd`）。
- 根据容器类型进行分支处理：
- PNG/BMP：bit-planes/LSB 和 chunk-level anomalies。
- JPEG：metadata + DCT-domain tooling（OutGuess/F5-style families）。
- GIF/APNG：frame extraction、frame differencing、palette tricks。

## Bit-planes / LSB

### Technique

PNG/BMP 在 CTF 中很常见，因为它们以便于进行 **bit-level manipulation** 的方式存储像素。经典的隐藏/提取机制如下：

- 每个像素通道（R/G/B/A）包含多个 bits。
- 每个通道的 **least significant bit**（LSB）对图像的改变非常小。
- 攻击者会将数据隐藏在这些低位 bits 中，有时还会使用 stride、permutation 或按通道选择。

挑战中可能遇到的情况：

- payload 仅位于一个通道中（例如 `R` LSB）。
- payload 位于 alpha 通道中。
- 提取后 payload 经过压缩/编码。
- 消息分布在多个 planes 中，或通过 planes 之间的 XOR 隐藏。

你可能遇到的其他 families（取决于具体实现）：

- **LSB matching**（不仅仅是翻转 bit，而是通过 +/-1 调整来匹配目标 bit）
- **Palette/index-based hiding**（indexed PNG/GIF：payload 位于 color indices 中，而不是原始 RGB 中）
- **Alpha-only payloads**（在 RGB view 中完全不可见）

### Tooling

#### zsteg

`zsteg` 会枚举 PNG/BMP 的多种 LSB/bit-plane extraction patterns：
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`：运行一系列 transforms（metadata、image transforms、brute forcing LSB variants）。
- `stegsolve`：手动 visual filters（channel isolation、plane inspection、XOR 等）。

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### 基于 FFT 的可见性技巧

FFT 不是 LSB extraction；它适用于内容被有意隐藏在 frequency space 或细微 patterns 中的情况。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

基于 Web 的 triage 常用于 CTF：

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals：chunks、corruption 和 hidden data

### Technique

PNG 是一种 chunked format。在许多 challenge 中，payload 存储在 container/chunk level，而不是 pixel values 中：

- **`IEND` 后的额外 bytes**（许多 viewers 会忽略 trailing bytes）
- **携带 payload 的 non-standard ancillary chunks**
- **隐藏 dimensions 或导致 parsers 在修复前无法解析的 corrupted headers**

需要重点检查的 chunk locations：

- `tEXt` / `iTXt` / `zTXt`（text metadata，有时经过 compressed）
- `iCCP`（ICC profile）以及其他用作 carrier 的 ancillary chunks
- `eXIf`（PNG 中的 EXIF data）

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
需要查看的内容：

- 异常的 width/height/bit-depth/colour-type 组合
- CRC/chunk 错误（pngcheck 通常会指出确切的偏移量）
- 关于 `IEND` 后存在 additional data 的警告

如果需要查看更深入的 chunk 信息：
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Useful references:

- PNG specification（structure, chunks）: https://www.w3.org/TR/PNG/
- File format tricks（PNG/JPEG/GIF corner cases）: https://github.com/corkami/docs

## JPEG：元数据、DCT 域工具和 ELA 限制

### Technique

JPEG 并非以原始像素存储；它是在 DCT 域中进行压缩的。这也是 JPEG stego tools 与 PNG LSB tools 不同的原因：

- 元数据/注释 payload 位于文件级别（高信号，且可快速检查）
- DCT 域 stego tools 将 bits 嵌入频率系数中

在实际操作中，应将 JPEG 视为：

- 元数据 segments 的容器（高信号，可快速检查）
- 压缩信号域（DCT 系数），专用 stego tools 在其中运行

### 快速检查
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
高信号位置：

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments（`APP1` 用于 EXIF，`APPn` 用于 vendor data）

### 常用工具

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

如果你专门面对 JPEG 中的 steghide payload，可以考虑使用 `stegseek`（比旧脚本的 bruteforce 更快）：

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA 会突出显示不同的 recompression artifacts；它可以帮助你定位被编辑的区域，但本身不是 stego detector：

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 动画图像

### 技术

对于动画图像，假设消息：

- 位于单个 frame 中（简单），或
- 分布在多个 frame 中（ordering 很重要），或
- 只有在对 consecutive frames 执行 diff 时才可见

### 提取 frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
然后将帧当作普通 PNG 处理：`zsteg`、`pngcheck`、通道隔离。

替代工具：

- `gifsicle --explode anim.gif`（快速提取帧）
- 使用 `imagemagick`/`magick` 进行逐帧转换

帧差分通常具有决定性作用：
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Detect APNG containers: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Extract frames without re-timing: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recover payloads encoded as per-frame pixel counts:
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
动画挑战可能会将每个字节编码为每帧中特定颜色的数量；将这些数量串联起来即可重建消息。<sup>[[1]](#references)</sup>

## 受密码保护的 embedding

如果你怀疑 embedding 是通过 passphrase 保护的，而不是通过像素级操作实现的，这通常是最快的路径。

### steghide

支持 `JPEG, BMP, WAV, AU`，并且可以嵌入/提取加密的 payloads。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
仓库: https://github.com/StefanoDeVuono/steghide

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
