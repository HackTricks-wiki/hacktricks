# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Prioritize container-level evidence before deep content analysis:

- Validate the file and inspect structure: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extract metadata and visible strings: `exiftool -a -u -g1`, `strings`.
- Check for embedded/appended content: `binwalk` and end-of-file inspection (`tail | xxd`).
- Branch by container:
- PNG/BMP: bit-planes/LSB and chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP are popular in CTFs because they store pixels in a way that makes **bit-level manipulation** easy. The classic hide/extract mechanism is:

- Each pixel channel (R/G/B/A) has multiple bits.
- The **least significant bit** (LSB) of each channel changes the image very little.
- Attackers hide data in those low-order bits, sometimes with a stride, permutation, or per-channel choice.

What to expect in challenges:

- The payload is in one channel only (e.g., `R` LSB).
- The payload is in the alpha channel.
- Payload is compressed/encoded after extraction.
- The message is spread across planes or hidden via XOR between planes.

Additional families you may encounter (implementation-dependent):

- **LSB matching** (not just flipping the bit, but +/-1 adjustments to match target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (completely invisible in RGB view)

### Tooling

#### zsteg

`zsteg` enumerates many LSB/bit-plane extraction patterns for PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: 运行一系列变换（metadata, image transforms, brute forcing LSB variants）。
- `stegsolve`: 手动可视过滤器（channel isolation, plane inspection, XOR 等）。

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT 不是 LSB 提取；它用于内容被故意隐藏在频域或微妙模式中的情况。

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG 是一种 chunked 格式。在许多题目中，payload 存储在容器/chunk 级别，而不是像素值中：

- **Extra bytes after `IEND`**（许多查看器会忽略尾随字节）
- **Non-standard ancillary chunks** 用于承载 payload
- **Corrupted headers** 会隐藏尺寸或使解析器出错，直到修复

值得检查的高价值 chunk 位置：

- `tEXt` / `iTXt` / `zTXt`（文本元数据，有时被压缩）
- `iCCP`（ICC 配置文件）及其他被用作载体的辅助 chunk
- `eXIf`（PNG 中的 EXIF 数据）

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
要注意的事项：

- 奇怪的宽度/高度/位深/颜色类型组合
- CRC/chunk 错误（pngcheck 通常会指出确切的偏移量）
- 关于 `IEND` 之后存在额外数据的警告

如果需要更深入的 chunk 视图：
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
有用的参考：

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### 技术

JPEG 并非以原始像素保存；它在 DCT 域被压缩。这也是 JPEG stego 工具与 PNG LSB 工具不同的原因：

- Metadata/comment payloads 属于文件级别（高信号，便于快速检查）
- DCT-domain stego 工具将比特嵌入到频率系数中

在操作上，应将 JPEG 视为：

- 一个用于 metadata segments 的容器（高信号，便于快速检查）
- 一个压缩的信号域（DCT coefficients），专门的 stego 工具在此运行

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

如果你在 JPEG 中专门遇到 steghide payloads，考虑使用 `stegseek`（比旧脚本更快的暴力破解）：

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA 突出显示不同的再压缩伪影；它可以指出被编辑的区域，但它本身不是 stego 检测器：

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Animated images

### 方法

对于动画图像，假定消息是：

- 存在于单帧中（简单），或
- 分布在多帧中（帧顺序很重要），或
- 仅在 diff 连续帧时可见

### Extract frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
然后像处理普通 PNG 一样处理帧： `zsteg`, `pngcheck`, channel isolation.

替代工具：

- `gifsicle --explode anim.gif` (快速帧提取)
- `imagemagick`/`magick` 用于逐帧变换

帧差分通常具有决定性：
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## 带密码保护的嵌入

如果你怀疑嵌入是由 passphrase 保护而不是像素级别的操作，这通常是最快的路径。

### steghide

支持 `JPEG, BMP, WAV, AU`，并且可以 embed/extract encrypted payloads。
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
我无法直接访问外部仓库。请把 src/stego/images/README.md 的完整内容粘贴到这里，我会按你的要求把其中的英文相关文本翻译成中文，保留所有 Markdown/HTML 标签、代码、路径和不应翻译的专有名词。
```bash
stegcracker file.jpg wordlist.txt
```
仓库: https://github.com/Paradoxis/StegCracker

### stegpy

支持 PNG/BMP/GIF/WebP/WAV。

仓库: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
