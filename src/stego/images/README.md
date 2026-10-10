# 图像隐写术

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF 图像隐写题都属于以下几类：

- LSB/位平面（PNG/BMP）
- 元数据/注释 payload
- PNG 块异常 / 损坏修复
- JPEG DCT 域工具（OutGuess 等）
- 基于帧的隐写（GIF/APNG）

## 快速排查

在深入分析内容之前，优先检查容器层面的证据：

- 验证文件并检查结构：`file`、`magick identify -verbose`、格式验证工具（如 `pngcheck`）。
- 提取元数据和可见字符串：`exiftool -a -u -g1`、`strings`。
- 检查是否嵌入或追加了内容：使用 `binwalk` 和文件末尾检查（`tail | xxd`）。
- 根据容器类型分支排查：
  - PNG/BMP：位平面/LSB 和块级异常。
  - JPEG：元数据 + DCT 域工具（OutGuess/F5 风格系列）。
  - GIF/APNG：提取帧、帧差分、调色板技巧。

## 位平面 / LSB

### 技术原理

PNG/BMP 在 CTF 中很常见，因为它们以便于**位级操作**的方式存储像素。经典的隐藏/提取机制如下：

- 每个像素通道（R/G/B/A）都有多个位。
- 每个通道的**最低有效位**（LSB）变化时，对图像的影响很小。
- 攻击者会在这些低位中隐藏数据，有时还会使用步长、置换或按通道选择。

题目中可能出现的情况：

- payload 只在一个通道中（例如 `R` 通道的 LSB）。
- payload 位于 alpha 通道中。
- 提取后还需对 payload 进行压缩/编码处理。
- 消息分散在多个位平面中，或通过位平面之间的 XOR 隐藏。

你可能遇到的其他类型（取决于具体实现）：

- **LSB 匹配**（不只是翻转位，而是通过 +/-1 调整来匹配目标位）
- **基于调色板/索引的隐藏**（索引 PNG/GIF：payload 隐藏在颜色索引中，而不是原始 RGB 值中）
- **仅使用 Alpha 通道的 payload**（在 RGB 视图中完全不可见）

### 工具

#### zsteg

`zsteg` 可以枚举 PNG/BMP 的多种 LSB/位平面提取模式：

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`：运行一系列变换（元数据、图像变换、暴力破解 LSB 变体）。
- `stegsolve`：手动视觉滤镜（通道隔离、平面检查、XOR 等）。

Stegsolve 下载：https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### 基于 FFT 的可见性技巧

FFT 不是 LSB 提取；它适用于内容被刻意隐藏在频域或细微图案中的情况。

- EPFL 演示：http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier：https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic：https://github.com/0xcomposure/FFTStegPic

CTF 中常用的基于 Web 的初步分析工具：

- Aperi’Solve：https://aperisolve.com/
- StegOnline：https://stegonline.georgeom.net/

## PNG 内部结构：数据块、损坏与隐藏数据

### 技术

PNG 是一种分块格式。在许多挑战中，payload 存储在容器/数据块层，而非像素值中：

- **`IEND` 后的额外字节**（许多查看器会忽略尾随字节）
- **包含 payload 的非标准辅助数据块**
- **损坏的头部**，用于隐藏尺寸信息，或在修复前破坏解析器

值得重点检查的数据块位置：

- `tEXt` / `iTXt` / `zTXt`（文本元数据，有时经过压缩）
- `iCCP`（ICC 配置文件）及其他用作载体的辅助数据块
- `eXIf`（PNG 中的 EXIF 数据）

### 初步分析命令

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

需要检查的内容：

- 异常的宽度/高度/位深/颜色类型组合
- CRC/数据块错误（pngcheck 通常会指出准确偏移量）
- 关于 `IEND` 后有额外数据的警告

如果需要更深入地查看数据块：

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

实用参考资料：

- PNG 规范（结构、区块）：https://www.w3.org/TR/PNG/
- 文件格式技巧（PNG/JPEG/GIF 边缘情况）：https://github.com/corkami/docs

## JPEG：元数据、DCT 域工具和 ELA 的局限

### 技术

JPEG 并非以原始像素形式存储，而是在 DCT 域中压缩。因此，JPEG stego 工具与 PNG LSB 工具有所不同：

- 元数据/注释载荷位于文件级别（信号明显，检查快速）
- DCT 域 stego 工具将位嵌入频率系数中

在实际操作中，可将 JPEG 视为：

- 一个元数据段容器（信号明显，检查快速）
- 一个压缩信号域（DCT 系数），专用 stego 工具会在其中运行

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

如果你专门在处理 JPEG 中的 steghide payloads，可以考虑使用 `stegseek`（比旧脚本的暴力破解速度更快）：

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA 会突出显示不同的重新压缩伪影；它可以帮助你定位被编辑过的区域，但本身并不是 stego 检测器：

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 动画图像

### 技术

对于动画图像，假设消息：

- 位于单个帧中（容易提取），或
- 分布在多个帧中（顺序很重要），或
- 只有在对连续帧进行 diff 时才可见

### 提取帧

```bash
ffmpeg -i anim.gif frame_%04d.png
```

然后像处理普通 PNG 一样处理帧：`zsteg`、`pngcheck`、通道隔离。

其他工具：

- `gifsicle --explode anim.gif`（快速提取帧）
- `imagemagick`/`magick` 用于逐帧转换

帧差分通常是关键：

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG 像素计数编码

- 检测 APNG 容器：`exiftool -a -G1 file.png | grep -i animation` 或 `file`。
- 提取帧且不重新计时：`ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- 恢复编码为逐帧像素计数的 payload：

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

动画类挑战可能会将每个字节编码为每帧中特定颜色的数量；将这些数量串联起来即可还原消息。<sup>[[1]](#references)</sup>

## 受密码保护的嵌入

如果你怀疑嵌入是由口令保护，而非通过像素级操作实现的，这通常是最快的处理方式。

### steghide

支持 `JPEG, BMP, WAV, AU`，并可嵌入/提取加密载荷。

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

- [1] [Flagvent 2025 (Medium) — 粉色、圣诞老人的愿望清单、圣诞节元数据、捕获的噪声](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
