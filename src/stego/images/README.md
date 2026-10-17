# 图像隐写术

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF 图像隐写题都属于以下几类：

- LSB/位平面（PNG/BMP）
- Metadata/注释载荷
- PNG chunk 异常 / 损坏修复
- JPEG DCT 域工具（OutGuess 等）
- 基于帧的隐写（GIF/APNG）

## 快速初步检查

在深入分析内容之前，优先检查容器层面的线索：

- 验证文件并检查结构：`file`、`magick identify -verbose`、格式验证工具（例如 `pngcheck`）。
- 提取 metadata 和可见字符串：`exiftool -a -u -g1`、`strings`。
- 检查是否有嵌入或追加的内容：`binwalk` 和文件末尾检查（`tail | xxd`）。
- 根据容器类型选择分析方向：
  - PNG/BMP：位平面/LSB 和 chunk 级异常。
  - JPEG：metadata + DCT 域工具（OutGuess/F5 类工具）。
  - GIF/APNG：提取帧、帧差分、调色板技巧。

## 位平面 / LSB

### 技术

PNG/BMP 在 CTF 中很常见，因为它们存储像素的方式便于进行**位级操作**。经典的隐藏/提取机制如下：

- 每个像素通道（R/G/B/A）都有多个位。
- 每个通道的**最低有效位**（LSB）发生变化时，对图像的影响很小。
- 攻击者会将数据隐藏在这些低位中，有时还会使用步长、置换或按通道选择。

题目中常见的情况：

- 载荷只在一个通道中（例如 `R` 通道的 LSB）。
- 载荷位于 alpha 通道。
- 提取后还需对载荷进行压缩/编码。
- 消息分散在多个位平面中，或通过位平面间的 XOR 隐藏。

你可能遇到的其他类型（取决于具体实现）：

- **LSB matching**（不只是翻转位，而是通过 +/-1 调整来匹配目标位）
- **基于调色板/索引的隐藏**（索引 PNG/GIF：载荷藏在颜色索引中，而不是原始 RGB 值中）
- **仅使用 alpha 通道的载荷**（在 RGB 视图中完全不可见）

### 工具

#### zsteg

`zsteg` 可以枚举 PNG/BMP 中多种 LSB/位平面提取模式：

```bash
zsteg -a file.png
```

仓库：https://github.com/zed-0xff/zsteg

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

PNG 是一种分块格式。在许多挑战中，payload 存储在容器/数据块层，而不是像素值中：

- **`IEND` 后的额外字节**（许多查看器会忽略尾随字节）
- **携带 payload 的非标准辅助数据块**；参见 [PNG 数据块遍历与提取工作流](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads)。
- **损坏的头部**，会隐藏尺寸信息，或导致解析器出错，直到修复为止

建议优先检查的数据块位置：

- `tEXt` / `iTXt` / `zTXt`（文本元数据，有时经过压缩）
- `iCCP`（ICC 配置文件）及用作载体的其他辅助数据块
- `eXIf`（PNG 中的 EXIF 数据）

### 初步分析命令

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

需要留意的内容：

- 奇怪的宽度/高度/位深/颜色类型组合
- CRC/块错误（pngcheck 通常会指出确切偏移量）
- 关于 `IEND` 后存在额外数据的警告

如果需要更深入地查看块：

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

有用的参考资料：

- PNG 规范（结构、chunks）：https://www.w3.org/TR/PNG/
- 文件格式技巧（PNG/JPEG/GIF 边缘情况）：https://github.com/corkami/docs

## JPEG：metadata、DCT 域工具和 ELA 的局限性

### 技术原理

JPEG 并非以原始像素形式存储，而是在 DCT 域中压缩。因此，JPEG stego 工具与 PNG LSB 工具不同：

- metadata/comment payloads 位于文件级别（信号明显，便于快速检查）
- DCT 域 stego 工具将比特嵌入频率系数中

实际操作中，可将 JPEG 视为：

- metadata segments 的容器（信号明显，便于快速检查）
- 一种压缩信号域（DCT 系数），专用 stego 工具会在其中运行

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

ELA 会突出显示不同的重新压缩伪影；它可以帮你定位被编辑过的区域，但本身并不是 stego 检测器：

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 动画图像

### 技术

对于动画图像，可以假设消息：

- 位于单个帧中（简单），或
- 分布在多个帧中（顺序很重要），或
- 只有在对比连续帧时才可见

### 提取帧

```bash
ffmpeg -i anim.gif frame_%04d.png
```

然后将帧当作普通 PNG 处理：`zsteg`、`pngcheck`、通道隔离。

其他工具：

- `gifsicle --explode anim.gif`（快速提取帧）
- `imagemagick`/`magick` 用于逐帧变换

帧差分往往能起到决定性作用：

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG 像素计数编码

- 检测 APNG 容器：`exiftool -a -G1 file.png | grep -i animation` 或 `file`。
- 提取帧且不重新定时：`ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`。
- 恢复按每帧像素计数编码的 payload：

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

动画挑战可能会将每个字节编码为每帧中特定颜色的计数；将这些计数串联起来即可还原消息。<sup>[[1]](#references)</sup>

## 受密码保护的嵌入

如果你怀疑嵌入内容是由密码短语保护，而不是通过像素级操作实现的，这通常是最快的切入点。

### steghide

支持 `JPEG, BMP, WAV, AU`，可嵌入/提取加密载荷。

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

仓库：https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

支持 PNG/BMP/GIF/WebP/WAV。

Repo: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025（Medium）— 粉色、Santa 的愿望清单、圣诞元数据、捕获的噪声](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
