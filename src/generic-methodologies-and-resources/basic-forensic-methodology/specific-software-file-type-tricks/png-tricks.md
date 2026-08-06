# PNG 技巧

{{#include ../../../banners/hacktricks-training.md}}

**PNG 文件**在 **CTF**、**事件响应**和**恶意软件 staging** 中非常常见，因为它们是**无损的**、**基于 chunk 的**，而且即使包含**额外元数据**、**附加 payload**或**部分损坏的 chunk**，许多工具仍会正常渲染它们。

应将 PNG 视为一个**容器**，而不仅仅是一张图片。

## 快速筛查

在开始进行 LSB stego 之前，先执行容器级检查。关于 bit-plane/LSB 工作流，请查看[专用的图像 stego 页面](../../../stego/images/README.md)。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
值得检查的内容：

- **Unexpected ancillary chunks**，例如 `tEXt`、`zTXt`、`iTXt`、`eXIf` 或 `iCCP`
- **CRC errors** 或格式错误的 chunk 长度
- `IEND` 之后的**额外数据**
- **多个 `IEND` 标记**，或文件正式结束后仍可恢复的 `IDAT` fragments
- 一个既是有效 PNG，**同时在 carving 时又呈现为 ZIP/PDF/script** 的文件

请记住，最小的有效结构通常是：

- `IHDR`（必须是第一个）
- `IDAT`（一个或多个连续的 chunks）
- `IEND`（必须是最后一个）

## `IEND` 之后的尾随数据

最值得关注的 PNG artefacts 之一，是在最后一个 `IEND` chunk **之后追加的数据**。许多 decoders 会忽略这些数据，因此它们可用于：

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- 从存在 bug 的编辑器中**恢复旧的图像数据**

快速检测：
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
如果你想提取最终 `IEND` 之后的所有内容：
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
还可以直接对 PNG 或 carve 出的尾部尝试使用通用归档解析器：
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style cropped/redacted screenshot recovery

A very practical recent PNG forensic trick is checking whether a screenshot editor **overwrote** a PNG without **truncating** the old file first. In those cases, bytes from the **previous image** can remain after `IEND`, and sometimes extra `IDAT` data can be partially reconstructed.

This became well known with **aCropalypse** (Google Pixel Markup) and the related **Windows Snipping Tool** issue. In practice, if a "cropped" or "redacted" PNG still contains old trailing data, you may be able to recover part of the original screenshot.<sup>[[1]](#references)</sup>

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
强烈证明需要进行更深入分析的迹象：

- `pngcheck` 报告 **`IEND` 之后存在额外数据**
- 发现 **多个 `IEND`**
- 在图像表面结束位置之后发现 **额外的 `IDAT` chunks**
- 截图来自已知受影响的设备/编辑器

如果出现这种情况，在认为修订内容可信之前，先将文件交给 **aCropalypse recovery tool** 处理。

## 实际中值得关注的 chunk abuse

调查中最有趣的 PNG chunks 通常不是显而易见的图像 chunks，而是能够携带 **文本**、**metadata** 或 **payload bytes** 的 chunks：

- `tEXt` / `zTXt` / `iTXt` – 文本 metadata 和压缩文本
- `eXIf` – PNG 内的 EXIF 数据
- `iCCP` – 嵌入的 ICC profile
- `PLTE` – indexed images 中的 palette data，同时也适用于 payload-smuggling 场景<sup>[[2]](#references)</sup>

使用以下命令将它们导出：
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
对于在 PNG chunks（例如能够绕过某些 PHP image transformations 的 **PLTE**、**IDAT** 或 **tEXt** tricks）中实现 offensive payload persistence，请参阅这里更详细的 upload-focused notes<sup>[[2]](#references)</sup>：

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

如需检查完整性并定位确切的损坏区域，**pngcheck** 仍然是最好的首选工具之一：

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

如果文件是损坏的，而非有意构造的 malicious 文件，**PCRT** 可用于 CTF 和 lab work，修复 bad headers、错误的 IHDR values、CRC problems 或 malformed chunk layouts 等常见问题。

如果你的目标是对包含可疑 trailer data 的 PNG 进行 **sanitize**，同时保留可见图像，ExifTool 可以显式移除 trailer：
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
对于敏感证据，始终在**副本**上操作，并在尝试修复之前保留原始文件的哈希值。

## References

- [1] [Exploiting aCropalypse: Recovering Truncated PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: How to inject PHP code in an image – and keep it there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
