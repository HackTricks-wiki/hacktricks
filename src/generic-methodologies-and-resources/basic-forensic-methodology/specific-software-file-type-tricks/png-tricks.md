# PNG Tricks

**PNG files** 在 **CTFs**、**incident response** 和 **malware staging** 中非常常见，因为它们是**无损**、**基于 chunk** 的，并且即使包含**额外 metadata**、**追加的 payload** 或**部分损坏的 chunks**，许多工具仍会正常渲染它们。

应将 PNG 视为一个**容器**，而不仅仅是一张图像。

## Quick triage

在进行 LSB stego 之前，先执行容器级检查。关于 bit-plane/LSB 工作流，请查看[专用的图像 stego 页面](../../../stego/images/README.md)。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
需要重点检查的内容：

- **意外的附加 chunks**，例如 `tEXt`、`zTXt`、`iTXt`、`eXIf` 或 `iCCP`
- **CRC errors** 或格式错误的 chunk 长度
- `IEND` 之后的**额外数据**
- **多个 `IEND` 标记**，或文件正式结束后仍可恢复的 `IDAT` 片段
- 一个文件既是有效的 PNG，**在进行 carving 时**又表现得像 ZIP/PDF/脚本

请记住，最小的有效结构通常是：

- `IHDR`（必须位于第一位）
- `IDAT`（一个或多个连续 chunks）
- `IEND`（必须位于最后）

## `IEND` 之后的尾随数据

PNG 中信号最强的 artefacts 之一，是**最终 `IEND` chunk 之后附加的数据**。许多 decoder 会忽略这些数据，因此它们可用于：

- **简单 stego / 隐藏 payloads**
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
还可以直接对 PNG 或提取出的尾部使用通用归档解析器：
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse 风格的裁剪/打码截图恢复

一个非常实用的近期 PNG 取证技巧，是检查截图编辑器是否在**未先截断**旧文件的情况下**覆盖**了 PNG。在这种情况下，**旧图像**的字节可能会保留在 `IEND` 之后，有时还可以部分重建额外的 `IDAT` 数据。

这一问题因 **aCropalypse**（Google Pixel Markup）以及相关的 **Windows Snipping Tool** 问题而广为人知。<sup>[[3]](#references)</sup> 实际上，如果一张“裁剪过”或“打码过”的 PNG 仍包含旧的尾部数据，你可能能够恢复原始截图的一部分。<sup>[[1]](#references)</sup>

实用流程：
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
强烈说明需要进行深入分析的迹象：

- `pngcheck` 报告 **`IEND` 后存在额外数据**
- 发现 **多个 `IEND`**
- 在图像表面结束位置之后发现 **额外的 `IDAT` chunks**
- 截图来自已知受影响的设备/editor

如果出现这种情况，在认为 redaction 可信之前，应先将文件交给 **aCropalypse recovery tool** 处理。

## 实际中值得关注的 Chunk abuse

对调查而言，最有趣的 PNG chunks 通常不是明显的图像 chunks，而是可以携带 **文本**、**metadata** 或 **payload bytes** 的 chunks：

- `tEXt` / `zTXt` / `iTXt` – 文本 metadata 和压缩文本
- `eXIf` – PNG 内的 EXIF 数据
- `iCCP` – 嵌入的 ICC profile
- `PLTE` – indexed images 中的 palette data，但在 payload-smuggling 场景中也很有用。<sup>[[2]](#references)</sup>

使用以下命令将其导出：
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
对于在 PNG chunks 中实现 offensive payload persistence（例如能够在某些 PHP image transformations 后保留的 **PLTE**、**IDAT** 或 **tEXt** tricks），请查看这里更详细的、专注于 upload 的 notes：<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

要检查完整性并定位确切的损坏区域，**pngcheck** 仍然是最佳的首选工具之一：

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

如果文件是损坏的，而不是故意构造的恶意文件，那么在 CTF 和实验环境中，**PCRT** 可用于修复常见问题，例如错误的 headers、错误的 IHDR 值、CRC 问题或格式错误的 chunk layouts。

如果你的目标是对包含可疑 trailer data 的 PNG 进行 **sanitize**，同时保留可见图像，ExifTool 可以明确移除该 trailer：
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
对于敏感证据，始终在**副本**上操作，并在尝试修复之前保留原始文件的哈希值。

## References

- [1] [利用 aCropalypse：恢复被截断的 PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG 中的持久 PHP payload：如何在图像中注入 PHP 代码并使其保留其中](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
