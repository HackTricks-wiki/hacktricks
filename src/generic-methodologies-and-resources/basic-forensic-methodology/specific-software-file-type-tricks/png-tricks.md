# PNG 技巧

{{#include ../../../banners/hacktricks-training.md}}

**PNG 文件**在 **CTF**、**事件响应**和**恶意软件 staging** 中非常常见，因为它们是**无损的**、**基于 chunk 的**，而且许多工具即使在文件包含**额外元数据**、**附加 payload**或**部分损坏的 chunk**时，也会正常渲染它们。

将 PNG 视为一个**容器**，而不只是图像。

## 快速初步检查

在开始 LSB stego 之前，先进行容器级检查。关于 bit-plane/LSB 工作流，请查看[专门的图像 stego 页面](../../../stego/images/README.md)。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
需要重点检查的内容：

- **意外的辅助数据块**，例如 `tEXt`、`zTXt`、`iTXt`、`eXIf` 或 `iCCP`
- **CRC 错误**或格式错误的数据块长度
- **`IEND` 之后的额外数据**
- **多个 `IEND` 标记**，或文件正式结束后仍可恢复的 `IDAT` 片段
- 一个既是有效 PNG，**又能在 carving 时表现为 ZIP/PDF/script 的文件**

请记住，最小的有效结构通常是：

- `IHDR`（必须是第一个）
- `IDAT`（一个或多个连续的数据块）
- `IEND`（必须是最后一个）

## `IEND` 之后的尾随数据

最值得关注的 PNG artefact 之一，是**在最后一个 `IEND` 数据块之后附加的数据**。许多解码器会忽略这些数据，因此它们可用于：

- **简单 stego / 隐藏 payload**
- **PNG polyglots**
- **Malware staging**
- **从存在缺陷的编辑器中恢复旧图像数据**

快速检测：
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
如果你想 carve 出最终 `IEND` 之后的所有内容：
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
也可直接对 PNG 或提取出的尾部数据尝试通用归档解析器：
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style cropped/redacted screenshot recovery

A very practical recent PNG forensic trick is checking whether a screenshot editor **overwrote** a PNG without **truncating** the old file first. In those cases, bytes from the **previous image** can remain after `IEND`, and sometimes extra `IDAT` data can be partially reconstructed.

This became well known with **aCropalypse** (Google Pixel Markup) and the related **Windows Snipping Tool** issue.<sup>[[3]](#references)</sup> In practice, if a "cropped" or "redacted" PNG still contains old trailing data, you may be able to recover part of the original screenshot.<sup>[[1]](#references)</sup>

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
强烈表明需要进行更深入分析的迹象：

- `pngcheck` 报告 **`IEND` 后存在额外数据**
- 发现 **多于一个 `IEND`**
- 在图像表面结束位置之后发现 **额外的 `IDAT` chunks**
- 截图来自已知受过影响的设备/编辑器

如果出现这种情况，请先将文件交给 **aCropalypse recovery tool**，然后再判断其遮挡是否可信。

## 实际中值得关注的 chunk 滥用

对调查而言，最有趣的 PNG chunks 通常不是显而易见的图像 chunks，而是那些可以携带 **文本**、**metadata** 或 **payload 字节**的 chunks：

- `tEXt` / `zTXt` / `iTXt` – 文本 metadata 和压缩文本
- `eXIf` – PNG 内的 EXIF 数据
- `iCCP` – 嵌入的 ICC profile
- `PLTE` – 索引图像中的调色板数据，也适用于 payload-smuggling 场景。<sup>[[2]](#references)</sup>

使用以下命令转储它们：
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
对于在 PNG chunks 中实现 offensive payload persistence（例如能够在某些 PHP image transformations 后仍然保留的 **PLTE**、**IDAT** 或 **tEXt** tricks），请参阅这里更详细的、以 upload 为重点的 notes：<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

要检查完整性并定位确切的损坏区域，**pngcheck** 仍然是最好的首选工具之一：

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

如果文件是损坏的，而不是被故意构造为 malicious，**PCRT** 可用于 CTF 和 lab work，修复常见问题，例如错误的 headers、错误的 IHDR values、CRC problems 或格式错误的 chunk layouts。

如果你的目标是对包含可疑 trailer data 的 PNG 进行 **sanitize**，同时保留可见图像，ExifTool 可以明确移除 trailer：
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
对于敏感证据，始终在**副本**上操作，并在尝试修复之前保留原始文件的哈希值。

## References

- [1] [利用 aCropalypse：恢复被截断的 PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG 中的持久 PHP payload：如何将 PHP 代码注入图像并使其保留其中](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
