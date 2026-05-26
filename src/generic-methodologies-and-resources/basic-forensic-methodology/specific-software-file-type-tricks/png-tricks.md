# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG 文件**在 **CTF**、**incident response** 和 **malware staging** 中非常常见，因为它们是**无损**的、**基于 chunk** 的，而且即使包含**额外元数据**、**附加 payload** 或**部分损坏的 chunk**，许多工具也能正常渲染它们。

将 PNG 视为一个**容器**，而不仅仅是一张图像。

## 快速分流

在进入 LSB stego 之前，先进行容器级检查。关于 bit-plane/LSB 工作流，请查看[专门的图像 stego 页面](../../../stego/images/README.md)。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
要查找的有用内容：

- **Unexpected 辅助 chunks**，例如 `tEXt`、`zTXt`、`iTXt`、`eXIf` 或 `iCCP`
- **CRC errors** 或格式错误的 chunk length
- **`IEND` 之后的额外数据**
- **多个 `IEND` 标记**，或在文件正式结束后仍可恢复的 `IDAT` 片段
- 既是有效 PNG，**又**在 carve 后看起来像 ZIP/PDF/script 的文件

记住，最小有效结构通常是：

- `IHDR`（必须第一个）
- `IDAT`（一个或多个连续 chunks）
- `IEND`（必须最后）

## `IEND` 之后的尾随数据

PNG 中最有信号的 artefacts 之一是 **附加在最后一个 `IEND` chunk 之后的数据**。很多 decoders 会忽略它，因此它可用于：

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **从有 bug 的 editors 中恢复更早的图像数据**

快速检测：
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
如果你想切出最后一个 `IEND` 之后的所有内容：
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
也可以直接用 generic archive parsers 针对 PNG 或者 carved trailer 进行尝试：
```bash
7z l suspect.png
unzip -l suspect.png
```
## 截图裁剪/遮挡后的 Acropalypse 风格恢复

一种非常实用的近期 PNG 取证技巧，是检查截图编辑器是否在**不先截断**旧文件的情况下直接**覆盖**了一个 PNG。在这种情况下，来自**上一张图像**的字节可能会保留在 `IEND` 之后，而且有时还能部分重建额外的 `IDAT` 数据。

这在 **aCropalypse**（Google Pixel Markup）以及相关的 **Windows Snipping Tool** 问题中变得广为人知。实际中，如果一个“裁剪后”或“已遮挡”的 PNG 仍然包含旧的尾随数据，你可能能够恢复原始截图的一部分。

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
识别出强烈需要进一步分析的迹象：

- `pngcheck` 报告 **`IEND` 之后还有额外数据**
- 你发现 **不止一个 `IEND`**
- 你发现 **看起来在图像结束后还有额外的 `IDAT` chunk**
- 截图来自一个已知受影响的设备/editor

如果发生这种情况，在把 redaction 视为可信之前，先把文件交给 **aCropalypse recovery tool**。

## 实战中重要的 chunk 滥用

在调查中，最值得关注的 PNG chunk 通常不是显眼的图像 chunk，而是那些可以携带 **text**、**metadata** 或 **payload bytes** 的 chunk：

- `tEXt` / `zTXt` / `iTXt` – text metadata 和 compressed text
- `eXIf` – PNG 内的 EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images 中的 palette data，但也常用于 payload-smuggling 场景

用以下方式 dump 它们：
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
对于在 PNG chunks 中持久化 offensive payload（例如 **PLTE**、**IDAT** 或 **tEXt** tricks，即便经过某些 PHP image transformations 也能保留），请查看这里更详细的 upload-focused notes：

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

要检查完整性并定位具体损坏区域，**pngcheck** 仍然是最好的首选工具之一：

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

如果文件是 damaged 而不是 intentionally malicious，那么 **PCRT** 在 CTFs 和 lab work 中会很有用，可用于修复常见问题，例如 bad headers、wrong IHDR values、CRC problems，或 malformed chunk layouts。

如果你的目标是 **sanitize** 一个包含 suspicious trailer data 但又要保留可见图像的 PNG，ExifTool 可以明确移除 trailer：
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
对于敏感证据，始终在**副本**上操作，并在尝试修复之前保留原始文件的 hash。

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
