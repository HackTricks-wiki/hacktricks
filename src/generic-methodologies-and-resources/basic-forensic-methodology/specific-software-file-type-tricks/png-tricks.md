# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** 在 **CTFs**、**incident response** 和 **malware staging** 中非常常见，因为它们是 **lossless**、**chunk-based** 的，而且许多工具即使在其中包含 **extra metadata**、**appended payloads** 或 **partially corrupted chunks** 时也能正常渲染。

把 PNG 当作一个 **container**，而不只是一个图像。

## Quick triage

先进行 container-level 检查，再去做 LSB stego。关于 bit-plane/LSB workflow，请查看 [the dedicated image stego page](../../../stego/images/README.md)。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Useful things to look for:

- **Unexpected ancillary chunks** such as `tEXt`, `zTXt`, `iTXt`, `eXIf`, or `iCCP`
- **CRC errors** or malformed chunk lengths
- **Additional data after `IEND`**
- **Multiple `IEND` markers** or recoverable `IDAT` fragments after the formal end of the file
- A file that is a valid PNG **and** also looks like a ZIP/PDF/script when carved

Remember the minimum valid structure is usually:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## `IEND` 后的尾随数据

最有信号的 PNG 取证痕迹之一是 **在最终 `IEND` chunk 之后追加的数据**。许多解码器会忽略它，因此它很适合用于：

- **简单 stego / 隐藏 payload**
- **PNG polyglots**
- **Malware staging**
- **从有 bug 的编辑器中恢复旧图像数据**

快速检测：
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
如果你想把最后一个 `IEND` 之后的所有内容都切出来：
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
也可以直接将 generic archive parsers 用于 PNG 或 carved trailer：
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style recovery of cropped/redacted screenshots

一个非常实用的近期 PNG forensic 技巧是检查截图编辑器是否在**未先截断**旧文件的情况下直接**覆盖**了一个 PNG。在这种情况下，来自**前一张图像**的字节可能会保留在 `IEND` 之后，有时还能部分重建额外的 `IDAT` 数据。

这类问题因 **aCropalypse**（Google Pixel Markup）以及相关的 **Windows Snipping Tool** 问题而广为人知。实际中，如果一个“cropped”或“redacted” PNG 仍然包含旧的尾随数据，你可能能够恢复原始截图的一部分。

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
强烈证明需要进一步分析的迹象：

- `pngcheck` 报告 **在 `IEND` 之后还有额外数据**
- 你发现 **不止一个 `IEND`**
- 你发现 **在图像看似结束后还有额外的 `IDAT` chunks**
- 截图来自一个已知受影响的设备/编辑器

如果发生这种情况，在把 redaction 视为可信之前，先将文件交给 **aCropalypse recovery tool**。

## 在实践中重要的 Chunk abuse

用于调查时，最有意思的 PNG chunks 通常不是那些显而易见的图像 chunks，而是那些可以携带 **text**、**metadata** 或 **payload bytes** 的 chunks：

- `tEXt` / `zTXt` / `iTXt` – text metadata 和压缩文本
- `eXIf` – PNG 内部的 EXIF data
- `iCCP` – 内嵌 ICC profile
- `PLTE` – 索引图像中的调色板数据，但在 payload-smuggling 场景中也很有用

用以下方式转储它们：
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
For offensive payload persistence inside PNG chunks (for example **PLTE**, **IDAT**, or **tEXt** tricks that survive some PHP image transformations), check the more detailed upload-focused notes here:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

For checking integrity and locating the exact broken area, **pngcheck** remains one of the best first tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

If the file is damaged rather than intentionally malicious, **PCRT** can be useful in CTFs and lab work for fixing common issues such as bad headers, wrong IHDR values, CRC problems, or malformed chunk layouts.

If your goal is to **sanitize** a PNG that contains suspicious trailer data while preserving the visible image, ExifTool can explicitly remove the trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
对于敏感 evidence，始终在 **copy** 上操作，并在尝试修复前保留 original 的 hashes。

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
