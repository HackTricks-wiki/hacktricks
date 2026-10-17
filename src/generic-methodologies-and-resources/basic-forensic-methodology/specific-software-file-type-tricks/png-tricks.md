# PNG 技巧

{{#include ../../../banners/hacktricks-training.md}}

**PNG 文件**在 **CTF**、**事件响应**和**恶意软件投放**中非常常见，因为它们是**无损的**、基于 **chunk** 的，而且许多工具即使遇到包含**额外元数据**、**附加 payload** 或**部分损坏的 chunk** 的文件，也会照常渲染。

应将 PNG 视为**容器**，而不只是图像。

## 快速初筛

在开始 LSB 隐写分析前，先检查容器层面的问题。关于位平面/LSB 工作流，请参阅[专门的图像隐写页面](../../../stego/images/)。

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

值得检查的内容：

- **意外的辅助数据块**，例如 `tEXt`、`zTXt`、`iTXt`、`eXIf` 或 `iCCP`
- **CRC 错误**或格式错误的数据块长度
- `IEND` 后的**附加数据**
- **多个 `IEND` 标记**，或文件正式结束后可恢复的 `IDAT` 片段
- 一个既是有效 PNG，**又**能在 carve 时呈现 ZIP/PDF/脚本特征的文件

请记住，最小的有效结构通常是：

- `IHDR`（必须位于首位）
- `IDAT`（一个或多个连续的数据块）
- `IEND`（必须位于末尾）

## `IEND` 后的尾随数据

PNG 中信号最强的伪影之一，是**在最后一个 `IEND` 数据块后附加的数据**。许多解码器会忽略这些数据，因此它们可用于：

- **简单的 stego / 隐藏载荷**
- **PNG polyglots**
- **恶意软件暂存**
- 从有缺陷的编辑器中**恢复旧图像数据**

快速检测：

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

对 `IEND` 进行字节搜索只能作为线索：相同的字节可能出现在 chunk 数据或伪造的尾部中。若要可靠地提取数据，应从 PNG 签名开始遍历带长度前缀的 chunk，并在遇到第一个结构有效的 `IEND` 时停止；[下面的 chunk 遍历器](#extract-ancillary-chunk-payloads)也会保存尾部内容。<sup>[[6]](#references)</sup>

也可以直接对 PNG 或提取出的尾部内容使用通用归档解析器：

```bash
7z l suspect.png
unzip -l suspect.png
```

## 类似 Acropalypse 的裁剪/涂黑截图恢复

一种非常实用的近期 PNG 取证技巧，是检查截图编辑器是否在**未先截断**旧文件的情况下**覆盖**了 PNG。在这种情况下，来自**先前图像**的字节可能会残留在 `IEND` 之后，有时还能部分重建额外的 `IDAT` 数据。

这一问题因 **aCropalypse**（Google Pixel Markup）及相关的 **Windows Snipping Tool** 问题而广为人知。<sup>[[3]](#references)</sup> 实际操作中，如果被“裁剪”或“涂黑”的 PNG 仍包含旧的尾随数据，你或许能恢复原始截图的部分内容。<sup>[[1]](#references)</sup>

实用工作流程：

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

值得进一步深入分析的强烈迹象：

- `pngcheck` 报告 **`IEND` 之后存在额外数据**
- 发现 **多个 `IEND`**
- 在图像表面上的结尾之后发现 **额外的 `IDAT` 块**
- 截图来自已知受过影响的设备/编辑器

如果出现这种情况，在将涂黑处理视为可信之前，先使用 **aCropalypse recovery tool** 处理该文件。

## 实际中值得关注的块滥用

调查中最有趣的 PNG 块通常不是显而易见的图像块，而是可能携带 **文本**、**元数据**或 **payload 字节**的块：

- `tEXt` / `zTXt` / `iTXt` – 文本元数据和压缩文本
- `eXIf` – PNG 内的 EXIF 数据
- `iCCP` – 嵌入的 ICC 配置文件
- `PLTE` – 索引图像中的调色板数据，也可用于 payload 走私场景。<sup>[[2]](#references)</sup>

使用以下命令转储它们：

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

对于在 PNG chunks 中持久化攻击 payload（例如能在某些 PHP 图像转换后保留的 **PLTE**、**IDAT** 或 **tEXt** tricks），请查看这里更详细的、侧重文件上传的笔记：<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 提取辅助 chunk payload

攻击者可以在 `IEND` 之前的**未知辅助 chunk**中放置任意字节。普通 PNG 解码器可以忽略未知辅助 chunk，而将图像作为字节获取的脚本则可以读取并使用其中的 payload；仅打开 PNG 不会执行它。<sup>[[4]](#references)[[6]](#references)</sup> 原始研究展示了一个经过压缩和加密的自定义 chunk。<sup>[[4]](#references)</sup> 后续的浏览器示例使用提取出的字节来提供 HTML 或下载内容。<sup>[[5]](#references)</sup>

chunk 类型的首字母为小写时表示 *辅助*；第二个字母为小写时表示 *私有*。例如，`paMP` 是私有的，而 `pAMP` 使用公共命名空间，尽管后者是为该演示而发明的。<sup>[[4]](#references)[[6]](#references)</sup> 一个 chunk 的结构为 `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`；CRC 覆盖 type 和 data。应解析此结构，而不是在压缩的 `IDAT` 数据中搜索类型名称。以下遍历器会验证边界和 CRC，将辅助 payload 导出为原始字节，并将结构性 `IEND` 之后的所有字节写入 `png-trailer.bin`。<sup>[[6]](#references)</sup>

<details>
<summary>提取辅助 chunks 和 PNG 尾随数据</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

使用 `file`、`strings` 或 `binwalk` 检查提取出的字节；只有载体确实经过压缩时才进行解压。<sup>[[4]](#references)</sup> 重新编码可能会剥离载体，因此在依赖它之前，请比较上传和取回的字节。<sup>[[2]](#references)[[6]](#references)</sup>

## 损坏 PNG 修复

要检查完整性并定位确切的损坏区域，**pngcheck** 仍是最好的首选工具之一：

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

如果文件是损坏而非故意恶意的，**PCRT** 在 CTF 和实验环境中可用于修复常见问题，例如错误的头部、错误的 IHDR 值、CRC 问题或格式错误的块布局。

如果你的目标是**清理**包含可疑尾随数据的 PNG，同时保留可见图像，ExifTool 可以明确移除尾随数据：

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

对于敏感证据，务必使用**副本**，并在尝试修复前保存原始文件的哈希值。



## References

- [1] [利用 aCropalypse：恢复被截断的 PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG 中的持久 PHP payload：如何在图像中注入 PHP 代码并使其留存](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [辅助数据块是存放敏感信息的理想位置](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [使用有效的辅助数据块向端点偷运数据](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [可移植网络图形（PNG）规范（第三版）](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
