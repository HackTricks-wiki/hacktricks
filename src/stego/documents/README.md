# 文档隐写术

{{#include ../../banners/hacktricks-training.md}}

许多文档格式是结构化容器，而不是单一的数据流：<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF（嵌入文件、streams）
- Office OOXML（`.docx/.xlsx/.pptx` 是 ZIPs）
- Legacy RTF 和 OLE/Compound File Binary 文档。RTF 以面向文本的格式存储 control words 和 groups，而 OLE compound files 则以类似文件系统的层次结构公开 storage objects 和 streams；两者都需要针对格式进行检查，以发现隐藏或嵌入的数据。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technique

PDF 文件可以包含 objects、streams、JavaScript 和嵌入文件。分析期间，常见任务包括：

- 提取嵌入的 attachments。
- 展开 object streams，以便更轻松地检查 objects。
- 识别 JavaScript、嵌入的 images 和异常的 streams。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### 快速检查
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
`--qdf --object-streams=disable` 组合会生成更易读的表示形式并移除 object streams，从而便于手动检查。<sup>[[2]](#references)</sup> 然后搜索 `out.pdf` 中可疑的对象和字符串。

## Office OOXML

### 技术

Office Open XML 文件（`.docx`、`.xlsx` 和 `.pptx`）使用 Open Packaging Conventions：一种基于 ZIP 的 package，由各个部件和 XML relationship 文件组成。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> 将 package 视为 relationship graph，并检查媒体、external relationships 和异常的 custom parts。

实际操作中：

- 文档是由 XML 和 assets 构成的目录树。
- `_rels/` relationship 文件可以指向 external resources 或隐藏的 parts。
- Embedded data 通常位于 `word/media/`、custom XML parts 或异常的 relationships 中。

### 快速检查
```bash
7z l file.docx
7z x file.docx -oout
```
然后检查：

- `word/document.xml`
- `word/_rels/` 中的 external relationships
- `word/media/` 中的 embedded media

## References

- [1] [Poppler pdfdetach 手册](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf 文档 - QDF 模式和 object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions 基础](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML 文件格式](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format 简介](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF specification 参考](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
