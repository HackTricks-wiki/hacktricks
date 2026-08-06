# 文档隐写术

{{#include ../../banners/hacktricks-training.md}}

文档通常只是容器：

- PDF（嵌入文件、流）
- Office OOXML（`.docx/.xlsx/.pptx` 是 ZIP）
- RTF / OLE legacy formats

## PDF

### Technique

PDF 是一种结构化容器，包含对象、流以及可选的嵌入文件。在 CTFs 中，你通常需要：

- 提取嵌入式附件
- 解压缩/扁平化对象流，以便搜索内容
- 识别隐藏对象（JS、嵌入图像、异常流）

### 快速检查
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
然后在 `out.pdf` 中搜索可疑的对象/字符串。

## Office OOXML

### Technique

将 OOXML 视为 ZIP + XML relationship graph；payload 通常隐藏在 media、relationships 或异常的 custom parts 中。

OOXML 文件是 ZIP 容器。这意味着：

- 文档是由 XML 和 assets 组成的目录树。
- `_rels/` relationship 文件可以指向 external resources 或 hidden parts。
- Embedded data 经常位于 `word/media/`、custom XML parts 或异常的 relationships 中。

### Quick checks
```bash
7z l file.docx
7z x file.docx -oout
```
然后检查：

- `word/document.xml`
- `word/_rels/` 中的 external relationships
- `word/media/` 中的 embedded media


{{#include ../../banners/hacktricks-training.md}}
