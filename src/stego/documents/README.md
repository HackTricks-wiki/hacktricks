# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

文档通常只是容器：

- PDF（嵌入的文件、流）
- Office OOXML (`.docx/.xlsx/.pptx` 是 ZIP 包)
- RTF / OLE 旧格式

## PDF

### 方法

PDF 是一个结构化的容器，包含对象、流，以及可选的嵌入文件。在 CTFs 中你经常需要：

- 提取嵌入的附件
- 解压/展开对象流，以便搜索内容
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

### 技术

将 OOXML 视为一个 ZIP + XML 的关系图；payloads 常常隐藏在媒体、关系或不寻常的自定义部件中。

OOXML 文件是 ZIP 容器。这意味着：

- 文档是由 XML 和资源组成的目录树。
- `_rels/` relationship 文件可以指向外部资源或隐藏的部分。
- 嵌入数据通常存在于 `word/media/`、自定义 XML 部分，或不常见的关系。

### 快速检查
```bash
7z l file.docx
7z x file.docx -oout
```
然后检查：

- `word/document.xml`
- `word/_rels/` 以查找外部关系
- 位于 `word/media/` 的嵌入媒体

{{#include ../../banners/hacktricks-training.md}}
