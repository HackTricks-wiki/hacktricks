# 文档隐写术

{{#include ../../banners/hacktricks-training.md}}

许多文档格式都是结构化容器，而非单一数据流：<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF（嵌入文件、流）
- Office OOXML（`.docx/.xlsx/.pptx` 是 ZIP 文件）
- 旧版 RTF 和 OLE/复合文件二进制文档。RTF 以面向文本的格式存储控制字和分组，而 OLE 复合文件则呈现类似文件系统的存储对象和流层级；两者都需要针对各自格式检查隐藏或嵌入的数据。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### 技术

PDF 文件可以包含对象、流、JavaScript 和嵌入文件。分析时常见的任务包括：

- 提取嵌入的附件。
- 展开对象流，以便更轻松地检查对象。
- 识别 JavaScript、嵌入图像和异常流。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### 快速检查

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

`--qdf --object-streams=disable` 组合会生成更易读的表示形式，并移除 object streams，从而便于手动检查。<sup>[[2]](#references)</sup> 然后在 `out.pdf` 中搜索可疑对象和字符串。

## Office OOXML

### 技术

Office Open XML 文件（`.docx`、`.xlsx` 和 `.pptx`）使用 Open Packaging Conventions：一种基于 ZIP 的包，由各个部件和 XML 关系文件组成。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> 将该包视为关系图，并检查媒体、外部关系和异常的自定义部件。

实际检查时：

- 文档由 XML 和资源组成的目录树构成。
- `_rels/` 关系文件可能指向外部资源或隐藏部件。
- 嵌入数据通常位于 `word/media/`、自定义 XML 部件或异常关系中。

### 快速检查

```bash
7z l file.docx
7z x file.docx -oout
```

然后检查：

- `word/document.xml`
- `word/_rels/` 中的外部关系
- `word/media/` 中的嵌入媒体

## References

- [1] [Poppler pdfdetach 手册](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf 文档 - QDF 模式和对象流](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions 基础知识](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML 文件格式](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary 文件格式简介](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF 规范参考](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
