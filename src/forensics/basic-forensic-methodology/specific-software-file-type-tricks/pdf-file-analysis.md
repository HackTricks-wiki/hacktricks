# PDF 文件分析

{{#include ../../../banners/hacktricks-training.md}}

**有关更多详细信息，请查看：** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF 格式因其复杂性和潜在的数据隐藏能力而闻名，使其成为 CTF 取证挑战的焦点。它结合了纯文本元素和二进制对象，这些对象可能被压缩或加密，并且可以包含 JavaScript 或 Flash 等语言的脚本。要理解 PDF 结构，可以参考 Didier Stevens 的 [入门材料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)，或使用文本编辑器或 PDF 专用编辑器如 Origami。

对于 PDF 的深入探索或操作，可以使用 [qpdf](https://github.com/qpdf/qpdf) 和 [Origami](https://github.com/mobmewireless/origami-pdf) 等工具。PDF 中的隐藏数据可能隐藏在：

- 隐形图层
- Adobe 的 XMP 元数据格式
- 增量生成
- 与背景颜色相同的文本
- 图像后面的文本或重叠的图像
- 不显示的注释

对于自定义 PDF 分析，可以使用 Python 库如 [PeepDF](https://github.com/jesparza/peepdf) 来制作定制的解析脚本。此外，PDF 隐藏数据存储的潜力非常巨大，以至于像 NSA 关于 PDF 风险和对策的指南，尽管不再托管在其原始位置，但仍提供了有价值的见解。可以参考 [该指南的副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) 和 Ange Albertini 的 [PDF 格式技巧集合](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 以获取更多相关阅读。

{{#include ../../../banners/hacktricks-training.md}}
