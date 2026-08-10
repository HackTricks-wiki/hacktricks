# PDF 文件分析

**更多详细信息请查看：** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)。<sup>[[1]](#references)</sup>

PDF 格式以其复杂性和隐藏数据的潜力而闻名，因此成为 CTF forensics challenges 的重点。它将纯文本元素与二进制对象结合在一起，这些对象可能经过压缩或加密，还可以包含 JavaScript 或 Flash 等语言编写的脚本。要了解 PDF 结构，可以参考 Didier Stevens 的[入门材料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)，或使用文本编辑器、Origami 等 PDF 专用编辑器。

对于 PDF 的深入探索或操作，可以使用 [qpdf](https://github.com/qpdf/qpdf) 和 [Origami](https://github.com/mobmewireless/origami-pdf) 等工具。PDF 中的隐藏数据可能隐藏在：

- 不可见层
- Adobe 的 XMP metadata 格式
- 增量生成
- 与背景颜色相同的文本
- 图像背后的文本或相互重叠的图像
- 不显示的注释

对于自定义 PDF 分析，可以使用 [PeepDF](https://github.com/jesparza/peepdf) 等 Python libraries 来编写定制的解析脚本。此外，PDF 用于存储隐藏数据的潜力非常大，因此诸如 NSA 关于 PDF risks and countermeasures 的指南虽然已不再托管于其原始位置，仍然可以提供有价值的见解。[该指南的副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)以及 Ange Albertini 编写的 [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 集合，可以提供更多相关资料。<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

攻击者经常滥用特定的 PDF objects 和 actions，使其在文档打开或交互时自动执行。值得搜索的 keywords：

* **/OpenAction, /AA** – 打开时或特定事件发生时执行的自动 actions。
* **/JS, /JavaScript** – 嵌入的 JavaScript（通常经过 obfuscated 处理，或分散在多个 objects 中）。
* **/Launch, /SubmitForm, /URI, /GoToE** – 外部 process / URL launchers。
* **/RichMedia, /Flash, /3D** – 可能隐藏 payloads 的 multimedia objects。
* **/EmbeddedFile /Filespec** – file attachments（EXE、DLL、OLE 等）。
* **/ObjStm, /XFA, /AcroForm** – 常被滥用于隐藏 shell-code 的 object streams 或 forms。
* **Incremental updates** – 多个 %%EOF markers 或非常大的 **/Prev** offset 可能表示在签名后追加了数据，以绕过 AV。

当前述 tokens 中的任意内容与可疑 strings（powershell、cmd.exe、calc.exe、base64 等）同时出现时，该 PDF 值得进行更深入的分析。

---

## Static analysis cheat-sheet

以下示例使用文档化的 `pdf-parser.py`、qpdf 和 pdfcpu command-line interfaces。<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
其他有用的项目（2023-2025 年仍在积极维护）：
* **pdfcpu** – 能够验证、解密、提取、优化和操作 PDF 的 Go library/CLI。<sup>[[9]](#references)</sup>
* **pdf-inspector** – 基于 browser 的 visualizer，可渲染 object graph 和 streams。
* **PyMuPDF** – 可编写脚本的 Python bindings，用于检查 PDF 并将页面渲染为 raster images。应将 parser/renderer 视为不可信文件 attack surface，并在适当隔离的 analysis environment 中运行。<sup>[[8]](#references)</sup>

---

## 最新的 attack techniques（2023-2025）

* **MalDoc in PDF polyglot（2023）** – JPCERT/CC 报告了一种 technique：将由 Word 创建的、包含 VBA macros 的 MHT file 附加到 PDF 中，使其保留 PDF magic，同时也能在 Word 中打开。仅进行 PDF 分析的 tools、sandboxes 或 antivirus 可能会漏掉该 macro，因为 malicious behavior 发生在以 Word 打开文件时；应在其他 MHT indicators 旁查找 `<w:WordDocument>` marker。<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackers 可以在 PDF 签名之前放置 hidden content，然后附加一个 incremental update，修改 catalog 或 object references，使 viewers 显示 hidden content，同时原始 signature 仍保持 valid。该 technique 可以绕过将此类 updates 归类为 harmless 的 viewers。<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284（Acrobat/Reader）** – Adobe 将此 critical vulnerability 评定为 use-after-free，可能导致 arbitrary code execution；APSB24-29 于 2024 年 5 月 14 日发布。<sup>[[3]](#references)</sup>

---

## YARA quick rule template
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## 防御建议

1. **快速打补丁** – 让 Acrobat/Reader 保持在最新的 Continuous track；在野外观察到的大多数 RCE 链都利用了数月前已修复的 n-day 漏洞。
2. **在网关剥离 active content** – 使用专用且由策略控制的 sanitizer 或 CDR 产品，并明确移除 JavaScript、嵌入文件、launch actions、表单和多媒体。`qpdf --qdf` 可让 PDF 对象更易于检查，而 pdfcpu 提供验证和操作功能；单独使用这两个命令都不能证明 active content 已被移除。<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – 在 sandbox 主机上将 PDF 转换为图像（或 PDF/A），在保留视觉保真度的同时丢弃 active objects。
4. **阻止很少使用的功能** – Reader 中的企业级 “Enhanced Security” 设置允许禁用 JavaScript、多媒体和 3D 渲染。
5. **用户教育** – social engineering（发票和简历诱饵）仍然是初始攻击向量；应培训员工将可疑附件转发给 IR。

## References

- [1] [Forensics CTF 现场指南](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – 通过将恶意 Word 文件嵌入 PDF 文件来绕过检测](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat 和 Reader 的安全更新可用（APSB24-29）](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - 指南副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF 格式技巧](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: 隐藏和替换已签名 PDF 中的内容](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF 教程](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf 命令行选项](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
