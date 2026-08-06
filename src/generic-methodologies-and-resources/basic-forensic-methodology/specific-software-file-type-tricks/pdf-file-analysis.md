# PDF 文件分析

{{#include ../../../banners/hacktricks-training.md}}

**如需进一步了解，请查看：** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF 格式因其复杂性和隐藏数据的潜力而闻名，是 CTF forensics 挑战的重点对象。它将纯文本元素与二进制对象结合在一起，这些对象可能经过压缩或加密，还可以包含 JavaScript 或 Flash 等语言的脚本。要了解 PDF 结构，可以参考 Didier Stevens 的[介绍性材料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)，也可以使用文本编辑器或 Origami 等 PDF 专用编辑器。

要深入探索或操作 PDF，可以使用 [qpdf](https://github.com/qpdf/qpdf) 和 [Origami](https://github.com/mobmewireless/origami-pdf) 等工具。PDF 中的隐藏数据可能被藏在：

- 不可见图层中
- Adobe 的 XMP 元数据格式中
- 增量生成内容中
- 与背景颜色相同的文本中
- 图像后方的文本或相互重叠的图像中
- 不显示的注释中

对于定制化 PDF 分析，可以使用 [PeepDF](https://github.com/jesparza/peepdf) 等 Python 库来编写专用解析脚本。此外，PDF 隐藏数据存储的潜力非常大，因此像 NSA 发布的 PDF 风险与对策指南这类资源，尽管已不再托管于其原始位置，仍然具有很高的参考价值。[该指南的副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)以及 Ange Albertini 收集的 [PDF 格式 tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)也可提供进一步阅读材料。

## 常见恶意构造

攻击者经常滥用特定的 PDF 对象和操作，使其在文档打开或用户交互时自动执行。值得搜索的关键词包括：

* **/OpenAction, /AA** – 在打开时或特定事件发生时执行的自动操作。
* **/JS, /JavaScript** – 嵌入的 JavaScript（通常经过混淆处理，或拆分到多个对象中）。
* **/Launch, /SubmitForm, /URI, /GoToE** – 外部进程 / URL 启动器。
* **/RichMedia, /Flash, /3D** – 可能隐藏 payload 的多媒体对象。
* **/EmbeddedFile /Filespec** – 文件附件（EXE、DLL、OLE 等）。
* **/ObjStm, /XFA, /AcroForm** – 经常被滥用于隐藏 shell-code 的对象流或表单。
* **增量更新** – 多个 %%EOF 标记或非常大的 **/Prev** 偏移量，可能表示在签名后追加了数据，以绕过 AV。

当前述 token 与可疑字符串（powershell、cmd.exe、calc.exe、base64 等）同时出现时，应对该 PDF 进行更深入的分析。

---

## 静态分析速查表
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
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
* **pdfcpu** – 能够对 PDF 执行 *lint*、*decrypt*、*extract*、*compress* 和 *sanitize* 的 Go library/CLI。
* **pdf-inspector** – 基于 browser 的 visualizer，可渲染 object graph 和 streams。
* **PyMuPDF (fitz)** – 可编写脚本的 Python engine，能够在 hardened sandbox 中安全地将页面渲染为图像，以 detonate embedded JS。

---

## 近期 attack techniques（2023-2025）

* **MalDoc in PDF polyglot（2023）** – JPCERT/CC 观察到 threat actors 在最终 **%%EOF** 之后追加基于 MHT、包含 VBA macros 的 Word document，从而生成同时为有效 PDF 和有效 DOC 的文件。仅解析 PDF layer 的 AV engines 会遗漏 macro。静态 PDF keywords 是干净的，但 `file` 仍会打印 `%PDF`。任何同时包含字符串 `<w:WordDocument>` 的 PDF 都应视为高度可疑。<sup>[[2]](#references)</sup>
* **Shadow-incremental updates（2024）** – adversaries 滥用 incremental update 功能，在保留 benign first revision 签名的同时，插入第二个带有恶意 `/OpenAction` 的 **/Catalog**。只检查第一个 xref table 的 tools 会被绕过。
* **Font parsing UAF chain – CVE-2024-30284（Acrobat/Reader）** – 可通过 embedded CIDType2 fonts 触发存在漏洞的 **CoolType.dll** function；打开 crafted document 后，攻击者可凭借 user 的权限实现 remote code execution。已在 APSB24-29（2024 年 5 月）中修复。<sup>[[3]](#references)</sup>

---

## YARA 快速规则模板
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

1. **快速打补丁** – 让 Acrobat/Reader 始终保持在最新的 Continuous track；实际环境中观察到的大多数 RCE 链都利用了数月前已经修复的 n-day 漏洞。
2. **在网关剥离 active content** – 使用 `pdfcpu sanitize` 或 `qpdf --qdf --remove-unreferenced`，从入站 PDF 中删除 JavaScript、嵌入文件和启动操作。
3. **Content Disarm & Reconstruction (CDR)** – 在 sandbox 主机上将 PDF 转换为图像（或 PDF/A），在保持视觉一致性的同时丢弃 active objects。
4. **禁用不常用功能** – Reader 的企业版“Enhanced Security”设置允许禁用 JavaScript、多媒体和 3D 渲染。
5. **用户教育** – social engineering（发票和简历诱饵）仍然是 initial vector；应培训员工将可疑附件转发给 IR。

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
