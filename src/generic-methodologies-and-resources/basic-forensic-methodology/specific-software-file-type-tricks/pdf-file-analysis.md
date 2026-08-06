# PDF 文件分析

{{#include ../../../banners/hacktricks-training.md}}

**For further details check:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF 格式以其复杂性和隐藏数据的潜力而闻名，因此成为 CTF forensics 挑战的重点。它将纯文本元素与二进制对象结合在一起，这些对象可能经过压缩或加密，并且可以包含 JavaScript 或 Flash 等语言的脚本。要了解 PDF 结构，可以参考 Didier Stevens 的 [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)，也可以使用文本编辑器或 Origami 等 PDF-specific editor。

如需深入探索或操作 PDF，可以使用 [qpdf](https://github.com/qpdf/qpdf) 和 [Origami](https://github.com/mobmewireless/origami-pdf) 等工具。PDF 中的隐藏数据可能隐藏在：

- 不可见图层
- Adobe 的 XMP metadata 格式
- 增量 generations
- 与背景颜色相同的文本
- 图像后方的文本或相互重叠的图像
- 不显示的 comments

对于定制 PDF 分析，可以使用 [PeepDF](https://github.com/jesparza/peepdf) 等 Python libraries 编写定制的 parsing scripts。此外，PDF 隐藏数据存储的潜力非常大，因此即使 NSA 关于 PDF risks and countermeasures 的指南已不再托管于其原始位置，仍然可以提供有价值的见解。[copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) 以及 Ange Albertini 编写的 [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 集合，可以提供更多相关资料。<sup>[[4]](#references)[[5]](#references)</sup>

## 常见的恶意构造

攻击者经常滥用特定的 PDF objects 和 actions，使其在文档打开或交互时自动执行。值得搜索的关键词包括：

* **/OpenAction, /AA** – 在打开时或特定事件发生时执行的自动 actions。
* **/JS, /JavaScript** – 嵌入的 JavaScript（通常经过 obfuscation 或拆分到多个 objects 中）。
* **/Launch, /SubmitForm, /URI, /GoToE** – 外部 process / URL launchers。
* **/RichMedia, /Flash, /3D** – 可以隐藏 payloads 的 multimedia objects。
* **/EmbeddedFile /Filespec** – file attachments（EXE、DLL、OLE 等）。
* **/ObjStm, /XFA, /AcroForm** – 经常被滥用于隐藏 shell-code 的 object streams 或 forms。
* **Incremental updates** – 多个 `%%EOF` markers 或非常大的 **/Prev** offset，可能表示在签名后追加了数据，以绕过 AV。

当上述任何 token 与可疑 strings（powershell、cmd.exe、calc.exe、base64 等）一起出现时，都应对该 PDF 进行更深入的分析。

---

## Static analysis cheat-sheet
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
* **pdfcpu** – 能够对 PDF 执行 *lint*、*decrypt*、*extract*、*compress* 和 *sanitize* 的 Go 库/CLI。
* **pdf-inspector** – 基于浏览器的可视化工具，可渲染对象图和 streams。
* **PyMuPDF (fitz)** – 可编写脚本的 Python 引擎，能够在 hardened sandbox 中安全地将页面渲染为图像，以 detonate embedded JS。

---

## 近期攻击技术（2023-2025）

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC 观察到 threat actors 在最终的 **%%EOF** 之后附加一个基于 MHT、包含 VBA macros 的 Word 文档，从而生成一个同时是有效 PDF 和有效 DOC 的文件。仅解析 PDF layer 的 AV engines 会漏掉该 macro。静态 PDF keywords 看起来正常，但 `file` 仍会输出 `%PDF`。任何同时包含字符串 `<w:WordDocument>` 的 PDF 都应视为高度可疑。<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries 滥用 incremental update 功能，在保留首个 benign revision 签名的同时，插入第二个带有恶意 `/OpenAction` 的 **/Catalog**。只检查第一个 xref table 的工具会被绕过。
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – 可通过 embedded CIDType2 fonts 触发易受攻击的 **CoolType.dll** 函数；一旦打开 crafted document，即可利用用户权限实现 remote code execution。该漏洞已在 APSB24-29（2024 年 5 月）中修复。<sup>[[3]](#references)</sup>

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

1. **快速打补丁** – 让 Acrobat/Reader 始终保持在最新的 Continuous track；现实中观察到的大多数 RCE chains 都利用了数月前已修复的 n-day vulnerabilities。
2. **在网关处移除 active content** – 使用 `pdfcpu sanitize` 或 `qpdf --qdf --remove-unreferenced`，从传入的 PDF 中删除 JavaScript、embedded files 和 launch actions。
3. **Content Disarm & Reconstruction (CDR)** – 在 sandbox host 上将 PDF 转换为图像（或 PDF/A），在保留视觉保真度的同时丢弃 active objects。
4. **阻止不常用的功能** – Reader 中的企业级 “Enhanced Security” 设置允许禁用 JavaScript、multimedia 和 3D rendering。
5. **用户教育** – social engineering（invoice 和 resume 诱饵）仍然是 initial vector；教育员工将可疑附件转发给 IR。

## 参考资料

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
