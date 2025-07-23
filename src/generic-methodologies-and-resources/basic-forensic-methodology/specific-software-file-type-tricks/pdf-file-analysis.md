# PDF 文件分析

{{#include ../../../banners/hacktricks-training.md}}

**有关更多详细信息，请查看：** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF 格式因其复杂性和隐藏数据的潜力而闻名，使其成为 CTF 取证挑战的焦点。它结合了纯文本元素和二进制对象，这些对象可能被压缩或加密，并且可以包含 JavaScript 或 Flash 等语言的脚本。要理解 PDF 结构，可以参考 Didier Stevens 的 [入门材料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)，或使用文本编辑器或 PDF 专用编辑器如 Origami。

对于 PDF 的深入探索或操作，可以使用 [qpdf](https://github.com/qpdf/qpdf) 和 [Origami](https://github.com/mobmewireless/origami-pdf) 等工具。PDF 中隐藏的数据可能隐藏在：

- 隐形层
- Adobe 的 XMP 元数据格式
- 增量生成
- 与背景颜色相同的文本
- 图像后面的文本或重叠图像
- 不显示的注释

对于自定义 PDF 分析，可以使用 Python 库如 [PeepDF](https://github.com/jesparza/peepdf) 来制作定制的解析脚本。此外，PDF 隐藏数据存储的潜力非常巨大，尽管 NSA 关于 PDF 风险和对策的指南不再托管在其原始位置，但仍提供了有价值的见解。可以参考 [该指南的副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) 和 Ange Albertini 的 [PDF 格式技巧集合](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 以获取更多阅读材料。

## 常见恶意构造

攻击者通常滥用特定的 PDF 对象和在打开或与文档交互时自动执行的操作。值得寻找的关键字：

* **/OpenAction, /AA** – 在打开或特定事件时执行的自动操作。
* **/JS, /JavaScript** – 嵌入的 JavaScript（通常被混淆或分散在对象中）。
* **/Launch, /SubmitForm, /URI, /GoToE** – 外部进程 / URL 启动器。
* **/RichMedia, /Flash, /3D** – 可以隐藏有效负载的多媒体对象。
* **/EmbeddedFile /Filespec** – 文件附件（EXE, DLL, OLE 等）。
* **/ObjStm, /XFA, /AcroForm** – 常被滥用以隐藏 shell-code 的对象流或表单。
* **增量更新** – 多个 %%EOF 标记或非常大的 **/Prev** 偏移可能表明在签名后附加的数据以绕过 AV。

当任何前面的标记与可疑字符串（powershell, cmd.exe, calc.exe, base64 等）一起出现时，PDF 值得进行更深入的分析。

---

## 静态分析备忘单
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
额外有用的项目（2023-2025年积极维护）：
* **pdfcpu** – Go库/CLI，能够*lint*、*decrypt*、*extract*、*compress*和*sanitize* PDF文件。
* **pdf-inspector** – 基于浏览器的可视化工具，渲染对象图和流。
* **PyMuPDF (fitz)** – 可脚本化的Python引擎，可以安全地将页面渲染为图像，以在加固的沙箱中引爆嵌入的JS。

---

## 最近的攻击技术（2023-2025年）

* **PDF多语言中的MalDoc（2023）** – JPCERT/CC观察到威胁行为者在最后的**%%EOF**后附加了一个基于MHT的Word文档，包含VBA宏，生成一个既是有效PDF又是有效DOC的文件。仅解析PDF层的AV引擎会错过宏。静态PDF关键字是干净的，但`file`仍然打印`%PDF`。将任何同时包含字符串`<w:WordDocument>`的PDF视为高度可疑。
* **Shadow增量更新（2024）** – 对手利用增量更新功能插入第二个**/Catalog**，并带有恶意的`/OpenAction`，同时保持良性的第一个修订版已签名。仅检查第一个xref表的工具被绕过。
* **字体解析UAF链 – CVE-2024-30284（Acrobat/Reader）** – 一个易受攻击的**CoolType.dll**函数可以通过嵌入的CIDType2字体访问，允许在打开经过精心制作的文档时以用户的权限进行远程代码执行。已在APSB24-29中修补，2024年5月。

---

## YARA快速规则模板
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

## 防御提示

1. **快速修补** – 保持 Acrobat/Reader 在最新的连续版本上；大多数在野外观察到的 RCE 链利用了几个月前修复的 n-day 漏洞。
2. **在网关处剥离活动内容** – 使用 `pdfcpu sanitize` 或 `qpdf --qdf --remove-unreferenced` 从入站 PDF 中删除 JavaScript、嵌入文件和启动操作。
3. **内容解除与重构 (CDR)** – 在沙箱主机上将 PDF 转换为图像（或 PDF/A），以保留视觉保真度，同时丢弃活动对象。
4. **阻止不常用的功能** – Reader 中的企业“增强安全”设置允许禁用 JavaScript、多媒体和 3D 渲染。
5. **用户教育** – 社会工程（发票和简历诱饵）仍然是初始向量；教员工将可疑附件转发给 IR。

## 参考文献

* JPCERT/CC – “MalDoc in PDF – 通过将恶意 Word 文件嵌入 PDF 文件来绕过检测”（2023年8月）
* Adobe – Acrobat 和 Reader 的安全更新 (APSB24-29, 2024年5月)


{{#include ../../../banners/hacktricks-training.md}}
