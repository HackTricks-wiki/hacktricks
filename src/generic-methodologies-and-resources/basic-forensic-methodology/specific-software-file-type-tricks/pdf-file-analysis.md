# PDF 文件分析

{{#include ../../../banners/hacktricks-training.md}}

**更多详情请查看：** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)。<sup>[[1]](#references)</sup>

PDF 格式以复杂且可能隐藏数据而闻名，因此常成为 CTF 取证挑战的重点。它结合了纯文本元素和二进制对象，这些对象可能经过压缩或加密，还可能包含 JavaScript 或 Flash 等语言编写的脚本。要了解 PDF 结构，可以参考 Didier Stevens 的[入门资料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)，或使用文本编辑器、Origami 等 PDF 专用编辑器。

要深入检查或修改 PDF，可以使用 [qpdf](https://github.com/qpdf/qpdf) 和 [Origami](https://github.com/mobmewireless/origami-pdf) 等工具。PDF 中的隐藏数据可能藏在：

- 不可见图层
- Adobe 的 XMP 元数据格式
- 增量版本
- 与背景颜色相同的文本
- 位于图像后方的文本或相互重叠的图像
- 不显示的注释

要自定义分析 PDF，可以使用 [PeepDF](https://github.com/jesparza/peepdf) 等 Python 库编写专用解析脚本。此外，PDF 隐藏数据存储的可能性极其广泛；虽然 NSA 关于 PDF 风险与对策的指南已不再托管于原始位置，但仍能提供有价值的见解。[指南副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)以及 Ange Albertini 汇编的 [PDF 格式技巧](https://github.com/corkami/docs/blob/master/PDF/PDF.md)可供进一步阅读。<sup>[[4]](#references)[[5]](#references)</sup>

## 常见恶意结构

攻击者经常滥用特定 PDF 对象和操作，使其在文档打开或被交互时自动执行。值得搜索的关键字：

* **/OpenAction, /AA** – 打开文档或发生特定事件时自动执行的操作。
* **/JS, /JavaScript** – 嵌入的 JavaScript（通常经过混淆或拆分到多个对象中）。
* **/Launch, /SubmitForm, /URI, /GoToE** – 用于启动外部进程或 URL 的操作。
* **/RichMedia, /Flash, /3D** – 可能用于隐藏 payload 的多媒体对象。
* **/EmbeddedFile /Filespec** – 文件附件（EXE、DLL、OLE 等）。
* **/ObjStm, /XFA, /AcroForm** – 常被滥用来隐藏 shell-code 的对象流或表单。
* **增量更新** – 多个 %%EOF 标记或非常大的 **/Prev** 偏移量，可能表示签名后追加了数据，以绕过 AV。

如果上述标记与可疑字符串（powershell、cmd.exe、calc.exe、base64 等）同时出现，就应深入分析该 PDF。

---

## 静态分析速查表

以下示例使用文档所述的 `pdf-parser.py`、qpdf 和 pdfcpu 命令行接口。<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

在 PDF 中对图像进行像素化处理，并不会移除其底层像素。如果一份可读文档似乎用这种方式隐藏了凭据，可提取嵌入的图像，在获得授权的情况下离线检查；结果取决于图像和合适的参考资料，且不保证能通过视觉方式恢复。恢复出的密码仍需单独验证，确认其确实属于你关注的账户。不要在常规主机枚举扫描中加入 PDF 提取或图像恢复环节。

其他实用项目（2023-2025 年持续维护）：
* **pdfcpu** – Go 库/CLI，可验证、解密、提取、优化和操作 PDF。<sup>[[9]](#references)</sup>
* **pdf-inspector** – 基于浏览器的可视化工具，可渲染对象图和数据流。
* **PyMuPDF** – 可编写脚本的 Python 绑定，用于检查 PDF 并将页面渲染为栅格图像。应将解析器/渲染器视为不可信文件攻击面，并在适当隔离的分析环境中运行。<sup>[[8]](#references)</sup>

---

## 近期攻击技术（2023-2025）

* **MalDoc in PDF polyglot（2023）** – JPCERT/CC 报告了一种技术：将使用 Word 创建的、带有 VBA 宏的 MHT 文件附加到 PDF 中，使其保留 PDF magic，同时也能在 Word 中打开。仅分析 PDF 的工具、沙箱或 antivirus 可能会漏掉宏，因为恶意行为会在文件作为 Word 文档打开时发生；应查找 `<w:WordDocument>` 标记及其他 MHT 指示特征。<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – 攻击者可以在 PDF 签署前放入隐藏内容，然后追加增量更新，以更改 catalog 或对象引用，使查看器显示隐藏内容，同时原始签名仍保持有效。这种技术可以绕过将此类更新判定为无害的查看器。<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284（Acrobat/Reader）** – Adobe 将此严重漏洞评定为 use-after-free，可能导致任意代码执行；APSB24-29 于 2024 年 5 月 14 日发布。<sup>[[3]](#references)</sup>

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

1. **快速打补丁** – 让 Acrobat/Reader 保持在最新的 Continuous 版本；在野外观察到的大多数 RCE 攻击链都利用了数月前已修复的 n-day 漏洞。
2. **在网关剥离活动内容** – 使用专门设计、受策略控制的净化工具或 CDR 产品，并明确移除 JavaScript、嵌入文件、启动操作、表单和多媒体。`qpdf --qdf` 可以让 PDF 对象更易于检查，而 pdfcpu 提供验证和操作功能；但单独运行这两个命令都不能证明活动内容已被移除。<sup>[[9]](#references)[[10]](#references)</sup>
3. **内容净化与重构（CDR）** – 在沙箱主机上将 PDF 转换为图像（或 PDF/A），在保留视觉保真度的同时丢弃活动对象。
4. **禁用较少使用的功能** – Reader 的企业版“增强安全性”设置允许禁用 JavaScript、多媒体和 3D 渲染。
5. **用户教育** – 社会工程（发票和简历诱饵）仍是最初的攻击途径；应教会员工将可疑附件转发给 IR。

## References

- [1] [取证 CTF 现场指南](https://trailofbits.github.io/ctf/forensics/)
- [2] [PDF 中的 MalDoc——通过将恶意 Word 文件嵌入 PDF 文件来绕过检测](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe 安全公告——Adobe Acrobat 和 Reader 安全更新（APSB24-29）](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - 指南副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF 格式技巧](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [影子攻击：隐藏和替换已签名 PDF 中的内容](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [Shadow Attacks: Hiding and Replacing Content in Signed PDFs](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF 教程](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf 命令行选项](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
