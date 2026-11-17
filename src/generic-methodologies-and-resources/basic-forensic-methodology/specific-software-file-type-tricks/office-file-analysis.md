# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}

如需了解更多信息，请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下仅为摘要：<sup>[[2]](#references)</sup>

Microsoft Office 文档常见的格式包括 RTF 和基于 OLE/CFBF 的 DOC、XLS、PPT 等旧格式，以及 DOCX、XLSX、PPTX 等较新的 **Office Open XML (OOXML)** 格式。Office 文档可能包含宏等活动内容，因此常被用于钓鱼和传播恶意软件。OOXML 文件是 ZIP 容器，可以通过解压查看其文件层级结构和 XML 内容。<sup>[[1]](#references)[[2]](#references)</sup>

文中介绍了用于探索 OOXML 文件结构的解压命令及输出结构。已有文档记录了在这些文件中隐藏数据的技术，表明 CTF 挑战中隐藏数据的方法仍在不断创新。<sup>[[2]](#references)</sup>

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的综合工具集。这些工具有助于识别和分析嵌入的宏；宏通常是传递恶意软件的途径，通常会下载并执行其他恶意载荷。无需 Microsoft Office，也可以使用 Libre Office 分析 VBA 宏，并通过断点和监视变量进行调试。<sup>[[2]](#references)</sup>

**oletools** 的安装和使用都很简单，文中提供了通过 pip 安装及从文档中提取宏的命令。在 Word 中，自动宏包括 `AutoExec` 和 `AutoOpen`，而 `Document_Open` 是一个打开事件过程。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA 宏分析：垃圾代码和 UserForms

## 垃圾代码

宏可能包含**不可达或无关代码**，用于拖慢分析。在花时间逆向某个分支之前，先识别恒定条件并追踪可达行为。下面的示例使用了一个永远不会为真的 `If` 条件来隐藏垃圾代码。

![包含带垃圾代码的不可达条件分支的 Word 宏](<../../../images/image (369).png>)

## 宏窗体

VBA UserForms 可以将数据存储在文本框等控件中。由于窗体、框架和页面都可以提供 `Controls` 集合，分析人员应枚举整个控件层级，而不能只依赖窗体上可见的内容。下面的示例将隐藏数据存储在相互重叠的文本框中。<sup>[[6]](#references)</sup>

在动态分析期间，VBA 的 `GetObject` 函数可以从文件中获取 Automation 对象，也可以连接到已运行的 Automation 服务器。宏可能利用此对象访问方式获取可见文档中不明显的数据；应检查返回的对象和 UserForm 控件树。<sup>[[7]](#references)</sup>

![在相互重叠的文本框中隐藏数据的宏 UserForm](<../../../images/image (344).png>)

有关受密码加密的 Office 文档，请参阅[基于语法的离线恢复工作流](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)。

---

对于使用 OLE/CFBF 的 Revit RFA 文件，请参阅[ECC 重新计算、受控 gzip 和反序列化器利用](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md)；该解析器利用工作流与 Office 文档初步分析是分开的。

## References

- [1] [OLE 复合文件 (CFBF) 文档](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [取证 CTF 实战指南](https://trailofbits.github.io/ctf/forensics/)
- [3] [olevba 文档（GitHub）](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [自动宏（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open 事件（Word）（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - 集合、控件和对象（Microsoft Forms）](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - `GetObject` 函数](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
