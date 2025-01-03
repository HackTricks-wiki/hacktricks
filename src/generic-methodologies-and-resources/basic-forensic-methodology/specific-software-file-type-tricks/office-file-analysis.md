# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}

有关更多信息，请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。这只是一个摘要：

微软创建了许多办公文档格式，主要有两种类型：**OLE 格式**（如 RTF、DOC、XLS、PPT）和 **Office Open XML (OOXML) 格式**（如 DOCX、XLSX、PPTX）。这些格式可以包含宏，使其成为网络钓鱼和恶意软件的目标。OOXML 文件结构为 zip 容器，可以通过解压缩进行检查，揭示文件和文件夹层次结构及 XML 文件内容。

要探索 OOXML 文件结构，提供了解压文档的命令和输出结构。隐藏数据的技术已被记录，表明在 CTF 挑战中数据隐蔽的持续创新。

对于分析，**oletools** 和 **OfficeDissector** 提供了全面的工具集，用于检查 OLE 和 OOXML 文档。这些工具有助于识别和分析嵌入的宏，这些宏通常作为恶意软件传递的载体，通常下载并执行额外的恶意负载。可以利用 Libre Office 对 VBA 宏进行分析，而无需 Microsoft Office，这允许使用断点和监视变量进行调试。

**oletools** 的安装和使用非常简单，提供了通过 pip 安装和从文档中提取宏的命令。宏的自动执行由 `AutoOpen`、`AutoExec` 或 `Document_Open` 等函数触发。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
