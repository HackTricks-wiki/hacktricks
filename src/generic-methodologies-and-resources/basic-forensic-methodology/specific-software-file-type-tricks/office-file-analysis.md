# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoft 创建了多种 office 文档格式，主要有两类：**OLE formats**（如 RTF、DOC、XLS、PPT）和 **Office Open XML (OOXML) formats**（如 DOCX、XLSX、PPTX）。这些格式可能包含 macros，使其成为钓鱼和恶意软件的目标。OOXML 文件以 zip 容器的形式组织，可以通过解压来检查，从而查看文件和文件夹层级以及 XML 文件内容。

为了查看 OOXML 文件结构，提供了解压文档的命令及其输出结构。已经记录了在这些文件中隐藏数据的技术，表明在 CTF 挑战中数据隐藏方法持续有新花样。

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的全面工具集。这些工具有助于识别和分析嵌入的 macros，嵌入的 macros 常作为恶意软件传递的载体，通常会下载并执行额外的恶意负载。可以使用 Libre Office 在不安装 Microsoft Office 的情况下分析 VBA macros，Libre Office 支持使用断点和监视变量进行调试。

安装和使用 **oletools** 十分简单，文中给出了通过 pip 安装以及从文档中提取 macros 的命令。macros 的自动执行由诸如 `AutoOpen`、`AutoExec` 或 `Document_Open` 之类的函数触发。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA 模型存储为 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（即 CFBF）。序列化的模型位于 storage/stream：

- 存储（Storage）： `Global`
- 流（Stream）： `Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 上观察到）：

- 头部
- GZIP-compressed payload（实际的序列化对象图）
- 零填充
- Error-Correcting Code (ECC) 尾随

Revit 会使用 ECC 尾随自动修复对流的小扰动，并会拒绝与 ECC 不匹配的流。因此，简单地编辑压缩字节不会持久化：你的更改要么被恢复，要么文件被拒绝。要确保对反序列化器看到的内容进行逐字节精确控制，你必须：

- 使用与 Revit 兼容的 gzip 实现重新压缩（以便 Revit 生成/接受的压缩字节与其期望一致）。
- 在带填充的流上重新计算 ECC 尾随，以便 Revit 接受修改后的流而不进行自动修复。

用于 patching/fuzzing RFA 内容的实用工作流程：

1) 展开 OLE 复合文档
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) 编辑 Global\Latest，采用 gzip/ECC 策略

- 拆解 `Global/Latest`：保留头部，对载荷执行 gunzip，变异字节，然后使用与 Revit 兼容的 deflate 参数重新 gzip。
- 保留零填充并重新计算 ECC 尾部，使 Revit 接受新的字节。
- 如果需要逐字节确定性重现，围绕 Revit 的 DLLs 构建一个最小包装器以调用其 gzip/gunzip 路径和 ECC 计算（如研究中所示），或重用任何可用的辅助工具来复制这些语义。

3) 重建 OLE 复合文档
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool 将存储/流写入文件系统，并对 NTFS 名称中无效的字符进行转义；输出树中你需要的流路径正是 `Global/Latest`。
- 当通过从 cloud storage 获取 RFAs 的生态系统插件投放大规模攻击时，先在本地确保你打过补丁的 RFA 能通过 Revit 的完整性检查（gzip/ECC correct），然后再尝试进行 network injection。

Exploitation insight (to guide what bytes to place in the gzip payload):

- Revit deserializer 读取一个 16-bit class index 并构造一个 object。某些类型是 non‑polymorphic 并且缺少 vtables；滥用 destructor 处理会导致 type confusion，使引擎通过一个 attacker-controlled pointer 执行 indirect call。
- 选择 `AString` (class index `0x1F`) 会在对象偏移 0 处放置一个 attacker-controlled heap pointer。在 destructor loop 期间，Revit 实际上执行：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 在序列化的 graph 中放置多个此类对象，使 destructor loop 的每次迭代执行一个 gadget（“weird machine”），并将 stack pivot 安排到常规的 x64 ROP chain。

参见 Windows x64 pivot/gadget 构建细节：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

以及通用 ROP 指南：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：

- CompoundFileTool (OSS) 用于展开/重建 OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD 用于 reverse/taint；使用 TTD 禁用 page heap 以保持 traces 紧凑。
- 本地代理（例如 Fiddler）可通过在插件流量中替换 RFAs 来模拟供应链交付以便测试。

## 参考资料

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
