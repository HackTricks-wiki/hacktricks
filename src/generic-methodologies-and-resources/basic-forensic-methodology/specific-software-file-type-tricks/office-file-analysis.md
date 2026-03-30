# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}


欲了解更多信息请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下为摘要：

Microsoft 创建了多种 office 文档格式，主要有两类：**OLE formats**（如 RTF、DOC、XLS、PPT）和 **Office Open XML (OOXML) formats**（如 DOCX、XLSX、PPTX）。这些格式可以包含 macros，使其成为 phishing 和 malware 的目标。OOXML 文件以 zip 容器的形式组织，可以通过解压来检查，从而查看文件和文件夹的层次结构以及 XML 文件的内容。

要探索 OOXML 文件结构，可以使用解压文档的命令并查看输出结构。已有关于在这些文件中隐藏数据的技术的记录，表明在 CTF 挑战中数据隐藏仍在不断创新。

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的综合工具集。这些工具有助于识别和分析嵌入的 macros，这些 macros 常作为 malware 传递的载体，通常会下载并执行额外的恶意载荷。VBA macros 的分析可以在不使用 Microsoft Office 的情况下进行：使用 Libre Office 可以进行调试，支持断点和监视变量。

**oletools** 的安装和使用比较简单，提供了通过 pip 安装以及从文档中提取 macros 的命令。宏的自动执行通常由类似 `AutoOpen`、`AutoExec` 或 `Document_Open` 的函数触发。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA 模型以 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（又称 CFBF）存储。序列化模型位于 storage/stream：

- 存储：`Global`
- 流：`Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 上观察到）：

- Header
- GZIP-compressed payload（实际的序列化对象图）
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit 会使用 ECC trailer 对流中的小扰动进行自动修复，并会拒绝与 ECC 不匹配的流。因此，简单地编辑压缩字节不会持久化：你的更改要么被还原，要么文件被拒绝。要确保对反序列化器看到的数据进行逐字节精确控制，你必须：

- 使用与 Revit 兼容的 gzip 实现重新压缩（以使 Revit 生成/接受的压缩字节与其预期匹配）。
- 在填充后的流上重新计算 ECC trailer，这样 Revit 会接受修改后的流而不会自动修复它。

用于 patching/fuzzing RFA 内容的实用工作流程：

1) 展开 OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) 编辑 `Global/Latest`，遵循 gzip/ECC 规则

- 解析 `Global/Latest`：保留头部，gunzip 有效负载，对字节进行变更，然后使用与 Revit 兼容的 deflate 参数重新 gzip 回去。
- 保留 zero-padding 并重新计算 ECC trailer，以便 Revit 接受新的字节。
- 如果需要确定性的逐字节复现，可构建一个围绕 Revit’s DLLs 的最小封装，调用其 gzip/gunzip 路径和 ECC 计算（如研究中所示），或重用任何能复现这些语义的现有辅助工具。

3) 重建 OLE 复合文档
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool writes storages/streams to the filesystem with escaping for characters invalid in NTFS names; the stream path you want is exactly `Global/Latest` in the output tree.
- When delivering mass attacks via ecosystem plugins that fetch RFAs from cloud storage, ensure your patched RFA passes Revit’s integrity checks locally first (gzip/ECC correct) before attempting network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Revit deserializer 读取一个 16-bit class index 并构造一个 object。某些类型是 non‑polymorphic 并缺少 vtables；滥用 destructor handling 会产生 type confusion，使 engine 通过一个 attacker-controlled pointer 执行 indirect call。
- 选择 `AString`（class index `0x1F`）会在 object offset 0 放置一个 attacker-controlled heap pointer。在 destructor loop 中，Revit 实际上执行：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 在 serialized graph 中放置多个此类对象，使 destructor loop 的每次迭代都执行一个 gadget（“weird machine”），并将 stack pivot 安排到常规的 x64 ROP chain 中。

参见 Windows x64 pivot/gadget building 细节：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

以及一般的 ROP 指南：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：

- CompoundFileTool (OSS) 用于展开/重建 OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD 用于 reverse/taint；使用 TTD 禁用 page heap 以保持 traces 紧凑。
- 本地代理（例如 Fiddler）可以通过在插件流量中替换 RFAs 来模拟供应链投递以进行测试。

## 参考

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
