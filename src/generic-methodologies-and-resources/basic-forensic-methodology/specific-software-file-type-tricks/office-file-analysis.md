# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}


更多信息参见 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下为摘要：

Microsoft 创建了许多 Office 文档格式，主要有两类：**OLE formats**（如 RTF、DOC、XLS、PPT）和 **Office Open XML (OOXML) formats**（如 DOCX、XLSX、PPTX）。这些格式可以包含宏，使它们成为钓鱼和恶意软件的目标。OOXML 文件以 zip 容器的形式组织，可以通过解压来检查，查看文件和文件夹层级以及 XML 文件内容。

要探索 OOXML 文件结构，给出了用于解压文档的命令及其输出结构。已经记录了在这些文件中隐藏数据的技术，表明在 CTF 挑战中数据隐藏手法仍在不断演进。

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的全面工具集。这些工具有助于识别和分析嵌入的宏，这些宏常作为恶意软件传播的载体，通常用于下载并执行额外的恶意负载。对 VBA 宏的分析可以不用 Microsoft Office，通过使用 Libre Office 完成，后者允许设置断点和监视变量进行调试。

安装和使用 **oletools** 很简单，文中提供了通过 pip 安装和从文档中提取宏的命令。宏的自动执行可以由 `AutoOpen`、`AutoExec` 或 `Document_Open` 等函数触发。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA 模型存储为 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（又名 CFBF）。序列化模型位于 storage/stream：

- 存储: `Global`
- 流: `Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 上观察到）：

- Header
- GZIP-compressed payload (实际的序列化对象图)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit 会使用 ECC trailer 对流中的小扰动进行自动修复，并会拒绝与 ECC 不匹配的流。因此，天真地编辑压缩字节不会持久生效：你的更改要么被还原，要么文件被拒绝。为确保反序列化器看到的字节精确可控，必须：

- 使用与 Revit 兼容的 gzip 实现重新压缩（这样 Revit 生成/接受的压缩字节与其期望的匹配）。
- 在填充后的流上重新计算 ECC trailer，以便 Revit 接受被修改的流而不会自动修复它。

用于 patching/fuzzing RFA 内容的实用工作流程：

1) 展开 OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) 使用 gzip/ECC 规则编辑 Global\Latest

- 拆解 `Global/Latest`：保留 header，gunzip payload，修改字节，然后使用与 Revit 兼容的 deflate 参数重新 gzip。
- 保留 zero-padding 并重新计算 ECC trailer，使 Revit 接受新的字节。
- 若需逐字节确定性重现，围绕 Revit 的 DLLs 构建最小 wrapper 来调用其 gzip/gunzip 路径和 ECC computation（如研究中所示），或重用任何可用的 helper 来复现这些语义。

3) 重建 OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
注意：

- CompoundFileTool 将 storages/streams 写入文件系统，并对 NTFS 名称中无效的字符进行转义；在输出树中你要的 stream 路径正是 `Global/Latest`。
- 在通过生态插件（ecosystem plugins）批量投放攻击，且这些插件会从云存储抓取 RFAs 时，先在本地确保你修改过的 RFA 能通过 Revit 的完整性检查（gzip/ECC 正确），然后再尝试进行网络注入。

Exploitation insight（用于指导在 gzip payload 中放置哪些字节）：

- Revit 的 deserializer 读取一个 16 位的 class index 并构造对象。某些类型是 non‑polymorphic 并且没有 vtables；滥用 destructor 的处理会导致 type confusion，使引擎通过一个受攻击者控制的指针执行间接调用。
- 选择 `AString`（class index `0x1F`）会在对象偏移 0 处放置一个受攻击者控制的 heap pointer。在 destructor 循环中，Revit 实际上会执行：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 在序列化图中放置多个这样的对象，使得析构循环的每次迭代执行一个 gadget (“weird machine”)，并安排一个 stack pivot 进入常规 x64 ROP chain。

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：

- CompoundFileTool (OSS) 用于展开/重建 OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD 用于 reverse/taint；使用 TTD 禁用 page heap 以保持 traces 紧凑。
- 本地代理（例如 Fiddler）可以通过在插件流量中交换 RFAs 来模拟供应链交付以进行测试。

## 参考

- [从 Autodesk Revit RFA 文件解析崩溃构建完整 Exploit RCE（ZDI 博客）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) 文档](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
