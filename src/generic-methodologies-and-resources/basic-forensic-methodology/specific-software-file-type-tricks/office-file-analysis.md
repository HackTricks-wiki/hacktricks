# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}


如需进一步了解，请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下仅为摘要：<sup>[[4]](#references)</sup>

Microsoft 创建了多种 office 文档格式，其中主要分为两类：**OLE formats**（如 RTF、DOC、XLS、PPT）和 **Office Open XML (OOXML) formats**（如 DOCX、XLSX、PPTX）。这些格式可以包含宏，因此成为 phishing 和 malware 的目标。OOXML 文件采用 zip 容器结构，可以通过解压进行检查，从而查看文件和文件夹层次结构以及 XML 文件内容。

要探索 OOXML 文件的结构，可以使用解压文档的命令及其输出结构。已有文档记录了在这些文件中隐藏数据的技术，这表明 CTF challenges 中的数据隐藏方式仍在持续创新。

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的综合工具集。这些工具有助于识别和分析嵌入的宏，而宏通常会被用作 malware delivery 的载体，通常用于下载并执行其他 malicious payloads。VBA 宏分析无需 Microsoft Office，可以使用 Libre Office，通过设置断点和 watch variables 进行调试。

**oletools** 的安装和使用非常简单，文中提供了通过 pip 安装以及从文档中提取宏的命令。宏的自动执行由 `AutoOpen`、`AutoExec` 或 `Document_Open` 等函数触发。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation：Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（也称为 CFBF）。序列化模型位于 storage/stream 中：<sup>[[1]](#references)</sup>

- Storage：`Global`
- Stream：`Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 中观察到）：

- Header
- GZIP-compressed payload（实际的序列化对象图）
- Zero padding
- Error-Correcting Code（ECC）trailer

Revit 会使用 ECC trailer 自动修复 stream 的小幅扰动，并拒绝与 ECC 不匹配的 stream。因此，直接编辑压缩字节不会持久生效：你的更改要么被还原，要么文件会被拒绝。要确保 deserializer 看到的内容能够进行字节级精确控制，你必须：

- 使用与 Revit 兼容的 gzip 实现重新压缩（这样生成或接受的压缩字节才能与 Revit 的预期匹配）。
- 在经过 padding 的 stream 上重新计算 ECC trailer，使 Revit 接受修改后的 stream，而不会自动修复它。

用于 patching/fuzzing RFA 内容的实际工作流：<sup>[[1]](#references)</sup>

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) 按照 gzip/ECC 规则编辑 `Global\Latest`

- 解构 `Global/Latest`：保留 header，对 payload 执行 gunzip，mutate bytes，然后使用与 Revit 兼容的 deflate 参数重新 gzip。
- 保留 zero-padding，并重新计算 ECC trailer，使 Revit 接受新的 bytes。
- 如果需要确定性的逐字节复现，请构建一个围绕 Revit DLL 的最小 wrapper，以调用其 gzip/gunzip 路径和 ECC computation（如 research 中所示），或者重新使用任何能够复现这些语义的可用 helper。

3) Rebuild OLE 复合文档
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool 将 storages/streams 写入文件系统，并对 NTFS 名称中无效的字符进行转义；你需要的 stream path 在输出树中正是 `Global/Latest`。
- 通过会从 cloud storage 获取 RFA 的 ecosystem plugins 进行 mass attacks 时，请先在本地确认你 patched 的 RFA 能通过 Revit 的完整性检查（gzip/ECC 正确），再尝试进行 network injection。

Exploitation insight（用于指导应放入 gzip payload 的字节）：<sup>[[1]](#references)</sup>

- Revit deserializer 读取一个 16 位 class index 并构造对象。某些类型是 non‑polymorphic 且没有 vtable；滥用 destructor handling 会产生 type confusion，使 engine 通过 attacker-controlled pointer 执行 indirect call。
- 选择 `AString`（class index `0x1F`）会将 attacker-controlled heap pointer 放置在对象偏移量 0 处。在 destructor loop 期间，Revit 实际上会执行：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 在 serialized graph 中放置多个此类对象，使 destructor loop 的每次迭代都执行一个 gadget（“weird machine”），并安排一次 stack pivot，转入传统的 x64 ROP chain。

Windows x64 pivot/gadget 构建细节见此处：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

通用 ROP 指导见此处：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS)，用于扩展/重建 OLE compound files：https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD，用于 reverse/taint；使用 TTD 时禁用 page heap，以保持 traces 简洁。
- 本地 proxy（例如 Fiddler）可通过在 plugin 流量中替换 RFA 来模拟 supply-chain delivery，以便进行测试。

## 参考资料

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
