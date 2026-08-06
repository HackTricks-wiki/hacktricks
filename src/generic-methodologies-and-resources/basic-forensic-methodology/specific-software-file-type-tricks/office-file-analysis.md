# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}


如需更多信息，请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下仅为摘要：<sup>[[4]](#references)</sup>

Microsoft 创建了许多 Office 文档格式，主要分为两类：**OLE formats**（如 RTF、DOC、XLS、PPT）和 **Office Open XML (OOXML) formats**（如 DOCX、XLSX、PPTX）。这些格式可以包含宏，因此会成为 phishing 和 malware 的目标。OOXML 文件以 zip 容器的形式组织，可以通过解压进行检查，从而查看文件和文件夹层级结构以及 XML 文件内容。

要探索 OOXML 文件结构，文中给出了用于解压文档的命令及其输出结构。相关文献已经记录了在这些文件中隐藏数据的技术，这表明 CTF challenges 中的数据隐藏方式仍在持续创新。

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的综合工具集。这些工具有助于识别和分析嵌入的宏，而宏通常是传递 malware 的途径，通常会下载并执行其他恶意 payload。无需 Microsoft Office，也可以使用 Libre Office 分析 VBA 宏，后者支持通过断点和监视变量进行调试。

**oletools** 的安装和使用非常简单，文中提供了通过 pip 安装以及从文档中提取宏的命令。宏的自动执行由 `AutoOpen`、`AutoExec` 或 `Document_Open` 等函数触发。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA 模型以 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（又称 CFBF）形式存储。序列化模型位于 storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 上观察到）：

- Header
- GZIP-compressed payload（实际的序列化对象图）
- Zero padding
- Error-Correcting Code（ECC）trailer

Revit 会使用 ECC trailer 自动修复 stream 的小幅扰动，并拒绝与 ECC 不匹配的 stream。因此，直接编辑压缩字节不会持久生效：你的修改要么会被还原，要么文件会被拒绝。要确保反序列化器看到的内容能够进行字节级精确控制，必须：

- 使用与 Revit 兼容的 gzip 实现重新压缩（使生成或接受的压缩字节与 Revit 预期一致）。
- 在填充后的 stream 上重新计算 ECC trailer，使 Revit 接受修改后的 stream，而不会自动修复它。

用于 patch/fuzzing RFA 内容的实际工作流程：<sup>[[1]](#references)</sup>

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) 使用 gzip/ECC 规范编辑 Global\Latest

- 解构 `Global/Latest`：保留 header，对 payload 执行 gunzip，修改字节，然后使用与 Revit 兼容的 deflate 参数重新 gzip。
- 保留零填充，并重新计算 ECC trailer，使 Revit 接受新的字节。
- 如果需要逐字节确定性复现，请围绕 Revit 的 DLL 构建一个最小 wrapper，以调用其 gzip/gunzip 路径和 ECC 计算功能（如研究中所示），或者重新使用任何可用的、能够复现这些语义的 helper。

3) 重建 OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool 将 storages/streams 写入文件系统，并对 NTFS 名称中无效的字符进行转义；你需要的 stream 路径在输出树中正好是 `Global/Latest`。
- 通过会从 cloud storage 获取 RFA 的 ecosystem plugins 发起大规模攻击时，请先在本地确认修补后的 RFA 能通过 Revit 的完整性检查（gzip/ECC 正确），然后再尝试进行网络注入。

Exploitation insight（用于指导应放入 gzip payload 的字节）：<sup>[[1]](#references)</sup>

- Revit deserializer 读取一个 16 位 class index 并构造对象。某些类型是 non‑polymorphic 且缺少 vtable；滥用 destructor 处理会导致 type confusion，使 engine 通过 attacker-controlled pointer 执行间接调用。
- 选择 `AString`（class index `0x1F`）会将 attacker-controlled heap pointer 放置在对象偏移 0 处。在 destructor loop 期间，Revit 实际上会执行：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 在 serialized graph 中放置多个此类对象，使 destructor loop 的每次迭代都执行一个 gadget（“weird machine”），并安排 stack pivot，转入常规的 x64 ROP chain。

有关 Windows x64 pivot/gadget 构建细节，请参阅：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

有关常规 ROP 指导，请参阅：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：<sup>[[1]](#references)</sup>

- CompoundFileTool（OSS），用于扩展/重建 OLE compound files： https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD，用于 reverse/taint；使用 TTD 时禁用 page heap，以保持 traces 精简。
- 本地 proxy（例如 Fiddler）可通过在 plugin traffic 中替换 RFA，模拟 supply-chain delivery 以进行测试。

## References

- [1] [从 Autodesk Revit RFA File Parsing 中的 Crash 构造完整 Exploit RCE（ZDI blog）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool（GitHub）](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File（CFBF）文档](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
