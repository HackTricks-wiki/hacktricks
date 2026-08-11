# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}

如需进一步了解，请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下仅为总结：<sup>[[4]](#references)</sup>

Microsoft Office 文档通常以 RTF 和基于 OLE/CFBF 的 DOC、XLS 与 PPT 等旧格式出现，也可能采用较新的 **Office Open XML (OOXML)** 格式，例如 DOCX、XLSX 和 PPTX。Office 文档可能包含宏等活动内容，因此经常被用于 phishing 和 malware 传播。OOXML 文件是 ZIP 容器，可以通过解压缩检查其文件层级结构和 XML 内容。<sup>[[3]](#references)[[4]](#references)</sup>

为了探索 OOXML 文件结构，下面给出了用于解压文档的命令及其输出结构。已有文档记录了在这些文件中隐藏数据的技术，表明 CTF 挑战中的数据隐藏方式仍在不断创新。<sup>[[4]](#references)</sup>

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的综合工具集。这些工具有助于识别和分析嵌入式宏，而宏通常是 malware 传播的载体，典型行为是下载并执行其他恶意 payload。利用 Libre Office，可以在不安装 Microsoft Office 的情况下分析 VBA 宏，并通过断点和监视变量进行调试。<sup>[[4]](#references)</sup>

**oletools** 的安装和使用都很简单，文中提供了通过 pip 安装以及从文档中提取宏的命令。在 Word 中，自动宏包括 `AutoExec` 和 `AutoOpen`，而 `Document_Open` 是一个打开事件过程。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC 重算与受控 gzip

Revit RFA 模型存储为 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（也称 CFBF）。序列化模型位于 storage/stream 中：<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 上观察到）：

- Header
- GZIP-compressed payload（实际的序列化对象图）
- Zero padding
- Error-Correcting Code（ECC）trailer

Revit 会使用 ECC trailer 自动修复 stream 中的小幅扰动，并拒绝与 ECC 不匹配的 stream。因此，直接编辑压缩字节不会持久生效：你的更改要么被还原，要么文件被拒绝。要确保对 deserializer 所读取内容进行逐字节精确控制，必须：<sup>[[1]](#references)</sup>

- 使用与 Revit 兼容的 gzip 实现重新压缩（使生成/接受的压缩字节与 Revit 的预期一致）。
- 在 padded stream 上重新计算 ECC trailer，使 Revit 接受修改后的 stream，而不会自动修复它。

用于 patching/fuzzing RFA 内容的实际工作流程：<sup>[[1]](#references)</sup>

1) Expand OLE compound document。<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) 使用 gzip/ECC 规则编辑 `Global\Latest`

- 解构 `Global/Latest`：保留 header，对 payload 执行 gunzip，修改字节，然后使用与 Revit 兼容的 deflate 参数重新 gzip。
- 保留 zero-padding，并重新计算 ECC trailer，以便 Revit 接受新的字节。
- 如果需要确定性的逐字节复现，请围绕 Revit 的 DLL 构建一个最小 wrapper，以调用其 gzip/gunzip 路径和 ECC 计算功能（如研究中所示），或重新使用任何可用的、能够复现这些语义的 helper。

3) 重新构建 OLE compound document。<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
注释：<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool 会将 storages/streams 写入文件系统，并对 NTFS 名称中无效的字符进行转义；输出树中所需的 stream path 正是 `Global/Latest`。
- 通过会从 cloud storage 获取 RFA 的生态系统插件实施大规模攻击时，请先在本地确保经过修补的 RFA 能通过 Revit 的完整性检查（gzip/ECC 正确），然后再尝试进行 network injection。

Exploitation insight（用于指导应放入 gzip payload 的字节）：<sup>[[1]](#references)</sup>

- Revit deserializer 会读取 16 位 class index 并构造一个对象。某些类型是 non-polymorphic 且缺少 vtable；滥用 destructor handling 会产生 type confusion，使 engine 通过 attacker-controlled pointer 执行 indirect call。
- 选择 `AString`（class index `0x1F`）会将 attacker-controlled heap pointer 放置在对象偏移量 0 处。在 destructor loop 期间，Revit 实际上会执行：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 在 serialized graph 中放置多个此类对象，使 destructor loop 的每次迭代都执行一个 gadget（“weird machine”），并安排一次 stack pivot，跳转到常规的 x64 ROP chain。

Windows x64 pivot/gadget 构建详情参见：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

一般 ROP 指南参见：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：<sup>[[1]](#references)</sup>

- CompoundFileTool（OSS），用于扩展/重建 OLE compound files：https://github.com/thezdi/CompoundFileTool。<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD，用于 reverse/taint；使用 TTD 时禁用 page heap，以保持 traces 紧凑。
- 本地 proxy（例如 Fiddler）可通过在 plugin 流量中替换 RFA，模拟 supply-chain delivery 以进行测试。

## References

- [1] [从 Autodesk Revit RFA 文件解析中的崩溃构造完整的 exploit RCE（ZDI blog）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool（GitHub）](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File（CFBF）文档](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF 实地指南](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba 文档（GitHub）](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event（Word）（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
