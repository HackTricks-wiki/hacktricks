# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}

如需进一步了解，请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下仅为总结：<sup>[[4]](#references)</sup>

Microsoft Office 文档通常以旧式格式出现，例如 RTF 和基于 OLE/CFBF 的 DOC、XLS 及 PPT；也可能采用较新的 **Office Open XML (OOXML)** 格式，例如 DOCX、XLSX 和 PPTX。Office 文档可能包含宏等 active content，因此常被用于 phishing 和 malware 传播。OOXML 文件是 ZIP 容器，可以通过解压来检查其文件层次结构和 XML 内容。<sup>[[3]](#references)[[4]](#references)</sup>

为了探索 OOXML 文件结构，下面给出了用于解压文档的命令及其输出结构。已有文档记录了在这些文件中隐藏数据的技术，表明 CTF challenges 中的数据隐藏方式仍在持续创新。<sup>[[4]](#references)</sup>

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的综合工具集。这些工具有助于识别和分析嵌入的宏，而宏通常被用作 malware 投递的 vector，通常会下载并执行其他恶意 payload。可以使用 Libre Office 分析 VBA macros，无需 Microsoft Office；Libre Office 支持通过断点和 watch variables 进行 debugging。<sup>[[4]](#references)</sup>

**oletools** 的安装和使用都很简单，文中提供了通过 pip 安装以及从文档中提取 macros 的命令。在 Word 中，自动 macros 包括 `AutoExec` 和 `AutoOpen`，而 `Document_Open` 是一种 open-event procedure。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
对于密码加密的 Office 文档，请参阅 [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)。

---

## OLE Compound File exploitation：Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA 模型存储为 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（又称 CFBF）。序列化模型位于 storage/stream 中：<sup>[[1]](#references)[[3]](#references)</sup>

- Storage：`Global`
- Stream：`Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 中观察到）：

- Header
- GZIP-compressed payload（实际的序列化对象图）
- Zero padding
- Error-Correcting Code（ECC）trailer

Revit 会使用 ECC trailer 自动修复 stream 中的小幅扰动，并拒绝与 ECC 不匹配的 stream。因此，直接编辑压缩字节不会持久生效：修改要么会被还原，要么文件会被拒绝。为了确保对 deserializer 所看到的内容进行字节级精确控制，必须：<sup>[[1]](#references)</sup>

- 使用与 Revit 兼容的 gzip 实现重新压缩（使 Revit 生成/接受的压缩字节与其预期一致）。
- 在填充后的 stream 上重新计算 ECC trailer，使 Revit 接受修改后的 stream，而不会自动修复它。

用于 patch/fuzzing RFA 内容的实际工作流：<sup>[[1]](#references)</sup>

1) 展开 OLE compound document。<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) 以 gzip/ECC 规范编辑 Global\Latest

- 解构 `Global/Latest`：保留 header，gunzip payload，修改 bytes，然后使用与 Revit 兼容的 deflate 参数重新 gzip。
- 保留 zero-padding，并重新计算 ECC trailer，使新 bytes 能被 Revit 接受。
- 如果需要确定性的逐字节复现，请构建一个围绕 Revit DLL 的最小 wrapper，以调用其 gzip/gunzip 路径和 ECC 计算功能（如研究中所示），或者重新使用任何能够复现这些语义的可用 helper。

3) 重新构建 OLE compound document。<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool 会将 storages/streams 写入文件系统，并对 NTFS 名称中无效的字符进行转义；输出树中所需的 stream 路径正是 `Global/Latest`。
- 通过会从 cloud storage 获取 RFA 的生态系统插件进行大规模攻击时，请先在本地确认修补后的 RFA 通过 Revit 的完整性检查（gzip/ECC 正确），再尝试进行网络注入。

Exploitation insight（用于指导应放入 gzip payload 的字节）：<sup>[[1]](#references)</sup>

- Revit deserializer 会读取一个 16 位 class index 并构造对象。某些类型是 non-polymorphic 且没有 vtable；滥用 destructor 处理会造成 type confusion，使 engine 通过 attacker-controlled pointer 执行 indirect call。
- 选择 `AString`（class index `0x1F`）会将 attacker-controlled heap pointer 放置在对象偏移量 0 处。在 destructor loop 中，Revit 实际上会执行：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 在序列化图中放置多个此类对象，使析构函数循环的每次迭代都执行一个 gadget（“weird machine”），并安排一次 stack pivot，跳转到常规的 x64 ROP chain。

有关 Windows x64 pivot/gadget 构建的详细信息，请参阅：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

有关通用 ROP 指导，请参阅：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：<sup>[[1]](#references)</sup>

- CompoundFileTool（OSS），用于扩展/重建 OLE compound files：https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD，用于逆向/taint；使用 TTD 时禁用 page heap，以保持 traces 紧凑。
- 本地 proxy（例如 Fiddler）可以通过在 plugin 流量中替换 RFA，模拟 supply-chain delivery 以进行测试。

## References

- [1] [从 Autodesk Revit RFA 文件解析崩溃构造完整的 Exploit RCE（ZDI blog）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool（GitHub）](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File（CFBF）文档](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba 文档（GitHub）](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event（Word）（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
