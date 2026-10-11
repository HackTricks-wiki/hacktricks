# Office 文件分析

{{#include ../../../banners/hacktricks-training.md}}

如需了解更多信息，请查看 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)。以下仅为摘要：<sup>[[4]](#references)</sup>

Microsoft Office 文档常见的格式包括 RTF 和基于 OLE/CFBF 的 DOC、XLS、PPT 等旧格式，以及 DOCX、XLSX、PPTX 等较新的 **Office Open XML (OOXML)** 格式。Office 文档可能包含宏等活动内容，因此常被用作钓鱼和恶意软件的载体。OOXML 文件是 ZIP 容器，解压后即可检查其文件层级和 XML 内容。<sup>[[3]](#references)[[4]](#references)</sup>

文中介绍了用于解压文档的命令及其输出结构，以便探索 OOXML 文件结构。相关资料还记录了在这些文件中隐藏数据的技术，表明 CTF 挑战中的数据隐藏手法仍在不断创新。<sup>[[4]](#references)</sup>

在分析方面，**oletools** 和 **OfficeDissector** 提供了用于检查 OLE 和 OOXML 文档的综合工具集。这些工具有助于识别和分析嵌入的宏；宏常被用作投递恶意软件的途径，通常会下载并执行其他恶意 payload。无需 Microsoft Office，也可以使用 Libre Office 分析 VBA 宏，并通过断点和监视变量进行调试。<sup>[[4]](#references)</sup>

**oletools** 的安装和使用都很简单，文中提供了通过 pip 安装以及从文档中提取宏的命令。在 Word 中，自动宏包括 `AutoExec` 和 `AutoOpen`，而 `Document_Open` 是一个打开事件过程。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

对于密码加密的 Office 文档，请参阅[语法驱动的离线恢复工作流](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)。

---

## OLE Compound File exploitation：Autodesk Revit RFA – ECC 重计算与受控 gzip

Revit RFA 模型以 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（又称 CFBF）格式存储。序列化模型位于 storage/stream 中：<sup>[[1]](#references)[[3]](#references)</sup>

- Storage：`Global`
- Stream：`Latest` → `Global\Latest`

`Global\Latest` 的关键布局（在 Revit 2025 上观察到）：

- Header
- GZIP 压缩负载（实际序列化对象图）
- 零填充
- 错误更正码（ECC）尾部

Revit 会使用 ECC 尾部自动修复对 stream 的微小扰动，并拒绝与 ECC 不匹配的 stream。因此，直接编辑压缩字节并不能保留修改：修改要么被还原，要么文件被拒绝。若要精确控制反序列化器读取的字节，必须：<sup>[[1]](#references)</sup>

- 使用与 Revit 兼容的 gzip 实现重新压缩（确保生成或接受的压缩字节符合 Revit 的预期）。
- 对填充后的 stream 重新计算 ECC 尾部，使 Revit 接受修改后的 stream，而不自动修复它。

修补/模糊测试 RFA 内容的实用工作流：<sup>[[1]](#references)</sup>

1) 展开 OLE compound document。<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) 按 gzip/ECC 规则编辑 `Global\Latest`

- 拆解 `Global/Latest`：保留 header，解压 payload，修改字节，然后使用与 Revit 兼容的 deflate 参数重新 gzip 压缩。
- 保留零填充并重新计算 ECC trailer，确保 Revit 接受新字节。
- 如果需要逐字节确定性复现，可围绕 Revit 的 DLL 构建一个最小 wrapper，以调用其 gzip/gunzip 路径和 ECC 计算（如研究中所示）；也可以复用能够复现这些语义的现有 helper。

3) 重建 OLE 复合文档。<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

备注：<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool 会将 storages/streams 写入文件系统，并对 NTFS 名称中无效的字符进行转义；你要找的 stream 路径在输出目录树中正好是 `Global/Latest`。
- 通过会从云存储获取 RFA 的生态系统插件投放大规模攻击时，先在本地确认修补后的 RFA 能通过 Revit 的完整性检查（gzip/ECC 正确），再尝试进行网络注入。

利用思路（用于判断 gzip payload 中应放置哪些字节）：<sup>[[1]](#references)</sup>

- Revit 的反序列化器会读取一个 16 位的 class index 并构造对象。某些类型不是多态类型且没有 vtable；滥用析构函数处理会造成 type confusion，使引擎通过攻击者控制的指针执行间接调用。
- 选择 `AString`（class index `0x1F`）会将攻击者控制的 heap 指针放在对象偏移量 0 处。在析构函数循环期间，Revit 实际执行：

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- 在序列化图中放置多个此类对象，使析构函数循环的每次迭代都执行一个 gadget（“weird machine”），并安排栈 pivot，跳转到常规的 x64 ROP chain。

Windows x64 pivot/gadget 构建详情见：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

ROP 通用指南见：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

工具：<sup>[[1]](#references)</sup>

- CompoundFileTool（OSS），用于展开/重建 OLE compound file：https://github.com/thezdi/CompoundFileTool。<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD，用于逆向分析/污点分析；在 TTD 中禁用 page heap，以保持跟踪记录精简。
- 本地代理（例如 Fiddler）可通过在插件流量中替换 RFA 来模拟供应链投递，以便测试。

## References

- [1] [从 Autodesk Revit RFA 文件解析崩溃中构造完整的 RCE exploit（ZDI 博客）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool（GitHub）](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) 文档](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF 实战指南](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba 文档（GitHub）](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [自动宏（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open 事件（Word）（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
