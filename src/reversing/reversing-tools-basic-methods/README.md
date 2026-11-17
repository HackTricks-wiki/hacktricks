# 逆向工具与基础方法

{{#include ../../banners/hacktricks-training.md}}

## 基于 ImGui 的逆向工具

软件：

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg 用户模式自动化

{{#ref}}
windbg-automation.md
{{#endref}}

## Office 文档宏分析

对于可疑的 Office 文档，请检查 [VBA 宏垃圾代码和隐藏的 UserForm 控件](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms)。

## Windows 异常驱动的控制流

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows 内核调试

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm 反编译器 / Wat 编译器

在线工具：

- 使用 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) 将 wasm（二进制）**反编译**为 wat（明文）
- 使用 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) 将 wat **编译**为 wasm
- 也可以尝试使用 [web-wasmdec](https://wwwg.github.io/web-wasmdec/) 进行反编译。

软件：

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 缓存字节码

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 虚拟化 payload 与自定义 VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET 反编译器

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一款反编译器，可**反编译并检查多种格式**，包括**库**（.dll）、**Windows 元数据文件**（.winmd）和**可执行文件**（.exe）。反编译后，可以将程序集保存为 Visual Studio 项目（.csproj）。

如果需要从旧版程序集中恢复丢失的源代码，这项功能可以节省时间。此外，dotPeek 还提供便捷的反编译代码导航功能，使其成为进行 **Xamarin 算法分析**的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

.NET Reflector 拥有全面的插件模型和可扩展 API，可根据你的具体需求进行定制，从而节省时间并简化开发。下面来看看这款工具提供的众多逆向工程功能：

- 深入了解数据如何在库或组件中流动
- 了解 .NET 语言和框架的实现与用法
- 查找未公开文档或未暴露的功能，以充分利用所用的 API 和技术
- 查找依赖项和不同的程序集
- 精确定位代码、第三方组件和库中的错误
- 调试你使用的所有 .NET 代码的源代码

### [ILSpy](https://github.com/icsharpcode/ILSpy) 与 [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[适用于 Visual Studio Code 的 ILSpy 插件](https://github.com/icsharpcode/ilspy-vscode)：可在任何 OS 上使用（可直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并**搜索 ILSpy**）。\
如果需要**反编译**、**修改**并重新**编译**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 或其仍在积极维护的 fork：[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（**右键单击 -> Modify Method** 可修改函数中的内容）。

### 使用 REA 进行无需执行的托管代码检查

**REA** 无需加载程序集即可检查 PE/CLI 元数据和 CIL。先确认 artifact 的身份，然后检查成员和声明的原生边界；在使用反编译器或运行程序之前审查可疑调用时，这种方法很有用。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

对于版本差异比对，`compare_managed_members` 使用原始 CIL/签名标识和解码指令指纹，而不是将元数据 token 视为在不同构建间保持稳定。P/Invoke 声明并不能证明原生代码已运行；`verify_managed_native_boundaries` 需要匹配的原生导出项或函数证据来检查该边界。请将制品摘要、MVID 和未解析的映射与结果一并保留。<sup>[[17]](#references)</sup>

### DNSpy 日志记录

若要让 **DNSpy 将某些信息记录到文件中**，可以使用以下代码片段：

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy 调试

要使用 DNSpy 调试代码，需要：

首先，更改与**调试**相关的**程序集属性**：

![DNSpy Logging - DNSpy 调试：首先，更改与调试相关的程序集属性](<../../images/image (973).png>)

从：

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

到：

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

然后点击 **compile**：

![DNSpy Logging - DNSpy Debugging：然后点击 compile](<../../images/image (314) (1).png>)

然后通过 _**File >> Save module...**_ 保存新文件：

![DNSpy Logging - DNSpy Debugging：然后通过 File Save module 保存新文件](<../../images/image (602).png>)

这一步很有必要，因为如果不这样做，代码在 **runtime** 时会应用多项 **optimisations**，可能导致调试时**断点始终无法命中**，或者某些**变量不存在**。

然后，如果你的 .NET 应用由 **IIS** **运行**，可以通过以下方式**重启**：

```
iisreset /noforce
```

然后，要开始调试，请关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![DNSpy Logging - DNSpy 调试：要开始调试，请关闭所有已打开的文件，并在 Debug Tab 中选择 Attach to Process](<../../images/image (318).png>)

然后选择 **w3wp.exe**，附加到 **IIS 服务器**，并点击 **attach**：

![DNSpy Logging - DNSpy 调试：选择 w3wp.exe 附加到 IIS 服务器，并点击 attach](<../../images/image (113).png>)

现在我们正在调试该进程，接下来需要暂停它并加载所有模块。先点击 _Debug >> Break All_，然后点击 _**Debug >> Windows >> Modules**_：

![DNSpy Logging - DNSpy 调试：现在我们正在调试该进程，接下来需要暂停它并加载所有模块。先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy 调试：现在我们正在调试该进程，接下来需要暂停它并加载所有模块。先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (834).png>)

在 **Modules** 中点击任意模块，然后选择 **Open All Modules**：

![DNSpy Logging - DNSpy 调试：在 Modules 中点击任意模块，然后选择 Open All Modules](<../../images/image (922).png>)

在 **Assembly Explorer** 中右键点击任意模块，然后点击 **Sort Assemblies**：

![DNSpy Logging - DNSpy 调试：在 Assembly Explorer 中右键点击任意模块，然后点击 Sort Assemblies](<../../images/image (339).png>)

## Java 反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## 调试 DLL

### 使用 IDA

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- 选择 **Windbg** 调试器
- 选择 "**Suspend on library load/unload**"

![调试 DLL - 使用 IDA：选择“ Suspend on library load/unload ”](<../../images/image (868).png>)

- 配置执行的**参数**，填入 **DLL 路径**和要调用的函数：

![调试 DLL - 使用 IDA：配置执行的参数，填入 DLL 路径和要调用的函数](<../../images/image (704).png>)

之后，开始调试时，**每次加载 DLL 都会暂停执行**；当 rundll32 加载你的 DLL 时，执行也会暂停。

此方法会在模块加载事件时暂停，但要到达已加载 DLL 的入口点，不如下面的 x64dbg 工作流直接。

### 使用 x64dbg/x32dbg

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- **更改命令行**（_File --> Change Command Line_），设置 DLL 路径和要调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- 更改 _Options --> Settings_，并选择 "**DLL Entry**"。
- 然后**开始执行**。调试器会在每个 dll main 处暂停；最终会**在你的 DLL 的入口点处暂停**。之后，只需找到你想设置断点的位置即可。

请注意，在 win64dbg 中，无论因何种原因暂停执行，都可以查看 **win64dbg 窗口顶部**，确认**当前所在的代码**：

![使用 IDA - 使用 x64dbg/x32dbg：请注意，在 win64dbg 中，无论因何种原因暂停执行，都可以查看 win64dbg 窗口顶部，确认当前所在的代码](<../../images/image (842).png>)

此指示器可确认执行是否已暂停在你要调试的 DLL 内部。

## GUI 应用 / 电子游戏

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一款实用程序，可用于查找正在运行的游戏中重要数值在内存中的存储位置并修改它们。更多信息请参见：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger (GDB) 的前端/逆向工程工具，专注于游戏。不过，它也可用于任何与逆向工程相关的工作。

[**Decompiler Explorer**](https://dogbolt.org/) 是多个反编译器的 Web 前端。此 Web 服务可让你比较不同反编译器对小型可执行文件生成的结果。

### Godot PCK 解密和项目恢复

对于已发布的 Godot 游戏，可在独立的 `.pck` 文件、附加或嵌入在可执行文件中的资源包，或 APK 的 `assets` 目录中找到其 PCK。[gore](https://github.com/figurophobia/gore) 可检查并提取资源包；若要完整重建脚本和资源，则需要 GDRE Tools（运行 `gore setup` 安装，或使用 `--gdre`）。此工具在此工作流中支持 Godot 4.x PCK 格式 v2–v4；它可以检测 v1 头部，但处理 v1 需要提供密钥。<sup>[[25]](#references)</sup>

自动恢复密钥需要加密的文件表；如果只有文件内容被加密，则应提供已知密钥。恢复失败并不能证明资源包未加密。<sup>[[28]](#references)</sup>

密钥搜索**并不是 AES-256 密钥空间攻击**。加密的文件表会暴露其明文的 MD5、明文长度、IV 和 AES-256-CFB 密文。<sup>[[27]](#references)</sup> `gore` 会将游戏可执行文件或相邻文件中的 32 字节窗口作为候选密钥进行测试。它会根据可能的解密路径长度和前缀筛选候选项，然后通过解密整个文件表并检查其 MD5 来确认二进制扫描命中的结果。<sup>[[26]](#references)[[28]](#references)</sup> 它会先搜索已初始化的 PE/ELF 数据段，若未找到则扫描整个文件；`--scan` 会将其他候选文件也纳入搜索。<sup>[[28]](#references)</sup>

如果没有找到嵌入的密钥，工具会尝试一小组内置密码；`--wordlist` 可用于指定其他候选项。每个密码都会以引擎派生的密码密钥表示形式、零填充的字面值或 64 个十六进制字符组成的密钥进行测试。与二进制扫描命中不同，此实现中的字典命中只会通过路径结构筛选。请通过打开资源包并验证提取出的资源来确认结果。<sup>[[26]](#references)[[28]](#references)</sup>

如果本地有游戏文件，可根据分析需要选择相应阶段。`recover` 会调用 GDRE 来重建可打开的项目，而 `extract` 只会解包原始文件。`key` 会输出可供其他工具使用的候选密钥。<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## 使用 REA 开展有证据支持的原生分析

**REA** 通过 CLI 和 MCP 提供 Hopper、Ghidra 和 IDA 分析功能。它需要 Node.js 22.x（至少 22.19）、24.x（至少 24.11）或 26+，以及 npm。请先配置现有的原生 provider；运行 `rea providers --json` 检查，并在有多个 provider 支持目标时明确选择一个。将下方的 `0x1000` 替换为清单中观察到的函数名或地址。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

从一个 feature 字符串或符号开始，沿着引用和调用者追踪，然后检查所选函数档案和 `rea decompile` 生成的伪代码。REA 会将会话绑定到所选 provider，不会在失败后悄悄替换 provider。要重复执行查询，`--snapshot PATH` 只会复用 artifact 字节、provider、设置、操作和参数均匹配的快照；快照是本地缓存，不是已保存的 provider 数据库。保留返回的 Evidence 和明确标注的未知项，不要把推断出的路径或反编译器文本当作原始源代码。<sup>[[16]](#references)[[18]](#references)</sup>

对于进入 native add-ons 的 JavaScript/Electron 入口点，请参阅 [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea)。

## 使用本地 TCP bridge 进行脚本化 IDA 和 Ghidra 分析

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) 在**已打开**的 IDA 数据库或 Ghidra CodeBrowser 程序中运行，允许独立脚本查询和修改该分析数据库。在 IDA 的 Python CLI 中运行 `ID_Server.py`（`import ID_Server`），或在 Ghidra 的 Script Manager 中运行 `Ghidra_Server.py`。IDA 从端口 `5073` 开始绑定到 `127.0.0.1`，并扫描更高的端口。当前的 Ghidra 脚本从端口 `5093` 开始，并尝试使用到 `5102` 的十个端口；其 Java socket 绑定到通配地址，而不只是 loopback。连接前，请检查该实例打印的端口。与 headless analyzer 不同，这个 bridge 操作的是当前在该 GUI 实例中打开的程序。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

每次连接发送**一条以换行符结尾的命令**，并读取以换行符结尾的响应。结果通常为 JSON。例如，找到与输入路径相关的导入 API 后，`IMPORTXREF` 可查找其调用点；接着，`DECOMP_XREF` 可批量反编译所选地址的调用者。`FUNC` 用于检查函数，`PCODE` 返回反编译器的中间表示。使用当前数据库中的地址，而不是从基址重定位方式不同的二进制文件中复制地址。下面的示例使用 IDA 的默认端口；对于 Ghidra，请使用其脚本打印的端口。<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

同一通道也能**修改分析数据库**：`RENAME_FUNC`、`RETYPE`、`SETCONV`、`DEFSTRUCT`/`SETFIELD`、`MAKEFUNC` 和 `PATCH` 会修改名称、类型、结构定义、函数边界或存储的字节。`PATCH` 是数据库编辑，**并不能证明实时进程已被修补**。两个监听器都没有说明是否启用了身份验证。IDA 仅监听 loopback，而 Ghidra 可能可通过网络接口访问；使用 Ghidra 时，请限制对其监听器的访问。`QUIT` 会停止任一监听器，IDA 还提供 `ida_bridge_stop()`。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### 使用 blobrunner 调试 shellcode

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 会分配 **shellcode**、输出其**内存地址**，然后暂停执行。\
附加 IDA 或 x64dbg 等调试器，在输出的地址处设置断点，然后继续执行以调试 shellcode。

GitHub releases 页面包含编译版本的 zip 文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在下面的链接中找到一个略作修改的 Blobrunner 版本。要编译它，只需**在 Visual Studio Code 中创建 C/C++ 项目，复制并粘贴代码，然后构建项目**。


{{#ref}}
blobrunner.md
{{#endref}}

### 使用 jmp2it 调试 shellcode

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) 与 BlobRunner 类似。它会分配 shellcode 并进入无限循环。附加调试器，继续执行 **2–5 秒**，然后在循环内暂停，并单步执行到随后将控制权转移给已分配 shellcode 的调用指令。

![调试器在 jmp2it 的无限循环中暂停，位置紧邻调用已分配 shellcode 的指令之前](<../../images/image (509).png>)

你可以在 [jmp2it 的 releases 页面](https://github.com/adamkramer/jmp2it/releases/)下载编译版本。

### 使用 Cutter 调试 shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 Cutter 可以模拟 shellcode 并动态检查它。

请注意，Cutter 允许你选择“Open File”和“Open Shellcode”。在我的案例中，将 shellcode 作为文件打开时，它能正确反编译；但作为 shellcode 打开时则不行：

![Cutter 显示将相同字节作为文件或 shellcode 打开时的不同分析结果](<../../images/image (562).png>)

要从指定位置开始模拟，请在那里设置 bp；Cutter 显然会自动从该处开始模拟：

![开始 Cutter 模拟前，在所需的 shellcode 入口处设置断点](<../../images/image (589).png>)

![Cutter 模拟器在选定的 shellcode 断点处暂停](<../../images/image (387).png>)

例如，你可以在 hex dump 中查看堆栈：

![在 Cutter 的 hex dump 中查看模拟的 shellcode 堆栈](<../../images/image (186).png>)

### 反混淆 shellcode 并获取已执行的函数

你可以试试 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。\
它会告诉你诸如 shellcode 使用了**哪些函数**，以及 shellcode 是否在内存中**解码**自身等信息。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg 还提供图形化启动器，你可以选择所需选项并执行 shellcode

![用于选择 shellcode 仿真和跟踪选项的 scDbg 图形化启动器](<../../images/image (258).png>)

**Create Dump** 选项会转储最终的 shellcode（如果 shellcode 在内存中被动态修改），这对下载解码后的 shellcode 很有用。**start offset** 可用于从特定偏移处开始执行 shellcode。**Debug Shell** 选项可用于通过 scDbg 终端调试 shellcode（不过我认为之前介绍的选项更适合此用途，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 反汇编

上传 shellcode 文件作为输入，并使用以下 recipe 进行反汇编：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 混淆去混淆

**混合布尔-算术（MBA）** 混淆会用混合算术运算符（`+`、`-`、`*`）和位运算符（`&`、`|`、`^`、`~`、移位）的公式，隐藏 `x + y` 这类简单表达式。关键在于，这些恒等式通常只在**固定宽度模运算**下成立，因此进位和溢出都很重要：

```c
(x ^ y) + 2 * (x & y) == x + y
```

如果使用通用代数工具简化这类表达式，很容易得到错误结果，因为忽略了位宽语义。<sup>[[1]](#references)</sup>

### 实用工作流程

1. **保留原始位宽**，以提升后的代码/IR/反编译器输出为准（`8/16/32/64` 位）。
2. **先对表达式分类**，再尝试简化：
   - **线性**：位运算原子的加权和
   - **半线性**：线性表达式加上 `x & 0xFF` 这类常量掩码
   - **多项式**：包含乘积
   - **混合型**：乘积与位运算逻辑交织，通常还会有重复的子表达式
3. **通过随机测试或 SMT 证明验证每个候选改写**。如果无法证明等价，就保留原始表达式，不要猜测。

### 用狭窄的执行切片绕过控制流平坦化

通常没必要还原完整的控制流图。遇到控制流平坦化、不透明谓词、大型分发器或 MBA-heavy 代码时，从加密数据块和输出缓冲区的引用入手，跟踪到负责转换它们的最小例程。然后只重现这个数据流切片，或独立执行它；如果能直接初始化相关状态，分发器就不是解决问题所必需的部分。<sup>[[7]](#references)</sup>

实用的工作流程如下：<sup>[[7]](#references)</sup>

1. 清点可执行段和数据段、重定位信息及交叉引用。从 `.rodata` 中转储候选表，同时保留其字节序和元素宽度。
2. 找出最后一个写入明文或输出缓冲区的例程。记录它的输入、引用的表、导入函数调用及所需的全局状态。
3. 只将这些操作提升为定宽 Python 模型。如果这个切片仍依赖过多状态，就在 Unicorn、QEMU 或调试器中调用该例程，并 hook 无关的导入函数，而不是模拟整个程序。
4. 验证提取器确实从所提供的二进制文件中推导出输出：移除静默回退，搜索其中是否嵌入了答案，并使用字符串、密钥、标识符、布局和混淆种子均有变化的未知构建版本进行测试。

首轮分析可使用以下命令：<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 检测伪装成常量的 MBA 表达式

一个表面上依赖输入的字节表达式，可能会完全抵消输入。提取其查找表后，在完整的 8 位取值域上计算该表达式；如果输出集合只有一个值，就能证明该字节是常量，无需恢复周围的状态机。<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

保留最后的掩码，因为原始加法会发生字节宽度的回绕。对于更大的取值范围，可以使用 SMT solver 检查两个位宽相同的符号输入是否满足 `f(x1) != f(x2)`：`unsat` 可证明函数不变，而 `sat` 会给出一个反例，说明不能丢弃该输入。<sup>[[7]](#references)</sup>

#### 识别受环境影响的解码

反分析检查不一定会触发分支或崩溃。解码器可以将传感器结果混入密钥位、opaque-predicate 常量或 flattened-dispatcher 状态中，继续正常执行，并在模拟器中生成看似合理但实际错误的明文。因此，仅修补可见的失败分支是不够的；应追踪环境探测结果到解码器状态的数据依赖，在真实设备和模拟器上比较相同代码片段，并测试强制设置每种传感器结果会如何改变最终缓冲区。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一款实用的 MBA 简化工具，适用于 malware analysis 和受保护二进制文件逆向。它会对表达式进行分类，并将其交给专用处理流水线，而不是对所有表达式都应用同一种通用重写流程。<sup>[[2]](#references)</sup>

快速用法：

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

适用场景：

- **Linear MBA**：CoBRA 在布尔输入上计算表达式，生成签名，并并行尝试多种恢复方法，例如模式匹配、ANF 转换和系数插值。
- **Semilinear MBA**：通过按位分区重建常量掩码原子，确保掩码区域保持正确。
- **Polynomial/Mixed MBA**：将乘积分解为核心项，并可将重复子表达式提升为临时变量，再简化外层关系。

一个通常值得尝试恢复的混合恒等式示例：

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

这可以简化为：

```c
x * y
```

### 逆向分析笔记

- 优先对 **lifted IR 表达式**或反编译器输出运行 CoBRA，并先隔离出精确的计算逻辑。
- 如果表达式来自掩码算术或窄寄存器，请显式使用 `--bitwidth`。
- 如果需要更强的证明步骤，请查看此处的 Z3 笔记：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 还提供 **LLVM pass 插件**（`libCobraPass.so`），适合在后续分析 pass 之前对充斥着 MBA 的 LLVM IR 进行规范化。
- 对于不支持的、对进位敏感的混合域残留表达式，应将其视为信号：保留原始表达式，并手动分析进位路径。

## 还原基于 XOR 状态的控制流扁平化

OLLVM 风格的扁平化器可能会将当前基本块状态保存在两个 64 位寄存器中，并在 dispatcher 处通过 XOR 重建状态。每个原始块都会写入表示其下一状态的寄存器对，然后跳回 dispatcher。条件块可以使用 `CMOVcc`，根据 CPU 标志替换寄存器对中的一半，因此只跟踪可见的分支指令会漏掉其中一个后继块。与间接跳转 dispatcher 不同，这种结构可以始终使用直接回边。<sup>[[19]](#references)[[20]](#references)</sup>

要还原控制流图，先找到 dispatcher 的比较树和两个状态寄存器，再将每个被比较的 XOR 状态映射到目标块，然后追踪每个原始块中写入寄存器对的到达定义。对于条件写入，要同时纳入设置标志的指令和 `CMOVcc` 的两种结果。将每个块的 dispatcher 出口改写为解析出的直接后继块或条件分支；无需修改二进制文件，dispatcher 随后就会变得不可达。这是一种完整 CFG 方法；如果只关注一个解码器，上文的[窄执行切片工作流](#bypass-flattened-control-flow-with-a-narrow-execution-slice)可能更快。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) 可以在 Binary Ninja 中自动处理这种结构。将 `plugins/DispatchThis` 复制到 Binary Ninja 用户插件目录并重启。在受影响的函数中，打开 **Function Settings** 并选择 `OLLVM_XOR_64`；如果分析没有启动，请使用 **Analysis → Reanalyze All Functions**。此模式会改写 MLIL 控制流边，而不会修改文件字节，也不需要 Z3 或间接跳转解析器。它已在 Binary Ninja 5.3.9757+ 上测试；它不会删除每个块中已失效的状态写入，因此不要将这些写入误认为仍然有效的状态转移。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

此混淆器会用基于 `mov` 的指令序列替代程序操作，并利用信号/异常处理来改变控制流。详情请参阅：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

对于受支持的二进制文件，[demovfuscator](https://github.com/kirschju/demovfuscator) 可以对结果进行反混淆。它依赖多个组件。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

并[安装 keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

如果你正在参加 **CTF，下面这个寻找 flag 的变通方法**可能很有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要找到 **entry point**，可以像下面这样搜索名称中包含 `::main` 的函数：

![在 Ghidra 中搜索函数名中的双冒号 main 来查找 Rust entry point](<../../images/image (1080).png>)

这个例子中的二进制文件名为 authenticator，因此很明显，这就是值得关注的 main 函数。\
知道了被调用**函数**的**名称**后，可以在**互联网上**搜索这些函数，了解它们的**输入**和**输出**。

### 从 ELF 固件中恢复 Rust 字符串

在 **Rust ELF** 二进制文件中，许多静态字符串并非通过 C 风格的 NUL 结尾指针引用。常见的 `rustc` 布局是在 **`.data.rel.ro`** 中存放一个**指针/长度元组**，指向存储于 **`.rodata`** 中的实际字符串数据：

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

这意味着 `strings` 或 Ghidra 的默认分析可能会合并相邻字符串，或完全漏掉交叉引用。<sup>[[3]](#references)</sup>

快速工作流程：

```bash
readelf -S <bin>
objdump -h <bin>
```

1. 获取 **`.rodata`** 的虚拟地址和大小。
2. 逐字枚举 **`.data.rel.ro`**。
3. 将 `.rodata` 地址范围内的值视为候选字符串指针。
4. 将下一个字视为候选长度。
5. 应用合理性筛选条件（例如，只保留长度在 **4** 到 **100** 字节之间的值）。
6. 从 `.rodata` 中精确读取 `length` 个字节，而不是一直扫描到 `0x00`。

最小提取器逻辑：

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

这在 firmware reversing 中尤其有用，因为恢复出的 Rust 字符串往往会揭示 **HTTP 路由、RPC 名称、日志消息、断言、文件名、配置键、命令处理程序以及与身份验证相关的逻辑**。

如果 Ghidra 未能识别这些字符串，可以运行自定义脚本/插件，应用相同的启发式方法，并在被引用的 `.rodata` 偏移处创建字符串数据。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` 工具可作为参考，帮助将这一思路应用于其他 **字长、字节序和节布局**。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

对于 Delphi 编译的二进制文件，可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果需要逆向 Delphi 二进制文件，我建议使用 IDA 插件 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

在 IDA 中按 **Alt+F7** 加载 Python 插件，然后选择插件文件。

该插件会执行二进制文件，并在调试开始时动态解析函数名。开始调试后，再按一次 Start 按钮（绿色按钮或 f9），断点就会在实际代码的开头触发。

如果在图形应用程序中按下某个按钮，调试器可以停在该按钮调用的函数中。

## Golang

对于普通的 Go 二进制文件，[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) 可以恢复运行时结构并改善 IDA 中的函数名。使用 **Alt+F7** 加载其 Python 插件。

如果需要逆向 Golang 二进制文件，我建议使用 IDA 插件 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

在 IDA 中按 **Alt+F7** 加载 Python 插件，然后选择插件文件。

它会解析函数名。

### 在没有符号表的情况下恢复元数据

经过 strip 处理的 Go 可执行文件仍需要运行时元数据，以将程序计数器映射到函数。[GoReSym](https://github.com/mandiant/GoReSym) 使用源自 Go runtime 的代码查找并解析 `pclntab` 和 `moduledata` 等结构。无需依赖传统符号表，它也能恢复函数边界、名称、源代码路径、类型和构建信息。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

混淆器可以保留这些结构供分析使用，同时替换恢复出的名称。例如，Garble 会对标识符和包路径进行哈希处理，并移除构建、模块和调试信息。<sup>[[12]](#references)</sup> 混淆后的包标记必须在该包的各个函数中保持一致。按重复出现的标记对函数分组，根据其中一个包的被调用函数、字符串和 API 推断包名，然后将该包标签应用到整个分组。<sup>[[13]](#references)</sup>

### 使用 GoResolver 恢复 Garble 名称

[GoResolver](https://github.com/volexity/GoResolver) 将运行时符号提取、干净参考二进制生成和控制流图（CFG）匹配结合起来。按以下步骤操作：<sup>[[10]](#references)[[13]](#references)</sup>

1. **识别编译器版本。** 首先尝试 `BuildInfo` 和嵌入的版本字符串。如果混淆器移除了这些信息，则将捆绑的 Go 运行时中的部分内容与不同版本的参考运行时进行比较。在 Volexity 的测试中，约 `2%` 的运行时内容就足以区分主要 Go 版本。应将其视为经验性优化，而非通用阈值。<sup>[[13]](#references)</sup>
2. **构建匹配的参考二进制。** 为已识别的 Go 版本、目标架构和可能使用的库生成干净二进制。匹配工具链可减少编译器生成的 CFG 差异。<sup>[[10]](#references)[[13]](#references)</sup>
3. **比较函数。** GoGrapher 会匹配函数 CFG，并输出从 `0.0` 到 `1.0` 的归一化分数。其基本块匹配基于对相似指令的加权比较。高置信度匹配可将随机化函数映射到干净实现。较弱的匹配仍可能识别出包或模块。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **验证并导入。** 使用调用关系、常量、字符串和副作用确认建议的名称，然后通过 IDA 或 Ghidra 的 GoResolver 插件导入 JSON 报告。<sup>[[10]](#references)[[13]](#references)</sup>

安装工具链并运行组合提取器和图匹配器：<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

默认的显著匹配阈值为 `0.9`。`--extract` 和 `--graph` 开关可以单独运行任一阶段；默认情况下两者都会运行，因为恢复出的 runtime 元数据和 CFG 证据可以互相补充。<sup>[[10]](#references)</sup> CFG 分数基于启发式：内联、构建标志、架构和库版本差异都可能改变图的形状，因此应保留尚未解析的函数，而不是强行赋予低置信度的名称。<sup>[[13]](#references)</sup>

### 恢复 Go 字符串表

Go 二进制文件会将所有已链接包中的字符串字节放在一个连续的表中。条目不以 NUL 结尾，runtime 结构也不会公开该表的基址或大小。不过，编译器在不同操作系统和架构上都会先按长度、再按字母顺序排列条目。因此，分析人员找到一个条目后，就可以遍历相邻条目，并利用数据交叉引用将字符串与代码关联起来。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) 可在 IDA Pro 和 Ghidra 中自动完成此流程。请先等待自动分析完成，因为该插件依赖数据段交叉引用。它默认以 runtime 字符串 `entersyscall` 为锚点，随后可以向任一方向扫描，在数据库中定义恢复出的字符串，并导出将字符串映射到引用它们的函数的 JSON 文件。<sup>[[14]](#references)</sup>

根据引用函数所属的包筛选报告，以便将应用程序或恶意软件代码与已链接库中的噪声区分开来。此技术无法恢复被混淆处理破坏的字面量，例如 Garble 的 `-literals` 转换所破坏的字面量。但它仍能整理未被混淆的 runtime 字符串。<sup>[[14]](#references)[[15]](#references)</sup>

### 恢复 Go runtime 类型

Go 会嵌入垃圾回收等功能使用的 runtime 类型信息。当构建信息被剥离，或反汇编器无法解析此元数据时，指令可能看起来像是在加载任意数据地址，而目标区域也会保持未定类型。恢复此元数据后，这些地址就会显示为可读的类型引用，也更容易理解各个包的功能。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) 可以提取符号，并将 runtime 类型解析为 JSON 报告。当前 CLI 使用 `resolve` 子命令：<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` 选项会启用类型解析。使用 GoResolver 的 IDA Pro 或 Ghidra 插件导入报告，以定义恢复出的类型，并在分析数据库中应用它们的引用。在此功能引入的报告格式中，如果省略 `-y`，RTTI 地址和恢复出的类型成员将为 null。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver 支持 x86、AMD64、ARM 和 ARM64 架构的 PE、ELF 和 Mach-O 样本，因此同一工作流程适用于来自 Windows、Linux 和 macOS 的 Go 二进制文件。<sup>[[10]](#references)</sup>

## Compiled Python

本页介绍如何从 ELF/EXE 格式的 Python 编译二进制文件中提取 Python 代码：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

如果你获得了 GBA 游戏的**二进制文件**，可以使用不同的工具对其进行**模拟**和**调试**：

- [**no$gba**](https://problemkaputt.de/gba.htm)（_下载 debug 版本_）- 包含带有界面的调试器
- [**mgba** ](https://mgba.io)- 包含 CLI 调试器
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 插件
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 插件

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，进入 _**Options --> Emulation Setup --> Controls**_** **，即可查看如何按下 Game Boy Advance 的**按钮**

![显示 Game Boy Advance 按钮映射的 no$gba 控制配置](<../../images/image (581).png>)

按下后，每个**按键都有一个用于标识它的值**：

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

因此，在这类程序中，有趣的部分是**程序如何处理用户输入**。在地址 **0x4000130** 处，你会找到常见的函数：**KEYINPUT**。

![Ghidra 中的 GBA 二进制文件视图，其中引用了地址 0x4000130 处的 KEYINPUT](<../../images/image (447).png>)

在上一张图片中可以看到，该函数由 **FUN_080015a8** 调用（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，经过一些初始化操作（无关紧要）后：

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

发现了这段代码：

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

最后一个 if 用于检查 **`uVar4`** 是否属于上一组按键，且不是当前按键；这也称为松开一个按钮（当前按键存储在 **`uVar1`** 中）。

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

在前面的代码中，可以看到我们将 **uVar1**（存放**按下按钮的值**的位置）与一些值进行比较：

- 首先，将它与**值 4**（**SELECT** 按钮）进行比较：在这个挑战中，此按钮会清除屏幕。
- 然后，将它与 **8**（**START** 按钮）进行比较；在这个挑战中，该分支会检查输入的代码是否有效。
  - 在这种情况下，变量 **`DAT_030000d8`** 会与 0xf3 进行比较；如果两者相同，就会执行某些代码。
- 在其他所有情况下，都会检查并递增一个计数器（`DAT_030000d4`）。\
  只要计数器小于 8，按键值就会累加到 `DAT_030000d8` 中。

因此，在这个挑战中，了解各个按钮对应的值后，你需要**按下长度小于 8、累加结果为 0xf3 的按键组合。**

**本教程的参考资料：** [已存档的 Nostalgia 挑战 writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 课程

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（Binary 去混淆）

## References

- [1] [使用 CoBRA 简化 MBA 混淆](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA 仓库](https://github.com/trailofbits/CoBRA)
- [3] [解码 Rust 字符串 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA 逆向教程（已存档）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [挫败 AI 辅助逆向工程，或者至少试一试](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [一种基于基本块匹配的控制流图比较方法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver 仓库](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble 混淆机制](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver：使用控制流图相似性自动去混淆 Golang 二进制文件](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor 仓库](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em：Volexity Golang 工具的更新](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA：逆向分析任何内容](https://github.com/morluto/rea)
- [17] [REA 托管代码分析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI 和证据指南](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis：Binary Ninja 控制流反扁平化工作流](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire：PaperCut MF 零日入侵、Java Loader、Web Shell 和 AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge 服务器实现](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge 服务器实现](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) 绑定到通配地址](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore：Godot 逆向工程工具包](https://github.com/figurophobia/gore)
- [26] [gore 密钥恢复实现](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore 加密数据块格式](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore 命令与恢复实现](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
