# 逆向工具与基本方法

{{#include ../../banners/hacktricks-training.md}}

## 基于 ImGui 的逆向工具

软件：

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg 用户模式自动化

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows 内核调试

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm 反编译器 / Wat 编译器

在线工具：

- 使用 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) 将 wasm（二进制）**反编译**为 wat（可读文本）
- 使用 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) 将 wat **编译**为 wasm
- 也可以尝试使用 [web-wasmdec](https://wwwg.github.io/web-wasmdec/) 进行反编译。

软件：

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 缓存字节码

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 虚拟化 payload 和自定义 VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET 反编译器

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一款反编译器，可**反编译和检查多种格式**，包括**库**（.dll）、**Windows 元数据文件**（.winmd）和**可执行文件**（.exe）。反编译后，可以将程序集保存为 Visual Studio 项目（.csproj）。

它的优点是，如果需要从旧版程序集恢复丢失的源代码，这一操作可以节省时间。此外，dotPeek 提供了便捷的反编译代码导航功能，是进行 **Xamarin 算法分析**的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

.NET Reflector 具有全面的加载项模型和可扩展 API，可根据你的具体需求定制工具，从而节省时间并简化开发。下面来看看它提供的丰富逆向工程功能：

- 深入了解数据如何流经库或组件
- 深入了解 .NET 语言和框架的实现与用法
- 查找未记录和未公开的功能，充分利用所使用的 API 和技术。
- 查找依赖项和不同的程序集
- 精确定位代码、第三方组件和库中的错误。
- 调试你所使用的所有 .NET 代码的源代码。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[适用于 Visual Studio Code 的 ILSpy 插件](https://github.com/icsharpcode/ilspy-vscode)：可在任何操作系统上使用（可直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并**搜索 ILSpy**）。\
如果需要**反编译**、**修改**并再次**重新编译**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 或其积极维护的分支 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（**右键单击 -> Modify Method** 可修改函数中的内容）。

### 使用 REA 进行无需执行的托管代码检查

**REA** 无需加载程序集，即可检查 PE/CLI 元数据和 CIL。先确认制品的身份，再检查其成员和声明的原生边界；在使用反编译器或运行程序之前审查可疑调用时，这种方法很有用。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

对于版本差异比较，`compare_managed_members` 使用原始 CIL/签名标识和解码指令指纹，而不是将元数据令牌视为不同构建之间稳定不变的标识。P/Invoke 声明并不能证明原生代码已运行；`verify_managed_native_boundaries` 需要匹配的原生导出或函数 Evidence，才能检查该边界。将 artifact digest、MVID 和未解析的映射与结果一并保留。<sup>[[17]](#references)</sup>

### DNSpy 日志记录

若要让 **DNSpy 将某些信息记录到文件中**，可以使用以下代码片段：

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy 调试

要使用 DNSpy 调试代码，你需要：

首先，更改与**调试**相关的**程序集属性**：

![DNSpy Logging - DNSpy 调试：首先，更改与调试相关的程序集属性](<../../images/image (973).png>)

从：

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

收件人：

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

然后点击 **compile**：

![DNSpy Logging - DNSpy Debugging: 然后点击 compile](<../../images/image (314) (1).png>)

然后通过 _**File >> Save module...**_ 保存新文件：

![DNSpy Logging - DNSpy Debugging: 然后通过 File Save module 保存新文件](<../../images/image (602).png>)

这一步很有必要，因为如果不这样做，代码在 **runtime** 时会应用多项 **optimisations**，调试时可能会出现**断点始终无法命中**或某些**变量不存在**的情况。

然后，如果你的 .NET 应用程序由 **IIS** **运行**，可以通过以下方式将其**重启**：

```
iisreset /noforce
```

然后，为了开始调试，你应该关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![DNSpy Logging - DNSpy Debugging: 然后，为了开始调试，你应该关闭所有已打开的文件，并在 Debug Tab 中选择 Attach to Process](<../../images/image (318).png>)

然后选择 **w3wp.exe** 以附加到 **IIS server**，并点击 **attach**：

![DNSpy Logging - DNSpy Debugging: 然后选择 w3wp.exe 以附加到 IIS server，并点击 attach](<../../images/image (113).png>)

现在我们正在调试该进程，接下来要暂停进程并加载所有模块。先点击 _Debug >> Break All_，然后点击 _**Debug >> Windows >> Modules**_：

![DNSpy Logging - DNSpy Debugging: 现在我们正在调试该进程，接下来要暂停进程并加载所有模块。先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: 现在我们正在调试该进程，接下来要暂停进程并加载所有模块。先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (834).png>)

在 **Modules** 中点击任意模块，然后选择 **Open All Modules**：

![DNSpy Logging - DNSpy Debugging: 在 Modules 中点击任意模块，然后选择 Open All Modules](<../../images/image (922).png>)

在 **Assembly Explorer** 中右键点击任意模块，然后点击 **Sort Assemblies**：

![DNSpy Logging - DNSpy Debugging: 在 Assembly Explorer 中右键点击任意模块，然后点击 Sort Assemblies](<../../images/image (339).png>)

## Java 反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## 调试 DLL

### 使用 IDA

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- 选择 **Windbg** 调试器
- 选择 "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: 选择 " Suspend on library load/unload "](<../../images/image (868).png>)

- 配置执行的 **parameters**，填入 **DLL 的路径**以及你想调用的函数：

![Debugging DLLs - Using IDA: 配置执行的 parameters，填入 DLL 的路径以及你想调用的函数](<../../images/image (704).png>)

然后，开始调试时，**每个 DLL 加载时执行都会暂停**；因此，当 rundll32 加载你的 DLL 时，执行会暂停。

此方法会在模块加载事件时暂停，但与下文的 x64dbg 工作流相比，抵达已加载 DLL 的入口点不那么直接。

### 使用 x64dbg/x32dbg

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- **更改命令行**（_File --> Change Command Line_），设置 dll 的路径和你想调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- 更改 _Options --> Settings_ 并选择 "**DLL Entry**"。
- 然后**开始执行**，调试器会在每个 dll main 处暂停；最终你会**在你的 dll Entry 处暂停**。然后只需找到你想设置断点的位置即可。

注意，在 win64dbg 中，执行因任何原因暂停时，你可以查看 **win64dbg 窗口顶部**，了解**当前所在的代码位置**：

![Using IDA - Using x64dbg/x32dbg: 注意，在 win64dbg 中，执行因任何原因暂停时，你可以查看 win64dbg 窗口顶部，了解当前所在的代码位置](<../../images/image (842).png>)

此指示器可确认执行是否已暂停在你想调试的 DLL 内部。

## GUI 应用 / 电子游戏

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个实用程序，可用于查找运行中游戏的重要数值在内存中的存储位置，并对其进行修改。更多信息请参阅：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger (GDB) 的前端/逆向工程工具，专注于游戏。不过，它也可用于任何与逆向工程相关的工作。

[**Decompiler Explorer**](https://dogbolt.org/) 是一个面向多个反编译器的 Web 前端。此 Web 服务可以让你比较不同反编译器对小型可执行文件的输出。

## 基于证据的原生程序分析：REA

**REA** 通过 CLI 和 MCP 提供 Hopper、Ghidra 和 IDA 分析功能。它需要 Node.js 22.x（至少为 22.19）、24.x（至少为 24.11）或 26+，以及 npm。先配置一个现有的原生 provider；运行 `rea providers --json` 查看，并在多个 provider 都支持目标时明确选择一个。将下方的 `0x1000` 替换为 inventory 中观察到的函数名或地址。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

从特征字符串或符号入手，沿着引用和调用关系追踪，然后检查选定函数的档案和伪代码，并使用 `rea decompile`。REA 会将会话绑定到选定的 provider，而不会在失败后悄然替换它。若要重复执行查询，`--snapshot PATH` 只会在制品字节、provider、设置、操作和参数均匹配时复用缓存；snapshot 是本地缓存，不是已保存的 provider 数据库。保留返回的 Evidence 和明确标注的未知项，不要将推断出的路径或反编译器文本当作原始源代码。<sup>[[16]](#references)[[18]](#references)</sup>

对于指向 native add-ons 的 JavaScript/Electron 入口点，请参阅 [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea)。

## 使用本地 TCP bridge 进行 IDA 和 Ghidra 脚本化分析

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) 在**已打开**的 IDA 数据库或 Ghidra CodeBrowser 程序中运行，使独立脚本能够查询和修改该分析数据库。在 IDA 的 Python CLI 中运行 `ID_Server.py`（`import ID_Server`），或在 Ghidra 的 Script Manager 中运行 `Ghidra_Server.py`。IDA 从端口 `5073` 开始绑定 `127.0.0.1`，并继续扫描更高端口。当前的 Ghidra 脚本从端口 `5093` 开始，并依次尝试至 `5102` 的十个端口；其 Java socket 绑定到通配地址，而不仅限于 loopback。连接前请检查该实例输出的端口。与 headless analyzer 不同，此 bridge 操作的是该 GUI 实例中当前打开的程序。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

每个连接发送**一条以换行符结尾的命令**，并读取以换行符结尾的响应。结果通常为 JSON。例如，找到与输入路径相关的导入 API 后，`IMPORTXREF` 可查找其调用位置；随后，`DECOMP_XREF` 可批量反编译选定地址的调用者。`FUNC` 用于检查函数，而 `PCODE` 返回反编译器的中间表示。请使用当前数据库中的地址，不要使用从基址重定位方式不同的二进制文件中复制的地址。以下示例使用 IDA 的默认端口；对于 Ghidra，请使用其脚本输出的端口。<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

同一 channel 也可以**修改分析数据库**：`RENAME_FUNC`、`RETYPE`、`SETCONV`、`DEFSTRUCT`/`SETFIELD`、`MAKEFUNC` 和 `PATCH` 可以更改名称、类型、结构定义、函数边界或存储的字节。`PATCH` 是数据库编辑，**并不代表对运行中的进程打了补丁**。这两个 listener 都没有说明是否需要身份验证。IDA 仅监听 loopback 地址，但 Ghidra 可能可通过网络接口访问；使用 Ghidra 时，请限制对其 listener 的访问。`QUIT` 可以停止任一 listener，IDA 还提供 `ida_bridge_stop()`。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### 使用 blobrunner 调试 shellcode

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 会分配 **shellcode**、打印其**内存地址**，并暂停执行。\
附加 IDA 或 x64dbg 等 debugger，在打印出的地址处设置 breakpoint，然后恢复执行即可调试 shellcode。

releases github 页面包含编译好的版本 zip 文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在以下链接中找到一个略作修改的 Blobrunner 版本。要编译它，只需**在 Visual Studio Code 中创建一个 C/C++ 项目，复制并粘贴代码，然后进行构建**。


{{#ref}}
blobrunner.md
{{#endref}}

### 使用 jmp2it 调试 shellcode

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) 与 BlobRunner 类似。它会分配 shellcode 并进入无限循环。附加 debugger，恢复执行 **2–5 秒**，然后在循环中暂停，并单步执行到后续将执行流转移到已分配 shellcode 的 call。

![Debugger 在 jmp2it 的无限循环中暂停，位置紧邻调用已分配 shellcode 的 call 之前](<../../images/image (509).png>)

你可以在 [jmp2it 的 releases 页面下载编译好的版本](https://github.com/adamkramer/jmp2it/releases/)。

### 使用 Cutter 调试 shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 Cutter 可以模拟 shellcode 并动态检查它。

注意，Cutter 允许你选择“Open File”和“Open Shellcode”。就我的情况而言，将 shellcode 作为文件打开时，它能正确反编译；但作为 shellcode 打开时则不行：

![Cutter 将相同字节作为文件或 shellcode 打开时显示不同的分析结果](<../../images/image (562).png>)

要从指定位置开始模拟，请在那里设置一个 breakpoint；Cutter 似乎会自动从该位置开始模拟：

![启动 Cutter 模拟前，在所需的 shellcode 入口处设置 breakpoint](<../../images/image (589).png>)

![Cutter emulator 在选定的 shellcode breakpoint 处暂停](<../../images/image (387).png>)

例如，你可以在 hex dump 中查看 stack：

![在 Cutter 的 hex dump 中查看模拟 shellcode 的 stack](<../../images/image (186).png>)

### 反混淆 shellcode 并获取已执行的函数

你可以尝试使用 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。\
它会告诉你 shellcode 使用了**哪些函数**，以及它是否正在内存中**解码**自身。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg 还提供图形启动器，可供你选择所需选项并执行 shellcode

![用于选择 shellcode 仿真和跟踪选项的 scDbg 图形启动器](<../../images/image (258).png>)

如果 shellcode 在内存中动态发生变化，**Create Dump** 选项会转储最终的 shellcode（可用于下载解码后的 shellcode）。**start offset** 可用于从指定偏移处启动 shellcode。**Debug Shell** 选项可用于通过 scDbg 终端调试 shellcode（不过，我认为前面介绍的任一选项都更适合，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 反汇编

上传 shellcode 文件作为输入，并使用以下 recipe 对其进行反汇编：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation 反混淆

**混合布尔-算术（MBA）** obfuscation 会把 `x + y` 这样的简单表达式隐藏在混合了算术运算符（`+`、`-`、`*`）和按位运算符（`&`、`|`、`^`、`~`、移位）的公式中。关键在于，这些恒等式通常只在**固定宽度的模运算**下成立，因此进位和溢出都会产生影响：

```c
(x ^ y) + 2 * (x & y) == x + y
```

如果使用通用代数工具简化这类表达式，很容易得到错误结果，因为忽略了位宽语义。<sup>[[1]](#references)</sup>

### 实用工作流程

1. **保留原始位宽**，以 lifted 代码/IR/decompiler 输出为准（`8/16/32/64` 位）。
2. **先对表达式分类**，再尝试化简：
   - **线性**：位运算原子项的加权和
   - **半线性**：线性表达式加上常量掩码，例如 `x & 0xFF`
   - **多项式**：包含乘积
   - **混合**：乘积与位运算逻辑交错，通常还包含重复子表达式
3. 使用随机测试或 SMT 证明验证每个候选改写。如果无法证明等价，就保留原表达式，不要猜测。

### 用窄范围执行切片绕过控制流扁平化

通常不需要还原完整的控制流图。面对控制流扁平化、不透明谓词、大型分发器或 MBA 密集型代码时，可以从加密数据块和输出缓冲区的引用入手，找到负责转换它们的最小例程。然后只复现该数据流切片，或单独执行它；如果可以直接初始化相关状态，分发器就不是必需的解决方案的一部分。<sup>[[7]](#references)</sup>

实用工作流程如下：<sup>[[7]](#references)</sup>

1. 盘点可执行区段和数据区段、重定位项以及交叉引用。从 `.rodata` 中转储候选表，同时保留其字节顺序和元素宽度。
2. 找出最后一个写入明文或输出缓冲区的例程。记录其输入、引用的表、导入调用以及所需的全局状态。
3. 只将这些操作提升到定宽 Python 模型中。如果该切片仍依赖过多状态，就在 Unicorn、QEMU 或调试器中调用该例程，并 hook 无关的导入函数，而不是模拟整个程序。
4. 验证提取器确实根据给定二进制推导输出：移除静默回退逻辑，搜索二进制中是否嵌入答案，并使用字符串、密钥、标识符、布局和混淆种子均有变化的未见过的构建版本进行测试。

首轮排查可使用以下命令：<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 检测伪装成常量的 MBA 表达式

一个看似依赖输入的字节表达式，可能会完全抵消输入。提取其查找表后，在完整的 8 位取值范围内计算该表达式；如果输出集合只有一个值，就能证明该字节为常量，无需还原外围状态机。<sup>[[7]](#references)</sup>

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

保留最终掩码，因为原始加法会发生字节宽度回绕。对于更宽的取值范围，可以让 SMT solver 检查：对于两个相同位宽的符号输入，`f(x1) != f(x2)` 是否可满足：`unsat` 可证明该函数不变，而 `sat` 会给出反例，说明不能丢弃该输入。<sup>[[7]](#references)</sup>

#### 识别与环境绑定的解码

反分析检查不一定会触发分支或导致崩溃。解码器可以将传感器结果混入密钥位、不透明谓词常量或扁平化分发器状态中，继续正常运行，并在 emulator 中生成看似合理但实际错误的明文。因此，仅修补可见的失败分支并不足够；应追踪环境探测结果到解码器状态的数据依赖，在真实设备和 emulator 上对比同一代码片段，并测试强制设置每种传感器结果会如何改变最终缓冲区。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一款实用的 MBA 简化工具，可用于 malware 分析和受保护二进制文件逆向分析。它会对表达式进行分类，并将其送入专用处理流水线，而不是对所有表达式一概应用通用重写流程。<sup>[[2]](#references)</sup>

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

- **线性 MBA**：CoBRA 在 Boolean 输入上计算表达式，推导出签名，并并行尝试多种恢复方法，例如模式匹配、ANF 转换和系数插值。
- **半线性 MBA**：使用按位分区重建来重建常量掩码原子，确保掩码区域保持正确。
- **多项式/混合 MBA**：将乘积分解为核心，并可在简化外层关系之前，将重复子表达式提升为临时变量。

一种通常值得尝试恢复的混合恒等式示例：

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

这可以简化为：

```c
x * y
```

### 逆向笔记

- 优先对**提升后的 IR 表达式**或反编译器输出运行 CoBRA，前提是你已经隔离出确切的计算过程。
- 如果表达式来自掩码算术或窄寄存器，请显式使用 `--bitwidth`。
- 如果需要更强的证明步骤，请查看此处的 Z3 笔记：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 还以 **LLVM pass 插件**（`libCobraPass.so`）的形式提供；如果你想在后续分析 pass 之前规范化 MBA 较多的 LLVM IR，这个插件会很有用。
- 对于不受支持、且对进位敏感的混合域残余表达式，应保留原始表达式，并手动分析进位路径。

## 还原基于 XOR 状态的控制流平坦化

OLLVM 风格的平坦化器可能会在两个 64 位寄存器中保存当前基本块状态，并在分发器处用 XOR 还原状态。每个原始块都会写入表示其下一状态的寄存器对，然后跳回分发器。条件块可以使用 `CMOVcc`，根据 CPU 标志替换寄存器对中的一半，因此只跟踪可见的分支指令会漏掉两个后继块。与间接跳转分发器不同，这种结构可以始终使用直接回边。<sup>[[19]](#references)[[20]](#references)</sup>

要还原控制流图，先找到分发器的比较树和两个状态寄存器，再将每个经过比较的 XOR 状态映射到目标块，然后追踪每个原始块中对寄存器对的到达写入。对于条件写入，要同时考虑设置标志的指令和 `CMOVcc` 的两种结果。将每个块的分发器出口改写为解析出的直接后继或条件分支；无需修改二进制文件，分发器就会变得不可达。这是完整 CFG 的处理方法；如果只关心某个解码器，上文的[窄执行切片工作流](#bypass-flattened-control-flow-with-a-narrow-execution-slice)可能更快。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) 可以在 Binary Ninja 中自动处理这种结构。将 `plugins/DispatchThis` 复制到 Binary Ninja 用户插件目录并重启。在受影响的函数中，打开 **Function Settings** 并选择 `OLLVM_XOR_64`；如果分析没有启动，请使用 **Analysis → Reanalyze All Functions**。此模式会改写 MLIL 控制流边，而不是文件字节，也不需要 Z3 或间接跳转解析器。它已在 Binary Ninja 5.3.9757+ 上测试；它不会移除每个块中无效的状态写入，因此不要将这些写入误认为仍然有效的状态转换。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

这个混淆器会用基于 `mov` 的指令序列替换程序操作，并使用信号/异常处理来改变控制流。详情请见：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

对于受支持的二进制文件，[demovfuscator](https://github.com/kirschju/demovfuscator) 可以对结果进行反混淆。它有几个依赖项。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

并且[安装 keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

如果你正在参加 **CTF，下面这个寻找 flag 的变通方法**可能会非常有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要找到**入口点**，可以搜索函数名中包含 `::main` 的函数，例如：

![在 Ghidra 中搜索函数名里的双冒号 main 来查找 Rust 入口点](<../../images/image (1080).png>)

在这个例子中，二进制文件名为 authenticator，因此很容易看出这是值得关注的 main 函数。\
知道了被调用**函数**的**名称**后，可以在**Internet**上搜索这些函数，以了解它们的**输入**和**输出**。

### 从 ELF 固件中恢复 Rust 字符串

在 **Rust ELF** 二进制文件中，许多静态字符串并非通过 C 风格的 NUL 结尾指针引用。常见的 `rustc` 布局是在 **`.data.rel.ro`** 中使用一个**指针/长度元组**，指向存储在 **`.rodata`** 中的实际字符串数据块：

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

这意味着 `strings` 或 Ghidra 默认分析可能会合并相邻字符串，或完全遗漏交叉引用。<sup>[[3]](#references)</sup>

快速工作流程：

```bash
readelf -S <bin>
objdump -h <bin>
```

1. 获取 **`.rodata`** 的虚拟地址和大小。
2. 逐个 word 枚举 **`.data.rel.ro`**。
3. 将 `.rodata` 地址范围内的任何值视为候选字符串指针。
4. 将下一个 word 视为候选长度。
5. 应用合理性筛选条件（例如，仅保留长度在 **4** 到 **100** 字节之间的值）。
6. 从 `.rodata` 中恰好读取 `length` 个字节，而不是一直扫描到 `0x00`。

最小提取器逻辑：

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

这在固件逆向中特别有用，因为恢复出的 Rust 字符串通常会揭示 **HTTP 路由、RPC 名称、日志消息、断言、文件名、配置键、命令处理程序以及与身份验证相关的逻辑**。

如果 Ghidra 漏掉了这些字符串，可以运行自定义脚本/插件，应用相同的启发式方法，并在引用的 `.rodata` 偏移处创建字符串数据。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` 工具是很好的参考，可用于将这个思路适配到其他 **字长、字节序和节布局**。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

对于 Delphi 编译的二进制文件，可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果需要逆向 Delphi 二进制文件，我建议使用 IDA 插件 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

在 IDA 中按 **Alt+F7** 加载 Python 插件，然后选择插件文件。

此插件会执行二进制文件，并在调试开始时动态解析函数名称。开始调试后，再按一次 Start 按钮（绿色按钮或 f9），断点就会在实际代码的开头命中。

如果在图形应用程序中按下按钮，调试器可能会停在该按钮调用的函数中。

## Golang

对于普通的 Go 二进制文件，[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) 可以恢复运行时结构，并改善 IDA 中的函数名称。使用 **Alt+F7** 加载其 Python 插件。

如果需要逆向 Golang 二进制文件，我建议使用 IDA 插件 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

在 IDA 中按 **Alt+F7** 加载 Python 插件，然后选择插件文件。

此插件会解析函数名称。

### 不使用符号表恢复元数据

经过剥离的 Go 可执行文件仍需要运行时元数据，以便将程序计数器映射到函数。[GoReSym](https://github.com/mandiant/GoReSym) 使用源自 Go runtime 的代码定位并解析 `pclntab` 和 `moduledata` 等结构。无需依赖传统符号表，即可恢复函数边界、名称、源文件路径、类型和构建信息。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

混淆器可以在替换恢复出的名称时，让这些结构仍可用。例如，Garble 会对标识符和包路径进行哈希处理，并移除构建、模块和调试信息。<sup>[[12]](#references)</sup> 来自同一包的函数，其混淆后的包标记必须保持一致。按重复出现的标记对函数分组，从某个函数的被调用函数、字符串和 API 推断一个包，然后将该包标签传播到整个分组。<sup>[[13]](#references)</sup>

### 使用 GoResolver 恢复 Garble 名称

[GoResolver](https://github.com/volexity/GoResolver) 将运行时符号提取与干净参考样本生成和控制流图（CFG）匹配相结合。按以下顺序操作：<sup>[[10]](#references)[[13]](#references)</sup>

1. **识别编译器版本。** 首先尝试 `BuildInfo` 和嵌入的版本字符串。如果混淆器已将它们移除，则将捆绑的 Go 运行时部分内容与带版本的参考运行时进行比较。在 Volexity 的测试中，约 `2%` 的运行时内容就足以区分主要 Go 版本。应将此视为经验性优化，而非通用阈值。<sup>[[13]](#references)</sup>
2. **构建匹配的参考样本。** 针对已识别的 Go 版本、目标架构和可能使用的库，生成未混淆的二进制文件。匹配工具链可减少编译器生成的 CFG 差异。<sup>[[10]](#references)[[13]](#references)</sup>
3. **比较函数。** GoGrapher 会匹配函数 CFG，并输出从 `0.0` 到 `1.0` 的归一化分数。其基本块匹配基于对相似指令进行加权比较。高置信度匹配可将随机化函数映射到干净实现。较弱的匹配仍可用于识别包或模块。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **验证并导入。** 使用调用关系、常量、字符串和副作用确认建议名称，然后通过适用于 IDA 或 Ghidra 的 GoResolver 插件导入 JSON 报告。<sup>[[10]](#references)[[13]](#references)</sup>

安装工具链并运行组合式提取器和图匹配器：<sup>[[10]](#references)</sup>

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

默认的 significant-match 阈值为 `0.9`。`--extract` 和 `--graph` 开关可分别单独运行其中一个阶段；默认情况下两者都会运行，因为恢复的 runtime 元数据与 CFG 证据可以互相补充。<sup>[[10]](#references)</sup> CFG 分数是启发式的：内联、构建标志、架构和库版本差异都可能改变图的结构，因此应保留尚未解析的函数，而不是强行赋予低置信度名称。<sup>[[13]](#references)</sup>

### 恢复 Go 字符串表

Go 二进制文件会将所有已链接包的字符串字节放入一个连续的表中。条目不以 NUL 结尾，runtime 结构也不会公开该表的基址或大小。不过，编译器在不同操作系统和架构上都会先按长度、再按字母顺序排列条目。因此，找到一个条目后，分析人员可以遍历相邻条目，并利用数据交叉引用将字符串与代码关联起来。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) 可在 IDA Pro 和 Ghidra 中自动完成此流程。请先等待自动分析完成，因为该插件依赖数据段交叉引用。它默认以 runtime 字符串 `entersyscall` 为锚点，之后可以向任一方向扫描，在数据库中定义恢复出的字符串，并导出字符串到引用函数的 JSON 映射。<sup>[[14]](#references)</sup>

按引用函数所属的包筛选报告，可将应用程序或恶意软件代码与已链接库产生的噪声区分开来。此技术无法恢复被混淆处理破坏的字面量，例如 Garble 的 `-literals` 转换所处理的内容。但它仍可整理未被混淆的 runtime 字符串。<sup>[[14]](#references)[[15]](#references)</sup>

### 恢复 Go runtime 类型

Go 会嵌入 runtime 类型信息，供垃圾回收等功能使用。如果构建信息已被剥除，或反汇编器无法解析这些元数据，指令可能看起来像是在加载任意数据地址，目标区域也会保持无类型状态。恢复这些元数据后，这些地址便会成为可读的类型引用，也更容易了解各个包的功能。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) 可以提取符号，并将 runtime 类型解析为 JSON 报告。当前 CLI 使用 `resolve` 子命令：<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` 选项会启用类型解析。使用 GoResolver 的 IDA Pro 或 Ghidra 插件导入报告，以定义恢复出的类型，并在分析数据库中应用其引用。在此功能引入的报告格式中，省略 `-y` 会使 RTTI 地址和恢复出的类型成员为空。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver 支持 x86、AMD64、ARM 和 ARM64 的 PE、ELF 和 Mach-O 样本，因此同一工作流程也适用于来自 Windows、Linux 和 macOS 的 Go 二进制文件。<sup>[[10]](#references)</sup>

## 编译后的 Python

本页介绍如何从 ELF/EXE 格式的 Python 编译二进制文件中提取 Python 代码：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

如果你获得了 GBA 游戏的**二进制文件**，可以使用不同的工具对其进行**模拟**和**调试**：

- [**no$gba**](https://problemkaputt.de/gba.htm)（_下载 debug 版本_）- 包含带界面的 debugger
- [**mgba** ](https://mgba.io)- 包含 CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 插件
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 插件

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，打开 _**Options --> Emulation Setup --> Controls**_** **，可以查看如何按下 Game Boy Advance 的**按键**

![no$gba 控制配置，显示 Game Boy Advance 按键映射](<../../images/image (581).png>)

按下时，每个**按键都有一个值**用于识别：

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

因此，在这类程序中，有意思的部分是**程序如何处理用户输入**。在地址 **0x4000130** 处，你会找到一个常见的函数：**KEYINPUT**。

![Ghidra 中显示 GBA 二进制文件在地址 0x4000130 引用 KEYINPUT](<../../images/image (447).png>)

在上图中可以看到，该函数由 **FUN_080015a8** 调用（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，执行完一些 init 操作（无关紧要）后：

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

最后一个 if 检查 **`uVar4`** 是否在上一次的 Keys 中，并且不是当前按键，这也称为松开按钮（当前按键存储在 **`uVar1`** 中）。

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

在前面的代码中可以看到，我们将 **uVar1**（存放**按下按钮的值**的位置）与一些值进行比较：

- 首先，它会与**值 4**（**SELECT** 按钮）比较：在这个挑战中，该按钮会清除屏幕。
- 然后，它会与 **8**（**START** 按钮）比较；在这个挑战中，该分支会检查输入的代码是否有效。
  - 在这种情况下，变量 **`DAT_030000d8`** 会与 0xf3 比较；如果两者相同，就会执行一些代码。
- 在其他所有情况下，都会检查并递增一个计数器（`DAT_030000d4`）。\
  只要计数器小于 8，按键值就会累加到 `DAT_030000d8` 中。

因此，在这个挑战中，已知各个按钮的值后，你需要**按下一个长度小于 8 的组合，使累加结果为 0xf3。**

**本教程的参考资料：** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 课程

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（二进制反混淆）

## References

- [1] [使用 CoBRA 简化 MBA 混淆](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA 仓库](https://github.com/trailofbits/CoBRA)
- [3] [解码 Rust 字符串 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA 逆向教程（存档版）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [挫败 AI 辅助逆向工程，或者至少尝试一下](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [一种基于基本块匹配的控制流图比较方法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver 仓库](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble 混淆机制](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver：利用控制流图相似度自动反混淆 Golang 二进制文件](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor 仓库](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em：Volexity Golang 工具的更新](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA：逆向分析任何事物](https://github.com/morluto/rea)
- [17] [REA 托管代码分析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI 和证据指南](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis：Binary Ninja 控制流反扁平化工作流](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire：PaperCut MF 零日入侵、Java Loader、Web Shell 和 AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge 服务端实现](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge 服务端实现](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) 绑定到通配地址](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
