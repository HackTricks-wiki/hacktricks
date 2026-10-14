# 逆向工具与基本方法

{{#include ../../banners/hacktricks-training.md}}

## 基于 ImGui 的逆向工具

软件：

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows 内核调试

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm 反编译器 / Wat 编译器

在线工具：

- 使用 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) 将 wasm（二进制）**反编译**为 wat（纯文本）
- 使用 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) 将 wat **编译**为 wasm
- 也可以尝试使用 [web-wasmdec](https://wwwg.github.io/web-wasmdec/) 进行反编译。

软件：

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 缓存字节码

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 虚拟化载荷与自定义 VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET 反编译器

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一款反编译器，可**反编译并检查多种格式**，包括**库**（.dll）、**Windows 元数据文件**（.winmd）和**可执行文件**（.exe）。反编译后，可以将程序集保存为 Visual Studio 项目（.csproj）。

如果需要从旧版程序集中恢复丢失的源代码，这款工具可以节省时间。此外，dotPeek 提供便捷的反编译代码导航功能，是进行 **Xamarin 算法分析**的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

.NET Reflector 具有完善的插件模型和可按需扩展工具的 API，能够节省时间并简化开发。下面来看看它提供的丰富逆向工程功能：

- 深入了解数据如何流经库或组件
- 了解 .NET 语言和框架的实现与用法
- 查找未文档化和未公开的功能，充分利用所用的 API 和技术。
- 查找依赖项和不同的程序集
- 精确定位代码、第三方组件和库中的错误。
- 调试所使用的所有 .NET 代码的源代码。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[适用于 Visual Studio Code 的 ILSpy 插件](https://github.com/icsharpcode/ilspy-vscode)：可在任何 OS 上使用（可直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并**搜索 ILSpy**）。\
如果需要**反编译**、**修改**并再次**重新编译**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 或其仍在积极维护的 fork——[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（**右键 -> Modify Method**，即可修改函数内部内容。）

### 使用 REA 进行无需执行的托管代码检查

**REA** 无需加载程序集，即可检查 PE/CLI 元数据和 CIL。首先确认工件标识，然后检查成员和声明的 native 边界；在使用反编译器或运行程序之前审查可疑调用时，这种方法很有用。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

进行版本差异比对时，`compare_managed_members` 使用原始 CIL/签名标识和解码指令指纹，而不将元数据 token 视为跨构建稳定。P/Invoke 声明并不能证明原生代码已运行；`verify_managed_native_boundaries` 需要匹配的原生导出或函数证据来检查该边界。请将 artifact digest、MVID 和未解析的映射与结果一并保留。<sup>[[17]](#references)</sup>

### DNSpy 日志记录

若要让 **DNSpy 将一些信息记录到文件中**，可以使用以下代码片段：

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

要使用 DNSpy 调试代码，你需要：

首先，更改与**调试**相关的 **Assembly attributes**：

![DNSpy Logging - DNSpy 调试：首先，更改与调试相关的 Assembly attributes](<../../images/image (973).png>)

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

接着通过 _**File >> Save module...**_ 保存新文件：

![DNSpy Logging - DNSpy Debugging: 接着通过 File Save module 保存新文件](<../../images/image (602).png>)

这一步很重要，因为如果不这样做，代码在 **runtime** 时会应用多项 **optimisations**，可能导致调试时**断点永远不会命中**，或者某些**变量不存在**。

然后，如果你的 .NET 应用由 **IIS** **运行**，可以使用以下命令将其**重启**：

```
iisreset /noforce
```

然后，为了开始调试，你应该关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![DNSpy Logging - DNSpy Debugging：然后，为了开始调试，你应该关闭所有已打开的文件，并在 Debug Tab 中选择 Attach to Process](<../../images/image (318).png>)

然后选择 **w3wp.exe**，附加到 **IIS server**，再点击 **attach**：

![DNSpy Logging - DNSpy Debugging：然后选择 w3wp.exe，附加到 IIS server，再点击 attach](<../../images/image (113).png>)

现在我们正在调试该进程，接下来需要暂停它并加载所有模块。先点击 _Debug >> Break All_，然后点击 _**Debug >> Windows >> Modules**_：

![DNSpy Logging - DNSpy Debugging：现在我们正在调试该进程，接下来需要暂停它并加载所有模块。先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging：现在我们正在调试该进程，接下来需要暂停它并加载所有模块。先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (834).png>)

在 **Modules** 中点击任意模块，然后选择 **Open All Modules**：

![DNSpy Logging - DNSpy Debugging：在 Modules 中点击任意模块，然后选择 Open All Modules](<../../images/image (922).png>)

在 **Assembly Explorer** 中右键点击任意模块，然后点击 **Sort Assemblies**：

![DNSpy Logging - DNSpy Debugging：在 Assembly Explorer 中右键点击任意模块，然后点击 Sort Assemblies](<../../images/image (339).png>)

## Java 反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## 调试 DLL

### 使用 IDA

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- 选择 **Windbg** debugger
- 选择 "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA：选择 " Suspend on library load/unload "](<../../images/image (868).png>)

- 配置执行的**参数**，填入 **DLL 的路径**以及要调用的函数：

![Debugging DLLs - Using IDA：配置执行参数，填入 DLL 的路径以及要调用的函数](<../../images/image (704).png>)

然后，开始调试时，**每次加载 DLL 时执行都会暂停**。因此，当 rundll32 加载你的 DLL 时，执行就会暂停。

此方法会在模块加载事件时暂停，但与下方的 x64dbg 工作流相比，抵达已加载 DLL 的入口点不那么直接。

### 使用 x64dbg/x32dbg

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- **更改命令行**（_File --> Change Command Line_），并设置 dll 的路径以及要调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- 更改 _Options --> Settings_，并选择 "**DLL Entry**"。
- 然后**开始执行**。debugger 会在每个 dll main 处暂停，最终你会**停在你的 dll 的 Entry 处**。从这里开始，只需找到你想设置断点的位置。

请注意，在 win64dbg 中，无论因何种原因暂停执行时，都可以查看 **win64dbg 窗口顶部**，了解**当前所在的代码位置**：

![Using IDA - Using x64dbg/x32dbg：请注意，在 win64dbg 中，无论因何种原因暂停执行时，都可以查看 win64dbg 窗口顶部，了解当前所在的代码位置](<../../images/image (842).png>)

此指示器可以确认执行是否已暂停在你要调试的 DLL 内部。

## GUI 应用 / 电子游戏

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个实用程序，可用于查找运行中游戏的重要数值在内存中的保存位置并修改它们。更多信息请参见：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger (GDB) 的前端/逆向工程工具，专注于游戏。不过，它也可用于任何与逆向工程相关的工作。

[**Decompiler Explorer**](https://dogbolt.org/) 是一个 Web 前端，可调用多种反编译器。此 Web 服务可以让你比较不同反编译器对小型可执行文件的输出。

## 使用 REA 进行有证据支持的原生程序调查

**REA** 通过 CLI 和 MCP 提供 Hopper、Ghidra 和 IDA 的分析功能。它需要 Node.js 22.x（至少 22.19）、24.x（至少 24.11）或 26+，以及 npm。请先配置现有的原生 provider；检查 `rea providers --json`，如果有多个 provider 支持目标，请显式选择一个。以下示例中的 `0x1000` 应替换为 inventory 中观察到的函数名称或地址。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

从 feature string 或 symbol 开始，沿着引用和调用者追踪，然后检查所选函数的 dossier 和伪代码（使用 `rea decompile`）。REA 会将 session 绑定到所选 provider，不会在失败后悄悄替换 provider。要重复执行查询，`--snapshot PATH` 只会复用 artifact 字节、provider、设置、操作和参数均匹配的内容；snapshot 是本地缓存，不是已保存的 provider 数据库。请保留返回的 Evidence 和明确标注的未知项，不要把推断出的路径或反编译器文本当作原始源代码。<sup>[[16]](#references)[[18]](#references)</sup>

对于进入 native add-ons 的 JavaScript/Electron 入口点，请参阅 [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea)。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### 使用 blobrunner 调试 shellcode

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 会分配 **shellcode**、打印其**内存地址**，并暂停执行。\
附加 IDA 或 x64dbg 等 debugger，在打印出的地址处设置断点，然后继续执行以调试 shellcode。

GitHub releases 页面包含编译好的版本压缩包：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在以下链接找到略作修改的 Blobrunner 版本。要编译它，只需**在 Visual Studio Code 中创建一个 C/C++ 项目，复制并粘贴代码，然后构建**。


{{#ref}}
blobrunner.md
{{#endref}}

### 使用 jmp2it 调试 shellcode

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) 与 BlobRunner 类似。它会分配 shellcode 并进入无限循环。附加 debugger，继续执行 **2–5 秒**，然后在该循环内暂停，并单步执行到随后将执行流程转移到已分配 shellcode 的调用处。

![Debugger 在 jmp2it 的无限循环中暂停，位置紧邻调用已分配 shellcode 之前](<../../images/image (509).png>)

你可以在 [releases 页面下载编译好的 jmp2it](https://github.com/adamkramer/jmp2it/releases/)。

### 使用 Cutter 调试 shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 Cutter 可以模拟 shellcode 并动态检查它。

请注意，Cutter 允许你选择“Open File”和“Open Shellcode”。在我的案例中，将 shellcode 作为文件打开时，它能正确反编译；但作为 shellcode 打开时则不行：

![Cutter 将相同字节分别作为文件和 shellcode 打开时显示不同的分析结果](<../../images/image (562).png>)

要从指定位置开始模拟，请在那里设置一个 bp；显然，Cutter 会自动从该处开始模拟：

![启动 Cutter 模拟前，在所需的 shellcode 入口处设置断点](<../../images/image (589).png>)

![Cutter emulator 在选定的 shellcode 断点处暂停](<../../images/image (387).png>)

例如，你可以在 hex dump 中查看 stack：

![在 Cutter 的 hex dump 中查看模拟得到的 shellcode stack](<../../images/image (186).png>)

### 反混淆 shellcode 并获取已执行的函数

你可以试试 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。\
它会告诉你 shellcode 使用了**哪些函数**，以及 shellcode 是否正在内存中**解码**自身。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg 还提供图形化启动器，你可以在其中选择所需选项并执行 shellcode

![用于选择 shellcode 仿真和跟踪选项的 scDbg 图形化启动器](<../../images/image (258).png>)

**Create Dump** 选项会在 shellcode 的内存内容发生动态变化时转储最终的 shellcode（适用于下载解码后的 shellcode）。**start offset** 可用于从特定偏移处开始执行 shellcode。**Debug Shell** 选项可通过 scDbg 终端调试 shellcode（不过，我认为前面介绍的选项更适合这种情况，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 反汇编

将 shellcode 文件作为输入上传，并使用以下 recipe 对其进行反汇编：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**混合布尔-算术（Mixed Boolean-Arithmetic，MBA）** 混淆会用混合算术运算符（`+`、`-`、`*`）和位运算符（`&`、`|`、`^`、`~`、移位）的公式，隐藏 `x + y` 这类简单表达式。关键在于，这些恒等式通常只在**固定宽度模运算**下成立，因此进位和溢出都很重要：

```c
(x ^ y) + 2 * (x & y) == x + y
```

如果使用通用代数工具简化这类表达式，很容易因为忽略位宽语义而得到错误结果。<sup>[[1]](#references)</sup>

### 实用工作流程

1. **保留原始位宽**，即提升后的代码/IR/反编译器输出中的位宽（`8/16/32/64` 位）。
2. 尝试简化前，先**对表达式分类**：
   - **线性**：位运算原子的加权和
   - **半线性**：线性项加上 `x & 0xFF` 之类的常量掩码
   - **多项式**：包含乘积
   - **混合**：乘积和位运算逻辑交错，通常含有重复子表达式
3. 使用随机测试或 SMT 证明验证每个候选改写。如果无法证明等价，就保留原始表达式，不要猜测。

### 使用窄执行切片绕过扁平化控制流

通常无需恢复完整的控制流图。遇到 control-flow flattening、opaque predicates、大型分发器或充斥 MBA 的代码时，从加密数据块和输出缓冲区开始追踪引用，找到对它们进行转换的最小例程。然后仅复现该数据流切片，或单独执行它；如果可以直接初始化相关状态，分发器就不是解决问题的必要部分。<sup>[[7]](#references)</sup>

实用工作流程如下：<sup>[[7]](#references)</sup>

1. 列出可执行段和数据段、重定位信息及交叉引用。在保留字节顺序和元素宽度的情况下，从 `.rodata` 导出候选表。
2. 找到最后一个写入明文或输出缓冲区的例程。记录其输入、引用的表、导入的调用以及所需的全局状态。
3. 将这些操作提升为定宽 Python 模型。如果该切片仍依赖过多状态，可在 Unicorn、QEMU 或调试器中调用该例程，并 hook 无关的导入项，而不是模拟整个程序。
4. 验证提取器确实从提供的二进制文件中推导出结果：移除静默回退逻辑，搜索其中是否嵌入答案，并使用字符串、密钥、标识符、布局和混淆种子均已更改的未知构建版本进行测试。

有用的初步命令如下：<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 检测伪装成常量的 MBA 表达式

一个看似依赖输入的字节表达式，可能会完全抵消输入的影响。提取其查找表后，遍历完整的 8 位取值域计算表达式；如果输出集合只有一个值，就能证明该字节是常量，无需还原外围状态机。<sup>[[7]](#references)</sup>

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

保留最终的掩码，因为原始加法会发生字节宽度回绕。对于更宽的定义域，可以询问 SMT 求解器：对于两个相同位宽的符号输入，`f(x1) != f(x2)` 是否可满足：`unsat` 可证明结果不变，而 `sat` 会给出反例，意味着不能丢弃该输入。<sup>[[7]](#references)</sup>

#### 识别受环境影响的解码

反分析检查不一定会触发分支或崩溃。解码器可以将传感器结果混入密钥位、不透明谓词常量或扁平化分发器状态中，继续正常运行，并在模拟器中生成看似合理但实际上错误的明文。因此，仅修补可见的失败分支并不足够；应追踪环境探测结果到解码器状态的数据依赖，在真实设备和模拟器上比较同一段代码，并测试强制设置各个传感器结果后最终缓冲区会如何变化。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一款实用的 MBA 简化工具，可用于恶意软件分析和受保护二进制文件逆向分析。它会对表达式进行分类，并将其交由专用流程处理，而不是对所有表达式一概应用同一种通用重写流程。<sup>[[2]](#references)</sup>

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

- **Linear MBA**：CoBRA 在 Boolean 输入上计算表达式，生成签名，并同时尝试多种恢复方法，例如模式匹配、ANF 转换和系数插值。
- **Semilinear MBA**：通过按位分区重建常量掩码原子，确保掩码区域仍然正确。
- **Polynomial/Mixed MBA**：将乘积分解为核心项，并可将重复子表达式提取为临时变量，再简化外层关系。

一个通常值得尝试恢复的混合恒等式示例：

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

这可以简化为：

```c
x * y
```

### 逆向分析笔记

- 优先对 **提升后的 IR 表达式** 或在隔离出精确计算后得到的反编译器输出运行 CoBRA。
- 如果表达式来自掩码运算或窄寄存器，请显式使用 `--bitwidth`。
- 如果需要更强的证明步骤，请查看此处的 Z3 笔记：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 还提供 **LLVM pass 插件**（`libCobraPass.so`），当你想在后续分析 pass 之前规范化 MBA 密集型 LLVM IR 时，这个插件很有用。
- 对于不受支持、对进位敏感的混合域残留表达式，应将其视为信号：保留原始表达式，并手动分析进位路径。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

这个混淆器会用基于 `mov` 的指令序列替换程序操作，并通过信号/异常处理来改变控制流。详情请见：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

对于受支持的二进制文件，[demovfuscator](https://github.com/kirschju/demovfuscator) 可以对结果进行反混淆。它有若干依赖项。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

并且[安装 keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

如果你正在参加 **CTF，下面这个寻找 flag 的变通方法**可能很有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要查找**入口点**，可以像下面这样搜索函数名中的 `::main`：

![在 Ghidra 中通过搜索包含双冒号 main 的函数名来查找 Rust 入口点](<../../images/image (1080).png>)

在这个例子中，二进制文件名为 authenticator，因此很容易看出这是值得关注的 main 函数。\
知道了被调用**函数**的**名称**后，可以在**互联网**上搜索它们，了解它们的**输入**和**输出**。

### 从 ELF 固件中恢复 Rust 字符串

在 **Rust ELF** 二进制文件中，许多静态字符串并非通过 C 风格的 NUL 终止指针来引用。常见的 `rustc` 布局是在 **`.data.rel.ro`** 中存储一个**指针/长度元组**，指向 **`.rodata`** 中存放的实际字符串数据：

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
2. 逐个字遍历 **`.data.rel.ro`**。
3. 将 `.rodata` 地址范围内的任何值视为候选字符串指针。
4. 将下一个字视为候选长度。
5. 应用合理性筛选条件（例如，只保留长度在 **4** 到 **100** 字节之间的值）。
6. 从 `.rodata` 中精确读取 `length` 个字节，而不是扫描到 `0x00` 为止。

最简提取器逻辑：

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

这在固件逆向中尤其有用，因为恢复出的 Rust 字符串通常会揭示 **HTTP 路由、RPC 名称、日志消息、断言、文件名、配置键、命令处理程序和认证相关逻辑**。

如果 Ghidra 漏掉了这些字符串，可以运行自定义脚本/插件，应用相同的启发式方法，并在被引用的 `.rodata` 偏移处创建字符串数据。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` 工具是很好的参考，可用于将这一思路调整到其他 **字长、字节序和节布局**。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

对于 Delphi 编译的二进制文件，可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果需要逆向 Delphi 二进制文件，建议使用 IDA 插件 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

在 IDA 中按 **Alt+F7** 加载 Python 插件，然后选择插件文件。

该插件会执行二进制文件，并在调试开始时动态解析函数名称。开始调试后，再次按下 Start 按钮（绿色按钮或 f9），断点就会在实际代码的开头触发。

如果在图形应用程序中按下某个按钮，调试器可以停在该按钮调用的函数中。

## Golang

对于普通的 Go 二进制文件，[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) 可以恢复运行时结构，并改进 IDA 中的函数名称。在 IDA 中按 **Alt+F7** 加载其 Python 插件。

如果需要逆向 Golang 二进制文件，建议使用 IDA 插件 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

在 IDA 中按 **Alt+F7** 加载 Python 插件，然后选择插件文件。

此插件会解析函数名称。

### 在没有符号表的情况下恢复元数据

经过剥离的 Go 可执行文件仍需要运行时元数据，才能将程序计数器映射到函数。[GoReSym](https://github.com/mandiant/GoReSym) 使用源自 Go runtime 的代码定位并解析 `pclntab` 和 `moduledata` 等结构。无需依赖常规符号表，它就能恢复函数边界、名称、源代码路径、类型和构建信息。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

混淆器可以保留这些结构，使其仍可用，同时替换恢复出的名称。例如，Garble 会对标识符和包路径进行哈希处理，并移除构建、模块和调试信息。<sup>[[12]](#references)</sup> 同一包中的函数必须使用一致的混淆包标记。按重复标记对函数分组，从某个函数的被调用函数、字符串和 API 推断出一个包，然后将该包标签传播到整个分组。<sup>[[13]](#references)</sup>

### 使用 GoResolver 恢复 Garble 名称

[GoResolver](https://github.com/volexity/GoResolver) 将 runtime 符号提取、干净参考文件生成和控制流图（CFG）匹配结合起来。按以下步骤操作：<sup>[[10]](#references)[[13]](#references)</sup>

1. **识别编译器版本。** 首先尝试使用 `BuildInfo` 和嵌入的版本字符串。如果混淆器移除了这些信息，则将捆绑的 Go runtime 的部分内容与不同版本的参考 runtime 进行比较。在 Volexity 的测试中，只需约 `2%` 的 runtime 内容就足以区分 Go 的主版本。请将此视为经验性优化，而非普遍适用的阈值。<sup>[[13]](#references)</sup>
2. **构建匹配的参考文件。** 为已识别的 Go 版本、目标架构和可能使用的库生成干净二进制文件。匹配工具链可以减少编译器生成的 CFG 差异。<sup>[[10]](#references)[[13]](#references)</sup>
3. **比较函数。** GoGrapher 会匹配函数 CFG，并输出从 `0.0` 到 `1.0` 的归一化分数。它基于相似指令的加权比较来匹配基本块。高置信度匹配可将随机化函数映射到干净实现。较弱的匹配仍可用于识别包或模块。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **验证并导入。** 使用调用关系、常量、字符串和副作用确认建议的名称，然后通过适用于 IDA 或 Ghidra 的 GoResolver 插件导入 JSON 报告。<sup>[[10]](#references)[[13]](#references)</sup>

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

默认的显著匹配阈值为 `0.9`。`--extract` 和 `--graph` 开关可以分别单独运行其中一个阶段；默认情况下会同时运行两个阶段，因为恢复出的运行时元数据和 CFG 证据可以互相补充。<sup>[[10]](#references)</sup> CFG 分数是启发式的：内联、编译标志、架构和库版本差异都可能改变图的形状，因此应保留尚未解析的函数，而不是强行赋予低置信度名称。<sup>[[13]](#references)</sup>

### 恢复 Go 字符串表

Go 二进制文件会将所有已链接包中的字符串字节放在一个连续的表中。表项没有以 NUL 结尾，运行时结构也不会公开该表的基址或大小。不过，在不同操作系统和架构下，编译器都会先按长度、再按字母顺序对表项排序。因此，分析人员找到一个表项后，可以遍历相邻表项，并利用数据交叉引用将字符串与代码关联起来。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) 可在 IDA Pro 和 Ghidra 中自动执行这一流程。请先等待自动分析完成，因为该插件依赖数据段交叉引用。它默认以运行时字符串 `entersyscall` 作为锚点，之后可以向任一方向扫描、在数据库中定义恢复出的字符串，并导出字符串到引用函数的 JSON 映射。<sup>[[14]](#references)</sup>

按引用函数所属的包筛选报告，可以将应用程序或恶意软件代码与已链接库产生的噪声区分开来。此技术无法恢复被混淆破坏的字面量，例如经 Garble 的 `-literals` 转换处理的字面量。但它仍可整理未被混淆的运行时字符串。<sup>[[14]](#references)[[15]](#references)</sup>

### 恢复 Go 运行时类型

Go 会嵌入垃圾回收等功能所需的运行时类型信息。如果构建信息已被剥离，或者反汇编工具无法解析这些元数据，指令可能看起来像是在加载任意数据地址，目标区域也会保持未类型化。恢复这些元数据后，这些地址就能显示为可读的类型引用，也更容易了解各个包的功能。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) 可以提取符号并将运行时类型解析为 JSON 报告。当前 CLI 使用 `resolve` 子命令：<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` 选项会启用类型解析。将报告导入 GoResolver 的 IDA Pro 或 Ghidra 插件，以定义恢复出的类型，并在分析数据库中应用其引用。在此功能引入的报告格式中，省略 `-y` 会使 RTTI 地址和恢复类型成员为 null。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver 支持 x86、AMD64、ARM 和 ARM64 的 PE、ELF 与 Mach-O 样本，因此同一工作流程也适用于来自 Windows、Linux 和 macOS 的 Go 二进制文件。<sup>[[10]](#references)</sup>

## 编译型 Python

本页介绍如何从 ELF/EXE 格式的 Python 编译二进制文件中提取 Python 代码：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

如果你获得了 GBA 游戏的**二进制文件**，可以使用不同的工具来**模拟**和**调试**：

- [**no$gba**](https://problemkaputt.de/gba.htm) (_下载调试版本_) - 包含带界面的调试器
- [**mgba** ](https://mgba.io)- 包含 CLI 调试器
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 插件
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 插件

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，前往 _**Options --> Emulation Setup --> Controls**_** **，可以查看如何按下 Game Boy Advance 的**按键**

![no$gba 控制配置，显示 Game Boy Advance 按键映射](<../../images/image (581).png>)

按下时，每个**按键都有一个用于识别它的值**：

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

因此，在这类程序中，有意思的部分是**程序如何处理用户输入**。在地址 **0x4000130** 处，你会找到常见的函数：**KEYINPUT**。

![Ghidra 视图：GBA 二进制文件在地址 0x4000130 处引用 KEYINPUT](<../../images/image (447).png>)

在上一张图中可以看到，该函数由 **FUN_080015a8** 调用（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，执行了一些初始化操作（无关紧要）：

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

会找到以下代码：

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

最后一个 if 正在检查 **`uVar4`** 是否位于**上一个 Keys**中，且不是当前按键；这也称为松开按键（当前按键存储在 **`uVar1`** 中）。

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

- 首先，它会与**值 4**（**SELECT** 按钮）比较：在这个挑战中，该按钮会清除屏幕
- 然后，它会与 **8**（**START** 按钮）比较；在这个挑战中，这条路径会检查输入的代码是否有效。
  - 在这种情况下，变量 **`DAT_030000d8`** 会与 0xf3 比较，如果值相同，就会执行某些代码。
- 在其他所有情况下，都会检查并递增一个计数器（`DAT_030000d4`）。\
  只要计数器小于 8，按键值就会累加到 `DAT_030000d8` 中。

因此，在这个挑战中，知道各个按钮的值后，你需要**按下一组长度小于 8 的按键，使累加结果为 0xf3。**

**本教程的参考资料：** [归档的 Nostalgia 挑战 writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 课程

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（Binary deobfuscation）

## References

- [1] [使用 CoBRA 简化 MBA 混淆](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA 仓库](https://github.com/trailofbits/CoBRA)
- [3] [解码 Rust 字符串 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA 逆向工程教程（归档版）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [击败 AI 辅助逆向工程，或者至少尝试一下](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [一种基于基本块匹配的控制流图比较方法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver 仓库](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble 混淆机制](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver：使用控制流图相似度自动反混淆 Golang 二进制文件](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor 仓库](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em：Volexity Golang 工具的更新](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA：逆向分析一切](https://github.com/morluto/rea)
- [17] [REA 托管代码分析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI 和证据指南](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
