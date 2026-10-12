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

在线：

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

## 虚拟化 payload 和自定义 VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET 反编译器

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一款反编译器，可**反编译并检查多种格式**，包括**库**（.dll）、**Windows 元数据文件**（.winmd）和**可执行文件**（.exe）。反编译后，可以将程序集保存为 Visual Studio 项目（.csproj）。

如果需要从旧版程序集恢复丢失的源代码，这项功能可以节省时间。此外，dotPeek 还提供便捷的反编译代码导航功能，是进行 **Xamarin 算法分析**的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

.NET Reflector 提供完善的加载项模型和 API，可根据你的具体需求扩展工具功能，从而节省时间并简化开发。下面来看看这款工具提供的丰富逆向工程功能：

- 帮助了解数据如何在库或组件中流动
- 帮助了解 .NET 语言和框架的实现方式及用法
- 查找未公开文档且未暴露的功能，从而充分利用所用的 API 和技术。
- 查找依赖项和不同的程序集
- 精确定位代码、第三方组件和库中的错误。
- 调试你使用的所有 .NET 代码的源代码。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code 的 ILSpy 插件](https://github.com/icsharpcode/ilspy-vscode)：它可以在任何操作系统上使用（可以直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并**搜索 ILSpy**）。\
如果需要**反编译**、**修改**并重新**编译**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 或其仍在积极维护的 fork [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（**右键单击 -> Modify Method**，即可修改函数中的内容。）

### DNSpy 日志记录

若要让 **DNSpy 将一些信息记录到文件中**，可以使用以下代码片段：

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy 调试

要使用 DNSpy 调试代码，你需要：

首先，更改与**调试**相关的 **Assembly attributes**：

![DNSpy Logging - DNSpy 调试：首先，更改与调试相关的 Assembly attributes](<../../images/image (973).png>)

从：

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

至：

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

这一步很重要，因为如果不这样做，代码在 **runtime** 时会应用几项 **optimisations**，可能导致调试时**断点始终无法命中**，或者某些**变量不存在**。

然后，如果你的 .NET 应用程序由 **IIS** **运行**，可以使用以下命令**重启**它：

```
iisreset /noforce
```

然后，为了开始调试，你应该关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![DNSpy Logging - DNSpy Debugging：然后，为了开始调试，你应该关闭所有已打开的文件，并在 Debug Tab 中选择 Attach to Process](<../../images/image (318).png>)

然后选择 **w3wp.exe** 以附加到 **IIS server**，并点击 **attach**：

![DNSpy Logging - DNSpy Debugging：然后选择 w3wp.exe 以附加到 IIS server，并点击 attach](<../../images/image (113).png>)

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

![调试 DLL - 使用 IDA：选择“Suspend on library load/unload”](<../../images/image (868).png>)

- 配置执行的 **parameters**，填入 **DLL 的路径**和你想调用的函数：

![调试 DLL - 使用 IDA：配置执行的 parameters，填入 DLL 的路径和你想调用的函数](<../../images/image (704).png>)

然后，开始调试时，**每次加载 DLL 时执行都会暂停**；因此，当 rundll32 加载你的 DLL 时，执行会暂停。

这种方法会在模块加载事件时暂停，但与下方的 x64dbg 工作流相比，到达已加载 DLL 的入口点不那么直接。

### 使用 x64dbg/x32dbg

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- **更改 Command Line**（_File --> Change Command Line_），并设置 dll 的路径以及你想调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- 更改 _Options --> Settings_ 并选择 "**DLL Entry**"。
- 然后**开始执行**。debugger 会在每个 dll main 处暂停；之后你会在某个时刻**停在你要调试的 dll 的 Entry 处**。接下来，只需找到你想设置断点的位置。

注意，在 win64dbg 中，无论因何种原因导致执行暂停，都可以通过查看 **win64dbg 窗口顶部**，了解**当前所在的代码**：

![使用 IDA - 使用 x64dbg/x32dbg：注意，在 win64dbg 中，无论因何种原因导致执行暂停，都可以通过查看 win64dbg 窗口顶部了解当前所在的代码](<../../images/image (842).png>)

这个指示器可以确认执行是否已暂停在你想调试的 DLL 内部。

## GUI 应用 / 电子游戏

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个实用程序，可以查找正在运行的游戏中重要数值在内存中的存储位置，并对其进行修改。更多信息请参见：


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger (GDB) 的前端/reverse engineering 工具，专注于游戏。不过，它也可用于任何与 reverse engineering 相关的工作。

[**Decompiler Explorer**](https://dogbolt.org/) 是多个反编译器的 Web 前端。这个 Web service 可以让你比较不同反编译器对小型可执行文件的输出。

## ARM 和 MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### 使用 blobrunner 调试 shellcode

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 会分配 **shellcode**、打印其**内存地址**，然后暂停执行。\
附加 IDA 或 x64dbg 等 debugger，在打印出的地址处设置断点，然后恢复执行以调试 shellcode。

GitHub releases 页面包含已编译版本的 zip 文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在以下链接找到稍作修改的 Blobrunner 版本。要编译它，只需**在 Visual Studio Code 中创建 C/C++ 项目，复制并粘贴代码，然后进行 build**。


{{#ref}}
blobrunner.md
{{#endref}}

### 使用 jmp2it 调试 shellcode

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) 与 BlobRunner 类似。它会分配 shellcode 并进入无限循环。附加 debugger，恢复执行 **2–5 秒**，在循环中暂停，然后单步执行到下一个将执行转移到已分配 shellcode 的调用。

![Debugger 在 jmp2it 的无限循环中暂停，正好位于调用已分配 shellcode 之前](<../../images/image (509).png>)

你可以在 [jmp2it 的 releases 页面下载编译版本](https://github.com/adamkramer/jmp2it/releases/)。

### 使用 Cutter 调试 shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 Cutter，你可以模拟 shellcode 并动态检查它。

请注意，Cutter 允许你选择“Open File”和“Open Shellcode”。在我的例子中，将 shellcode 作为文件打开时，反编译结果正确；但将其作为 shellcode 打开时，结果不正确：

![Cutter 展示将相同字节作为文件或 shellcode 打开时产生的不同分析结果](<../../images/image (562).png>)

要从你指定的位置开始模拟，请在那里设置一个 bp；Cutter 显然会自动从该位置开始模拟：

![启动 Cutter 模拟前，在 shellcode 的目标入口处设置断点](<../../images/image (589).png>)

![Cutter emulator 在选定的 shellcode 断点处暂停](<../../images/image (387).png>)

例如，你可以在 hex dump 中查看 stack：

![在 Cutter 的 hex dump 中查看模拟的 shellcode stack](<../../images/image (186).png>)

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

scDbg 还提供一个图形启动器，你可以在其中选择所需选项并执行 shellcode

![用于选择 shellcode 仿真和跟踪选项的 scDbg 图形启动器](<../../images/image (258).png>)

**Create Dump** 选项会在 shellcode 于内存中动态发生任何变化时转储最终的 shellcode（可用于下载解码后的 shellcode）。**start offset** 可用于从特定偏移量开始运行 shellcode。**Debug Shell** 选项可用于通过 scDbg 终端调试 shellcode（不过，我认为前面介绍的任何一种选项都更适合此用途，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 反汇编

上传 shellcode 文件作为输入，并使用以下 recipe 对其进行反汇编：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 混淆反混淆

**混合布尔-算术（MBA）** 混淆会用混合算术运算符（`+`、`-`、`*`）和位运算符（`&`、`|`、`^`、`~`、移位）的公式，隐藏 `x + y` 这类简单表达式。关键在于，这些恒等式通常只有在**固定宽度模运算**下才成立，因此进位和溢出都很重要：

```c
(x ^ y) + 2 * (x & y) == x + y
```

如果使用通用代数工具简化这类表达式，很容易得到错误结果，因为这些工具忽略了位宽语义。<sup>[[1]](#references)</sup>

### 实用工作流程

1. **保留原始位宽**，即提升后的代码/IR/反编译器输出中的位宽（`8/16/32/64` 位）。
2. **先对表达式分类**，再尝试简化：
   - **线性**：按权重求和的位运算原子项
   - **半线性**：线性表达式加上 `x & 0xFF` 之类的常量掩码
   - **多项式**：包含乘积
   - **混合型**：乘积与位运算逻辑交错，通常还包含重复子表达式
3. **使用随机测试或 SMT 证明验证每个候选改写**。如果无法证明等价，就保留原始表达式，不要猜测。

### 通过窄范围执行切片绕过扁平化控制流

通常不必恢复完整的控制流图。遇到控制流扁平化、不透明谓词、大型分发器或大量 MBA 代码时，应从加密数据块和输出缓冲区追踪引用，找到负责转换它们的最小例程。然后只复现这段数据流切片，或独立执行它；如果可以直接初始化相关状态，分发器就不是必需解决方案的一部分。<sup>[[7]](#references)</sup>

实用工作流程如下：<sup>[[7]](#references)</sup>

1. 清点可执行段和数据段、重定位项及交叉引用。从 `.rodata` 转储候选表，同时保留其字节序和元素宽度。
2. 找出最后一个写入明文或输出缓冲区的例程。记录其输入、引用的表、导入函数调用以及所需的全局状态。
3. 仅将这些操作提升为定宽 Python 模型。如果该切片仍依赖过多状态，就在 Unicorn、QEMU 或调试器中调用该例程，并通过 hook 处理无关的导入函数，而不是模拟整个程序。
4. 验证提取器确实是从所提供的二进制文件中推导出输出：移除静默回退逻辑，搜索二进制文件中是否嵌入了答案，并使用字符串、密钥、标识符、布局和混淆种子均已更改的未知构建版本进行测试。

适合第一轮分析的命令如下：<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 检测伪装成常量的 MBA 表达式

一个看似依赖输入的字节表达式，可能会完全抵消其输入。提取其表后，在完整的 8 位取值域上计算该表达式；若输出集合只有一个值，即可证明该字节为常量，无需还原外围状态机。<sup>[[7]](#references)</sup>

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

保留最终掩码，因为原始加法会发生字节宽度的回绕。对于更宽的域，询问 SMT solver：对于两个相同位宽的符号输入，`f(x1) != f(x2)` 是否可满足：`unsat` 可证明该函数具有不变性，而 `sat` 会给出一个反例，表明不能丢弃该输入。<sup>[[7]](#references)</sup>

#### 识别与环境绑定的解码

反分析检查不一定会触发分支或崩溃。解码器可以将传感器结果混入密钥位、不透明谓词常量或扁平化分发器状态中，继续正常运行，并在模拟器中生成看似合理但实际错误的明文。因此，仅修补明显的失败分支并不足够；应追踪环境探测结果到解码器状态的数据依赖关系，在真实设备和模拟器上比较相同代码片段，并测试强制每种传感器结果会如何改变最终缓冲区。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一款实用的 MBA 简化工具，可用于恶意软件分析和受保护二进制文件逆向。它会对表达式进行分类，并将其交给专门的处理流水线，而不是对所有内容都应用同一套通用重写流程。<sup>[[2]](#references)</sup>

快速使用：

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

有用的场景：

- **Linear MBA**：CoBRA 在布尔输入上计算表达式，生成特征签名，并同时尝试多种恢复方法，例如模式匹配、ANF 转换和系数插值。
- **Semilinear MBA**：使用按位分区重建来还原带常量掩码的原子，从而确保掩码区域保持正确。
- **Polynomial/Mixed MBA**：将乘积分解为核心项，并可在简化外层关系前，将重复子表达式提取为临时变量。

一种通常值得尝试恢复的混合恒等式示例：

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

这可以简化为：

```c
x * y
```

### Reversing 笔记

- 优先对 **lifted IR expressions** 或反编译器输出运行 CoBRA，前提是你已隔离出精确的计算过程。
- 如果表达式来自 masked arithmetic 或窄寄存器，请显式使用 `--bitwidth`。
- 如果需要更强的证明步骤，请查看这里的 Z3 笔记：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 还以 **LLVM pass plugin**（`libCobraPass.so`）的形式提供；当你希望在后续分析 pass 之前规范化 MBA-heavy LLVM IR 时，这很有用。
- 对于不受支持且对 carry 敏感的混合域残留表达式，应将其视为信号：保留原始表达式，并手动分析 carry 路径。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

这个 obfuscator 会将程序操作替换为基于 `mov` 的指令序列，并利用信号/异常处理来改变控制流。详情请见：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

对于受支持的二进制文件，[demovfuscator](https://github.com/kirschju/demovfuscator) 可以反混淆结果。它有若干依赖项。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

并且[安装 keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

如果你正在玩 **CTF，这个寻找 flag 的变通方法**可能会很有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要找到**入口点**，可以像下面这样搜索函数名中的 `::main`：

![在 Ghidra 中通过搜索包含双冒号 main 的函数名来查找 Rust 入口点](<../../images/image (1080).png>)

在这个案例中，二进制文件名为 authenticator，因此显然这个 main 函数值得关注。\
知道被调用的**函数**的**名称**后，可以在**Internet**上搜索它们，以了解它们的**输入**和**输出**。

### 从 ELF 固件中恢复 Rust 字符串

在 **Rust ELF** 二进制文件中，许多静态字符串并非通过 C 风格的 NUL 结尾指针引用。常见的 `rustc` 布局是在 **`.data.rel.ro`** 中存储一个**指针/长度元组**，指向存储在 **`.rodata`** 中的实际字符串数据块：

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
2. 按字逐个枚举 **`.data.rel.ro`**。
3. 将 `.rodata` 地址范围内的任何值视为候选字符串指针。
4. 将下一个字视为候选长度。
5. 应用合理性筛选条件（例如，仅保留 **4** 到 **100** 字节的长度）。
6. 从 `.rodata` 中准确读取 `length` 个字节，而不是一直扫描到 `0x00`。

提取器的最简逻辑：

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

这在 firmware reversing 中尤其有用，因为恢复出的 Rust 字符串通常会揭示 **HTTP 路由、RPC 名称、日志消息、断言、文件名、配置键、命令处理程序以及与身份验证相关的逻辑**。

如果 Ghidra 漏掉了这些字符串，可以运行自定义脚本/插件，应用相同的启发式方法，并在被引用的 `.rodata` 偏移处创建字符串数据。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` 工具是很好的参考，可用于将这个思路改编到其他 **字长、字节序和节布局**。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

对于 Delphi 编译的二进制文件，可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果需要逆向 Delphi 二进制文件，建议使用 IDA 插件 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

在 IDA 中按 **Alt+F7** 加载 Python 插件，然后选择插件文件。

该插件会执行二进制文件，并在调试开始时动态解析函数名称。开始调试后，再次按下 Start 按钮（绿色按钮或 f9），断点就会在实际代码的开头触发。

如果在图形应用程序中按下某个按钮，调试器可以停在该按钮调用的函数中。

## Golang

对于普通的 Go 二进制文件，[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) 可以恢复运行时结构，并改进 IDA 中的函数名称。使用 **Alt+F7** 加载其 Python 插件。

### 不依赖符号表恢复元数据

经过剥离的 Go 可执行文件仍需要运行时元数据，以将程序计数器映射到函数。[GoReSym](https://github.com/mandiant/GoReSym) 使用源自 Go 运行时的代码定位并解析 `pclntab` 和 `moduledata` 等结构。无需依赖传统符号表，即可恢复函数边界、名称、源文件路径、类型和构建信息。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

混淆器可以保留这些结构的可用性，同时替换恢复出的名称。例如，Garble 会对标识符和 package 路径进行哈希处理，并移除 build、module 和 debug 信息。<sup>[[12]](#references)</sup> 同一 package 中各函数的混淆 package token 必须保持一致。按重复出现的 token 对函数分组，根据其中一个 package 的 callees、字符串和 API 推断其 package，然后将该 package 标签传播到整个组。<sup>[[13]](#references)</sup>

### 使用 GoResolver 恢复 Garble 名称

[GoResolver](https://github.com/volexity/GoResolver) 将 runtime 符号提取与 clean reference 生成及控制流图（CFG）匹配相结合。按以下顺序操作：<sup>[[10]](#references)[[13]](#references)</sup>

1. **识别编译器版本。** 首先尝试 `BuildInfo` 和嵌入的版本字符串。如果混淆器已将其移除，则将捆绑的 Go runtime 部分内容与带版本信息的 reference runtime 进行比较。在 Volexity 的测试中，只需约 `2%` 的 runtime 内容就足以区分主要 Go 版本。请将其视为经验性优化，而非通用阈值。<sup>[[13]](#references)</sup>
2. **构建匹配的 reference。** 为已识别的 Go 版本、目标架构和可能使用的库生成 clean binary。匹配 toolchain 可减少编译器生成的 CFG 差异。<sup>[[10]](#references)[[13]](#references)</sup>
3. **比较函数。** GoGrapher 会匹配函数 CFG，并输出范围为 `0.0` 到 `1.0` 的归一化分数。它基于相似指令的加权比较来匹配 basic block。高置信度匹配可将随机化函数映射到 clean 实现。置信度较低的匹配仍可用于识别 package 或 module。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **验证并导入。** 根据调用关系、常量、字符串和副作用确认建议的名称，然后使用 GoResolver 插件将 JSON 报告导入 IDA 或 Ghidra。<sup>[[10]](#references)[[13]](#references)</sup>

安装 toolchain 并运行组合 extractor 和 graph matcher：<sup>[[10]](#references)</sup>

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

默认的显著匹配阈值为 `0.9`。`--extract` 和 `--graph` 开关可以分别单独运行任一阶段；默认情况下两者都会运行，因为恢复出的运行时元数据和 CFG 证据可以互为补充。<sup>[[10]](#references)</sup> CFG 分数是启发式的：内联、构建标志、架构和库版本差异都可能改变图的形状，因此应保留尚未解析的函数，而不要强行赋予低置信度名称。<sup>[[13]](#references)</sup>

## 编译后的 Python

本页介绍如何从 ELF/EXE 格式的 Python 编译二进制文件中提取 Python 代码：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

如果你获得了 GBA 游戏的**二进制文件**，可以使用不同的工具对其进行**模拟**和**调试**：

- [**no$gba**](https://problemkaputt.de/gba.htm)（_下载调试版本_）- 包含带界面的调试器
- [**mgba** ](https://mgba.io)- 包含 CLI 调试器
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 插件
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 插件

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，前往 _**Options --> Emulation Setup --> Controls**_** **，可以查看如何按下 Game Boy Advance 的**按键**

![no$gba 控制配置，显示 Game Boy Advance 按键映射](<../../images/image (581).png>)

按下按键时，每个**按键都有一个值**用于标识它：

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

![GBA 二进制文件中引用地址 0x4000130 处 KEYINPUT 的 Ghidra 视图](<../../images/image (447).png>)

在上一张图片中，你可以看到该函数由 **FUN_080015a8** 调用（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，执行一些初始化操作后（这些操作并不重要）：

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

找到以下代码：

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

最后一个 if 检查 **`uVar4`** 是否在上一次的 Keys 中，且不是当前键；这也称为松开按钮（当前键存储在 **`uVar1`** 中）。

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

- 首先，它与**值 4**（**SELECT** 按钮）进行比较：在这个挑战中，此按钮会清除屏幕
- 然后，它与 **8**（**START** 按钮）进行比较；在这个挑战中，该分支会检查输入的代码是否有效。
  - 在这种情况下，变量 **`DAT_030000d8`** 会与 0xf3 进行比较；如果值相同，就会执行一些代码。
- 在其他所有情况下，都会检查并递增一个计数器（`DAT_030000d4`）。\
  当计数器小于 8 时，按键的值会累加到 `DAT_030000d8` 中。

因此，在这个挑战中，已知各个按钮的值后，你需要**按下一个长度小于 8 的组合，使其累加结果为 0xf3。**

**本教程参考资料：** [归档的 Nostalgia 挑战 writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - GBA 逆向工程教程（归档）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [击败 AI 辅助逆向工程，或者至少尝试一下](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [一种基于基本块匹配的控制流图比较方法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble 混淆机制](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver：利用控制流图相似性自动反混淆 Golang 二进制文件](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
