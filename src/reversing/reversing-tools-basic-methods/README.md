# Reversing 工具与基本方法

{{#include ../../banners/hacktricks-training.md}}

## 基于 ImGui 的 Reversing 工具

软件：

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

在线工具：

- 使用 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) 将 wasm（二进制）**decompile** 为 wat（明文）
- 使用 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) 将 wat **compile** 为 wasm
- 你也可以尝试使用 [web-wasmdec](https://wwwg.github.io/web-wasmdec/) 进行 decompilation。

软件：

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一个能够 **decompile 和检查多种格式**的 decompiler，包括 **libraries**（.dll）、**Windows metadata file**（.winmd）和 **executables**（.exe）。完成 decompile 后，可以将 assembly 保存为 Visual Studio project（.csproj）。

其优点在于，如果需要从 legacy assembly 中恢复丢失的 source code，这一操作可以节省时间。此外，dotPeek 还提供了在 decompiled code 中进行便捷导航的功能，使其成为 **Xamarin algorithm analysis** 的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

.NET reflector 具有全面的 add-in model 和可扩展其功能以满足你确切需求的 API，可以节省时间并简化开发。下面来看看该工具提供的大量 reverse engineering 服务：

- 了解 data 如何流经 library 或 component
- 了解 .NET languages 和 frameworks 的实现与使用方式
- 查找未记录和未公开的 functionality，从而更充分地利用所使用的 APIs 和 technologies。
- 查找 dependencies 和不同的 assemblies
- 定位代码、third-party components 和 libraries 中错误的确切位置。
- 调试你所使用的所有 .NET code 的 source。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[适用于 Visual Studio Code 的 ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode)：你可以在任意 OS 上使用它（可以直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并 **search ILSpy**）。\
如果你需要 **decompile**、**modify** 并再次 **recompile**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases)，或其仍在积极维护的 fork：[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（使用 **Right Click -> Modify Method** 修改 function 内的内容）。

### DNSpy Logging

为了让 **DNSpy 将一些信息记录到文件中**，你可以使用以下 snippet：
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy 调试

要使用 DNSpy 调试代码，你需要：

首先，更改与**调试**相关的 **Assembly 属性**：

![DNSpy Logging - DNSpy 调试：首先，更改与调试相关的 Assembly 属性](<../../images/image (973).png>)

从：
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
致：
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

这是必要的，因为如果不这样做，在 **runtime** 期间，代码会应用多项 **optimisations**，因此在调试时可能出现 **break-point never hit** 或某些 **variables don't exist** 的情况。

然后，如果你的 .NET 应用程序由 **IIS** **run**，可以通过以下方式将其 **restart**：
```
iisreset /noforce
```
然后，为了开始 debugging，你应关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![DNSpy Logging - DNSpy Debugging：然后，为了开始 debugging，你应关闭所有已打开的文件，并在 Debug Tab 中选择 Attach to Process](<../../images/image (318).png>)

然后选择 **w3wp.exe** 以附加到 **IIS server**，并点击 **attach**：

![DNSpy Logging - DNSpy Debugging：然后选择 w3wp.exe 以附加到 IIS server，并点击 attach](<../../images/image (113).png>)

现在我们已经在 debugging 该进程，接下来需要停止它并加载所有 modules。首先点击 _Debug >> Break All_，然后点击 _**Debug >> Windows >> Modules**_：

![DNSpy Logging - DNSpy Debugging：现在我们已经在 debugging 该进程，接下来需要停止它并加载所有 modules。首先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging：现在我们已经在 debugging 该进程，接下来需要停止它并加载所有 modules。首先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (834).png>)

在 **Modules** 中点击任意 module，然后选择 **Open All Modules**：

![DNSpy Logging - DNSpy Debugging：在 Modules 中点击任意 module，然后选择 Open All Modules](<../../images/image (922).png>)

右键点击 **Assembly Explorer** 中的任意 module，然后点击 **Sort Assemblies**：

![DNSpy Logging - DNSpy Debugging：右键点击 Assembly Explorer 中的任意 module，然后点击 Sort Assemblies](<../../images/image (339).png>)

## Java 反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### 使用 IDA

- **Load rundll32**（64bits 位于 C:\Windows\System32\rundll32.exe，32 bits 位于 C:\Windows\SysWOW64\rundll32.exe）
- 选择 **Windbg** debugger
- 选择 "**Suspend on library load/unload**"

![Debugging DLLs - 使用 IDA：选择 " Suspend on library load/unload "](<../../images/image (868).png>)

- 配置执行的 **parameters**，填入 **path to the DLL** 以及你想调用的 function：

![Debugging DLLs - 使用 IDA：配置执行的 parameters，填入 path to the DLL 以及你想调用的 function](<../../images/image (704).png>)

然后，当你开始 debugging 时，**每个 DLL 被加载时，execution 都会停止**；因此，当 rundll32 加载你的 DLL 时，execution 将会停止。

此方法会在 module-load events 处停止，但与下面的 x64dbg workflow 相比，到达已加载 DLL 的 entry point 不够直接。

### 使用 x64dbg/x32dbg

- **Load rundll32**（64bits 位于 C:\Windows\System32\rundll32.exe，32 bits 位于 C:\Windows\SysWOW64\rundll32.exe）
- **Change the Command Line**（_File --> Change Command Line_），并设置 dll 的 path 以及你想调用的 function，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- 更改 _Options --> Settings_，并选择 "**DLL Entry**"。
- 然后 **start the execution**，debugger 将在每个 dll main 处停止；在某个时刻，你会 **stop in the dll Entry of your dll**。从那里开始，只需查找你想设置 breakpoint 的位置。

注意，当 execution 因任何原因在 win64dbg 中停止时，你可以查看当前位于 **which code**，位置在 win64dbg 窗口的**顶部**：

![Using IDA - 使用 x64dbg/x32dbg：注意，当 execution 因任何原因在 win64dbg 中停止时，你可以在 win64dbg 窗口顶部查看当前位于 which code](<../../images/image (842).png>)

此 indicator 可确认 execution 已在你想要 debugging 的 DLL 内部停止。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个实用程序，可用于查找重要数值在运行中 game 的 memory 内保存的位置，并修改这些数值。更多信息：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger（GDB）的 front-end/reverse engineering tool，专注于 games。不过，它也可以用于任何与 reverse-engineering 相关的工作。

[**Decompiler Explorer**](https://dogbolt.org/) 是一个面向多个 decompilers 的 web front-end。该 web service 可让你比较不同 decompilers 对小型 executables 的输出。

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### 使用 blobrunner debugging shellcode

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 会分配 **shellcode**，打印其 **memory address**，并暂停 execution。\
附加 IDA 或 x64dbg 等 debugger，在打印出的 address 处设置 breakpoint，然后恢复 execution 以 debugging shellcode。

releases github page 包含含有已编译 releases 的 zips：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在以下 link 中找到一个略有修改的 Blobrunner 版本。要编译它，只需**在 Visual Studio Code 中创建 C/C++ project，复制并粘贴 code，然后 build**。


{{#ref}}
blobrunner.md
{{#endref}}

### 使用 jmp2it debugging shellcode

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) 与 BlobRunner 类似。它会分配 shellcode 并进入 infinite loop。附加 debugger，恢复 execution **2–5 秒**，在该 loop 内暂停，然后 single-step 到下面将 execution 转移到已分配 shellcode 的 call。

![Debugger 在 jmp2it 的 infinite loop 中暂停，紧接着调用已分配的 shellcode 之前](<../../images/image (509).png>)

你可以从 [releases page 中的 jmp2it](https://github.com/adamkramer/jmp2it/releases/) 下载已编译版本。

### 使用 Cutter debugging shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 Cutter，你可以 emulate shellcode 并动态 inspect 它。

请注意，Cutter 允许你选择 "Open File" 和 "Open Shellcode"。在我的情况下，将 shellcode 作为 file 打开时，它能够正确 decompile；但将其作为 shellcode 打开时却无法正确处理：

![Cutter 将相同 bytes 作为 file 或 shellcode 打开时显示不同的 analysis results](<../../images/image (562).png>)

要从你想要的位置开始 emulation，请在那里设置 bp；显然，Cutter 会自动从该位置开始 emulation：

![启动 Cutter emulation 前，在所需的 shellcode entry 处设置 breakpoint](<../../images/image (589).png>)

![Cutter emulator 在选定的 shellcode breakpoint 处暂停](<../../images/image (387).png>)

例如，你可以在 hex dump 中查看 stack：

![在 Cutter 的 hex dump 中查看 emulated shellcode stack](<../../images/image (186).png>)

### Deobfuscating shellcode 并获取 executed functions

你应该尝试 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。\
它会告诉你诸如 shellcode 正在使用**哪些 functions**，以及 shellcode 是否正在 memory 中**decode 自身**等信息。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg 还提供了一个图形化启动器，你可以在其中选择所需的选项并执行 shellcode

![scDbg 用于选择 shellcode 模拟和跟踪选项的图形化启动器](<../../images/image (258).png>)

**Create Dump** 选项会转储最终的 shellcode，前提是 shellcode 在内存中被动态修改过（对于下载已解码的 shellcode 很有用）。**start offset** 可用于从特定偏移量开始执行 shellcode。**Debug Shell** 选项可用于通过 scDbg 终端调试 shellcode（不过我认为前面介绍的任一选项都更适合此用途，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 进行反汇编

将 shellcode 文件作为输入上传，并使用以下 recipe 对其进行反汇编：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 混淆去混淆

**Mixed Boolean-Arithmetic (MBA)** 混淆会通过混合算术运算（`+`、`-`、`*`）和位运算符（`&`、`|`、`^`、`~`、移位）的公式，将 `x + y` 等简单表达式隐藏起来。关键在于，这些恒等式通常只在**固定宽度的模运算**下成立，因此进位和溢出非常重要：
```c
(x ^ y) + 2 * (x & y) == x + y
```
如果使用通用代数工具简化这类表达式，很容易得到错误结果，因为忽略了位宽语义。<sup>[[1]](#references)</sup>

### 实用工作流

1. **保留原始位宽**，即从提升后的代码/IR/反编译器输出中获取的位宽（`8/16/32/64` 位）。
2. **在尝试简化之前对表达式进行分类**：
- **线性**：位运算原子的加权和
- **半线性**：线性表达式加上常量掩码，例如 `x & 0xFF`
- **多项式**：包含乘积
- **混合型**：乘积与位运算逻辑交错，通常还包含重复的子表达式
3. **使用随机测试或 SMT 证明验证每个候选重写**。如果无法证明等价，应保留原始表达式，而不是猜测。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一种实用的 MBA 简化器，用于 malware analysis 和受保护二进制文件的 reversing。它会对表达式进行分类，并将其导入专用 pipeline，而不是对所有内容应用同一个通用重写流程。<sup>[[2]](#references)</sup>

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

- **Linear MBA**：CoBRA 在 Boolean inputs 上评估表达式，推导出 signature，并同时尝试多种 recovery methods，例如 pattern matching、ANF conversion 和 coefficient interpolation。
- **Semilinear MBA**：constant-masked atoms 使用 bit-partitioned reconstruction 进行重建，从而确保 masked regions 保持正确。
- **Polynomial/Mixed MBA**：products 被分解为 cores，并且在简化 outer relation 之前，可以将 repeated subexpressions 提取为 temporaries。

一个通常值得尝试恢复的 mixed identity：
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
这可以简化为：
```c
x * y
```
### Reversing notes

- 优先在 **lifted IR expressions** 或 decompiler 输出上运行 CoBRA，前提是你已经隔离出确切的计算过程。
- 如果表达式来自 masked arithmetic 或窄寄存器，请显式使用 `--bitwidth`。
- 如果需要更强的证明步骤，请查看此处的本地 Z3 notes：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 还以 **LLVM pass plugin**（`libCobraPass.so`）的形式提供；当你想在后续分析 pass 之前规范化包含大量 MBA 的 LLVM IR 时，它非常有用。
- 对于不受支持且对 carry 敏感的 mixed-domain residuals，应将其视为保留原始表达式并手动分析 carry path 的信号。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

该 obfuscator 使用基于 `mov` 的指令序列替换程序操作，并利用 signal/exception handling 来改变控制流。详情请参阅：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

对于受支持的 binary，[demovfuscator](https://github.com/kirschju/demovfuscator) 可以对结果进行 deobfuscate。它有多个 dependencies。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
并且[install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

如果你正在进行 **CTF，那么这个用于查找 flag 的 workaround** 可能非常有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要查找 **entry point**，可以像下面这样通过 `::main` 搜索函数：

![在 Ghidra 中通过搜索包含双冒号 main 的函数名来查找 Rust entry point](<../../images/image (1080).png>)

在本例中，二进制文件名为 authenticator，因此很明显这就是需要关注的 main 函数。\
获取被调用 **functions** 的 **name** 后，在 **Internet** 上搜索它们，以了解其 **inputs** 和 **outputs**。

### 从 ELF firmware 中恢复 Rust 字符串

在 **Rust ELF** 二进制文件中，许多静态字符串并不是通过 C 风格的 NUL 终止指针引用的。常见的 `rustc` 布局是在 **`.data.rel.ro`** 中使用一个指向真实字符串 blob 的**指针/长度元组**，而该字符串 blob 存储在 **`.rodata`** 中：
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
这意味着 `strings` 或 Ghidra 的默认分析可能会合并相邻字符串，或完全遗漏交叉引用。<sup>[[3]](#references)</sup>

快速工作流程：
```bash
readelf -S <bin>
objdump -h <bin>
```
1. 获取 **`.rodata`** 的虚拟地址和大小。
2. 逐字枚举 **`.data.rel.ro`**。
3. 将 `.rodata` 地址范围内的任何值视为候选字符串指针。
4. 将下一个 word 视为候选长度。
5. 应用合理性过滤条件（例如，仅保留 **4** 到 **100** 字节之间的长度）。
6. 从 `.rodata` 中准确读取 `length` 个字节，而不是一直扫描到 `0x00`。

最小提取器逻辑：
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
这在 firmware reversing 中尤其有用，因为恢复出的 Rust 字符串通常会揭示 **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers 和 auth-related logic**。

如果 Ghidra 未能识别这些字符串，请运行自定义 script/plugin，应用相同的启发式方法，并在所引用的 `.rodata` 偏移处创建 string data。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` 工具是很好的参考，可用于将这一思路适配到其他 **word sizes、endianness 和 section layouts**。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

对于 Delphi compiled binaries，可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果必须 reverse 一个 Delphi binary，建议使用 IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

在 IDA 中按 **Alt+F7** 加载 Python plugin，然后选择 plugin file。

该 plugin 会执行 binary，并在 debugging 开始时动态解析 function names。开始 debugging 后，再次按下 Start button（绿色按钮或 f9），断点会在 real code 的开头命中。

如果在 graphical application 中按下某个 button，debugger 可以停在该 button 调用的 function 中。

## Golang

如果必须 reverse 一个 Golang binary，建议使用 IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

在 IDA 中按 **Alt+F7** 加载 Python plugin，然后选择 plugin file。

这会解析 function names。

## Compiled Python

在此页面中，你可以找到如何从 ELF/EXE Python compiled binary 中获取 Python code：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

如果获得了 GBA game 的 **binary**，可以使用不同的工具对其进行 **emulate** 和 **debug**：

- [**no$gba**](https://problemkaputt.de/gba.htm) (_下载 debug version_) - 包含带 interface 的 debugger
- [**mgba** ](https://mgba.io)- 包含 CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

在 [**no$gba**](https://problemkaputt.de/gba.htm) 的 _**Options --> Emulation Setup --> Controls**_** 中，可以查看如何按下 Game Boy Advance 的 **buttons**

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

按下时，每个 **key 都有一个 value** 用于识别它：
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
因此，在这类程序中，有趣的部分将是**程序如何处理用户输入**。在地址 **0x4000130** 处，你会找到常见的函数：**KEYINPUT**。

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

在上一张图片中，你可以看到该函数由 **FUN_080015a8** 调用（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，经过一些初始化操作（没有任何重要性）之后：
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
最后一个 **if** 检查 **uVar4** 是否在 **last Keys** 中，并且不是当前 key；这也称为松开按钮（当前 key 存储在 **uVar1** 中）。
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
在前面的代码中可以看到，我们正在将 **uVar1**（存放**按下按钮的值**的位置）与一些值进行比较：

- 首先，它与**值 4**（**SELECT** 按钮）进行比较：在该 challenge 中，此按钮会清除屏幕
- 然后，它将该值与 **8**（**START** 按钮）进行比较；在该 challenge 中，该路径会检查输入的代码是否有效。
- 在这种情况下，变量 **`DAT_030000d8`** 会与 0xf3 进行比较，如果值相同，则执行某些代码。
- 在其他所有情况下，都会检查并递增一个计数器（`DAT_030000d4`）。\
当计数器小于 8 时，按下的按键值会累积到 `DAT_030000d8` 中。

因此，在该 challenge 中，已知按钮的值后，你需要**按下一个长度小于 8，且最终相加结果为 0xf3 的组合。**

**本教程的参考资料：** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 课程

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（Binary deobfuscation）

## References

- [1] [使用 CoBRA 简化 MBA obfuscation](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [解码 Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
