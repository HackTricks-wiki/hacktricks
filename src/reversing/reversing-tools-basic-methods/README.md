# Reversing 工具与基础方法

{{#include ../../banners/hacktricks-training.md}}

## 基于 ImGui 的 Reversing 工具

软件：

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

在线工具：

- 使用 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) 将 wasm（二进制）**反编译**为 wat（纯文本）
- 使用 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) 将 wat **编译**为 wasm
- 你也可以尝试使用 [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) 进行反编译

软件：

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一个 **反编译并检查多种格式**的 decompiler，包括 **libraries**（.dll）、**Windows metadata files**（.winmd）和 **executables**（.exe）。反编译后，可以将 assembly 保存为 Visual Studio project（.csproj）。

这里的优势在于，如果需要从 legacy assembly 中恢复丢失的 source code，此操作可以节省时间。此外，dotPeek 提供了在反编译 code 中进行便捷导航的功能，使其成为 **Xamarin algorithm analysis** 的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

借助全面的 add-in model 和可扩展该工具以满足确切需求的 API，.NET reflector 可以节省时间并简化 development。下面来看看该工具提供的大量 reverse engineering services：

- 了解 data 如何流经 library 或 component
- 深入了解 .NET languages 和 frameworks 的 implementation 与 usage
- 查找未记录且未公开的 functionality，以便更充分地利用所使用的 APIs 和 technologies。
- 查找 dependencies 和不同的 assemblies
- 精确定位 code、third-party components 和 libraries 中 errors 的位置。
- Debug 你使用的所有 .NET code 的 source。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode)：你可以在任何 OS 上使用它（可以直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并 **搜索 ILSpy**）。\
如果你需要再次**反编译**、**修改**和**重新编译**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 或其仍在积极维护的 fork：[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（使用 **右键单击 -> Modify Method** 来修改 function 内部的内容）。

### DNSpy Logging

为了让 **DNSpy 将某些信息记录到文件中**，你可以使用以下 snippet：
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy 调试

要使用 DNSpy 调试代码，你需要：

首先，更改与调试相关的 **Assembly 属性**：

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

这是必要的，因为如果不这样做，在 **runtime** 期间，代码会应用多项 **optimisations**，可能导致调试时某个 **break-point 永远不会被命中**，或者某些 **变量不存在**。

然后，如果你的 .NET 应用程序由 **IIS** **运行**，可以使用以下方式将其**重启**：
```
iisreset /noforce
```
然后，为了开始 debugging，你应关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![DNSpy Logging - DNSpy Debugging：然后，为了开始 debugging，你应关闭所有已打开的文件，并在 Debug Tab 中选择 Attach to Process](<../../images/image (318).png>)

然后选择 **w3wp.exe** 以连接到 **IIS server**，并点击 **attach**：

![DNSpy Logging - DNSpy Debugging：然后选择 w3wp.exe 以连接到 IIS server，并点击 attach](<../../images/image (113).png>)

现在我们正在 debugging 该进程，接下来需要停止它并加载所有模块。首先点击 _Debug >> Break All_，然后点击 _**Debug >> Windows >> Modules**_：

![DNSpy Logging - DNSpy Debugging：现在我们正在 debugging 该进程，接下来需要停止它并加载所有模块。首先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging：现在我们正在 debugging 该进程，接下来需要停止它并加载所有模块。首先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (834).png>)

在 **Modules** 中点击任意模块，然后选择 **Open All Modules**：

![DNSpy Logging - DNSpy Debugging：在 Modules 中点击任意模块，然后选择 Open All Modules](<../../images/image (922).png>)

右键点击 **Assembly Explorer** 中的任意模块，然后点击 **Sort Assemblies**：

![DNSpy Logging - DNSpy Debugging：右键点击 Assembly Explorer 中的任意模块，然后点击 Sort Assemblies](<../../images/image (339).png>)

## Java 反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## 调试 DLL

### 使用 IDA

- **Load rundll32**（64bits 位于 C:\Windows\System32\rundll32.exe，32 bits 位于 C:\Windows\SysWOW64\rundll32.exe）
- 选择 **Windbg** debugger
- 选择 "**Suspend on library load/unload**"

![调试 DLL - 使用 IDA：选择 " Suspend on library load/unload "](<../../images/image (868).png>)

- 配置执行的 **parameters**，填入 **path to the DLL** 以及你想调用的函数：

![调试 DLL - 使用 IDA：配置执行的 parameters，填入 path to the DLL 以及你想调用的函数](<../../images/image (704).png>)

然后，当你开始 debugging 时，**the execution will be stopped when each DLL is loaded**；当 rundll32 加载你的 DLL 时，执行也会停止。

但是，如何才能进入已加载 DLL 的代码？使用这种方法，我不知道该怎么做。

### 使用 x64dbg/x32dbg

- **Load rundll32**（64bits 位于 C:\Windows\System32\rundll32.exe，32 bits 位于 C:\Windows\SysWOW64\rundll32.exe）
- **Change the Command Line**（_File --> Change Command Line_），设置 dll 的 path 以及你想调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- 更改 _Options --> Settings_ 并选择 "**DLL Entry**"。
- 然后**start the execution**，debugger 会在每个 dll main 处停止，最终你会在自己 DLL 的 **dll Entry** 处停止。从那里开始，只需搜索你想要设置 breakpoint 的位置。

注意，当 win64dbg 因任何原因停止执行时，你可以在 **win64dbg window 的顶部**看到当前所在的**代码位置**：

![Using IDA - Using x64dbg/x32dbg：注意，当执行因任何原因在 win64dbg 中停止时，你可以在 win64dbg window 的顶部看到当前所在的代码位置](<../../images/image (842).png>)

通过查看这里，你可以得知执行何时停止在想要 debugging 的 dll 中。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个实用程序，可以查找运行中游戏的内存中保存重要值的位置并修改这些值。更多信息请参阅：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger（GDB）的 front-end/reverse engineering tool，专注于 games。不过，它也可以用于任何与 reverse-engineering 相关的工作。

[**Decompiler Explorer**](https://dogbolt.org/) 是一个面向多个 decompiler 的 web front-end。该 web service 允许你比较不同 decompiler 对小型可执行文件生成的输出。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### 使用 blobrunner debugging shellcode

[**Blobrunner**](https://github.com/OALabs/BlobRunner) 会在一段内存空间中 **allocate** **shellcode**，**indicate** shellcode 被分配到的 **memory address**，并**stop**执行。\
然后，你需要将 **debugger**（Ida 或 x64dbg）**attach** 到该进程，在所示的 memory address 处设置 **breakpoint**，并 **resume** 执行。这样就可以 debugging shellcode。

releases github page 包含带有已编译 releases 的 zip 文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在以下链接中找到略微修改过的 Blobrunner 版本。要进行编译，只需**在 Visual Studio Code 中 create a C/C++ project，复制并粘贴代码，然后 build it**。


{{#ref}}
blobrunner.md
{{#endref}}

### 使用 jmp2it debugging shellcode

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) 与 blobrunner 非常相似。它会在一段内存空间中 **allocate** **shellcode**，并启动一个**eternal loop**。然后你需要将 **debugger** **attach** 到该进程，**play start wait 2-5 secs and press stop**，此时你会处于 **eternal loop** 中。跳转到 eternal loop 的下一条 instruction，因为它将调用 shellcode，最终你会发现自己正在执行 shellcode。

![Debugging a shellcode with blobrunner - 使用 jmp2it debugging shellcode：jmp2it 与 blobrunner 非常相似。它会在一段内存空间中 allocate shellcode，并启动一个...](<../../images/image (509).png>)

你可以在 [releases page 中下载已编译版本的 jmp2it](https://github.com/adamkramer/jmp2it/releases/)。

### 使用 Cutter debugging shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 Cutter，你可以 emulate shellcode 并对其进行动态 inspect。

注意，Cutter 允许你选择 "Open File" 和 "Open Shellcode"。在我的情况下，将 shellcode 作为 file 打开时可以正确 decompile，但将其作为 shellcode 打开时却无法正确 decompile：

![Debugging a shellcode with jmp2it - 使用 Cutter debugging shellcode：注意，Cutter 允许你选择 "Open File" 和 "Open Shellcode"。在我的情况下，将 shellcode 作为 file 打开时...](<../../images/image (562).png>)

要从指定位置开始 emulation，请在那里设置 bp，Cutter 似乎会自动从该位置开始 emulation：

![Debugging a shellcode with jmp2it - 使用 Cutter debugging shellcode：要从指定位置开始 emulation，请在那里设置 bp，Cutter 似乎会自动...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - 使用 Cutter debugging shellcode：要从指定位置开始 emulation，请在那里设置 bp，Cutter 似乎会自动...](<../../images/image (387).png>)

例如，你可以在 hex dump 中查看 stack：

![Debugging a shellcode with jmp2it - 使用 Cutter debugging shellcode：例如，你可以在 hex dump 中查看 stack](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

你应该尝试使用 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。\
它会告诉你诸如 shellcode 正在使用**哪些 functions**，以及 shellcode 是否正在内存中**decoding**自身等信息。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg 还提供了一个图形化启动器，你可以在其中选择所需的选项并执行 shellcode

![使用 Cutter 调试 shellcode - 反混淆 shellcode 并获取已执行的函数：scDbg 还提供了一个图形化启动器，你可以在其中选择所需的选项并执行...](<../../images/image (258).png>)

**Create Dump** 选项会转储最终的 shellcode，前提是 shellcode 在内存中被动态修改过（对于下载解码后的 shellcode 很有用）。**start offset** 可用于从特定偏移量开始执行 shellcode。**Debug Shell** 选项可用于使用 scDbg 终端调试 shellcode（不过我认为前面介绍的任何选项都更适合此用途，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 进行反汇编

将 shellcode 文件作为输入上传，并使用以下 recipe 对其进行反汇编：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 混淆反混淆

**Mixed Boolean-Arithmetic (MBA)** 混淆会将 `x + y` 之类的简单表达式隐藏在混合使用算术运算（`+`、`-`、`*`）和按位运算符（`&`、`|`、`^`、`~`、移位）的公式后面。关键在于，这些恒等式通常只有在**固定宽度的模运算**下才成立，因此进位和溢出非常重要：
```c
(x ^ y) + 2 * (x & y) == x + y
```
如果使用通用代数工具简化这类表达式，很容易得到错误结果，因为忽略了位宽语义。<sup>[[1]](#references)</sup>

### 实用工作流程

1. **保留原始位宽**，该位宽来自提升后的代码/IR/反编译器输出（`8/16/32/64` 位）。
2. **在尝试简化之前对表达式进行分类**：
- **线性**：位运算原子的加权和
- **半线性**：线性表达式加上 `x & 0xFF` 等常量掩码
- **多项式**：存在乘法
- **混合**：乘法与位逻辑交错出现，通常还包含重复的子表达式
3. **使用随机测试或 SMT 证明验证每个候选重写**。如果无法证明等价，应保留原始表达式，而不是进行猜测。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一个用于 malware analysis 和 protected-binary reversing 的实用 MBA simplifier。它会对表达式进行分类，并将其路由到专用 pipeline，而不是对所有内容统一应用一个通用 rewrite pass。<sup>[[2]](#references)</sup>

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
实用场景：

- **Linear MBA**：CoBRA 在 Boolean inputs 上评估表达式，推导出 signature，并同时尝试多种 recovery methods，例如 pattern matching、ANF conversion 和 coefficient interpolation。
- **Semilinear MBA**：通过 bit-partitioned reconstruction 重建 constant-masked atoms，从而确保 masked regions 保持正确。
- **Polynomial/Mixed MBA**：将 products 分解为 cores，并可在简化 outer relation 之前，将重复的 subexpressions 提取到 temporaries 中。

一个通常值得尝试恢复的 mixed identity 示例：
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
这可以简化为：
```c
x * y
```
### Reversing 笔记

- 优先在你隔离出精确计算之后，对 **lifted IR expressions** 或反编译器输出运行 CoBRA。
- 如果表达式来自掩码算术或窄寄存器，请显式使用 `--bitwidth`。
- 如果需要更强的证明步骤，请查看这里的本地 Z3 笔记：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 还以 **LLVM pass plugin**（`libCobraPass.so`）的形式提供，当你希望在后续分析 pass 之前对包含大量 MBA 的 LLVM IR 进行规范化时，它会很有用。
- 对于不受支持的、对 carry 敏感的混合域残余，应将其视为保留原始表达式并手动分析 carry 路径的信号。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

该混淆器**修改所有 `mov` 指令**（没错，真的很酷）。它还使用中断来改变执行流。有关其工作原理的更多信息：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

如果你足够幸运，[demovfuscator](https://github.com/kirschju/demovfuscator) 会对该二进制文件进行脱混淆。它有多个依赖项
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
以及 [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

如果你正在进行 **CTF，以下用于查找 flag 的 workaround 可能非常有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要查找 **entry point**，可以像下面这样通过 `::main` 搜索函数：

![Movfuscator - Rust：要查找 entry point，可以像下面这样通过 ::main 搜索函数](<../../images/image (1080).png>)

在本例中，二进制文件名为 authenticator，因此很明显，这就是值得关注的 main 函数。\
知道被调用 **functions** 的 **name** 后，可以在 **Internet** 上搜索它们，以了解其 **inputs** 和 **outputs**。

### 从 ELF firmware 中恢复 Rust strings

在 **Rust ELF** binaries 中，许多 static strings 并不是以 C-style NUL-terminated pointers 的形式被引用。常见的 `rustc` layout 是位于 **`.data.rel.ro`** 中的 **pointer/length tuple**，它指向存储在 **`.rodata`** 中的实际 string blob：
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
这意味着 `strings` 或 Ghidra 的默认分析可能会合并相邻字符串，或完全遗漏交叉引用。<sup>[[3]](#references)</sup>

快速工作流：
```bash
readelf -S <bin>
objdump -h <bin>
```
1. 获取 **`.rodata`** 的虚拟地址和大小。
2. 逐 word 枚举 **`.data.rel.ro`**。
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
这在 firmware reversing 中尤其有用，因为恢复出的 Rust strings 通常会揭示 **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers 和 auth-related logic**。

如果 Ghidra 遗漏了这些 strings，请运行一个 custom script/plugin，应用相同的 heuristic，并在所引用的 `.rodata` offsets 处创建 string data。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` tools 是很好的参考，可用于将这一思路适配到其他 **word sizes、endianness 和 section layouts**。<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

对于 Delphi compiled binaries，可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果需要 reverse 一个 Delphi binary，建议使用 IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

只需按下 **ATL+f7**（在 IDA 中 import python plugin），然后选择该 python plugin。

该 plugin 会执行 binary，并在 debugging 开始时动态解析 function names。开始 debugging 后，再次按下 Start button（绿色按钮或 f9），断点将在 real code 的开头命中。

这也非常有趣，因为如果你在 graphic application 中按下一个按钮，debugger 将停在由该按钮执行的 function 中。

## Golang

如果需要 reverse 一个 Golang binary，建议使用 IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

只需按下 **ATL+f7**（在 IDA 中 import python plugin），然后选择该 python plugin。

这将解析 functions 的 names。

## Compiled Python

在此页面中，你可以找到如何从 ELF/EXE python compiled binary 中获取 python code：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

如果你获得了 GBA game 的 **binary**，可以使用不同的 tools 对其进行 **emulate** 和 **debug**：

- [**no$gba**](https://problemkaputt.de/gba.htm)（_Download the debug version_）- 包含带 interface 的 debugger
- [**mgba** ](https://mgba.io)- 包含 CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，在 _**Options --> Emulation Setup --> Controls**_** ** 内，可以查看如何按下 Game Boy Advance **buttons**

![显示 Game Boy Advance button mappings 的 no$gba controls configuration](<../../images/image (581).png>)

按下后，每个 **key 都有一个 value** 用于识别它：
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
因此，在这类程序中，有趣的部分将是**程序如何处理用户输入**。在地址 **0x4000130** 中，你会找到一个常见的函数：**KEYINPUT**。

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

在上一张图中可以看到，该函数由 **FUN_080015a8** 调用（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，经过一些初始化操作（并不重要）之后：
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
最后一个 if 正在检查 **`uVar4`** 是否位于 **last Keys** 中，并且不是当前 key，也称为松开按钮（当前 key 存储在 **`uVar1`** 中）。
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
在前面的代码中可以看到，我们正在将 **uVar1**（存放**被按下按钮的值**的位置）与一些值进行比较：

- 首先，它会与**值 4**（**SELECT** button）进行比较：在这个 challenge 中，该按钮会清除屏幕
- 然后，它会与**值 8**（**START** button）进行比较：在这个 challenge 中，该按钮会检查 code 是否有效，以获取 flag。
- 在这种情况下，var **`DAT_030000d8`** 会与 0xf3 进行比较，如果值相同，就会执行一些代码。
- 在其他情况下，会检查某个 cont（**`DAT_030000d4`**）。之所以称为 cont，是因为进入 code 后它会立即加 1。\
**I**f 小于 8，就会执行涉及向 **`DAT_030000d8`** **adding** 值的操作（基本上，只要 cont 小于 8，就会将按下按键的值加到这个变量中）。

因此，在这个 challenge 中，知道各个按钮的值后，你需要**按下一个长度小于 8 的组合，使最终的加和值为 0xf3。**

**本教程的 Reference：** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 课程

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## 参考资料

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
