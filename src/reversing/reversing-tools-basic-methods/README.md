# Reversing 工具与基础方法

{{#include ../../banners/hacktricks-training.md}}

## 基于 ImGui 的 Reversing 工具

软件：

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

在线工具：

- 使用 [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) 将 wasm（二进制）**decompile** 为 wat（纯文本）
- 使用 [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) 将 wat **compile** 为 wasm
- 你也可以尝试使用 [web-wasmdec](https://wwwg.github.io/web-wasmdec/) 进行 decompilation。

软件：

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一个 decompiler，可以**decompile 和检查多种格式**，包括**libraries**（.dll）、**Windows metadata file**（.winmd）和**executables**（.exe）。完成 decompile 后，可以将 assembly 保存为 Visual Studio project（.csproj）。

其优点在于，如果需要从 legacy assembly 中恢复丢失的 source code，这一操作可以节省时间。此外，dotPeek 还提供了在 decompiled code 中便捷导航的功能，使其成为用于 **Xamarin algorithm analysis** 的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

.NET reflector 具有全面的 add-in model 和可扩展工具以满足你确切需求的 API，可以节省时间并简化开发。下面来看看该工具提供的众多 reverse engineering 服务：

- 深入了解数据如何流经 library 或 component
- 深入了解 .NET languages 和 frameworks 的实现与使用方式
- 查找未记录且未公开的功能，以更充分地利用所使用的 APIs 和 technologies。
- 查找 dependencies 和不同的 assemblies
- 确定 code、third-party components 和 libraries 中错误的准确位置。
- 调试你所使用的所有 .NET code 的 source。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode)：你可以在任何 OS 上使用它（可以直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并**搜索 ILSpy**）。\
如果需要 **decompile**、**modify** 并再次 **recompile**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases)，或其仍在积极维护的 fork：[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（**右键单击 -> Modify Method** 可修改函数内部的内容）。

### DNSpy Logging

为了让 **DNSpy 将某些信息记录到文件中**，你可以使用以下 snippet：
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
收件人：
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
然后点击 **compile**：

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

然后通过 _**File >> Save module...**_ 保存新文件：

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

这是必要的，因为如果不这样做，在 **runtime** 中会对代码应用多项 **optimisations**，并且可能出现调试时某个 **break-point 永远不会被命中**，或某些 **variables 不存在** 的情况。

然后，如果你的 .NET 应用程序正由 **IIS** **run**，可以使用以下命令将其 **restart**：
```
iisreset /noforce
```
然后，为了开始调试，你应该关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![DNSpy Logging - DNSpy Debugging：然后，为了开始调试，你应该关闭所有已打开的文件，并在 Debug Tab 中选择 Attach to Process](<../../images/image (318).png>)

然后选择 **w3wp.exe** 以附加到 **IIS server**，并点击 **attach**：

![DNSpy Logging - DNSpy Debugging：然后选择 w3wp.exe 以附加到 IIS server，并点击 attach](<../../images/image (113).png>)

现在我们已经在调试该进程，接下来需要停止进程并加载所有模块。首先点击 _Debug >> Break All_，然后点击 _**Debug >> Windows >> Modules**_：

![DNSpy Logging - DNSpy Debugging：现在我们已经在调试该进程，接下来需要停止进程并加载所有模块。首先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging：现在我们已经在调试该进程，接下来需要停止进程并加载所有模块。首先点击 Debug Break All，然后点击 Debug Windows Modules](<../../images/image (834).png>)

在 **Modules** 中点击任意模块，然后选择 **Open All Modules**：

![DNSpy Logging - DNSpy Debugging：在 Modules 中点击任意模块，然后选择 Open All Modules](<../../images/image (922).png>)

右键点击 **Assembly Explorer** 中的任意模块，然后点击 **Sort Assemblies**：

![DNSpy Logging - DNSpy Debugging：右键点击 Assembly Explorer 中的任意模块，然后点击 Sort Assemblies](<../../images/image (339).png>)

## Java 反编译器

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## 调试 DLL

### 使用 IDA

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- 选择 **Windbg** debugger
- 选择 "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA：选择 " Suspend on library load/unload "](<../../images/image (868).png>)

- 配置执行的 **parameters**，填入 **DLL 的路径**以及你想要调用的函数：

![Debugging DLLs - Using IDA：配置执行的 parameters，填入 DLL 的路径以及你想要调用的函数](<../../images/image (704).png>)

然后，当你开始调试时，**每个 DLL 加载时执行都会暂停**；因此，当 rundll32 加载你的 DLL 时，执行会暂停。

此方法会在模块加载事件处暂停，但与下面的 x64dbg workflow 相比，到达已加载 DLL 的 entry point 不够直接。

### 使用 x64dbg/x32dbg

- **加载 rundll32**（64 位版本位于 C:\Windows\System32\rundll32.exe，32 位版本位于 C:\Windows\SysWOW64\rundll32.exe）
- **更改 Command Line**（_File --> Change Command Line_），并设置 dll 的路径和你想要调用的函数，例如："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- 更改 _Options --> Settings_，然后选择 "**DLL Entry**"。
- 然后**开始执行**，debugger 会在每个 dll main 处停止；在某个时刻，你将会**停在你的 dll Entry 处**。从那里开始，只需寻找你想要设置 breakpoint 的位置。

注意，当 win64dbg 因任何原因暂停执行时，你可以通过查看 **win64dbg 窗口顶部**来了解**当前所在的 code**：

![Using IDA - Using x64dbg/x32dbg：注意，当执行因任何原因在 win64dbg 中暂停时，你可以通过查看 win64dbg 窗口顶部来了解当前所在的 code](<../../images/image (842).png>)

该 indicator 确认执行已经在你想要调试的 DLL 内部暂停。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个有用的程序，可以查找重要数值在运行中 game 的 memory 中保存的位置，并修改这些数值。更多信息：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger（GDB）的 front-end/reverse engineering tool，专注于 games。不过，它也可以用于任何与 reverse-engineering 相关的工作。

[**Decompiler Explorer**](https://dogbolt.org/) 是多个 decompiler 的 web front-end。该 web service 允许你比较不同 decompiler 在小型 executable 上的输出。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### 使用 blobrunner 调试 shellcode

[**BlobRunner**](https://github.com/OALabs/BlobRunner) 会分配 **shellcode**，打印其 **memory address**，然后暂停执行。\
附加 IDA 或 x64dbg 等 debugger，在打印出的 address 处设置 breakpoint，然后恢复执行以调试 shellcode。

releases github page 包含包含已编译 releases 的 zip 文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在以下链接中找到略作修改的 Blobrunner 版本。要进行编译，只需**在 Visual Studio Code 中创建 C/C++ project，复制并粘贴 code，然后 build**。


{{#ref}}
blobrunner.md
{{#endref}}

### 使用 jmp2it 调试 shellcode

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) 与 BlobRunner 类似。它会分配 shellcode 并进入 infinite loop。附加 debugger，恢复执行 **2–5 秒**，在该 loop 内暂停，然后单步执行到下一个将执行转移到已分配 shellcode 的 call。

![Debugger 在 jmp2it 的 infinite loop 中暂停，紧接着位于调用已分配 shellcode 之前](<../../images/image (509).png>)

你可以从 [releases page 中的 jmp2it](https://github.com/adamkramer/jmp2it/releases/) 下载已编译版本。

### 使用 Cutter 调试 shellcode

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 Cutter，你可以 emulate shellcode 并对其进行动态检查。

注意，Cutter 允许你使用 "Open File" 和 "Open Shellcode"。在我的情况下，将 shellcode 作为 file 打开时，它能够正确 decompile；但作为 shellcode 打开时则不能：

![Cutter 将相同 bytes 作为 file 或 shellcode 打开时显示不同的 analysis 结果](<../../images/image (562).png>)

为了从你想要的位置开始 emulation，请在那里设置 bp；Cutter 显然会自动从该位置开始 emulation：

![在启动 Cutter emulation 前，在所需 shellcode entry 处设置 breakpoint](<../../images/image (589).png>)

![Cutter emulator 在选定的 shellcode breakpoint 处暂停](<../../images/image (387).png>)

例如，你可以在 hex dump 中查看 stack：

![在 Cutter 的 hex dump 中查看 emulated shellcode stack](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

你应该尝试 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。\
它会告诉你诸如 shellcode 正在使用**哪些 functions**，以及 shellcode 是否正在 memory 中**自行 decoding** 等信息。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg 还提供了一个图形化启动器，你可以在其中选择所需的选项并执行 shellcode

![用于选择 shellcode 仿真和 tracing 选项的 scDbg 图形化启动器](<../../images/image (258).png>)

**Create Dump** 选项会转储最终的 shellcode，前提是 shellcode 在内存中被动态修改过（适用于下载解码后的 shellcode）。**start offset** 可用于从特定偏移处开始执行 shellcode。**Debug Shell** 选项可用于通过 scDbg terminal 调试 shellcode（不过在此方面，我认为前面介绍的任何选项都更好，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 进行反汇编

将 shellcode 文件作为输入上传，并使用以下 recipe 对其进行反编译：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 混淆去混淆

**Mixed Boolean-Arithmetic (MBA)** 混淆通过混合 arithmetic（`+`、`-`、`*`）和 bitwise operators（`&`、`|`、`^`、`~`、移位）的公式，将 `x + y` 等简单表达式隐藏起来。重要的是，这些恒等式通常只有在**固定宽度的模运算**下才成立，因此进位和溢出十分重要：
```c
(x ^ y) + 2 * (x & y) == x + y
```
如果使用通用代数工具简化这类表达式，很容易得到错误结果，因为忽略了位宽语义。<sup>[[1]](#references)</sup>

### 实用工作流

1. **保留原始位宽**，来自提升后的 code/IR/decompiler 输出（`8/16/32/64` 位）。
2. **在尝试简化之前对表达式进行分类**：
- **线性**：位运算原子的加权和
- **半线性**：线性表达式加上 `x & 0xFF` 等常量掩码
- **多项式**：出现乘积
- **混合型**：乘积与位运算逻辑交错，通常还包含重复子表达式
3. **通过随机测试或 SMT 证明验证每个候选重写**。如果无法证明等价，请保留原始表达式，不要猜测。

### 使用窄执行切片绕过扁平化控制流

恢复完整的控制流图通常没有必要。面对控制流扁平化、opaque predicates、大型 dispatcher 或充满 MBA 的 code 时，应从 encrypted blobs 和 output buffers 的引用入手，跟踪到转换它们的最小 routine。然后只复现该 data-flow slice，或独立执行它；如果可以直接初始化相关 state，则 dispatcher 并不是解决方案所必需的部分。<sup>[[7]](#references)</sup>

一个实用的工作流是：<sup>[[7]](#references)</sup>

1. 清点 executable 和 data sections、relocations 以及 cross-references。在保留字节顺序和元素宽度的前提下，从 `.rodata` dump 候选表。
2. 确定最后一个写入 plaintext 或 output buffer 的 routine。记录其 inputs、referenced tables、imported calls 以及所需的 global state。
3. 仅将这些 operations 提升到固定宽度的 Python model 中。如果该 slice 仍依赖过多 state，则在 Unicorn、QEMU 或 debugger 下调用该 routine，并 hook 无关的 imports，而不是 emulation 整个程序。
4. 验证 extractor 确实从所提供的 binary 推导其 output：移除 silent fallbacks，搜索其中是否嵌入了 answers，并使用修改过 strings、keys、identifiers、layouts 和 obfuscation seeds 的 unseen builds 运行测试。

第一轮分析可使用的实用 commands 是：<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Detect 伪装成常量的 MBA 表达式

一个表面上依赖输入的字节表达式可能会完全抵消其输入。提取其 tables 后，在完整的 8 位域上计算该表达式；如果输出集合只有一个元素，即可证明该字节为 constant，而无需还原外围的 state machine。<sup>[[7]](#references)</sup>
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
保留最终的掩码，因为原始加法存在按字节宽度的回绕。对于更宽的域，可以询问 SMT solver：对于两个相同宽度的符号输入，`f(x1) != f(x2)` 是否可满足：`unsat` 证明不变性，而 `sat` 会提供反例，意味着不能丢弃该输入。<sup>[[7]](#references)</sup>

#### 识别与环境绑定的解码

反分析检查不一定需要进行分支或导致崩溃。decoder 可以将传感器结果混入密钥位、不透明谓词常量或扁平化 dispatcher 状态中，继续正常运行，并在 emulator 中生成看似合理但实际错误的明文。因此，仅修补可见的失败分支是不够的；应从环境探针追踪到 decoder 状态的数据依赖，在真实设备和 emulator 上比较相同的切片，并测试强制每个传感器结果发生变化时最终 buffer 的变化。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一个用于 malware analysis 和受保护 binary reversing 的实用 MBA simplifier。它会对表达式进行分类，并将其导入专用 pipeline，而不是对所有内容统一应用一个通用的 rewrite pass。<sup>[[2]](#references)</sup>

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
实用案例：

- **Linear MBA**：CoBRA 在 Boolean 输入上计算表达式，推导出 signature，并通过 pattern matching、ANF conversion 和 coefficient interpolation 等多种 recovery methods 进行竞争。
- **Semilinear MBA**：使用 bit-partitioned reconstruction 重建 constant-masked atoms，从而确保 masked regions 保持正确。
- **Polynomial/Mixed MBA**：将 products 分解为 cores，并可在简化 outer relation 之前，将重复的 subexpressions 提取为 temporaries。

一个通常值得尝试恢复的 mixed identity 示例：
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
这可以简化为：
```c
x * y
```
### Reversing 笔记

- 优先在 **lifted IR expressions** 或 decompiler output 上运行 CoBRA，前提是你已经隔离出精确的 computation。
- 如果该 expression 来自 masked arithmetic 或 narrow registers，请显式使用 `--bitwidth`。
- 如果需要更强的 proof step，请查看这里的本地 Z3 笔记：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 还以 **LLVM pass plugin**（`libCobraPass.so`）的形式提供；当你希望在后续 analysis passes 之前规范化包含大量 MBA 的 LLVM IR 时，它非常有用。
- 对于不受支持的、对 carry 敏感的 mixed-domain residuals，应将其视为保留原始 expression 并手动分析 carry path 的信号。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

该 obfuscator 使用基于 `mov` 的 instruction sequences 替换程序操作，并利用 signal/exception handling 改变 control flow。详情请参阅：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

对于受支持的 binaries，[demovfuscator](https://github.com/kirschju/demovfuscator) 可以对结果进行 deobfuscate。它有多个 dependencies。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
并且[安装 keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

如果你正在进行 **CTF，这种寻找 flag 的 workaround** 可能会非常有用：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要查找 **entry point**，可以像下面这样搜索带有 `::main` 的函数：

![在 Ghidra 中通过搜索包含双冒号 main 的函数名称来查找 Rust entry point](<../../images/image (1080).png>)

在这个案例中，binary 名称为 authenticator，因此很明显，这就是感兴趣的 main 函数。\
获取被调用 **functions** 的 **name** 后，在 **Internet** 上搜索它们，以了解其 **inputs** 和 **outputs**。

### 从 ELF firmware 中恢复 Rust strings

在 **Rust ELF** binaries 中，许多 static strings 并不是以 C-style NUL-terminated pointers 的形式被引用的。常见的 `rustc` layout 是：位于 **`.data.rel.ro`** 中的 **pointer/length tuple**，指向存储在 **`.rodata`** 中的实际 string blob：
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
这意味着，`strings` 或 Ghidra 的默认分析可能会合并相邻字符串，或完全遗漏交叉引用。<sup>[[3]](#references)</sup>

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
这在 firmware reversing 中尤其有用，因为恢复出的 Rust 字符串通常会揭示 **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers 和 auth-related logic**。

如果 Ghidra 遗漏了这些字符串，请运行一个 custom script/plugin，应用相同的 heuristic，并在所引用的 `.rodata` offsets 处创建 string data。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` 工具是很好的参考，可用于将这一思路调整到其他 **word sizes、endianness 和 section layouts**。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

对于 Delphi 编译的 binary，可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果必须 reverse 一个 Delphi binary，建议使用 IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

在 IDA 中按 **Alt+F7** 加载 Python plugin，然后选择 plugin 文件。

该 plugin 会执行 binary，并在 debugging 开始时动态解析 function names。开始 debugging 后，再次按下 Start 按钮（绿色按钮或 f9），断点会在 real code 的开头命中。

如果在 graphical application 中按下某个按钮，debugger 可以停在该按钮调用的 function 中。

## Golang

如果必须 reverse 一个 Golang binary，建议使用 IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

在 IDA 中按 **Alt+F7** 加载 Python plugin，然后选择 plugin 文件。

这会解析 functions 的 names。

## Compiled Python

在此页面中可以找到如何从 ELF/EXE python compiled binary 中获取 python code：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

如果获得了 GBA 游戏的 **binary**，可以使用不同的工具对其进行 **emulate** 和 **debug**：

- [**no$gba**](https://problemkaputt.de/gba.htm) (_下载 debug version_) - 包含带 interface 的 debugger
- [**mgba** ](https://mgba.io)- 包含 CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，在 _**Options --> Emulation Setup --> Controls**_** 中可以查看如何按下 Game Boy Advance 的 **buttons**

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

按下时，每个 **key has a value** 用于识别它：
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
因此，在这类程序中，有趣的部分将是**程序如何处理用户输入**。在地址 **0x4000130** 处，你会找到一个常见的函数：**KEYINPUT**。

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

在上一张图片中，你可以看到该函数是从 **FUN_080015a8** 调用的（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，经过一些初始化操作后（这些操作并不重要）：
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
找到这段代码：
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
最后一个 if 正在检查 **`uVar4`** 是否位于 **last Keys** 中且不是当前按键，也就是松开某个按钮（当前按键存储在 **`uVar1`** 中）。
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
在前面的代码中可以看到，我们正在将 **uVar1**（存放**所按按钮值**的位置）与一些值进行比较：

- 首先，它会与**值 4**（**SELECT** 按钮）进行比较：在该 challenge 中，此按钮会清除屏幕
- 然后，它会将该值与 **8**（**START** 按钮）进行比较；在该 challenge 中，该路径会检查输入的代码是否有效。
- 在这种情况下，变量 **`DAT_030000d8`** 会与 0xf3 进行比较，如果值相同，则会执行某些代码。
- 在其他所有情况下，都会检查并递增一个计数器（`DAT_030000d4`）。\
当计数器小于 8 时，按键值会累积到 `DAT_030000d8` 中。

因此，在该 challenge 中，在已知按钮值的情况下，你需要**按下一个长度小于 8 的组合，使相加结果为 0xf3。**

**本教程的参考资料：** [已存档的 Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## 课程

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [使用 CoBRA 简化 MBA obfuscation](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [解码 Rust 字符串 - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing 教程（已存档）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [击败 AI 辅助的 Reverse Engineering，或者至少尝试这样做](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
