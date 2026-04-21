# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek 是一款反编译器，能够**反编译并检查多种格式**，包括**库** (.dll)、**Windows metadata file**s (.winmd) 和**可执行文件** (.exe)。反编译后，可以将程序集保存为 Visual Studio 项目 (.csproj)。

这里的优点是，如果丢失的源代码需要从旧程序集恢复，这一操作可以节省时间。此外，dotPeek 提供了便捷的反编译代码导航，使其成为 **Xamarin algorithm analysis** 的理想工具之一。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

借助完整的 add-in model 和可扩展工具以满足你的确切需求的 API，.NET reflector 能节省时间并简化开发。下面看看这款工具提供的丰富 reverse engineering 服务：

- 提供对数据如何在库或组件中流动的洞察
- 提供对 .NET 语言和 frameworks 的实现与使用方式的洞察
- 查找未文档化和未公开的功能，以便更充分地利用所用的 APIs 和 technologies。
- 查找依赖关系和不同的 assemblies
- 追踪代码、第三方组件和库中错误的确切位置。
- 调试你所使用的所有 .NET code 的源代码。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): 你可以在任何 OS 上使用它（可以直接从 VSCode 安装，无需下载 git。点击 **Extensions** 并 **search ILSpy**）。\
如果你需要再次**decompile**、**modify** 并**recompile**，可以使用 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 或其一个仍在维护的 fork，[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)。（在函数内部想改东西时，**Right Click -> Modify Method**）。

### DNSpy Logging

为了让 **DNSpy** 将一些信息记录到文件中，你可以使用这段 snippet：
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy 调试

要使用 DNSpy 调试代码，你需要：

首先，更改与 **debugging** 相关的 **Assembly attributes**：

![](<../../images/image (973).png>)

From:
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

![](<../../images/image (314) (1).png>)

然后通过 _**File >> Save module...**_ 保存新文件：

![](<../../images/image (602).png>)

这是必要的，因为如果你不这样做，在 **runtime** 时会对代码应用若干 **optimisations**，这可能导致在调试时某个 **break-point is never hit**，或者某些 **variables don't exist**。

然后，如果你的 .NET 应用是由 **IIS** **run** 的，你可以用以下方式重启它：
```
iisreset /noforce
```
然后，为了开始调试，你应该关闭所有已打开的文件，并在 **Debug Tab** 中选择 **Attach to Process...**：

![](<../../images/image (318).png>)

然后选择 **w3wp.exe** 以附加到 **IIS server**，并点击 **attach**：

![](<../../images/image (113).png>)

现在我们正在调试该进程，是时候停止它并加载所有 modules 了。先点击 _Debug >> Break All_，然后点击 _**Debug >> Windows >> Modules**_：

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

在 **Modules** 中点击任意 module，然后选择 **Open All Modules**：

![](<../../images/image (922).png>)

在 **Assembly Explorer** 中右键任意 module，然后点击 **Sort Assemblies**：

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- 配置执行的 **parameters**，填入 **DLL 的路径** 和你想调用的函数：

![](<../../images/image (704).png>)

然后，当你开始调试时，**execution will be stopped when each DLL is loaded**，之后，当 rundll32 加载你的 DLL 时，execution will be stopped。

但是，如何才能到达已加载的 DLL 的代码呢？使用这种方法，我不知道。

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

注意，当 execution 因任何原因在 win64dbg 中停止时，你可以通过查看 **win64dbg window** 顶部来看到**你所在的 code**：

![](<../../images/image (842).png>)

然后，通过查看这个可以知道 execution 何时在你想调试的 dll 中停止。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个有用的程序，用来查找运行中游戏的 memory 中重要值被保存的位置并修改它们。更多信息见：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) 是 GNU Project Debugger (GDB) 的前端/reverse engineering 工具，专注于游戏。不过，它也可用于任何与 reverse-engineering 相关的内容。

[**Decompiler Explorer**](https://dogbolt.org/) 是多个 decompiler 的 web 前端。这个 web service 允许你对小型 executable 上不同 decompiler 的输出进行比较。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) 会在一段 memory 空间中 **allocate** **shellcode**，会 **indicate** shellcode 被分配到的 **memory address**，并 **stop** execution。\
然后，你需要将 **debugger**（Ida 或 x64dbg）**attach** 到该 process，并在指示的 memory address 处设置 **breakpoint**，然后 **resume** execution。这样你就能调试 shellcode 了。

releases github page 包含带有编译后 release 的 zip 文件：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
你可以在下面的链接中找到一个稍作修改的 Blobrunner 版本。为了编译它，只需在 Visual Studio Code 中 **create a C/C++ project**，复制并粘贴代码，然后 build 它。


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)和 blobrunner 非常相似。它会在一段 memory 空间中 **allocate** **shellcode**，并启动一个 **eternal loop**。然后你需要将 **debugger** **attach** 到该 process，**play start wait 2-5 secs and press stop**，你会发现自己进入了 **eternal loop**。跳到 eternal loop 的下一条 instruction，因为那会是一个对 shellcode 的 call，最后你就会发现自己正在执行 shellcode。

![](<../../images/image (509).png>)

你可以在 releases page 下载 jmp2it 的编译版本：[https://github.com/adamkramer/jmp2it/releases/](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) 是 radare 的 GUI。使用 cutter 你可以 emulation shellcode 并动态检查它。

注意 Cutter 允许你 "Open File" 和 "Open Shellcode"。在我的案例中，当我把 shellcode 作为 file 打开时，它正确地 decompiled 了，但当我把它作为 shellcode 打开时则没有：

![](<../../images/image (562).png>)

为了在你想要的位置开始 emulation，在那里设置一个 bp，apparently cutter 会自动从那里开始 emulation：

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

例如，你可以在一个 hex dump 中看到 stack：

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

你应该试试 [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)。\
它会告诉你诸如 **which functions** shellcode 正在使用，以及 shellcode 是否在 memory 中自行 **decoding**。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg 还带有一个图形化启动器，你可以在其中选择所需选项并执行 shellcode

![](<../../images/image (258).png>)

**Create Dump** 选项会在 shellcode 在内存中动态修改后，将最终的 shellcode 导出（用于下载解码后的 shellcode 很有用）。**start offset** 可用于从特定偏移处启动 shellcode。**Debug Shell** 选项可用于通过 scDbg 终端调试 shellcode（不过在这方面我觉得前面解释的任一选项都更好，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 进行反汇编

将你的 shellcode 文件作为输入上传，并使用以下 recipe 对其进行反编译：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 混淆去混淆

**Mixed Boolean-Arithmetic (MBA)** 混淆会用混合了算术运算符（`+`、`-`、`*`）和位运算符（`&`、`|`、`^`、`~`、移位）的公式来隐藏像 `x + y` 这样的简单表达式。关键在于，这些恒等式通常只在**固定宽度模运算**下才成立，因此进位和溢出很重要：
```c
(x ^ y) + 2 * (x & y) == x + y
```
如果你用通用代数工具简化这类表达式，很容易得到错误结果，因为忽略了 bit-width 语义。

### Practical workflow

1. **保留原始 bit-width**，来自 lifted code/IR/decompiler 输出（`8/16/32/64` bits）。
2. 在尝试简化之前先**分类表达式**：
- **Linear**: bitwise atoms 的加权和
- **Semilinear**: linear 加上常量 masks，例如 `x & 0xFF`
- **Polynomial**: 出现乘积
- **Mixed**: 乘积和 bitwise logic 交织，常常还有重复子表达式
3. 用随机测试或 SMT proof **验证每个候选重写**。如果无法证明等价，就保留原表达式，不要猜。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一个实用的 MBA simplifier，适用于 malware analysis 和 protected-binary reversing。它会先对表达式分类，再把它送入专门的 pipelines，而不是对所有内容都应用同一个通用 rewrite pass。

Quick usage:
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

- **Linear MBA**：CoBRA 在 Boolean 输入上求值该表达式，导出一个 signature，并并行尝试多种恢复方法，例如 pattern matching、ANF conversion 和 coefficient interpolation。
- **Semilinear MBA**：使用 bit-partitioned reconstruction 重建 constant-masked atoms，使被掩码的区域保持正确。
- **Polynomial/Mixed MBA**：将乘积分解为 cores，并且在简化外部关系之前，可以把重复的 subexpressions 提升为 temporaries。

一个通常值得尝试恢复的 mixed identity 示例：
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
这可以归结为：
```c
x * y
```
### 反汇编笔记

- 优先在 **lifted IR expressions** 或在你已隔离出精确计算后的 decompiler output 上运行 CoBRA。
- 当表达式来自 masked arithmetic 或 narrow registers 时，显式使用 `--bitwidth`。
- 如果你需要更强的证明步骤，请查看这里的本地 Z3 笔记：


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA 也作为一个 **LLVM pass plugin**（`libCobraPass.so`）提供，这在你想在后续 analysis passes 之前先规范化大量 MBA 的 LLVM IR 时很有用。
- 不支持的 carry-sensitive mixed-domain residuals 应被视为一个信号：保留原始表达式，并手动推理 carry path。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

这个 obfuscator **修改了所有 `mov` 的指令**（没错，真的很酷）。它还使用 interruptions 来改变执行流。有关它如何工作的更多信息：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

如果你幸运的话，[demovfuscator](https://github.com/kirschju/demovfuscator) 会对 binary 进行 deofuscate。它有几个 dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
并且 [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

如果你在玩 **CTF, this workaround to find the flag** 会非常有用: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

要找到 **entry point**，像这样通过 `::main` 搜索 functions:

![](<../../images/image (1080).png>)

在这个例子里，这个 binary 叫 authenticator，所以很明显这就是有意思的 main function。\
掌握正在被调用的 **functions** 的 **name** 后，在 **Internet** 上搜索它们，了解它们的 **inputs** 和 **outputs**。

## **Delphi**

对于用 Delphi 编译的 binaries，你可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果你需要 reverse 一个 Delphi binary，我建议你使用 IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

只需按 **ATL+f7**（在 IDA 中导入 python plugin）并选择 python plugin。

这个 plugin 会在 debugging 开始时执行 binary 并动态解析 function names。启动 debugging 后，再次按 Start 按钮（绿色按钮或 f9），然后会在真实 code 的开头触发一个 breakpoint。

这也非常有意思，因为如果你在 graphic application 中按下一个 button，debugger 会停在执行那个 button 的 function 上。

## Golang

如果你需要 reverse 一个 Golang binary，我建议你使用 IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

只需按 **ATL+f7**（在 IDA 中导入 python plugin）并选择 python plugin。

这会解析 functions 的 names。

## Compiled Python

在这个页面你可以找到如何从 ELF/EXE python compiled binary 中获取 python code：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

如果你拿到一个 GBA game 的 **binary**，你可以使用不同的 tools 来 **emulate** 和 **debug** 它：

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Contains a debugger with interface
- [**mgba** ](https://mgba.io)- Contains a CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，在 _**Options --> Emulation Setup --> Controls**_** ** 你可以看到如何按下 Game Boy Advance **buttons**

![](<../../images/image (581).png>)

当按下时，每个 **key has a value** 用于识别它：
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
所以，在这种程序中，重点会是**程序如何处理用户输入**。在地址 **0x4000130** 你会找到常见的函数：**KEYINPUT**。

![](<../../images/image (447).png>)

在前面的图片中，你可以看到该函数是从 **FUN_080015a8** 中调用的（地址：_0x080015fa_ 和 _0x080017ac_）。

在那个函数中，在一些初始化操作之后（没有任何重要性）：
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
最后一个 if 正在检查 **`uVar4`** 是否在 **last Keys** 中，而不是当前按键，也就是松开一个按钮（当前按键存储在 **`uVar1`** 中）。
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
在前面的代码中，你可以看到我们正在将 **uVar1**（即 **按下按钮的值** 所在的位置）与一些值进行比较：

- 首先，它与 **值 4**（**SELECT** button）进行比较：在这个 challenge 中，这个按钮会清空屏幕
- 然后，它与 **值 8**（**START** button）进行比较：在这个 challenge 中，这会检查代码是否有效以获取 flag。
- 在这种情况下，var **`DAT_030000d8`** 会与 0xf3 进行比较，如果值相同，就会执行一些代码。
- 在其他任何情况下，都会检查一个 cont（**`DAT_030000d4`**）。之所以称它为 cont，是因为进入 code 后它会立刻加 1。\
**如**果小于 8，就会执行一些涉及向 **`DAT_030000d8`** **添加** 值的操作（基本上，只要 cont 小于 8，就把按下的 key 的值加到这个变量里）。

所以，在这个 challenge 中，知道了按钮的值后，你需要 **按下一个长度小于 8 的组合，使得最终的加和为 0xf3。**

**本教程参考：** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)

{{#include ../../banners/hacktricks-training.md}}
