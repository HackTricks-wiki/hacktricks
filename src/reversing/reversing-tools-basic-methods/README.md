# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## 基于 ImGui 的 Reversing tools

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

dotPeek is a decompiler that **decompiles and examines multiple formats**, including **libraries** (.dll), **Windows metadata file**s (.winmd), and **executables** (.exe). Once decompiled, an assembly can be saved as a Visual Studio project (.csproj).

The merit here is that if a lost source code requires restoration from a legacy assembly, this action can save time. Further, dotPeek provides handy navigation throughout the decompiled code, making it one of the perfect tools for **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

With a comprehensive add-in model and an API that extends the tool to suit your exact needs, .NET reflector saves time and simplifies development. Let's take a look at the plethora of reverse engineering services this tool provides:

- Provides an insight into how the data flows through a library or component
- Provides insight into the implementation and usage of .NET languages and frameworks
- Finds undocumented and unexposed functionality to get more out of the APIs and technologies used.
- Finds dependencies and different assemblies
- Tracks down the exact location of errors in your code, third-party components, and libraries.
- Debugs into the source of all the .NET code you work with.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): You can have it in any OS (you can install it directly from VSCode, no need to download the git. Click on **Extensions** and **search ILSpy**).\
If you need to **decompile**, **modify** and **recompile** again you can use [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) or an actively maintained fork of it, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** to change something inside a function).

### DNSpy Logging

In order to make **DNSpy log some information in a file**, you could use this snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy 调试

为了使用 DNSpy 调试代码，你需要：

首先，修改与**调试**相关的**Assembly attributes**：

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

然后通过 _**File >> Save module...**_ 保存新文件：

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

这是必要的，因为如果你不这样做，在 **runtime** 时会对代码应用若干 **optimisations**，这可能导致在调试时 **break-point is never hit**，或者某些 **variables don't exist**。

然后，如果你的 .NET application 是由 **IIS** **run** 的，你可以使用以下方式 **restart** 它：
```
iisreset /noforce
```
Then, in order to start debugging you should close all the opened files and inside the **Debug Tab** select **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Then select **w3wp.exe** to attach to the **IIS server** and click **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Now that we are debugging the process, it's time to stop it and load all the modules. First click on _Debug >> Break All_ and then click on _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Click any module on **Modules** and select **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Right click any module in **Assembly Explorer** and click **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg 还带有一个图形化启动器，你可以在其中选择想要的选项并执行 shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

**Create Dump** 选项会在 shellcode 在内存中动态发生任何变化时，导出最终的 shellcode（用于下载解码后的 shellcode 很有用）。**start offset** 在你想从某个特定偏移开始执行 shellcode 时会很有用。**Debug Shell** 选项用于通过 scDbg 终端调试 shellcode（不过在这方面我觉得前面解释的任何一种选项都更好，因为你可以使用 Ida 或 x64dbg）。

### 使用 CyberChef 进行反汇编

将你的 shellcode 文件作为输入上传，并使用以下 recipe 对其进行反编译： [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA 混淆去混淆

**Mixed Boolean-Arithmetic (MBA)** 混淆通过将简单表达式如 `x + y` 藏在混合了算术运算（`+`、`-`、`*`）和按位运算符（`&`、`|`、`^`、`~`、移位）的公式后面来实现隐藏。关键在于，这些恒等式通常只在**固定宽度模运算**下才是正确的，因此进位和溢出很重要：
```c
(x ^ y) + 2 * (x & y) == x + y
```
如果你用通用代数工具去简化这类表达式，很容易得到错误结果，因为忽略了 bit-width 语义。

### Practical workflow

1. **保留原始 bit-width**，来自 lifted code/IR/decompiler 输出（`8/16/32/64` bits）。
2. **先对表达式分类**，再尝试简化：
- **Linear**: 位运算原子项的加权和
- **Semilinear**: 线性项加上常量掩码，例如 `x & 0xFF`
- **Polynomial**: 出现乘积
- **Mixed**: 乘积和位运算逻辑交织在一起，通常还有重复的子表达式
3. 用随机测试或 SMT 证明**验证每一个候选重写**。如果无法证明等价，就保留原始表达式，不要猜。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) 是一个实用的 MBA simplifier，用于 malware analysis 和 protected-binary reversing。它会先对表达式分类，再送入专门的处理流水线，而不是把同一个通用 rewrite pass 用到所有内容上。

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
有用的情况：

- **Linear MBA**: CoBRA 在 Boolean 输入上对表达式求值，导出一个签名，并并行尝试多种恢复方法，如 pattern matching、ANF conversion 和 coefficient interpolation。
- **Semilinear MBA**: 使用 bit-partitioned reconstruction 重建常量掩码的原子，使被掩码的区域保持正确。
- **Polynomial/Mixed MBA**: 将乘积分解为 cores，并且在简化外层关系之前，可以把重复子表达式提升为 temporaries。

通常值得尝试恢复的 mixed identity 示例：
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
这可以简化为：
```c
x * y
```
### Reversing notes

- Prefer running CoBRA on **lifted IR expressions** or decompiler output after you isolated the exact computation.
- Use `--bitwidth` explicitly when the expression came from masked arithmetic or narrow registers.
- If you need a stronger proof step, check the local Z3 notes here:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA also ships as an **LLVM pass plugin** (`libCobraPass.so`), which is useful when you want to normalize MBA-heavy LLVM IR before later analysis passes.
- Unsupported carry-sensitive mixed-domain residuals should be treated as a signal to keep the original expression and reason about the carry path manually.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

To find the **entry point** search the functions by `::main` like in:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

In this case the binary was called authenticator, so it's pretty obvious that this is the interesting main function.\
Having the **name** of the **functions** being called, search for them on the **Internet** to learn about their **inputs** and **outputs**.

### Recovering Rust strings from ELF firmware

In **Rust ELF** binaries, many static strings are not referenced as C-style NUL-terminated pointers. A common `rustc` layout is a **pointer/length tuple** inside **`.data.rel.ro`** pointing into the real string blob stored in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
这意味着 `strings` 或默认的 Ghidra 分析可能会合并相邻字符串，或者完全漏掉 cross-references。

Quick workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. 获取 **`.rodata`** 的虚拟地址和大小。
2. 逐个 word 枚举 **`.data.rel.ro`**。
3. 将 `.rodata` 地址范围内的任何值视为候选字符串指针。
4. 将下一个 word 视为候选长度。
5. 应用合理性过滤器（例如，将长度保持在 **4** 到 **100** 字节之间）。
6. 直接从 `.rodata` 读取恰好 `length` 个字节，而不是一直扫描到 `0x00`。

最小提取器逻辑：
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
这在 firmware reversing 中尤其有用，因为恢复出的 Rust strings 往往会暴露 **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers，以及与 auth 相关的逻辑**。

如果 Ghidra 漏掉了这些 strings，可以运行一个自定义 script/plugin，应用相同的 heuristic，并在引用的 `.rodata` offsets 处创建 string data。Pen Test Partners 发布的 `rust-strings` 和 `RustStrings.py` tools 是将这个思路适配到其他 **word sizes、endianness 和 section layouts** 的很好参考。

## **Delphi**

对于 Delphi 编译的 binaries，你可以使用 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

如果你需要 reverse 一个 Delphi binary，我建议你使用 IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

只需按 **ATL+f7**（在 IDA 中导入 python plugin）并选择 python plugin。

这个 plugin 会在 debugging 开始时执行 binary 并动态 resolve function names。开始 debugging 后，再次按 Start 按钮（绿色那个或 f9），然后会在真正代码的开头触发一个 breakpoint。

这也很有意思，因为如果你在图形应用里按下一个按钮，debugger 会停在该按钮执行的 function 处。

## Golang

如果你需要 reverse 一个 Golang binary，我建议你使用 IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

只需按 **ATL+f7**（在 IDA 中导入 python plugin）并选择 python plugin。

这会 resolve 这些 functions 的名字。

## Compiled Python

在这个页面你可以找到如何从 ELF/EXE python compiled binary 中获取 python code：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

如果你拿到一个 GBA game 的 **binary**，你可以使用不同的工具来 **emulate** 和 **debug** 它：

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - 包含一个带界面的 debugger
- [**mgba** ](https://mgba.io)- 包含一个 CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

在 [**no$gba**](https://problemkaputt.de/gba.htm) 中，在 _**Options --> Emulation Setup --> Controls**_** ** 里你可以看到如何按下 Game Boy Advance 的 **buttons**

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

按下后，每个 **key 都有一个 value** 用来标识它：
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
因此，在这种程序中，重点在于 **程序如何处理用户输入**。在地址 **0x4000130** 你会找到常见的函数：**KEYINPUT**。

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

在前面的图片中你可以看到，该函数是从 **FUN_080015a8** 调用的（地址：_0x080015fa_ 和 _0x080017ac_）。

在该函数中，在一些初始化操作之后（没有任何重要性）：
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
最后一个 if 在检查 **`uVar4`** 是否在 **最后的 Keys** 中，而不是当前 key，也就是释放一个按钮（当前 key 存储在 **`uVar1`** 中）。
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
在前面的代码中，你可以看到我们在将 **uVar1**（也就是 **按下按钮的值** 所在的位置）与一些值进行比较：

- 首先，它与 **值 4**（**SELECT** 按钮）比较：在这个 challenge 中，这个按钮会清屏
- 然后，它与 **值 8**（**START** 按钮）比较：在这个 challenge 中，这会检查 code 是否有效以获取 flag。
- 在这种情况下，变量 **`DAT_030000d8`** 会与 0xf3 比较，如果值相同，就会执行某些 code。
- 在其他任何情况下，会检查某个 cont（**`DAT_030000d4`**）。之所以说它是 cont，是因为进入 code 后它会立刻加 1。\
**I**f 小于 8，就会执行一些涉及向 **`DAT_030000d8`** 添加值的操作（基本上是在这个变量中累加按下的按键值，只要 cont 小于 8）。

所以，在这个 challenge 中，已知按钮的值后，你需要 **按下一个长度小于 8 的组合，使得累加结果为 0xf3。**

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
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
