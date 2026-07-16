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

dotPeek は、**複数の形式を逆コンパイルして解析**できる decompiler で、**libraries** (.dll)、**Windows metadata file**s (.winmd)、**executables** (.exe) を含みます。逆コンパイル後、assembly は Visual Studio project (.csproj) として保存できます。

ここでの利点は、失われたソースコードをレガシー assembly から復元する必要がある場合に、この作業で時間を節約できることです。さらに、dotPeek は逆コンパイルされた code 全体を便利にナビゲートできるため、**Xamarin algorithm analysis.** に最適な tools の1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的な add-in model と、tool を必要に応じて拡張する API により、.NET reflector は時間を節約し、development を簡素化します。この tool が提供する豊富な reverse engineering services を見てみましょう:

- library や component を通じて data がどのように流れるかを把握できる
- .NET languages と frameworks の実装および使用方法について把握できる
- undocumented かつ未公開の functionality を見つけ、使用している APIs と technologies をより活用できる
- dependencies と異なる assemblies を見つけられる
- code、third-party components、libraries 内のエラーの正確な場所を追跡できる
- 作業しているすべての .NET code の source にデバッグできる

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): 任意の OS で利用できます（git をダウンロードする必要はなく、VSCode から直接インストールできます。**Extensions** をクリックして **ILSpy** を検索してください）。\
もし **decompile**、**modify**、そして再度 **recompile** したいなら、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases) またはそのアクティブに保守されている fork である [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) を使えます。（関数内の何かを変更するには **Right Click -> Modify Method**）。

### DNSpy Logging

**DNSpy が情報を file に log する**ようにするには、この snippet を使えます:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpyを使ってコードをデバッグするには、次のことが必要です:

まず、**debugging**に関連する**Assembly attributes**を変更します:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
To:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
そして **compile** をクリックします:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

その後、_**File >> Save module...**_ から新しいファイルを保存します:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これは必要です。これを行わないと、**runtime** でコードにいくつかの **optimisations** が適用され、デバッグ中に **break-point is never hit** したり、いくつかの **variables don't exist** ことが起こり得ます。

その後、.NET アプリケーションが **IIS** によって **run** されている場合は、次のように **restart** できます:
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

## DLL のデバッグ

### IDA を使用する

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- **parameters** を設定し、**DLL のパス**と呼び出したい関数を指定する:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### x64dbg/x32dbg を使用する

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **コマンドラインを変更**する ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内で重要な値がどこに保存されているかを見つけて変更するのに便利なプログラムです。詳細は以下:

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

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

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
scDbg には、オプションを選んで shellcode を実行できるグラフィカルランチャーもあります

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

**Create Dump** オプションは、shellcode がメモリ上で動的に変更された場合に最終的な shellcode をダンプします（デコード後の shellcode を取得するのに便利です）。**start offset** は、shellcode を特定のオフセットから開始するのに役立ちます。**Debug Shell** オプションは、scDbg ターミナルを使って shellcode をデバッグするのに便利です（ただし、この用途では前に説明したいずれかのオプションのほうがより良いと考えます。Ida や x64dbg を使えるためです）。

### CyberChef を使った逆アセンブル

shellcode ファイルを入力としてアップロードし、次の recipe を使って逆コンパイルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation の deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation は、`x + y` のような単純な式を、算術演算子 (`+`, `-`, `*`) とビット演算子 (`&`, `|`, `^`, `~`, シフト) を混ぜた数式の背後に隠します。重要なのは、これらの恒等式は通常、**固定幅のモジュラー算術** の下でのみ正しいという点で、キャリーとオーバーフローが重要になります:
```c
(x ^ y) + 2 * (x & y) == x + y
```
この種の式を generic な algebra ツールで単純化すると、bit-width の意味が無視されているため、簡単に誤った結果になることがあります。

### Practical workflow

1. **元の bit-width を維持する**。lift された code/IR/decompiler output の (`8/16/32/64` bits) をそのまま使う。
2. **単純化を試す前に式を分類する**:
- **Linear**: bitwise atoms の重み付き和
- **Semilinear**: `x & 0xFF` のような定数 mask を含む linear
- **Polynomial**: 積が現れる
- **Mixed**: 積と bitwise logic が交互に現れ、しばしば repeated subexpressions を伴う
3. **各候補の rewrite を検証する**。random testing か SMT proof を使う。等価性を証明できないなら、推測せず元の式を保持する。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis と protected-binary reversing のための practical な MBA simplifier です。1つの generic rewrite pass をすべてに適用するのではなく、式を分類して specialized pipelines に振り分けます。

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
有用なケース:

- **Linear MBA**: CoBRA は Boolean 入力上で式を評価し、シグネチャを導出し、pattern matching、ANF 変換、係数補間などの複数の復元方法を競合させます。
- **Semilinear MBA**: constant-masked atom は bit-partitioned reconstruction で再構築され、masked regions が正しく保たれます。
- **Polynomial/Mixed MBA**: 積は cores に分解され、繰り返し現れる subexpressions は外側の関係を単純化する前に temporaries に持ち上げられます。

一般に復元を試す価値がある mixed identity の例:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
これは次のように短縮できます:
```c
x * y
```
### Reversing notes

- CoBRAは、**lifted IR expressions** または、正確な計算を特定した後のdecompiler outputに対して実行するのが望ましいです。
- 式がmasked arithmeticやnarrow registers由来の場合は、`--bitwidth` を明示的に使ってください。
- もっと強い証明ステップが必要なら、ここにあるローカルのZ3ノートを確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRAは **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続のanalysis passesの前にMBA-heavyなLLVM IRを正規化したいときに便利です。
- unsupportedなcarry-sensitive mixed-domain residualsは、元のexpressionを保持し、carry pathを手動で検討するべきだというサインとして扱ってください。

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

CTFをプレイしているなら、**flag を見つけるためのこの回避策**はとても役立つかもしれません: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** を見つけるには、関数を `::main` で検索します。例:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

この場合、バイナリ名は authenticator だったので、これが興味深い main function であるのは明らかです。\
呼び出されている **functions** の **name** が分かっているなら、それらの **inputs** と **outputs** を知るために **Internet** で検索してください。

### Recovering Rust strings from ELF firmware

**Rust ELF** バイナリでは、多くの static strings は C-style の NUL-terminated ポインタとして参照されません。一般的な `rustc` のレイアウトでは、**`.data.rel.ro`** 内の **pointer/length tuple** が、**`.rodata`** に保存された実際の string blob を指しています:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
これは、`strings` やデフォルトの Ghidra 分析が隣接する文字列を結合したり、cross-references を完全に見逃したりする可能性があることを意味します。

簡単なワークフロー:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** の仮想アドレスとサイズを取得する。
2. **`.data.rel.ro`** を1ワードずつ列挙する。
3. `.rodata` のアドレス範囲内にある値を、候補の文字列ポインタとして扱う。
4. 次のワードを候補の長さとして扱う。
5. 妥当性フィルタを適用する（たとえば、長さを **4** 〜 **100** バイトに制限する）。
6. `0x00` を探して走査する代わりに、`.rodata` からちょうど `length` バイトを読み取る。

最小抽出ロジック:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
これは、特に firmware reversing で非常に有用です。というのも、復元された Rust の文字列はしばしば **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, and auth-related logic** を示すからです。

Ghidra がそれらの文字列を見逃す場合は、同じヒューリスティックを適用し、参照先の `.rodata` オフセットに string data を作成するカスタム script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` ツールは、**word sizes, endianness, and section layouts** に合わせてこのアイデアを他へ適用する際の良い参考になります。

## **Delphi**

Delphi でコンパイルされた binaries には [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使えます。

Delphi binary を reverse する必要があるなら、IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をおすすめします。

**ATL+f7**（IDA で python plugin を import）を押して、python plugin を選択するだけです。

この plugin は binary を実行し、debugging の開始時に function names を動的に解決します。debugging を開始したあと、もう一度 Start button（緑のボタン、または f9）を押すと、実際の code の冒頭で breakpoint が hit します。

また、graphic application で button を押すと、その bottom によって実行された function で debugger が stop するので、とても興味深いです。

## Golang

Golang binary を reverse する必要があるなら、IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使うことをおすすめします。

**ATL+f7**（IDA で python plugin を import）を押して、python plugin を選択するだけです。

これで function の names が解決されます。

## Compiled Python

このページでは、ELF/EXE の python compiled binary から python code を取得する方法を確認できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

GBA game の **binary** を入手したら、それを **emulate** して **debug** するために、いくつかのツールを使えます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - debugger 付きの interface を含む
- [**mgba** ](https://mgba.io)- CLI debugger を含む
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **buttons** の押し方を確認できます。

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

押されたとき、各 **key** には識別用の値があります:
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
したがって、この種のプログラムでは、注目すべき点は **プログラムがユーザー入力をどう扱うか** です。アドレス **0x4000130** には、よく見られる関数 **KEYINPUT** があります。

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

前の画像から、この関数が **FUN_080015a8** から呼ばれていることがわかります（アドレス: _0x080015fa_ と _0x080017ac_）。

その関数では、いくつかの初期化処理の後（重要ではありませんが）:
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
このコードが見つかりました:
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
最後の if は、**`uVar4`** が**最後の Keys**にあり、現在の key ではないことを確認しています。これはボタンを離したことを示しており、現在の key は **`uVar1`** に保存されています。
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
前のコードでは、**uVar1**（**押されたボタンの値**が入る場所）をいくつかの値と比較しているのが分かる：

- まず、**value 4**（**SELECT** ボタン）と比較している: この challenge では、このボタンで画面を消す
- 次に、**value 8**（**START** ボタン）と比較している: この challenge では、flag を取得するために code が有効かどうかを確認する
- この場合、var **`DAT_030000d8`** は 0xf3 と比較され、値が同じなら何らかの code が実行される
- それ以外の場合は、何らかの cont（**`DAT_030000d4`**）がチェックされる。これは、code に入った直後に 1 を足しているので cont である。\
**I**f 8 未満なら、**`DAT_030000d8`** に values を**加算**する処理が行われる（基本的には、cont が 8 未満である限り、この variable に押された keys の values を加算している）。

つまり、この challenge では、button の values を知っていれば、**長さが 8 未満で、加算結果が 0xf3 になる組み合わせを押す**必要があった。

**この tutorial の Reference:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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
