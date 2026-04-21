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

dotPeek は、**decompile** して複数の形式を調査できる **decompiler** で、**libraries** (.dll)、**Windows metadata file**s (.winmd)、**executables** (.exe) を含みます。decompile 後、assembly は Visual Studio project (.csproj) として保存できます。

ここでの利点は、失われた source code を legacy assembly から復元する必要がある場合、この作業で時間を節約できることです。さらに、dotPeek は decompiled code 全体を簡単にナビゲートできるため、**Xamarin algorithm analysis** に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的な add-in model と、ツールを正確なニーズに合わせて拡張する API により、.NET reflector は時間を節約し、開発を簡素化します。このツールが提供する多くの reverse engineering services を見てみましょう:

- library や component 内で data がどのように flow するかを把握できる
- .NET languages と frameworks の implementation と usage について把握できる
- API や technologies で使われている undocumented かつ unexposed な functionality を見つけ、より多くを引き出せる
- dependencies と異なる assemblies を見つける
- code、third-party components、libraries 内の error の正確な位置を特定する
- 作業しているすべての .NET code の source を debug できる

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code 用の ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): どの OS でも使えます（VSCode から直接インストールでき、git をダウンロードする必要はありません。**Extensions** をクリックして **search ILSpy**）。\
もし **decompile**、**modify**、そして再度 **recompile** したいなら [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) か、その actively maintained fork である [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) を使えます。（関数内を変更するには **Right Click -> Modify Method**）。

### DNSpy Logging

**DNSpy が file にいくつかの情報を log する** には、次のスニペットを使えます:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpyを使用してコードをデバッグするには、次の手順が必要です:

まず、**debugging** に関連する **Assembly attributes** を変更します:

![](<../../images/image (973).png>)

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

![](<../../images/image (314) (1).png>)

その後、_**File >> Save module...**_ で新しいファイルを保存します:

![](<../../images/image (602).png>)

これは必要です。これをしないと、**runtime** においていくつかの**optimisations**がコードに適用され、デバッグ中に**break-point**が一度もヒットしなかったり、いくつかの**variables**が存在しなかったりする可能性があるためです。

その後、.NET アプリケーションが **IIS** によって**run**されている場合は、次の方法で再起動できます:
```
iisreset /noforce
```
Then, debuggingを開始するには、開いているファイルをすべて閉じて、**Debug Tab** 内で **Attach to Process...** を選択します:

![](<../../images/image (318).png>)

次に、**w3wp.exe** を選択して **IIS server** にアタッチし、**attach** をクリックします:

![](<../../images/image (113).png>)

これでプロセスのデバッグができるので、今度は停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、その後 _**Debug >> Windows >> Modules**_ をクリックします:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

**Modules** で任意のモジュールをクリックし、**Open All Modules** を選択します:

![](<../../images/image (922).png>)

**Assembly Explorer** で任意のモジュールを右クリックし、**Sort Assemblies** をクリックします:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLsのデバッグ

### IDAを使う場合

- **Load rundll32**（64bitsは C:\Windows\System32\rundll32.exe、32 bitsは C:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debugger を選択
- "**Suspend on library load/unload**" を選択

![](<../../images/image (868).png>)

- 実行の**parameters** を、**DLLのpath** と呼び出したい function を入れて設定します:

![](<../../images/image (704).png>)

その後、debuggingを開始すると、**各 DLL が読み込まれるたびに実行が停止**します。つまり、rundll32 があなたの DLL を読み込むと実行は停止します。

しかし、読み込まれた DLL の code へはどうやって行けばよいのでしょうか？この方法では、私はわかりません。

### x64dbg/x32dbgを使う場合

- **Load rundll32**（64bitsは C:\Windows\System32\rundll32.exe、32 bitsは C:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更**（ _File --> Change Command Line_ ）し、dll の path と呼び出したい function を設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- その後 **実行を開始**すると、debugger は各 dll main で停止します。ある時点で、**あなたの dll の dll Entry で停止**します。そこから、breakpoint を置きたい場所を探すだけです。

win64dbg で何らかの理由で実行が停止したとき、**どの code にいるか** は **win64dbg window の上部** を見ることで確認できます:

![](<../../images/image (842).png>)

それを見れば、実行が止まったのが debug したい dll かどうかがわかります。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームの memory 内の重要な values がどこに保存されているかを見つけて変更するのに便利な program です。詳細は以下:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、ゲームに特化した GNU Project Debugger (GDB) 向けの front-end/reverse engineering tool です。ただし、reverse-engineering 関連のあらゆる用途に使えます

[**Decompiler Explorer**](https://dogbolt.org/) は、複数の decompiler の web front-end です。この web service を使うと、小さな executable に対する異なる decompiler の出力を比較できます。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerでshellcodeをデバッグする

[**Blobrunner**](https://github.com/OALabs/BlobRunner) は **shellcode** をメモリ空間内に **allocate** し、shellcode が割り当てられた **memory address** を **示し**、実行を **停止** します。\
その後、プロセスに **debugger を attach**（Ida または x64dbg）し、示された memory address に **breakpoint** を置いて実行を **resume** する必要があります。これで shellcode をデバッグできます。

releases の github page には、コンパイル済み release を含む zip があります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクで、少し変更された Blobrunner の version を見つけられます。コンパイルするには、**Visual Studio Code で C/C++ project を作成し、code をコピー＆ペーストして build** するだけです。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itでshellcodeをデバッグする

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) は blobrunner に非常によく似ています。**shellcode** をメモリ空間内に **allocate** し、**eternal loop** を開始します。その後、**debugger を process に attach** し、**play start wait 2-5 secs and press stop** すると、**eternal loop** の中に入れます。次に eternal loop の次の instruction にジャンプしてください。そこは shellcode への call になっているので、最終的に shellcode を実行している状態になります。

![](<../../images/image (509).png>)

[jmp2it の releases page からコンパイル済み version をダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使ってshellcodeをデバッグする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) は radare の GUI です。Cutter を使うと shellcode を emulation し、動的に inspect できます。

Cutter には "Open File" と "Open Shellcode" の両方があります。私の場合、shellcode を file として開くと正しく decompile されましたが、shellcode として開くとそうではありませんでした:

![](<../../images/image (562).png>)

希望する場所から emulation を開始するには、そこに bp を設定します。すると、Cutter は自動的にそこから emulation を開始するようです:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

たとえば hex dump 内で stack を見ることができます:

![](<../../images/image (186).png>)

### shellcodeのdeobfuscateと実行関数の把握

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試すべきです。\
これにより、shellcode がどの **functions** を使っているか、また shellcode がメモリ内で自分自身を **decoding** しているかなどがわかります。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg には、オプションを選んで shellcode を実行できるグラフィカルランチャーもある

![](<../../images/image (258).png>)

**Create Dump** オプションは、メモリ上で shellcode に動的な変更が加えられた場合、最終的な shellcode をダンプする（デコード済みの shellcode をダウンロードするのに便利）。**start offset** は、shellcode を特定のオフセットから開始するのに便利。**Debug Shell** オプションは、scDbg ターミナルを使って shellcode をデバッグするのに便利（ただし、この用途では、前に説明したどのオプションよりも、Ida や x64dbg を使えるのでそちらの方がよいと考える）。

### CyberChef を使った Disassembling

shellcode ファイルを input としてアップロードし、以下の recipe を使って decompile する: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation は、`x + y` のような単純な式を、算術演算子 (`+`, `-`, `*`) とビット演算子 (`&`, `|`, `^`, `~`, シフト) を組み合わせた formula の背後に隠す。重要なのは、これらの identity は通常、**固定幅の modular arithmetic** の下でのみ正しいため、キャリーとオーバーフローが重要になることだ:
```c
(x ^ y) + 2 * (x & y) == x + y
```
この種の式を汎用的な代数ツールで簡略化すると、bit-width の意味論が無視されるため、簡単に誤った結果になることがあります。

### 実践的なワークフロー

1. **元の bit-width を保持する**: 持ち上げられたコード/IR/decompiler 出力の `8/16/32/64` bits をそのまま使う。
2. **簡略化を試す前に式を分類する**:
- **Linear**: bitwise atom の重み付き和
- **Semilinear**: `x & 0xFF` のような定数マスクを含む linear
- **Polynomial**: 積が現れる
- **Mixed**: 積と bitwise logic が交互に現れ、しばしば repeated subexpressions を伴う
3. **すべての候補 rewrite を検証する**: random testing か SMT proof を使う。等価性を証明できない場合は、推測せず元の式を保持する。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis と protected-binary reversing のための実用的な MBA simplifier です。式を分類し、すべてに対して1つの汎用 rewrite pass を適用するのではなく、専用の pipeline に振り分けます。

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

- **Linear MBA**: CoBRA は Boolean 入力上で式を評価し、シグネチャを導出し、pattern matching、ANF conversion、coefficient interpolation などの複数の復元手法を並行して試行します。
- **Semilinear MBA**: constant-masked atoms は bit-partitioned reconstruction で再構築され、masked regions が正しいまま保たれます。
- **Polynomial/Mixed MBA**: 積は cores に分解され、繰り返し現れる subexpressions は外側の関係を簡約する前に temporaries に持ち上げることができます。

一般的に復元を試す価値のある mixed identity の例:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
これは次のように要約できます:
```c
x * y
```
### Reversing notes

- **lifted IR expressions** か、exact computation を isolated した後の decompiler output で CoBRA を実行するのがよい。
- expression が masked arithmetic や narrow registers 由来なら、`--bitwidth` を明示的に使う。
- より強い proof step が必要なら、ここで local の Z3 notes を確認する:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続の analysis passes の前に MBA-heavy LLVM IR を normalize したいときに便利。
- unsupported な carry-sensitive mixed-domain residuals は、original expression を保持し、carry path を manual に reason about するサインとして扱うべき。

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

**entry point** を見つけるには、`::main` のような関数を検索します。例えば:

![](<../../images/image (1080).png>)

この場合、バイナリ名は authenticator だったので、これが興味深い main 関数であることは明らかです。\
呼び出されている **functions** の **name** が分かれば、**Internet** で検索して **inputs** と **outputs** を調べてください。

## **Delphi**

Delphi でコンパイルされたバイナリには [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使えます

Delphi バイナリをリバースする必要があるなら、IDA プラグイン [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) を使うことを勧めます

**ATL+f7**（IDA で python plugin を import）を押して、python plugin を選択してください。

このプラグインはバイナリを実行し、デバッグ開始時に動的に function name を解決します。デバッグを開始したあと、もう一度 Start ボタン（緑のボタン、または f9）を押すと、実際の code の冒頭で breakpoint がヒットします。

グラフィックアプリケーションでボタンを押したとき、そのボタンで実行される function で debugger が停止するので、とても興味深いです。

## Golang

Golang バイナリをリバースする必要があるなら、IDA プラグイン [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使うことを勧めます

**ATL+f7**（IDA で python plugin を import）を押して、python plugin を選択してください。

これで function の name が解決されます。

## Compiled Python

このページでは、ELF/EXE の python compiled binary から python code を取り出す方法を紹介しています:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

GBA game の **binary** を入手したら、さまざまな tools を使って **emulate** し、**debug** できます:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version を Download_) - interface 付き debugger を含む
- [**mgba** ](https://mgba.io)- CLI debugger を含む
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** で、Game Boy Advance の **buttons** の押し方を確認できます

![](<../../images/image (581).png>)

押されたとき、それぞれの **key has a value** で識別されます:
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
なので、この種のプログラムでは、興味深いのは **プログラムがユーザー入力をどう扱うか** です。アドレス **0x4000130** では、よく見られる関数である **KEYINPUT** を見つけることができます。

![](<../../images/image (447).png>)

前の画像では、その関数が **FUN_080015a8** から呼び出されていることがわかります（アドレス: _0x080015fa_ と _0x080017ac_）。

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
最後の if は、**`uVar4`** が **最後の Keys** に含まれていて、現在の key ではないことを確認しています。これは、ボタンを離したことを判定するものでもあります（現在の key は **`uVar1`** に格納されています）。
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
前のコードでは、**uVar1**（**押されたボタンの値**が入る場所）をいくつかの値と比較しているのがわかります。

- まず、**値 4**（**SELECT** button）と比較しています: challenge ではこの button は screen をクリアします
- 次に、**値 8**（**START** button）と比較しています: challenge ではこれは flag を取得できる code が正しいかをチェックします。
- この場合、var **`DAT_030000d8`** は 0xf3 と比較され、値が同じなら some code が実行されます。
- それ以外の場合は、some cont (**`DAT_030000d4`**) がチェックされます。これは code に入った直後に 1 を加算しているので cont です。\
**こ**こで 8 未満なら、**`DAT_030000d8`** に値を**加算**する処理が行われます（基本的には、cont が 8 未満である限り、押された key の値をこの variable に足していきます）。

したがって、この challenge では button の値を知っていれば、**長さが 8 未満で、合計が 0xf3 になる組み合わせを押す**必要がありました。

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

{{#include ../../banners/hacktricks-training.md}}
