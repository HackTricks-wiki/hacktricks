# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) を使用して、wasm（バイナリ）から wat（読みやすいテキスト）へ **decompile** します
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) を使用して、wat から wasm へ **compile** します
- decompilation には [web-wasmdec](https://wwwg.github.io/web-wasmdec/) も利用できます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek は、**libraries**（.dll）、**Windows metadata file**s（.winmd）、**executables**（.exe）など、**複数の形式を decompile して調査**できる decompiler です。decompile した後、assembly を Visual Studio project（.csproj）として保存できます。

ここでの利点は、失われた source code を legacy assembly から復元する必要がある場合に、この作業によって時間を節約できることです。さらに、dotPeek は decompiled code 全体を便利に移動できるため、**Xamarin algorithm analysis** に最適なツールの一つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的な add-in model と、ツールを正確なニーズに合わせて拡張できる API により、.NET reflector は時間を節約し、開発を簡素化します。このツールが提供する数多くの reverse engineering サービスを見てみましょう。

- library または component 内でデータがどのように流れるかを把握できます
- .NET languages および frameworks の実装と使用方法を把握できます
- 使用している API と technologies をさらに活用するため、documented されていない、または公開されていない functionality を見つけます。
- dependencies と異なる assemblies を見つけます
- code、third-party components、libraries 内の errors の正確な場所を特定します。
- 使用しているすべての .NET code の source に対して debug できます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): どの OS でも利用できます（VSCode から直接 install できるため、git を download する必要はありません。**Extensions** をクリックし、**search ILSpy** を実行してください）。\
**decompile**、**modify**、そして再度 **recompile** する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases) または現在も保守されている fork である [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) を使用できます。（関数内の何かを変更するには **Right Click -> Modify Method**）。

### DNSpy Logging

**DNSpy に情報を file に log させる**には、次の snippet を使用できます。
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpyを使用してコードをdebugするには、次の操作が必要です。

まず、**debugging**に関連する**Assembly attributes**を変更します。

![DNSpy Logging - DNSpy Debugging: まず、debuggingに関連するAssembly attributesを変更します](<../../images/image (973).png>)

変更前:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
宛先:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
そして **compile** をクリックします。

![DNSpy Logging - DNSpy Debugging: compileをクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: File Save moduleから新しいファイルを保存](<../../images/image (602).png>)

これは、これを行わない場合、**runtime** でコードに複数の **optimisations** が適用され、デバッグ中に **break-point が一度もヒットしない**、または一部の **variables が存在しない** 可能性があるため必要です。

次に、.NET application が **IIS** によって **run** されている場合は、次の方法で **restart** できます。
```
iisreset /noforce
```
Then、debuggingを開始するには、開いているすべてのファイルを閉じ、**Debug Tab** 内で **Attach to Process...** を選択します：

![DNSpy Logging - DNSpy Debugging: Then、debuggingを開始するには、開いているすべてのファイルを閉じ、Debug Tab 内で Attach to Process を選択します](<../../images/image (318).png>)

次に、**IIS server** にattachするため **w3wp.exe** を選択し、**attach** をクリックします：

![DNSpy Logging - DNSpy Debugging: 次に、IIS server にattachするため w3wp.exe を選択し、attach をクリックします](<../../images/image (113).png>)

これでprocessをdebuggingしているので、停止してすべてのmoduleをloadします。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします：

![DNSpy Logging - DNSpy Debugging: processをdebuggingしているので、停止してすべてのmoduleをloadします。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: processをdebuggingしているので、停止してすべてのmoduleをloadします。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意のmoduleをクリックし、**Open All Modules** を選択します：

![DNSpy Logging - DNSpy Debugging: Modules 内の任意のmoduleをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のmoduleを右クリックし、**Sort Assemblies** をクリックします：

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のmoduleを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs のdebugging

### Using IDA

- **Load rundll32** (64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debuggerを選択します
- "**Suspend on library load/unload**" を選択します

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択します](<../../images/image (868).png>)

- 実行の **parameters** を設定し、**path to the DLL** と呼び出したいfunctionを指定します：

![Debugging DLLs - Using IDA: 実行のparametersを設定し、path to the DLLと呼び出したいfunctionを指定します](<../../images/image (704).png>)

その後、debuggingを開始すると、**各DLLがloadされたときに実行が停止します**。つまり、rundll32がDLLをloadすると、実行が停止します。

この方法ではmodule-load eventで停止しますが、loadされたDLLのentry pointに到達する手順は、以下のx64dbg workflowほど直接的ではありません。

### Using x64dbg/x32dbg

- **Load rundll32** (64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe)
- **Command Line** ( _File --> Change Command Line_ ) を変更し、dllのpathと呼び出したいfunctionを設定します。例： "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- その後、**executionを開始**します。debuggerは各dll mainで停止し、しばらくすると**対象dllのdll Entryで停止します**。そこから、breakpointを設定したい箇所を探します。

win64dbgで何らかの理由によりexecutionが停止した場合、**win64dbg windowの上部**を見ることで、**現在どのcodeにいるか**を確認できます：

![Using IDA - Using x64dbg/x32dbg: executionが何らかの理由で停止した場合、win64dbg windowの上部を見ることで、現在どのcodeにいるかを確認できます](<../../images/image (842).png>)

このindicatorにより、debugging対象のDLL内部でexecutionが停止したことを確認できます。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のgameのmemory内で重要なvalueが保存されている場所を見つけ、それらを変更するための便利なprogramです。詳細：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、gameに重点を置いた GNU Project Debugger (GDB) 用のfront-end/reverse engineering toolです。ただし、reverse-engineeringに関連するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数のdecompilerに対応したweb front-endです。このweb serviceを使用すると、小さなexecutableに対する異なるdecompilerのoutputを比較できます。

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerを使用したshellcodeのdebugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner) は **shellcode** をallocateし、その **memory address** を表示して、executionをpauseします。\
IDAやx64dbgなどのdebuggerをattachし、表示されたaddressにbreakpointを設定してからexecutionをresumeすると、shellcodeをdebuggingできます。

releases github pageには、compiled releasesを含むzipがあります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のlinkから、少し変更されたBlobrunner versionを入手できます。compileするには、**Visual Studio CodeでC/C++ projectを作成し、codeをcopy and pasteしてbuildします**。

{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itを使用したshellcodeのdebugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) はBlobRunnerに似ています。shellcodeをallocateしてinfinite loopに入ります。debuggerをattachし、**2–5秒間** resumeしてから、そのloop内でpauseし、executionをallocateされたshellcodeへtransferする次のcallまでstepします。

![allocateされたshellcodeへのcallの直前でjmp2itのinfinite loop内でpauseしているdebugger](<../../images/image (509).png>)

compiled versionの [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/) をdownloadできます。

### Cutterを使用したshellcodeのdebugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) はradareのGUIです。Cutterを使用すると、shellcodeをemulateし、動的にinspectできます。

Cutterでは "Open File" と "Open Shellcode" を選択できます。同じbytesをfileとして開いた場合は正しくdecompileされましたが、shellcodeとして開いた場合は正しくdecompileされませんでした：

![同じbytesをfileまたはshellcodeとして開いたときに異なるanalysis resultsを表示するCutter](<../../images/image (562).png>)

指定した場所からemulationを開始するには、そこにbpを設定します。すると、Cutterはその場所から自動的にemulationを開始するようです：

![Cutterのemulationを開始する前に、目的のshellcode entryにbreakpointを設定](<../../images/image (589).png>)

![選択したshellcode breakpointでpauseしているCutter emulator](<../../images/image (387).png>)

例えば、hex dump内でstackを確認できます：

![Cutterのhex dumpでemulateされたshellcode stackを表示](<../../images/image (186).png>)

### shellcodeのdeobfuscatingと実行されたfunctionの取得

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試してください。\
shellcodeが**どのfunction**を使用しているか、またshellcodeがmemory内で自身を**decoding**しているかなどを確認できます。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbgには、必要なオプションを選択してshellcodeを実行できるgraphical launcherもあります。

![shellcodeのemulationおよびtracingオプションを選択するためのscDbg graphical launcher](<../../images/image (258).png>)

**Create Dump**オプションを使用すると、メモリ上でshellcodeに動的な変更が行われた場合に、最終的なshellcodeをdumpできます（decoded shellcodeのダウンロードに便利です）。**start offset**は、特定のoffsetからshellcodeを開始する場合に便利です。**Debug Shell**オプションは、scDbg terminalを使用してshellcodeをdebugする場合に便利です（ただし、この用途では、前述したいずれかのオプションのほうが優れていると思います。Idaやx64dbgを使用できるためです）。

### CyberChefを使用したDisassembling

shellcodeファイルをinputとしてuploadし、次のrecipeを使用してdecompileします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationのdeobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、arithmetic（`+`、`-`、`*`）とbitwise operator（`&`、`|`、`^`、`~`、shift）を組み合わせたformulaによって、`x + y`のような単純なexpressionを隠します。重要なのは、これらのidentityが通常、**fixed-width modular arithmetic**の下でのみ正しいという点です。そのため、carryとoverflowが重要になります:
```c
(x ^ y) + 2 * (x & y) == x + y
```
この種の式を generic algebra tooling で単純化すると、bit-width の意味論が無視されるため、簡単に誤った結果になります。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. **元の bit-width を維持する**。lifted code/IR/decompiler の出力にある `8/16/32/64` ビットを使用します。
2. **単純化を試みる前に式を分類する**。
- **Linear**: bitwise atom の加重和
- **Semilinear**: `x & 0xFF` のような定数マスクを含む linear
- **Polynomial**: 積が含まれる
- **Mixed**: 積と bitwise logic が交互に現れ、多くの場合、部分式が繰り返される
3. **すべての候補となる書き換えを、random testing または SMT proof で検証する**。等価性を証明できない場合は、推測で変更せず、元の式を維持します。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis と protected-binary reversing のための実用的な MBA simplifier です。式を分類し、すべてに対して単一の汎用 rewrite pass を適用するのではなく、専用の pipeline に振り分けます。<sup>[[2]](#references)</sup>

簡単な使用方法:
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

- **Linear MBA**: CoBRA は Boolean inputs 上で式を評価してシグネチャを導出し、pattern matching、ANF conversion、coefficient interpolation など複数の復元手法を競合させます。
- **Semilinear MBA**: constant-masked atoms は bit-partitioned reconstruction によって再構築されるため、マスクされた領域も正しく維持されます。
- **Polynomial/Mixed MBA**: 積は cores に分解され、simplifying the outer relation の前に、繰り返し現れる部分式を temporaries に切り出せます。

復元を試す価値が一般的にある mixed identity の例:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
これは次のように簡略化できます:
```c
x * y
```
### Reversing notes

- **lifted IR expressions** または、正確な計算部分を分離した後の decompiler output に対して CoBRA を実行することを推奨します。
- 式が masked arithmetic または narrow registers に由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な proof step が必要な場合は、こちらの local Z3 notes を確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin**（`libCobraPass.so`）としても提供されており、後続の analysis passes の前に MBA-heavy LLVM IR を normalize したい場合に便利です。
- Unsupported carry-sensitive mixed-domain residuals は、元の式を保持し、carry path を手動で推論すべきであることを示す signal として扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの operation を `mov` ベースの instruction sequences に置き換え、signal/exception handling を使用して control flow を変更します。詳細:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応している binary では、[demovfuscator](https://github.com/kirschju/demovfuscator) を使用して結果を deobfuscate できます。複数の dependencies が必要です。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして [keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTFをプレイしている場合、この**flagを見つけるためのworkaroundが非常に役立つ可能性があります: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**を見つけるには、次の例のように`::main`でfunctionsを検索します:

![double-colon mainでfunction namesを検索してGhidraでRustのentry pointを見つける](<../../images/image (1080).png>)

このケースではbinaryの名前がauthenticatorだったため、これが対象となるmain functionであることはかなり明白です。\
呼び出されている**functions**の**name**がわかったら、**Internet**で検索して、それらの**inputs**と**outputs**について学びます。

### ELF firmwareからRust stringsを復元する

**Rust ELF** binariesでは、多くのstatic stringsがC-styleのNUL-terminated pointersとして参照されていません。一般的な`rustc`のlayoutでは、実際のstring blobが格納されている**`.rodata`**を指す**pointer/length tuple**が**`.data.rel.ro`**内に配置されています:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
これは、`strings` や Ghidra のデフォルト解析では、隣接する文字列が結合されたり、cross-reference が完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

簡単なワークフロー:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** の仮想アドレスとサイズを取得する。
2. **`.data.rel.ro`** を 1 ワードずつ列挙する。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱う。
4. 次のワードを、候補の長さとして扱う。
5. サニティフィルターを適用する（例: 長さが **4**〜**100** バイトのものだけを保持する）。
6. `0x00` までスキャンするのではなく、`.rodata` から正確に `length` バイトを読み取る。

最小限の extractor ロジック:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
これは、復元された Rust 文字列から **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth-related logic** が判明することが多いため、firmware reversing で特に便利です。

Ghidra がこれらの文字列を見つけられない場合は、同じ heuristic を適用し、参照先の `.rodata` offsets に string data を作成するカスタム script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` ツールは、このアイデアを他の **word sizes、endianness、section layouts** に適応する際の優れた参考資料です。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries には [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi binary を reverse する必要がある場合は、IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をお勧めします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin file を選択します。

この plugin は binary を実行し、debugging の開始時に function names を動的に解決します。debugging を開始した後、もう一度 Start button（緑色のボタンまたは f9）を押すと、real code の先頭で breakpoint が発生します。

graphical application で button を押すと、debugger はその button によって呼び出された function で停止できます。

## Golang

Golang binary を reverse する必要がある場合は、IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をお勧めします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin file を選択します。

これにより function names が解決されます。

## Compiled Python

このページでは、ELF/EXE python compiled binary から python code を取得する方法を説明しています。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA game の **binary** を入手した場合は、これを **emulate** および **debug** するためのさまざまなツールを使用できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version をダウンロード_) - interface 付き debugger
- [**mgba** ](https://mgba.io)- CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance **buttons** の押し方を確認できます。

![Game Boy Advance の button mappings を示す no$gba controls configuration](<../../images/image (581).png>)

押すと、各 **key には値が割り当てられ**、それを識別に使用できます。
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
この種のプログラムでは、興味深い部分は **プログラムがユーザー入力をどのように処理するか** です。アドレス **0x4000130** には、一般的に見つかる関数 **KEYINPUT** があります。

![アドレス 0x4000130 の KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像から、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

この関数では、いくつかの init operations（重要ではありません）の後に、次の処理が行われます。
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
このコードが見つかります:
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
最後の if は、**`uVar4`** が**最後の Keys**に含まれており、現在のキーではないことを確認しています。これは、ボタンを離した状態とも呼ばれます（現在のキーは **`uVar1`** に格納されています）。
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
前のコードでは、**uVar1**（**押されたボタンの値**が格納されている場所）をいくつかの値と比較していることがわかります。

- 最初に、**値 4**（**SELECT** button）と比較されます。この challenge では、このボタンによって画面がクリアされます。
- 次に、値を **8**（**START** button）と比較します。この challenge では、この経路で入力されたコードが有効かどうかをチェックします。
- この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が同じ場合は一部のコードが実行されます。
- それ以外の場合は、カウンタ（`DAT_030000d4`）がチェックされ、インクリメントされます。\
カウンタが 8 未満の間、押されたキーの値が `DAT_030000d8` に累積されます。

したがって、この challenge ではボタンの値を知ったうえで、**長さが 8 未満で、加算結果が 0xf3 になる組み合わせを押す必要がありました。**

**このチュートリアルの Reference:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリ難読化解除）

## References

- [1] [MBA obfuscation を CoBRA で簡略化する](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
