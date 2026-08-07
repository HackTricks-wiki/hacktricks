# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui ベースの Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) を使用して、wasm（バイナリ）からwat（テキスト）へ **decompile** する
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) を使用して、watからwasmへ **compile** する
- [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) を使用してdecompileすることもできる

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、**libraries**（.dll）、**Windows metadata file**（.winmd）、**executables**（.exe）など、複数の形式を**decompileして調査する**decompilerです。decompile後は、assemblyをVisual Studio project（.csproj）として保存できます。

ここでの利点は、失われたsource codeをlegacy assemblyから復元する必要がある場合、この作業によって時間を節約できることです。さらに、dotPeekはdecompiled code全体を便利にナビゲートできるため、**Xamarin algorithm analysis**に最適なtoolsの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なadd-in modelと、正確なニーズに合わせてtoolを拡張できるAPIを備えた.NET reflectorは、時間を節約し、developmentを簡素化します。このtoolが提供する多数のreverse engineering servicesを見てみましょう。

- libraryまたはcomponentを通過するdataのflowを把握できる
- .NET languagesおよびframeworksのimplementationとusageを把握できる
- 使用されているAPIとtechnologiesをさらに活用するため、document化されていない、または公開されていないfunctionalityを見つけられる
- dependenciesと異なるassembliesを見つけられる
- code、third-party components、libraries内のerrorsの正確なlocationを追跡できる
- 使用するすべての.NET codeのsourceに対してdebugできる

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode)：あらゆるOSで利用できます（VSCodeから直接installでき、gitをdownloadする必要はありません。**Extensions**をクリックして**search ILSpy**を実行してください）。\
**decompile**、**modify**、再度**recompile**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)またはそのactively maintained forkである[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内の何かを変更するには、**Right Click -> Modify Method**を実行します）。

### DNSpy Logging

**DNSpyにfile内の情報をlogさせる**には、次のsnippetを使用できます。
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy デバッグ

DNSpyを使用してコードをデバッグするには、以下を行う必要があります。

まず、**デバッグ**に関連する**Assembly attributes**を変更します。

![DNSpy Logging - DNSpy Debugging: まず、デバッグに関連するAssembly attributesを変更します](<../../images/image (973).png>)

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
そして **compile** をクリックします:

![DNSpy Logging - DNSpy Debugging: compile をクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します:

![DNSpy Logging - DNSpy Debugging: File Save module から新しいファイルを保存](<../../images/image (602).png>)

これは、これを行わない場合、**runtime** にコードへ複数の **optimisations** が適用され、debugging 中に **break-point が一度も hit しない**、または一部の **variables が存在しない** 可能性があるため必要です。

次に、.NET application が **IIS** によって **run** されている場合は、次の方法で **restart** できます:
```
iisreset /noforce
```
Then、debugging を開始するには、開いているすべてのファイルを閉じ、**Debug Tab** で **Attach to Process...** を選択します：

![DNSpy Logging - DNSpy Debugging：debugging を開始するには、開いているすべてのファイルを閉じ、Debug Tab で Attach to Process を選択します](<../../images/image (318).png>)

次に、**IIS server** に attach するため **w3wp.exe** を選択し、**attach** をクリックします：

![DNSpy Logging - DNSpy Debugging：次に、IIS server に attach するため w3wp.exe を選択し、attach をクリックします](<../../images/image (113).png>)

これで process の debugging が開始されたので、process を停止してすべての modules を load します。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします：

![DNSpy Logging - DNSpy Debugging：process の debugging が開始されたので、process を停止してすべての modules を load します。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging：process の debugging が開始されたので、process を停止してすべての modules を load します。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意の module をクリックし、**Open All Modules** を選択します：

![DNSpy Logging - DNSpy Debugging：Modules 内の任意の module をクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意の module を右クリックし、**Sort Assemblies** をクリックします：

![DNSpy Logging - DNSpy Debugging：Assembly Explorer 内の任意の module を右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger を選択します
- "**Suspend on library load/unload**" を選択します

![Debugging DLLs - Using IDA："Suspend on library load/unload" を選択します](<../../images/image (868).png>)

- 実行の **parameters** を設定し、**path to the DLL** と呼び出したい function を入力します：

![Debugging DLLs - Using IDA：実行の parameters を設定し、path to the DLL と呼び出したい function を入力します](<../../images/image (704).png>)

その後、debugging を開始すると、**各 DLL が load されるたびに execution が停止します**。したがって、rundll32 が DLL を load すると execution が停止します。

しかし、load された DLL の code に移動するにはどうすればよいでしょうか？この方法では、その方法がわかりません。

### Using x64dbg/x32dbg

- **Load rundll32** (64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe)
- **Command Line を変更**します ( _File --> Change Command Line_ )。dll の path と呼び出したい function を設定します。例："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- その後、**execution を開始**します。debugger は各 dll main で停止し、最終的に **自分の dll の dll Entry で停止します**。そこから、breakpoint を設定したい箇所を探すだけです。

win64dbg で何らかの理由により execution が停止した場合、**win64dbg window の上部**を見ることで、**現在どの code にいるか**を確認できます：

![Using IDA - Using x64dbg/x32dbg：execution が何らかの理由で停止した場合、win64dbg window の上部を見ることで、現在どの code にいるかを確認できます](<../../images/image (842).png>)

これを見ることで、debug したい dll で execution が停止したことを確認できます。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中の game の memory 内で重要な values が保存されている場所を見つけ、それらを変更するために便利な program です。詳細は以下を参照してください：


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、game に重点を置いた GNU Project Debugger (GDB) 用の front-end/reverse engineering tool です。ただし、reverse-engineering に関連するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数の decompiler 用の web front-end です。この web service を使用すると、小規模な executables に対する異なる decompiler の output を比較できます。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) は、memory 内の領域に **shellcode** を **allocate** し、shellcode が allocate された **memory address** を **indicate** して、execution を **stop** します。\
次に、process に **attach a debugger** (Ida または x64dbg) し、指定された memory address に **breakpoint** を設定して、execution を **resume** する必要があります。これにより shellcode を debugging できます。

releases github page には、compiled releases を含む zip が置かれています：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
次の link には、少し変更された Blobrunner version があります。compile するには、**Visual Studio Code で C/C++ project を作成し、code を copy and paste して build** するだけです。


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) は blobrunner と非常によく似ています。memory 内の領域に **shellcode** を **allocate** し、**eternal loop** を開始します。次に process に **attach the debugger** し、**play start wait 2-5 secs and press stop** すると、**eternal loop** 内にいることがわかります。eternal loop の次の instruction に jump してください。そこから shellcode への call になっているため、最終的に shellcode を実行している状態になります。

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it：jmp2it は blobrunner と非常によく似ています。memory 内の領域に shellcode を allocate し、...](<../../images/image (509).png>)

compiled version の [jmp2it は releases page から download できます](https://github.com/adamkramer/jmp2it/releases/)。

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) は radare の GUI です。Cutter を使用すると shellcode を emulate し、動的に inspect できます。

Cutter では "Open File" と "Open Shellcode" を使用できることに注意してください。私の場合、shellcode を file として open すると正しく decompile されましたが、shellcode として open すると正しく decompile されませんでした：

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter：Cutter では "Open File" と "Open Shellcode" を使用できます。私の場合、shellcode を file として open すると...](<../../images/image (562).png>)

指定した場所から emulation を開始するには、そこに bp を設定します。すると、Cutter はそこから自動的に emulation を開始するようです：

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter：指定した場所から emulation を開始するには、そこに bp を設定します。すると、Cutter はそこから自動的に emulation を開始するようです](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter：指定した場所から emulation を開始するには、そこに bp を設定します。すると、Cutter はそこから自動的に emulation を開始するようです](<../../images/image (387).png>)

例えば、hex dump 内で stack を確認できます：

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter：例えば、hex dump 内で stack を確認できます](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試してください。\
shellcode が使用している **functions** や、shellcode が memory 内で自分自身を **decoding** しているかどうかなどを確認できます。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg には、必要なオプションを選択して shellcode を実行できる graphical launcher もあります

![Cutter を使用した shellcode の debugging - shellcode の deobfuscation と実行された functions の取得：scDbg には、必要なオプションを選択して shellcode を実行できる graphical launcher もあります](<../../images/image (258).png>)

**Create Dump** オプションは、メモリ上で shellcode が動的に変更された場合、最終的な shellcode を dump します（decoded shellcode の download に便利です）。**start offset** は、特定の offset から shellcode を開始する場合に便利です。**Debug Shell** オプションは、scDbg terminal を使用して shellcode を debug する場合に便利です（ただし、この用途では、前述したいずれかのオプションの方が優れていると思います。Ida や x64dbg を使用できるためです）。

### CyberChef を使用した Disassembling

shellcode file を input として upload し、以下の recipe を使用して decompile します：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation の deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation は、arithmetic（`+`、`-`、`*`）と bitwise operators（`&`、`|`、`^`、`~`、shift）を組み合わせた formula によって、`x + y` のような単純な expression を隠します。重要なのは、これらの恒等式が通常、**固定幅の modular arithmetic** の下でのみ正しいという点です。そのため、carry と overflow が重要になります。
```c
(x ^ y) + 2 * (x & y) == x + y
```
この種の式を汎用的な代数ツールで単純化すると、ビット幅のセマンティクスが無視されるため、簡単に誤った結果を得る可能性があります。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトされた code/IR/decompiler output から、**元のビット幅**（`8/16/32/64` bits）を維持する。
2. 単純化を試みる前に、**式を分類する**：
- **Linear**：bitwise atom の重み付き和
- **Semilinear**：`x & 0xFF` のような定数マスクを含む linear
- **Polynomial**：積が現れる
- **Mixed**：積と bitwise logic が入り交じり、しばしば部分式が繰り返される
3. random testing または SMT proof によって、候補となる書き換えをすべて**検証する**。等価性を証明できない場合は、推測で置き換えず、元の式を維持する。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis や protected-binary reversing のための実用的な MBA simplifier です。式を分類し、すべてに対して単一の汎用 rewrite pass を適用するのではなく、専用の pipeline に振り分けます。<sup>[[2]](#references)</sup>

簡単な使い方：
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

- **Linear MBA**: CoBRA は Boolean inputs 上で式を評価し、signature を導出したうえで、pattern matching、ANF conversion、coefficient interpolation など複数の recovery methods を競合させます。
- **Semilinear MBA**: constant-masked atoms は bit-partitioned reconstruction によって再構築されるため、masked regions は正確な状態に保たれます。
- **Polynomial/Mixed MBA**: products は cores に分解され、simplifying the outer relation の前に、繰り返し現れる subexpressions を temporaries に移せます。

一般的に復元を試す価値のある mixed identity の例:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
これは次のように簡略化できます:
```c
x * y
```
### Reversing notes

- **lifted IR expressions** または decompiler の出力に対して、正確な計算を分離した後に CoBRA を実行することを推奨します。
- 式が masked arithmetic または narrow registers に由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な proof step が必要な場合は、こちらのローカル Z3 notes を確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続の analysis passes の前に MBA-heavy LLVM IR を normalize したい場合に便利です。
- Unsupported carry-sensitive mixed-domain residuals は、元の式を保持し、carry path を手動で推論し続けるべきことを示す signal として扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は **`mov` のすべての instructions を変更します**（そう、本当にすごいです）。また、interruptions を使用して execution flows を変更します。動作の詳細については、以下を参照してください:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

運が良ければ、[demovfuscator](https://github.com/kirschju/demovfuscator) が binary を deofuscate してくれます。いくつかの dependencies があります。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして [keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTFをプレイしている場合、このworkaroundでflagを見つけられる**可能性があります: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**を見つけるには、次のように`::main`で関数を検索します:

![Movfuscator - Rust: `::main`で関数を検索してentry pointを見つける](<../../images/image (1080).png>)

この場合、バイナリの名前はauthenticatorだったため、これが興味深いmain関数であることは明らかです。\
呼び出されている**関数**の**名前**を使って**Internet**で検索し、それらの**入力**と**出力**について学習します。

### ELF firmwareからRust stringsを復元する

**Rust ELF**バイナリでは、多くのstatic stringsがC-styleのNUL終端ポインタとして参照されていません。一般的な`rustc`のlayoutでは、実際のstring blobを格納する**`.rodata`**を指す**pointer/length tuple**が**`.data.rel.ro`**内に存在します:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
これは、`strings` または Ghidra のデフォルト解析では、隣接する文字列が結合されたり、cross-references が完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

簡単なワークフロー:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** の仮想アドレスとサイズを取得する。
2. **`.data.rel.ro`** を1ワードずつ列挙する。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインタの候補として扱う。
4. 次のワードを候補の長さとして扱う。
5. サニティフィルターを適用する（例：長さを **4**〜**100** バイトに限定する）。
6. `0x00` までスキャンするのではなく、`.rodata` から正確に `length` バイトを読み取る。

最小限の抽出ロジック：
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
これは、復元された Rust strings から **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth-related logic** が明らかになることが多いため、firmware reversing で特に有用です。

Ghidra がこれらの strings を見逃す場合は、同じ heuristic を適用し、参照された `.rodata` offsets に string data を作成する custom script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` tools は、このアイデアを他の **word sizes、endianness、section layouts** に適応する際の優れた参考資料です。<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries には [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi binary を reverse する必要がある場合は、IDA plugin の [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をお勧めします。

**ATL+f7**（IDA に python plugin を import）を押し、python plugin を選択してください。

この plugin は binary を実行し、debugging の開始時に function names を動的に resolve します。debugging を開始した後、もう一度 Start button（緑色のボタン、または f9）を押すと、real code の先頭で breakpoint が hit します。

また、graphic application の button を押すと、debugger がその button によって実行された function で停止するため、非常に興味深い機能です。

## Golang

Golang binary を reverse する必要がある場合は、IDA plugin の [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をお勧めします。

**ATL+f7**（IDA に python plugin を import）を押し、python plugin を選択してください。

これにより function names が resolve されます。

## Compiled Python

このページでは、ELF/EXE python compiled binary から python code を取得する方法を説明しています:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

GBA game の **binary** を取得した場合は、これを **emulate** および **debug** するためのさまざまな tools を使用できます:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - interface 付きの debugger
- [**mgba** ](https://mgba.io)- CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **buttons** の押し方を確認できます。

![Game Boy Advance の button mappings を示す no$gba controls configuration](<../../images/image (581).png>)

押すと、各 **key has a value** が割り当てられ、それによって識別できます:
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
この種のプログラムでは、興味深い部分は**プログラムがユーザー入力をどのように処理するか**です。アドレス **0x4000130** には、よく見られる関数 **KEYINPUT** があります。

![アドレス 0x4000130 の KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

その関数では、いくつかの初期化処理（重要ではありません）の後に:
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
最後の if は、**`uVar4`** が **最後の Keys** に含まれており、現在のキーではないことを確認しています（現在のキーは **`uVar1`** に格納されています）。これは、ボタンを離す操作とも呼ばれます。
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

- 最初に、**値 4**（**SELECT**ボタン）と比較されます。このchallengeでは、このボタンによって画面がクリアされます。
- 次に、**値 8**（**START**ボタン）と比較されます。このchallengeでは、コードが有効かどうかを確認してflagを取得します。
- この場合、var **`DAT_030000d8`** は0xf3と比較され、値が同じ場合は何らかのコードが実行されます。
- それ以外の場合は、何らかのcont（**`DAT_030000d4`**）がチェックされます。コードに入った直後に1を加算しているため、これはcontです。\
**8 未満なら**、**`DAT_030000d8`** に値を**加算**する処理が実行されます（基本的には、contが8未満である限り、押されたキーの値をこの変数に加算します）。

したがって、このchallengeではボタンの値がわかっていれば、**長さが8未満で、合計が0xf3になる組み合わせを押す必要がありました。**

**このチュートリアルのReference:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリのdeobfuscation）

## References

- [1] [CoBRAによるMBA obfuscationの簡略化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust stringsのdecoding - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
