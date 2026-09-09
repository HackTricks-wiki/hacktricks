# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui ベースの Reversing tools

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) を使用して、wasm（バイナリ）から wat（テキスト）へ **decompile** できます
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) を使用して、wat から wasm へ **compile** できます
- decompilation には [web-wasmdec](https://wwwg.github.io/web-wasmdec/) も試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek は、**ライブラリ**（.dll）、**Windows metadata file**（.winmd）、**実行ファイル**（.exe）など、複数の形式を **decompile して調査**できる decompiler です。decompile 後は、assembly を Visual Studio project（.csproj）として保存できます。

ここでの利点は、失われた source code を legacy assembly から復元する必要がある場合に、この作業によって時間を節約できることです。さらに、dotPeek は decompiled code 内を簡単に移動できる便利なナビゲーション機能を備えているため、**Xamarin algorithm analysis** に最適なツールの一つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的な add-in model と、ツールを正確なニーズに合わせて拡張できる API により、.NET reflector は時間を節約し、開発を簡素化します。このツールが提供する多数の reverse engineering 機能を見てみましょう。

- library または component 内でデータがどのように流れるかを把握できます
- .NET languages および frameworks の実装と使用方法を把握できます
- undocumented かつ unexposed な機能を見つけ、使用している API や technologies をさらに活用できます。
- dependencies と異なる assemblies を見つけられます
- code、third-party components、libraries 内のエラーが発生した正確な場所を追跡できます。
- 使用しているすべての .NET code の source に対して debug できます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code 用 ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): どの OS でも使用できます（VSCode から直接インストールできます。git を download する必要はありません。**Extensions** をクリックして **search ILSpy** を実行してください）。\
**decompile**、**modify**、そして再度 **recompile** する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases) または現在も保守されている fork である [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) を使用できます。（関数内の何かを変更するには、**Right Click -> Modify Method** を使用します）。

### DNSpy Logging

**DNSpy にファイルへ情報を log させる**には、次の snippet を使用できます。
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy デバッグ

DNSpy を使用してコードをデバッグするには、次の操作が必要です。

まず、**デバッグ**に関連する **Assembly attributes** を変更します。

![DNSpy Logging - DNSpy Debugging: まず、デバッグに関連する Assembly attributes を変更します](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これは必要な手順です。これを行わないと、**runtime** にコードへ複数の **optimisations** が適用され、debugging 中に **break-point が一度もヒットしない**、または一部の **variables が存在しない** 可能性があります。

次に、.NET application が **IIS** によって **run** されている場合は、以下のコマンドで **restart** できます:
```
iisreset /noforce
```
その後、debugging を開始するには、開いているすべてのファイルを閉じ、**Debug Tab** で **Attach to Process...** を選択します。

![DNSpy Logging - DNSpy Debugging: その後、debugging を開始するには、開いているすべてのファイルを閉じ、Debug Tab で Attach to Process を選択します](<../../images/image (318).png>)

次に、**IIS server** に attach するために **w3wp.exe** を選択し、**attach** をクリックします。

![DNSpy Logging - DNSpy Debugging: 次に、IIS server に attach するために w3wp.exe を選択し、attach をクリックします](<../../images/image (113).png>)

これで process の debugging が始まったので、停止してすべての module を load します。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: これで process の debugging が始まったので、停止してすべての module を load します。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: これで process の debugging が始まったので、停止してすべての module を load します。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意の module をクリックし、**Open All Modules** を選択します。

![DNSpy Logging - DNSpy Debugging: Modules 内の任意の module をクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意の module を右クリックし、**Sort Assemblies** をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意の module を右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs の debugging

### IDA の使用

- **Load rundll32** (64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger を選択します
- "**Suspend on library load/unload**" を選択します

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択します](<../../images/image (868).png>)

- **parameters** に、**path to the DLL** と呼び出したい function を指定して、実行の **parameters** を設定します。

![Debugging DLLs - Using IDA: path to the DLL と呼び出したい function を指定して、実行の parameters を設定します](<../../images/image (704).png>)

その後、debugging を開始すると、**各 DLL が load されたときに execution が停止します**。つまり、rundll32 が DLL を load すると execution が停止します。

この方法では module-load event で停止しますが、load された DLL の entry point に到達する方法は、以下の x64dbg workflow ほど直接的ではありません。

### x64dbg/x32dbg の使用

- **Load rundll32** (64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) を選択し、dll の path と呼び出したい function を設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- その後 **execution を開始**すると、debugger は各 dll main で停止します。しばらくすると、**自分の dll の dll Entry で停止します**。そこから、breakpoint を設定したい箇所を探すだけです。

win64dbg で何らかの理由により execution が停止した場合、**win64dbg window の上部**を見ると、**どの code にいるか**を確認できることに注意してください。

![Using IDA - Using x64dbg/x32dbg: win64dbg で何らかの理由により execution が停止した場合、win64dbg window の上部を見ると、どの code にいるかを確認できます](<../../images/image (842).png>)

この indicator により、debugging したい DLL 内で execution が停止したことを確認できます。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中の game の memory 内で重要な value が保存されている場所を見つけ、それらを変更するための便利な program です。詳細情報:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、GNU Project Debugger (GDB) 用の front-end/reverse engineering tool で、game に重点を置いています。ただし、reverse-engineering に関連するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数の decompiler 用の web front-end です。この web service では、小規模な executable に対する異なる decompiler の出力を比較できます。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner を使用した shellcode の debugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner) は **shellcode** を allocate し、その **memory address** を表示して execution を pause します。\
IDA や x64dbg などの debugger を attach し、表示された address に breakpoint を設定して execution を resume すると、shellcode を debugging できます。

releases github page には、compiled releases を含む zip があります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下の link には、少し変更された Blobrunner の version があります。compile するには、**Visual Studio Code で C/C++ project を作成し、code を copy and paste して build する**だけです。

{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it を使用した shellcode の debugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) は BlobRunner に似ています。shellcode を allocate して infinite loop に入ります。debugger を attach し、**2～5 秒間** resume した後、その loop 内で pause し、execution を allocate された shellcode に transfer する次の call まで step します。

![allocate された shellcode への call の直前に jmp2it の infinite loop で pause している debugger](<../../images/image (509).png>)

compiled version の [jmp2it は releases page から download できます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutter を使用した shellcode の debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) は radare の GUI です。Cutter を使用すると、shellcode を emulate して動的に inspect できます。

Cutter では "Open File" と "Open Shellcode" を選択できることに注意してください。私の場合、shellcode を file として開くと正しく decompile されましたが、shellcode として開くと正しく decompile されませんでした。

![同じ bytes を file として開いた場合と shellcode として開いた場合の異なる analysis 結果を表示する Cutter](<../../images/image (562).png>)

指定した場所から emulation を開始するには、そこに bp を設定します。すると、Cutter はその場所から自動的に emulation を開始するようです。

![Cutter の emulation を開始する前に、目的の shellcode entry に breakpoint を設定](<../../images/image (589).png>)

![選択した shellcode breakpoint で pause している Cutter emulator](<../../images/image (387).png>)

例えば、hex dump 内で stack を確認できます。

![Cutter の hex dump で emulate された shellcode の stack を表示](<../../images/image (186).png>)

### shellcode の deobfuscating と実行された function の取得

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試してください。\
shellcode が **どの function** を使用しているか、また shellcode が memory 内で自身を **decoding** しているかなどを確認できます。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg には、必要なオプションを選択して shellcode を実行できる graphical launcher もあります。

![shellcode のエミュレーションおよび tracing オプションを選択する scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** オプションを使用すると、メモリ上で shellcode に動的な変更が加えられた場合に、最終的な shellcode を dump できます（decode された shellcode のダウンロードに便利です）。**start offset** は、特定の offset から shellcode を開始する場合に便利です。**Debug Shell** オプションを使用すると、scDbg terminal で shellcode を debug できます（ただし、この用途では前述したオプションのほうが便利だと思います。IDA や x64dbg を使用できるためです）。

### CyberChef を使用した disassembling

shellcode ファイルを input として upload し、次の recipe を使用して decompile します：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation は、arithmetic（`+`、`-`、`*`）と bitwise operators（`&`、`|`、`^`、`~`、shift）を組み合わせた formula によって、`x + y` のような単純な expression を隠します。重要なのは、これらの identity が通常、**fixed-width modular arithmetic** の下でのみ正しくなるという点です。そのため、carry と overflow が重要になります。
```c
(x ^ y) + 2 * (x & y) == x + y
```
この種の式を generic algebra tooling で簡略化すると、bit-width のセマンティクスが無視されるため、簡単に誤った結果を得る可能性があります。<sup>[[1]](#references)</sup>

### Practical workflow

1. **元の bit-width を維持する**：lifted code/IR/decompiler の出力にある値（`8/16/32/64` bits）。
2. 簡略化を試す前に、**式を分類する**：
- **Linear**：bitwise atom の weighted sum
- **Semilinear**：`x & 0xFF` のような constant mask を含む linear
- **Polynomial**：products が現れる
- **Mixed**：products と bitwise logic が interleave され、多くの場合 repeated subexpressions を含む
3. random testing または SMT proof によって、**すべての candidate rewrite を検証する**。equivalence を証明できない場合は、推測で変更せず元の式を維持する。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis および protected-binary reversing 向けの実用的な MBA simplifier です。式を分類し、すべてに対して1つの generic rewrite pass を適用するのではなく、specialized pipeline に振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA は Boolean inputs 上で式を評価して signature を導出し、pattern matching、ANF conversion、coefficient interpolation など複数の recovery methods を競合させます。
- **Semilinear MBA**: constant-masked atoms は bit-partitioned reconstruction によって再構築されるため、masked regions が正しく維持されます。
- **Polynomial/Mixed MBA**: products は cores に分解され、simplifying the outer relation の前に、繰り返し現れる subexpressions を temporaries に切り出せます。

一般的に復元を試す価値のある mixed identity の例:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
以下のように簡略化できます：
```c
x * y
```
### リバースエンジニアリングのメモ

- 正確な計算を分離した後、**lifted IR expressions** または decompiler の出力に対して CoBRA を実行することを推奨します。
- 式が masked arithmetic または narrow registers に由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な証明ステップが必要な場合は、こちらのローカルな Z3 notes を確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin**（`libCobraPass.so`）としても提供されており、後続の analysis passes の前に MBA-heavy LLVM IR を normalize したい場合に便利です。
- Unsupported carry-sensitive mixed-domain residuals は、元の式を維持し、carry path を手動で推論し続けるべきであることを示すシグナルとして扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの operations を `mov` ベースの instruction sequences に置き換え、signal/exception handling を使用して control flow を変更します。詳細:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応している binaries については、[demovfuscator](https://github.com/kirschju/demovfuscator) で結果を deobfuscate できます。いくつかの dependencies が必要です。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTFをプレイしている場合、**[この workaround で flag を見つけられる](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)可能性があります。

## Rust

**entry point**を見つけるには、次のように `::main` で関数を検索します。

![Ghidraで関数名をダブルコロン付きのmainで検索してRustのentry pointを見つける](<../../images/image (1080).png>)

この場合、binaryの名前は authenticator だったため、これが興味深い main function であることはかなり明白です。\
呼び出されている**関数**の**名前**を使って、**inputs**と**outputs**について知るために**Internet**で検索します。

### ELF firmwareからRust stringsを復元する

**Rust ELF** binariesでは、多くのstatic stringsがC-styleのNUL-terminated pointersとして参照されていません。一般的な `rustc` layoutでは、実際のstring blobが格納された **`.rodata`** を指す **pointer/length tuple** が **`.data.rel.ro`** 内に存在します。
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
これは、`strings` または Ghidra のデフォルト解析によって、隣接する文字列が結合されたり、cross-references が完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

簡単なワークフロー:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** の仮想アドレスとサイズを取得する。
2. **`.data.rel.ro`** を 1 ワードずつ列挙する。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱う。
4. 次のワードを、候補の長さとして扱う。
5. サニティフィルターを適用する（例: 長さが **4** ～ **100** バイトのものを保持する）。
6. `0x00` までスキャンするのではなく、`.rodata` から正確に `length` バイトを読み取る。

最小限の抽出ロジック:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
これは、復元された Rust strings から **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth-related logic** が明らかになることが多いため、firmware reversing で特に役立ちます。

Ghidra がこれらの strings を見落とす場合は、同じ heuristic を適用し、参照された `.rodata` offsets に string data を作成する custom script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` ツールは、このアイデアを他の **word sizes、endianness、section layouts** に適用する際の優れた参考資料です。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries には [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi binary を reverse する必要がある場合は、IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をお勧めします。

IDA で **Alt+F7** を押して Python plugin を load し、plugin file を選択します。

この plugin は binary を実行し、debugging の開始時に function names を動的に解決します。debugging を開始した後、もう一度 Start button（green one または f9）を押すと、real code の先頭で breakpoint が hit します。

graphical application で button を押すと、debugger はその button によって invoke された function で停止できます。

## Golang

Golang binary を reverse する必要がある場合は、IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をお勧めします。

IDA で **Alt+F7** を押して Python plugin を load し、plugin file を選択します。

これにより function names が解決されます。

## Compiled Python

このページでは、ELF/EXE の compiled Python binary から python code を取得する方法を確認できます:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA game の **binary** を入手した場合は、さまざまな tools を使用して **emulate** および **debug** できます:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - interface を備えた debugger
- [**mgba** ](https://mgba.io)- CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **buttons** の押し方を確認できます。

![Game Boy Advance の button mappings を示す no$gba controls configuration](<../../images/image (581).png>)

押すと、各 **key has a value** で識別できます:
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
この種のプログラムでは、興味深い部分は**プログラムがユーザー入力をどのように扱うか**です。アドレス **0x4000130** には、一般的に見られる関数 **KEYINPUT** があります。

![アドレス 0x4000130 の KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像から、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

この関数では、いくつかの初期化処理（重要ではありません）の後に:
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
このコードが見つかりました。
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
最後の if は、**`uVar4`** が **last Keys** に含まれており、現在のキーではないことを確認しています。これは、ボタンを離すこととも呼ばれます（現在のキーは **`uVar1`** に保存されています）。
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

- まず、**値 4**（**SELECT** ボタン）と比較されます。この challenge では、このボタンによって画面がクリアされます
- 次に、値を **8**（**START** ボタン）と比較します。この challenge では、このパスで入力されたコードが有効かどうかを確認します。
- この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が同じ場合は一部のコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
カウンターが 8 未満である間、押されたキーの値が `DAT_030000d8` に累積されます。

したがって、この challenge ではボタンの値がわかっていれば、**長さが 8 未満で、加算結果が 0xf3 になる組み合わせを押す必要がありました。**

**このチュートリアルの Reference:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA による MBA obfuscation の簡略化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings の decoding - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (アーカイブ)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
