# Reversing ツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGui ベースの Reversing ツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) を使用して、wasm（バイナリ）から wat（テキスト）へ **decompile** できます
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) を使用して、wat から wasm へ **compile** できます
- [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) を使用して decompile することもできます

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek は、**ライブラリ**（.dll）、**Windows メタデータファイル**（.winmd）、**実行ファイル**（.exe）など、複数の形式を **decompile して調査**する decompiler です。decompile した後、アセンブリを Visual Studio プロジェクト（.csproj）として保存できます。

ここでの利点は、失われたソースコードをレガシーアセンブリから復元する必要がある場合に、この作業によって時間を節約できることです。さらに、dotPeek は decompile されたコード内を便利に移動できるため、**Xamarin のアルゴリズム解析**に最適なツールのひとつです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的な add-in model と、ツールを正確なニーズに合わせて拡張できる API により、.NET Reflector は時間を節約し、開発を簡素化します。このツールが提供する数多くの reverse engineering サービスを見てみましょう。

- ライブラリまたはコンポーネント内でデータがどのように流れるかを把握できます
- .NET 言語および framework の実装と使用方法を把握できます
- 使用中の API やテクノロジーをさらに活用するため、ドキュメント化されていない、公開されていない機能を見つけられます
- 依存関係と異なるアセンブリを見つけられます
- コード、third-party コンポーネント、ライブラリ内のエラーの正確な場所を追跡できます
- 使用しているすべての .NET コードの source に対して debug できます

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code 用 ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): 任意の OS で使用できます（VSCode から直接インストールできるため、git をダウンロードする必要はありません。**Extensions** をクリックして **ILSpy** を検索してください）。\
**decompile**、**modify**、さらに再度 **recompile** する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases) または現在も保守されている fork である [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) を使用できます。（関数内を変更するには **Right Click -> Modify Method** を使用します）。

### DNSpy Logging

**DNSpy にファイル内の情報を log させる**には、次の snippet を使用できます。
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
そして **compile** をクリックします：

![DNSpy Logging - DNSpy Debugging: compile をクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します：

![DNSpy Logging - DNSpy Debugging: File Save module から新しいファイルを保存](<../../images/image (602).png>)

これは、これを行わないと **runtime** にコードへ複数の **optimisations** が適用され、デバッグ中に **ブレークポイントがヒットしない**、または一部の **変数が存在しない** 可能性があるため必要です。

次に、.NET アプリケーションが **IIS** によって **実行** されている場合は、次の方法で **再起動** できます：
```
iisreset /noforce
```
Then, debuggingを開始するには、開いているすべてのファイルを閉じ、**Debug Tab** 内で **Attach to Process...** を選択します:

![DNSpy Logging - DNSpy Debugging: その後、debuggingを開始するには、開いているすべてのファイルを閉じ、Debug Tab 内で Attach to Process を選択します](<../../images/image (318).png>)

次に、**IIS server** にattachするため **w3wp.exe** を選択し、**attach** をクリックします:

![DNSpy Logging - DNSpy Debugging: 次に、IIS server にattachするため w3wp.exe を選択し、attach をクリックします](<../../images/image (113).png>)

これでprocessをdebuggingしているので、processを停止してすべてのmoduleをloadします。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします:

![DNSpy Logging - DNSpy Debugging: これでprocessをdebuggingしているので、processを停止してすべてのmoduleをloadします。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: これでprocessをdebuggingしているので、processを停止してすべてのmoduleをloadします。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意のmoduleをクリックし、**Open All Modules** を選択します:

![DNSpy Logging - DNSpy Debugging: Modules 内の任意のmoduleをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のmoduleを右クリックし、**Sort Assemblies** をクリックします:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のmoduleを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs のdebugging

### IDA の使用

- **rundll32 をload** (64bits版は C:\Windows\System32\rundll32.exe、32bits版は C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debuggerを選択
- "**Suspend on library load/unload**" を選択

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択](<../../images/image (868).png>)

- **parameters** of the executionを設定し、**path to the DLL** と呼び出したいfunctionを指定します:

![Debugging DLLs - Using IDA: executionのparametersを設定し、DLLへのpathと呼び出したいfunctionを指定します](<../../images/image (704).png>)

debuggingを開始すると、**各DLLがloadされるたびにexecutionが停止**します。そのため、rundll32がDLLをloadするとexecutionが停止します。

しかし、loadされたDLLのcodeにはどうやって到達できるのでしょうか? この方法でそれを実現する方法はわかりません。

### x64dbg/x32dbg の使用

- **rundll32 をload** (64bits版は C:\Windows\System32\rundll32.exe、32bits版は C:\Windows\SysWOW64\rundll32.exe)
- **Command Line を変更** ( _File --> Change Command Line_ ) し、dllのpathと呼び出したいfunctionを設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- その後、**executionを開始**します。debuggerは各dll mainで停止し、しばらくすると**対象DLLのdll Entryで停止**します。そこから、breakpointを設定したい箇所を探すだけです。

win64dbgで何らかの理由によりexecutionが停止した場合、**win64dbg windowの上部**を見ると、**どのcodeにいるか**を確認できます:

![Using IDA - Using x64dbg/x32dbg: win64dbgで何らかの理由によりexecutionが停止した場合、win64dbg windowの上部を見ると、どのcodeにいるかを確認できます](<../../images/image (842).png>)

これを見ると、debugしたいdllでexecutionが停止したタイミングを確認できます。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のgameのmemory内で重要なvalueが保存されている場所を見つけ、それらを変更するための便利なprogramです。詳細については:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、GNU Project Debugger (GDB) 用のfront-end/reverse engineering toolで、gameに重点を置いています。ただし、reverse-engineeringに関連するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数のdecompiler用のweb front-endです。このweb serviceでは、小さなexecutableに対する異なるdecompilerのoutputを比較できます。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerを使用したshellcodeのdebugging

[**Blobrunner**](https://github.com/OALabs/BlobRunner) は、memory領域内に**shellcodeをallocate**し、shellcodeがallocateされた**memory addressを通知**してから、executionを**停止**します。\
次に、processに**debuggerをattach**し (Idaまたはx64dbg)、通知されたmemory addressに**breakpointを設定**して、executionを**resume**します。これによりshellcodeをdebuggingできます。

releases github pageには、compiled releasesを含むzipがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
次のlinkには、少し変更されたBlobrunnerのversionがあります。compileするには、**Visual Studio CodeでC/C++ projectを作成し、codeをcopy and pasteしてbuild**するだけです。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itを使用したshellcodeのdebugging

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) はblobrunnerと非常によく似ています。memory領域内に**shellcodeをallocate**し、**eternal loop**を開始します。次にprocessに**debuggerをattach**し、**play start、2～5秒待ってからstopを押す**と、**eternal loop** 内にいることが確認できます。eternal loopの次のinstructionへjumpすると、それがshellcodeへのcallになっているため、最終的にshellcodeを実行している状態になります。

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it はblobrunnerと非常によく似ています。memory領域内にshellcodeをallocateし、...](<../../images/image (509).png>)

compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/) をdownloadできます。

### Cutterを使用したshellcodeのdebugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) はradareのGUIです。Cutterを使用すると、shellcodeをemulateして動的に調査できます。

Cutterでは "Open File" と "Open Shellcode" を使用できることに注意してください。私の場合、shellcodeをfileとして開くと正しくdecompileされましたが、shellcodeとして開くと正しくdecompileされませんでした:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Cutterでは "Open File" と "Open Shellcode" を使用できます。私の場合、shellcodeをfileとして開くと...](<../../images/image (562).png>)

指定した場所からemulationを開始するには、そこにbpを設定します。すると、Cutterがそこから自動的にemulationを開始するようです:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: 指定した場所からemulationを開始するには、そこにbpを設定します。すると、Cutterがそこから自動的にemulationを開始するようです](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: 指定した場所からemulationを開始するには、そこにbpを設定します。すると、Cutterがそこから自動的にemulationを開始するようです](<../../images/image (387).png>)

例えば、hex dump内でstackを確認できます:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: 例えば、hex dump内でstackを確認できます](<../../images/image (186).png>)

### shellcodeをDeobfuscatingして実行されたfunctionsを取得する

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試してください。\
shellcodeが使用している**functions**や、shellcodeがmemory内で自身を**decoding**しているかどうかなどを確認できます。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg には、必要なオプションを選択して shellcode を実行できる graphical launcher もあります

![Cutter を使用した shellcode の Debugging - shellcode の Deobfuscating と実行された functions の取得: scDbg には、必要なオプションを選択して shellcode を実行できる graphical launcher もあります](<../../images/image (258).png>)

**Create Dump** オプションを使用すると、shellcode がメモリ上で動的に変更された場合に、最終的な shellcode を dump できます（decoded shellcode のダウンロードに便利です）。**start offset** は、特定の offset から shellcode を開始する場合に便利です。**Debug Shell** オプションを使用すると、scDbg の terminal で shellcode を debug できます（ただし、この目的では前述したいずれかのオプションの方が優れていると思います。Ida や x64dbg を使用できるためです）。

### CyberChef を使用した Disassembling

shellcode ファイルを input として upload し、以下の recipe を使用して decompile します: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation の deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation は、arithmetic (`+`, `-`, `*`) と bitwise operators (`&`, `|`, `^`, `~`, shifts) を組み合わせた formula によって、`x + y` のような単純な expression を隠します。重要なのは、これらの identity が通常、**fixed-width modular arithmetic** の下でのみ正しいという点です。そのため、carry と overflow が重要になります:
```c
(x ^ y) + 2 * (x & y) == x + y
```
この種の式を generic algebra tooling で簡略化すると、bit-width のセマンティクスが無視されるため、簡単に誤った結果を得てしまいます。

### Practical workflow

1. **元の bit-width を維持する**。lifted code/IR/decompiler output から取得した `8/16/32/64` ビットを使用します。
2. **簡略化を試みる前に式を分類する**。
- **Linear**: bitwise atom の加重和
- **Semilinear**: `x & 0xFF` のような constant mask を含む linear
- **Polynomial**: 積が含まれる
- **Mixed**: 積と bitwise logic が交互に現れ、多くの場合 repeated subexpression を含む
3. **すべての候補 rewrite を random testing または SMT proof で検証する**。等価性を証明できない場合は、推測で書き換えず元の式を維持します。

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis と protected-binary reversing のための実用的な MBA simplifier です。式を分類し、すべてに対して1つの generic rewrite pass を適用するのではなく、specialized pipeline に振り分けます。<sup>[[1]](#references)[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA は Boolean inputs 上で式を評価し、signature を導出してから、pattern matching、ANF conversion、coefficient interpolation など複数の recovery methods を競合させます。
- **Semilinear MBA**: constant-masked atoms は bit-partitioned reconstruction によって再構築されるため、masked regions も正しく維持されます。
- **Polynomial/Mixed MBA**: products は cores に分解され、simplifying the outer relation の前に、repeated subexpressions を temporaries に持ち上げることができます。

よく recovery を試す価値がある mixed identity の例:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
これは次のように簡略化できます:
```c
x * y
```
### Reversing notes

- **lifted IR expressions** または decompiler の出力に対して CoBRA を実行することを優先してください。実行前に、正確な computation を分離しておきます。
- 式が masked arithmetic または narrow registers に由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な proof step が必要な場合は、こちらのローカルな Z3 notes を確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続の analysis passes の前に MBA-heavy LLVM IR を normalize したい場合に便利です。
- Unsupported carry-sensitive mixed-domain residuals は、元の式を保持し、carry path を手動で推論し続けるべきことを示す signal として扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は **すべての `mov` 命令を変更します**（本当にすごいです）。また、interruptions を使用して execution flows を変更します。仕組みの詳細については、以下を参照してください:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

運が良ければ、[demovfuscator](https://github.com/kirschju/demovfuscator) が binary を deobfuscate してくれます。いくつかの dependencies があります。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF をプレイしている場合、この **flag を見つけるための workaround** は非常に役立つ可能性があります: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** を見つけるには、次のように `::main` で functions を検索します:

![Movfuscator - Rust: ::main で functions を検索して entry point を見つける](<../../images/image (1080).png>)

この場合、binary の名前は authenticator だったため、これが興味深い main function であることは明らかです。\
呼び出されている **functions** の **name** を使って **Internet** で検索し、それらの **inputs** と **outputs** について学びましょう。

### ELF firmware から Rust strings を復元する

**Rust ELF** binaries では、多くの static strings が C-style の NUL-terminated pointers として参照されていません。一般的な `rustc` の layout では、実際の string blob が格納されている **`.rodata`** を指す **pointer/length tuple** が **`.data.rel.ro`** 内にあります:<sup>[[3]](#references)</sup>
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
これは、`strings` または Ghidra のデフォルト解析によって、隣接する文字列が結合されたり、cross-references が完全に見落とされたりする可能性があることを意味します。

簡単なワークフロー:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** の virtual address と size を取得する。
2. **`.data.rel.ro`** を 1 word ずつ列挙する。
3. `.rodata` の address range 内にある値を、candidate string pointer として扱う。
4. 次の word を candidate length として扱う。
5. sanity filters を適用する（例: **4**〜**100** bytes の length のみ保持する）。
6. `0x00` まで scan する代わりに、`.rodata` から正確に `length` bytes を読み取る。

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
これは、復元された Rust の文字列から **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth-related logic** が明らかになることが多いため、firmware reversing で特に役立ちます。

Ghidra がこれらの文字列を見逃す場合は、同じ heuristic を適用し、参照先の `.rodata` offsets に string data を作成する custom script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` tools は、このアイデアを他の **word sizes、endianness、section layouts** に適応するための優れた参考資料です。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries には [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi binary を reverse する必要がある場合は、IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をおすすめします。

**ATL+f7**（IDA に python plugin を import）を押して、python plugin を選択します。

この plugin は binary を実行し、debugging の開始時に function names を動的に resolve します。debugging を開始した後、もう一度 Start button（緑色のもの、または f9）を押すと、real code の先頭で breakpoint に到達します。

また、graphic application で button を押すと、debugger がその button によって実行された function で停止するため、非常に興味深い機能です。

## Golang

Golang binary を reverse する必要がある場合は、IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をおすすめします。

**ATL+f7**（IDA に python plugin を import）を押して、python plugin を選択します。

これにより function names が resolve されます。

## Compiled Python

このページでは、ELF/EXE python compiled binary から python code を取得する方法を確認できます。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

GBA game の **binary** を取得した場合、さまざまな tools を使用して **emulate** および **debug** できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - interface を備えた debugger
- [**mgba** ](https://mgba.io)- CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **buttons** の押し方を確認できます。

![Game Boy Advance の button mappings を示す no$gba controls configuration](<../../images/image (581).png>)

押すと、各 **key には値が設定され**、識別に使用されます。
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
したがって、この種類のプログラムでは、重要なのは**プログラムがユーザー入力をどのように処理するか**です。アドレス **0x4000130** には、よく見られる関数 **KEYINPUT** があります。

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

前の画像から、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

この関数では、いくつかの init 操作（重要ではありません）の後に、次の処理が行われます。
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
以下のコードが見つかりました:
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
最後の if は、**`uVar4`** が **last Keys** に含まれており、現在のキーではないことを確認しています。これはボタンを離した状態とも呼ばれます（現在のキーは **`uVar1`** に格納されています）。
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

- まず、**値 4**（**SELECT** ボタン）と比較されます。この challenge では、このボタンによって画面がクリアされます。
- 次に、**値 8**（**START** ボタン）と比較されます。この challenge では、コードが有効かどうかを確認して flag を取得します。
- この場合、変数 **`DAT_030000d8`** は 0xf3 と比較され、値が同じ場合は一部のコードが実行されます。
- それ以外の場合は、別の cont（**`DAT_030000d4`**）がチェックされます。コードの入力直後に 1 が加算されるため、これは cont です。\
**I**f 8 未満の場合、**`DAT_030000d8`** に値を**加算**する処理が行われます（基本的には、cont が 8 未満である限り、押されたキーの値がこの変数に加算されます）。

したがって、この challenge ではボタンの値がわかっているため、**長さが 8 未満で、加算結果が 0xf3 になる組み合わせを入力する必要がありました。**<sup>[[6]](#references)</sup>

**このチュートリアルの Reference:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## ゲームボーイ


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリ難読化解除）

## 参考文献

- [1] [CoBRA による MBA obfuscation の簡略化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
