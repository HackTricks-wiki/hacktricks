# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) を使用して、wasm（バイナリ）から wat（プレーンテキスト）へ**decompile**します
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) を使用して、wat から wasm へ**compile**します
- decompilation には [web-wasmdec](https://wwwg.github.io/web-wasmdec/) も試すことができます。

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek は、**ライブラリ**（.dll）、**Windows metadata file**（.winmd）、**実行ファイル**（.exe）など、複数の形式を**decompileして調査する**decompilerです。decompile後は、assembly を Visual Studio project（.csproj）として保存できます。

ここでの利点は、失われたソースコードを legacy assembly から復元する必要がある場合に、この作業によって時間を節約できることです。さらに、dotPeek は decompiled code 内を便利に移動できるため、**Xamarin algorithm analysis**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的な add-in model と、ツールを正確なニーズに合わせて拡張できる API により、.NET Reflector は時間を節約し、開発を簡略化します。このツールが提供する豊富な reverse engineering サービスを見てみましょう。

- library または component 内で data がどのように flow するかを把握できます
- .NET languages および frameworks の実装と使用方法を把握できます
- 使用している APIs および technologies をさらに活用するため、document化されていない、または公開されていない functionality を見つけます。
- dependencies と異なる assemblies を見つけます
- code、third-party components、libraries 内の errors の正確な位置を追跡します。
- 使用しているすべての .NET code の source に対して debug できます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code 用 ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode)：任意の OS で使用できます（VSCode から直接 install できます。git を download する必要はありません。**Extensions**をクリックし、**ILSpy を検索**してください）。\
**decompile**、**modify**、そして再度**recompile**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases) または actively maintained な fork である [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) を使用できます。（function 内の何かを変更するには、**Right Click -> Modify Method** を使用します）。

### DNSpy Logging

**DNSpy に file へ情報を log 出力させる**には、次の snippet を使用できます。
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

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
そして **compile** をクリックします。

![DNSpy Logging - DNSpy Debugging: compile をクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: File Save module から新しいファイルを保存](<../../images/image (602).png>)

これは必要な手順です。実行しない場合、**runtime** でコードに複数の **optimisations** が適用され、デバッグ中に **break-point が一度もヒットしない**、または一部の **variables が存在しない** 可能性があります。

次に、.NET アプリケーションが **IIS** によって **run** されている場合は、次のコマンドで **restart** できます。
```
iisreset /noforce
```
Then、デバッグを開始するには、開いているすべてのファイルを閉じ、**Debug Tab** 内で **Attach to Process...** を選択します：

![DNSpy Logging - DNSpy Debugging: デバッグを開始するには、開いているすべてのファイルを閉じ、Debug Tab 内で Attach to Process を選択します](<../../images/image (318).png>)

次に **w3wp.exe** を選択して **IIS server** にアタッチし、**attach** をクリックします：

![DNSpy Logging - DNSpy Debugging: w3wp.exe を選択して IIS server にアタッチし、attach をクリックします](<../../images/image (113).png>)

プロセスをデバッグしているので、次はプロセスを停止してすべてのモジュールをロードします。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします：

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしているので、プロセスを停止してすべてのモジュールをロードします。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしているので、プロセスを停止してすべてのモジュールをロードします。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意のモジュールをクリックし、**Open All Modules** を選択します：

![DNSpy Logging - DNSpy Debugging: Modules 内の任意のモジュールをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のモジュールを右クリックし、**Sort Assemblies** をクリックします：

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のモジュールを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Javaデコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのデバッグ

### IDAを使用する

- **rundll32をロード**（64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debugger を選択します
- "**Suspend on library load/unload**" を選択します

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択します](<../../images/image (868).png>)

- 実行の **parameters** を設定し、**path to the DLL** と呼び出したい関数を指定します：

![Debugging DLLs - Using IDA: path to the DLL と呼び出したい関数を指定して実行の parameters を設定します](<../../images/image (704).png>)

その後、デバッグを開始すると、**各 DLL がロードされるたびに実行が停止します**。つまり、rundll32 が DLL をロードすると、実行が停止します。

この方法では module-load events で停止しますが、ロードされた DLL の entry point に到達する操作は、以下の x64dbg workflow より直接的ではありません。

### x64dbg/x32dbgを使用する

- **rundll32をロード**（64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe）
- **Command Line を変更**（ _File --> Change Command Line_ ）し、dll の path と呼び出したい関数を設定します。例："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- 次に **実行を開始** すると、debugger は各 dll main で停止します。そのうち **対象 DLL の dll Entry で停止します**。そこから、breakpoint を設定したい箇所を探します。

win64dbg では、何らかの理由で実行が停止したとき、**win64dbg window の上部**を見ることで、**どの code にいるか**確認できることに注意してください：

![Using IDA - Using x64dbg/x32dbg: 何らかの理由で実行が停止したとき、win64dbg window の上部を見ることで、どの code にいるか確認できます](<../../images/image (842).png>)

この indicator により、デバッグ対象の DLL 内で実行が停止したことを確認できます。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中の game の memory 内で重要な値が保存されている場所を見つけ、それらを変更するための便利な program です。詳細情報:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、games に重点を置いた GNU Project Debugger (GDB) 用の front-end/reverse engineering tool です。ただし、reverse-engineering に関連するあらゆる用途に使用できます

[**Decompiler Explorer**](https://dogbolt.org/) は、複数の decompiler 用の web front-end です。この web service を使用すると、小さな executable に対する異なる decompiler の output を比較できます。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerでshellcodeをデバッグする

[**BlobRunner**](https://github.com/OALabs/BlobRunner) は **shellcode** を allocate し、その **memory address** を表示して、実行を pause します。\
IDA や x64dbg などの debugger をアタッチし、表示された address に breakpoint を設定して実行を再開すると、shellcode をデバッグできます。

releases github page には、compiled releases を含む zip があります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
次の link には、わずかに変更された Blobrunner の version があります。compile するには、**Visual Studio Code で C/C++ project を作成し、code を copy and paste して build するだけです**。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itでshellcodeをデバッグする

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) は BlobRunner に似ています。shellcode を allocate して infinite loop に入ります。debugger をアタッチし、**2–5 seconds** 実行を再開して、その loop 内で pause し、allocate された shellcode に execution を transfer する次の call まで step します。

![Debugger paused in jmp2it's infinite loop immediately before the call to the allocated shellcode](<../../images/image (509).png>)

compiled version の [jmp2it は releases page からダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使用してshellcodeをデバッグする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) は radare の GUI です。Cutter を使用すると shellcode を emulate し、動的に inspect できます。

Cutter では "Open File" と "Open Shellcode" を使用できることに注意してください。私の場合、shellcode を file として開くと正しく decompile されましたが、shellcode として開くと正しく処理されませんでした：

![Cutter showing different analysis results when opening the same bytes as a file or as shellcode](<../../images/image (562).png>)

指定した場所から emulation を開始するには、そこに bp を設定します。すると Cutter はそこから自動的に emulation を開始するようです：

![Setting a breakpoint at the desired shellcode entry before starting Cutter emulation](<../../images/image (589).png>)

![Cutter emulator paused at the selected shellcode breakpoint](<../../images/image (387).png>)

例えば、hex dump 内で stack を確認できます：

![Viewing the emulated shellcode stack in Cutter's hex dump](<../../images/image (186).png>)

### shellcodeをdeobfuscateして実行されたfunctionを取得する

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試してください。\
shellcode が使用している **functions** や、shellcode が memory 内で自身を **decoding** しているかどうかなどを確認できます。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbgには、必要なオプションを選択してshellcodeを実行できる graphical launcher も用意されています。

![shellcodeのエミュレーションおよびトレースオプションを選択するためのscDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** オプションを使用すると、メモリ上でshellcodeに動的な変更が加えられた場合に、最終的なshellcodeをダンプできます（デコードされたshellcodeのダウンロードに便利です）。**start offset** は、特定のoffsetからshellcodeを開始する場合に便利です。**Debug Shell** オプションを使用すると、scDbg terminalでshellcodeをデバッグできます（ただし、この用途では、前述したオプションのいずれかを使用する方が便利です。Idaやx64dbgを使用できるためです）。

### CyberChefを使用したDisassembling

shellcodeファイルをinputとしてアップロードし、次のrecipeを使用してdecompileします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationのdeobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、arithmetic（`+`、`-`、`*`）とbitwise operators（`&`、`|`、`^`、`~`、shift）を組み合わせたformulaによって、`x + y`のような単純なexpressionを隠します。重要なのは、これらのidentityが通常、**fixed-width modular arithmetic**の下でのみ正しいという点です。そのため、carryとoverflowが重要になります:
```c
(x ^ y) + 2 * (x & y) == x + y
```
この種の式を汎用的な代数ツールで簡略化すると、bit-width の意味論が無視されるため、簡単に誤った結果になります。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトされたコード/IR/decompiler の出力から、元の bit-width（`8/16/32/64` bits）を**維持する**。
2. 簡略化を試みる前に、式を**分類する**:
- **Linear**: bitwise atom の加重和
- **Semilinear**: `x & 0xFF` のような定数マスクを含む linear
- **Polynomial**: 積が含まれる
- **Mixed**: 積と bitwise logic が交互に現れ、同じ部分式が繰り返されることが多い
3. すべての候補となる書き換えを、random testing または SMT proof で**検証する**。等価性を証明できない場合は、推測で変更せず、元の式を維持する。

### narrow execution slice で control-flow flattening をバイパスする

完全な control-flow graph の復元は、多くの場合不要です。control-flow flattening、opaque predicates、大規模な dispatcher、または MBA-heavy code がある場合は、encrypted blobs と output buffers から参照をたどり、それらを変換する最小の routine まで追跡します。その後、その data-flow slice だけを再現するか、独立して実行します。関連する state を直接初期化できるなら、dispatcher は必要な solution の一部ではありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです:<sup>[[7]](#references)</sup>

1. executable および data sections、relocations、cross-references を一覧化する。`.rodata` から候補となる table を、byte order と element width を維持したまま dump する。
2. plaintext または output buffer に最後に書き込む routine を特定する。その inputs、参照する tables、imported calls、必要な global state を記録する。
3. それらの operations だけを fixed-width Python model に lift する。その slice が依然として過剰な state に依存する場合は、プログラム全体を emulating する代わりに、Unicorn、QEMU、または debugger の下で routine を呼び出し、無関係な imports を hook する。
4. extractor が実際に supplied binary から output を導出していることを検証する。silent fallbacks を削除し、embedded answers を検索し、strings、keys、identifiers、layouts、obfuscation seeds を変更した未確認の builds に対して実行する。

first-pass で役立つ commands は次のとおりです:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### 偽装された定数であるMBA式を検出する

一見すると入力に依存しているバイト式でも、入力が完全に相殺されることがあります。テーブルを抽出した後、8ビットの全領域にわたって式を評価します。出力集合が単一要素であれば、周囲のステートマシンを復元しなくても、そのバイトが定数であることを証明できます。<sup>[[7]](#references)</sup>
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
最終的なマスクは保持してください。元の加算にはバイト幅のラップアラウンドがあるためです。より広い領域では、同じ幅の2つのsymbolic inputに対して `f(x1) != f(x2)` が充足可能かどうかをSMT solverに問い合わせます。`unsat` なら不変性が証明され、`sat` なら反例が提供されるため、そのinputを破棄できないことを意味します。<sup>[[7]](#references)</sup>

#### environment-bound decodingを認識する

Anti-analysisチェックは、分岐やクラッシュを伴う必要はありません。decoderは、sensorの結果をkey bit、opaque-predicate constant、またはflattened-dispatcher stateに混ぜ込み、正常に処理を続け、emulator内で妥当そうに見えるが誤ったplaintextを生成できます。したがって、目に見えるfailure branchだけをpatchするのでは不十分です。environment probeからdecoder stateへのdata dependencyをtraceし、authentic deviceとemulatorで同じsliceを比較し、各sensor resultを強制したときに最終bufferがどのように変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)は、malware analysisおよびprotected-binary reversing向けの実用的なMBA simplifierです。expressionを分類し、すべてに対して1つのgeneric rewrite passを適用するのではなく、specialized pipelineに振り分けます。<sup>[[2]](#references)</sup>

簡単な使い方:
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

- **Linear MBA**: CoBRA は Boolean inputs 上で expression を評価して signature を導出し、pattern matching、ANF conversion、coefficient interpolation など複数の recovery methods を競合させます。
- **Semilinear MBA**: constant-masked atoms は bit-partitioned reconstruction によって再構築されるため、masked regions は正確な状態に保たれます。
- **Polynomial/Mixed MBA**: products は cores に分解され、simplifying the outer relation の前に、repeated subexpressions を temporaries に lift できます。

一般的に recovery を試す価値がある mixed identity の例:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
これは次のように簡略化できます:
```c
x * y
```
### Reversing notes

- 正確な計算を切り分けた後、**lifted IR expressions** または decompiler の出力に対して CoBRA を実行することを推奨します。
- 式が masked arithmetic または narrow registers に由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な proof step が必要な場合は、こちらのローカルな Z3 notes を確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続の analysis passes の前に MBA-heavy な LLVM IR を normalize したい場合に便利です。
- Unsupported carry-sensitive mixed-domain residuals は、元の式を保持し、carry path を手動で推論し続けるべきであることを示す signal として扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの operation を `mov` ベースの instruction sequences に置き換え、signal/exception handling を使用して control flow を変更します。詳細:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応している binaries では、[demovfuscator](https://github.com/kirschju/demovfuscator) によって結果を deobfuscate できます。いくつかの dependencies があります。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして [keystoneをinstall](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTFをプレイしている場合、**この**flagを見つけるためのworkaround**が非常に役立つ可能性があります：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**を見つけるには、次のように`::main`で関数を検索します：

![Ghidraで関数名をダブルコロンのmainで検索してRustのentry pointを見つける](<../../images/image (1080).png>)

この場合、binaryの名前はauthenticatorだったため、これが調査対象のmain関数であることはかなり明らかです。\
呼び出されている**関数**の**name**がわかったら、**Internet**で検索してそれらの**inputs**と**outputs**について学習します。

### ELF firmwareからRust stringsを復元する

**Rust ELF** binariesでは、多くのstatic stringsがC-styleのNUL-terminated pointersとして参照されていません。一般的な`rustc`のlayoutでは、実際のstring blobを格納している**`.rodata`**を指す**pointer/length tuple**が**`.data.rel.ro`**内に存在します：
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
これは、`strings` や Ghidra のデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

簡単なワークフロー:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** の仮想アドレスとサイズを取得する。
2. **`.data.rel.ro`** を 1 ワードずつ列挙する。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱う。
4. 次のワードを、候補の長さとして扱う。
5. サニティフィルターを適用する（例：長さを **4**～**100** バイトに限定する）。
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
これは firmware reversing で特に有用です。復元された Rust strings から、**HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth-related logic** が明らかになることがよくあります。

Ghidra がこれらの strings を見逃す場合は、同じ heuristic を適用し、参照先の `.rodata` offsets に string data を作成する custom script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` tools は、このアイデアを他の **word sizes、endianness、section layouts** に適用する際の優れた参考資料です。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries には [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi binary を reverse する必要がある場合は、IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をお勧めします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin file を選択します。

この plugin は binary を実行し、debugging の開始時に function names を動的に解決します。debugging を開始した後、もう一度 Start button（緑色のボタン、または f9）を押すと、real code の先頭で breakpoint に到達します。

graphical application でボタンを押すと、debugger はそのボタンによって呼び出された function で停止できます。

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

GBA game の **binary** を入手した場合は、これを **emulate** および **debug** するためのさまざまな tools を使用できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - interface 付き debugger が含まれています
- [**mgba** ](https://mgba.io)- CLI debugger が含まれています
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **buttons** の押し方を確認できます。

![Game Boy Advance のボタンマッピングを示す no$gba controls configuration](<../../images/image (581).png>)

押すと、各 **key has a value** を持ち、それによって識別されます。
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
この種類のプログラムでは、興味深い部分は**プログラムがユーザー入力をどのように処理するか**です。アドレス **0x4000130** には、よく見られる関数 **KEYINPUT** があります。

![アドレス 0x4000130 で KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像から、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

その関数では、いくつかの初期化処理（重要ではないため省略）の後に、次の処理が行われます。
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
次のコードが見つかります:
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
最後の if は、**`uVar4`** が **last Keys** に含まれており、現在のキーではないことを確認しています。これは、ボタンを離した状態とも呼ばれます（現在のキーは **`uVar1`** に格納されています）。
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

- 最初に、**値 4**（**SELECT**ボタン）と比較します。この challenge では、このボタンによって画面がクリアされます。
- 次に、値を **8**（**START**ボタン）と比較します。この challenge では、このパスによって入力されたコードが有効かどうかを確認します。
- この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が同じ場合に一部のコードが実行されます。
- その他の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
カウンターが 8 未満の間、押されたキーの値が `DAT_030000d8` に累積されます。

したがって、この challenge ではボタンの値がわかっているため、**長さが 8 未満で、加算結果が 0xf3 になる組み合わせを押す必要がありました。**

**この tutorial の参考資料:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRAによるMBA obfuscationの簡略化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust stringsのデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI-Assisted Reverse Engineeringを打ち破る、少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
