# リバースエンジニアリングツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのリバースエンジニアリングツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windowsカーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasmデコンパイラ / Watコンパイラ

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使うと、wasm（バイナリ）からwat（プレーンテキスト）に**デコンパイル**できます
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使うと、watからwasmに**コンパイル**できます
- デコンパイルには[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8のキャッシュされたバイトコード

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NETデコンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、ライブラリ（.dll）、**Windows metadata file**（.winmd）、実行ファイル（.exe）など、複数の形式を**デコンパイルして調査する**デコンパイラです。デコンパイルしたアセンブリは、Visual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、このツールを使えば時間を節約できます。また、dotPeekにはデコンパイルされたコードを便利にたどれる機能があり、**Xamarinのアルゴリズム解析**に最適なツールの一つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供する豊富なリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内でデータがどのように流れるかを把握できます
- .NET言語やフレームワークの実装と使い方を把握できます
- ドキュメント化されていない機能や公開されていない機能を見つけ、使用しているAPIやテクノロジーをより活用できます
- 依存関係や各種アセンブリを見つけられます
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な場所を特定できます
- 使用しているすべての.NETコードのソースをデバッグできます

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): どのOSでも利用できます（VSCodeから直接インストールできるため、gitをダウンロードする必要はありません。**Extensions**をクリックして、**ILSpy**を検索してください）。\
**デコンパイル**して**変更**し、再度**再コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または現在も積極的にメンテナンスされているフォークの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内の内容を変更するには、**右クリック -> Modify Method**を選択します）。

### DNSpyのログ出力

**DNSpyでファイルに情報をログ出力する**には、次のスニペットを使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpyのデバッグ

DNSpyを使ってコードをデバッグするには、次の手順が必要です。

まず、**デバッグ**に関連する**アセンブリ属性**を変更します。

![DNSpy Logging - DNSpyのデバッグ: まず、デバッグに関連するアセンブリ属性を変更します](<../../images/image (973).png>)

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

そして、**compile**をクリックします:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_から新しいファイルを保存します:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これを行わないと、**実行時**にコードにいくつかの**最適化**が適用され、デバッグ中に**ブレークポイントに到達しない**、または**変数が存在しない**可能性があるため、これは必要です。

.NETアプリケーションが**IIS**によって**実行**されている場合は、次のコマンドで**再起動**できます:

```
iisreset /noforce
```

その後、debuggingを開始するには、開いているファイルをすべて閉じ、**Debug Tab**で**Attach to Process...**を選択します。

![DNSpy Logging - DNSpy Debugging: debuggingを開始するには、開いているファイルをすべて閉じ、Debug TabでAttach to Processを選択します](<../../images/image (318).png>)

次に、**w3wp.exe**を選択して**IIS server**にattachし、**attach**をクリックします。

![DNSpy Logging - DNSpy Debugging: w3wp.exeを選択してIIS serverにattachし、attachをクリックします](<../../images/image (113).png>)

プロセスをdebuggingしている状態になったので、次はプロセスを停止して、すべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしている状態になったら、プロセスを停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、次にDebug Windows Modulesをクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしている状態になったら、プロセスを停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、次にDebug Windows Modulesをクリックします](<../../images/image (834).png>)

**Modules**内の任意のモジュールをクリックし、**Open All Modules**を選択します。

![DNSpy Logging - DNSpy Debugging: Modules内の任意のモジュールをクリックし、Open All Modulesを選択します](<../../images/image (922).png>)

**Assembly Explorer**内の任意のモジュールを右クリックし、**Sort Assemblies**をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer内の任意のモジュールを右クリックし、Sort Assembliesをクリックします](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのdebugging

### IDAを使用する

- **rundll32を読み込みます**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debuggerを選択します
- "**Suspend on library load/unload**"を選択します

![Debugging DLLs - Using IDA: 「Suspend on library load/unload」を選択します](<../../images/image (868).png>)

- 実行の**parameters**を設定し、**DLLのpath**と呼び出したい関数を指定します。

![Debugging DLLs - Using IDA: DLLのpathと呼び出したい関数を指定して、実行のparametersを設定します](<../../images/image (704).png>)

debuggingを開始すると、**各DLLの読み込み時に実行が停止します**。そのため、rundll32がDLLを読み込むと、実行が停止します。

この方法ではモジュールの読み込みイベントで停止しますが、読み込まれたDLLのentry pointに到達する手順は、以下のx64dbgを使う方法より直接的ではありません。

### x64dbg/x32dbgを使用する

- **rundll32を読み込みます**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更**し（_File --> Change Command Line_）、dllのpathと呼び出したい関数を設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_を変更し、"**DLL Entry**"を選択します。
- **実行を開始**すると、debuggerは各dll mainで停止します。いずれ、対象dllのEntryで**停止します**。そこから、breakpointを設定したい箇所を探してください。

win64dbgで何らかの理由により実行が停止した場合、**win64dbgウィンドウの上部**を見ると、**どのコード上にいるか**を確認できます。

![Using IDA - Using x64dbg/x32dbg: 実行が何らかの理由でwin64dbg上で停止した場合、win64dbgウィンドウの上部を見ると、どのコード上にいるかを確認できます](<../../images/image (842).png>)

この表示により、debugging対象のDLL内で実行が停止したことを確認できます。

## GUIアプリ / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内で重要な値が保存されている場所を見つけて変更するのに便利なプログラムです。詳しくは以下を参照してください。

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)は、ゲームに特化したGNU Project Debugger（GDB）のフロントエンド/reverse engineering toolです。ただし、reverse engineeringに関するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/)は、複数のdecompilerを利用できるWebフロントエンドです。このWebサービスでは、小さな実行ファイルに対する異なるdecompilerの出力を比較できます。

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### blobrunnerでshellcodeをdebuggingする

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**をメモリに割り当て、その**memory address**を出力して実行を一時停止します。\
IDAやx64dbgなどのdebuggerをattachし、出力されたアドレスにbreakpointを設定してから実行を再開すると、shellcodeをdebuggingできます。

GitHubのreleasesページには、コンパイル済みreleaseを含むzipファイルがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクからBlobrunnerを少し変更したバージョンを入手できます。コンパイルするには、Visual Studio Codeで**C/C++ projectを作成し、コードをコピーして貼り付け、buildします**。

{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itでshellcodeをdebuggingする

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerに似ています。shellcodeをメモリに割り当て、無限ループに入ります。debuggerをattachして**2～5秒間**実行を再開し、そのループ内で一時停止したら、割り当てられたshellcodeに実行を移す次のcallまでstep実行します。

![割り当てられたshellcodeを呼び出す直前の、jmp2itの無限ループで一時停止したdebugger](<../../images/image (509).png>)

コンパイル済みの[jmp2itはreleasesページからダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使ってshellcodeをdebuggingする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使うとshellcodeをemulateし、動的に調査できます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。私の場合、shellcodeをファイルとして開くと正しくdecompileされましたが、shellcodeとして開くと正しく処理されませんでした。

![同じバイト列をファイルとして開いた場合とshellcodeとして開いた場合で、異なる解析結果を表示するCutter](<../../images/image (562).png>)

指定した位置からemulationを開始するには、その位置にbpを設定します。すると、Cutterはそこから自動的にemulationを開始するようです。

![Cutterのemulation開始前に、目的のshellcode entryにbreakpointを設定](<../../images/image (589).png>)

![選択したshellcode breakpointで一時停止したCutter emulator](<../../images/image (387).png>)

たとえば、hex dump内でstackを確認できます。

![Cutterのhex dumpでemulate中のshellcode stackを表示](<../../images/image (186).png>)

### shellcodeをdeobfuscateして実行された関数を特定する

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してください。\
shellcodeが使用している**関数**や、メモリ内で自身を**decode**しているかどうかなどを確認できます。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbgには、必要なオプションを選択してshellcodeを実行できるグラフィカルランチャーもあります。

![shellcodeのエミュレーションとトレースのオプションを選択するscDbgグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump**オプションを使うと、メモリ上でshellcodeが動的に変更された場合に、最終的なshellcodeをダンプできます（デコード済みshellcodeのダウンロードに便利です）。**start offset**は、特定のオフセットからshellcodeを開始する場合に便利です。**Debug Shell**オプションを使うと、scDbgターミナルでshellcodeをデバッグできます（ただし、この目的には前述の他のオプションのほうが適していると思います。Idaやx64dbgを使用できるためです）。

### CyberChefを使った逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、`x + y`のような単純な式を、算術演算（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた数式で隠します。重要なのは、こうした恒等式が通常、**固定幅の剰余算術**のもとでのみ成り立つという点です。そのため、桁上がりとオーバーフローが重要になります:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用の代数ツールで簡約すると、bit-width の意味が考慮されず、誤った結果になりやすいです。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトされたコード／IR／decompiler の出力にある**元の bit-width**（`8/16/32/64` bits）を維持する。
2. 簡約を試す前に、式を分類する。
   - **Linear**: bitwise atom の重み付き和
   - **Semilinear**: `x & 0xFF` のような定数マスクを含む linear 式
   - **Polynomial**: 積を含む式
   - **Mixed**: 積と bitwise logic が交互に現れ、同じ部分式が繰り返されることが多い式
3. 候補となる各書き換えを、random testing または SMT proof で検証する。同値性を証明できない場合は、推測で書き換えず元の式を維持する。

### narrow execution slice で flatten された control flow を回避する

完全な control-flow graph の復元は、多くの場合不要です。Control-flow flattening、opaque predicate、大規模な dispatcher、または MBA が多用されたコードでは、encrypted blob や output buffer から参照をたどり、それらを変換する最小の routine を特定します。その後、その data-flow slice だけを再現するか、単独で実行します。関連する state を直接初期化できるなら、dispatcher は解決に必要ありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocation、cross-reference を調べる。`.rodata` から候補となる table を、byte order と element width を維持して dump する。
2. plaintext または output buffer を最後に書き込む routine を特定する。その入力、参照する table、import された call、必要な global state を記録する。
3. それらの操作だけを fixed-width の Python model にリフトする。slice がまだ多くの state に依存する場合は、プログラム全体を emulate する代わりに、Unicorn、QEMU、または debugger 上で routine を呼び出し、不要な import を hook する。
4. extractor が実際に与えられた binary から出力を導出していることを検証する。無言の fallback を削除し、埋め込みの答えを検索し、文字列、key、identifier、layout、obfuscation seed を変更した未知の build で実行する。

最初に使えるコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装したMBA expressionsを検出する

一見すると入力に依存するバイト式でも、入力が完全に相殺される場合があります。テーブルを抽出した後、8ビットの全領域にわたって式を評価します。出力集合が単一の値なら、周囲の状態機械を復元しなくても、そのバイトが定数であると証明できます。<sup>[[7]](#references)</sup>

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

最終マスクは維持してください。元の加算はバイト幅でラップアラウンドするためです。より広い値域では、同じ幅のシンボリック入力2つに対して、SMT solverで `f(x1) != f(x2)` が充足可能か確認してください。`unsat` なら不変性が証明され、`sat` なら反例が得られるため、その入力は破棄できません。<sup>[[7]](#references)</sup>

#### 環境依存のデコードを見分ける

Anti-analysis チェックは、分岐やクラッシュを伴うとは限りません。decoder はセンサーの結果をキーのビット、opaque-predicate の定数、または flattened-dispatcher の状態に混ぜ込み、正常に処理を続けながら、emulator 内で一見もっともらしい偽の平文を生成することがあります。そのため、目に見える失敗分岐だけをパッチするのでは不十分です。環境プローブから decoder の状態へのデータ依存を追跡し、実機と emulator で同じスライスを比較して、各センサー結果を強制的に変更した場合に最終バッファがどう変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis や保護されたバイナリの reversing に実用的な MBA simplifier です。式を分類し、すべてに汎用の書き換えパスを適用するのではなく、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA は Boolean 入力で式を評価してシグネチャを導出し、パターンマッチング、ANF 変換、係数補間など、複数の復元手法を並行して実行します。
- **Semilinear MBA**: 定数でマスクされたアトムは、マスク領域が正しく保たれるよう、ビット分割による再構成で復元されます。
- **Polynomial/Mixed MBA**: 積はコアに分解され、簡約前に繰り返し現れる部分式を一時変数に切り出せます。

復元を試す価値のある、よくある mixed identity の例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のように簡略化できます:

```c
x * y
```

### Reversing のメモ

- CoBRA は、正確な計算を切り分けた後の **lifted IR 式** またはデコンパイラの出力に対して実行するのがおすすめです。
- 式がマスク演算や狭いレジスタに由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な証明手順が必要な場合は、こちらの Z3 のメモを確認してください。

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA には **LLVM pass plugin**（`libCobraPass.so`）も付属しています。後続の解析パスの前に、MBA を多用した LLVM IR を正規化する場合に便利です。
- サポートされていない、キャリーに依存する混合ドメインの残余式は、元の式を保持し、キャリー経路を手動で解析すべきという合図です。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この難読化ツールは、プログラムの演算を `mov` ベースの命令シーケンスに置き換え、シグナル／例外処理を使って制御フローを変更します。詳細はこちらを参照してください。

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応するバイナリであれば、[demovfuscator](https://github.com/kirschju/demovfuscator) を使って結果を逆難読化できます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして [keystone をインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

**CTF** に参加している場合、**flag を見つけるためのこの回避策**が役立つかもしれません：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** を見つけるには、次のように `::main` で関数を検索します。

![Ghidra で関数名をダブルコロン付きの main で検索して Rust の entry point を見つける](<../../images/image (1080).png>)

この場合、バイナリ名は authenticator だったので、これが注目すべき main 関数であることは明らかです。\
呼び出されている**関数**の**名前**がわかったら、**入力**と**出力**を調べるために**インターネット**で検索します。

### ELF ファームウェアから Rust 文字列を復元する

**Rust ELF** バイナリでは、多くの静的文字列は C 形式の NUL 終端ポインターから参照されていません。一般的な `rustc` のレイアウトでは、実際の文字列データが格納された **`.rodata`** を指す **ポインターと長さのタプル**が **`.data.rel.ro`** 内にあります：

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

これは、`strings` や Ghidra のデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

クイックワークフロー:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得します。
2. **`.data.rel.ro`** をワード単位で列挙します。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインター候補として扱います。
4. 次のワードを長さ候補として扱います。
5. 妥当性フィルターを適用します（例：長さが **4** ～ **100** バイトのものを保持）。
6. `0x00` までスキャンするのではなく、`.rodata` から `length` バイトを正確に読み取ります。

最小限の抽出ロジック：

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

これは firmware のリバースエンジニアリングで特に役立ちます。復元された Rust の文字列から、**HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、認証関連のロジック**が判明することがよくあります。

Ghidra がこれらの文字列を見つけられない場合は、同じヒューリスティックを適用し、参照先の `.rodata` オフセットに文字列データを作成するカスタムスクリプト/pluginを実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` は、この手法を他の**word sizes、endianness、section layouts**に適用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphiでコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます。

Delphiバイナリをリバースする必要がある場合は、IDA pluginの[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)の使用をおすすめします。

IDAで**Alt+F7**を押してPython pluginを読み込み、pluginファイルを選択します。

このpluginはバイナリを実行し、デバッグ開始時に関数名を動的に解決します。デバッグを開始したら、もう一度Startボタン（緑色のボタン、またはf9）を押すと、実際のコードの先頭でブレークポイントにヒットします。

グラフィカルアプリケーションのボタンを押すと、デバッガーはそのボタンによって呼び出された関数で停止します。

## Golang

一般的なGoバイナリには、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使うと、runtime structuresを復元し、IDA上の関数名を改善できます。**Alt+F7**でPython pluginを読み込んでください。

### シンボルテーブルなしでmetadataを復元する

strippedされたGo実行ファイルでも、program counterを関数に対応付けるためにruntime metadataが必要です。[GoReSym](https://github.com/mandiant/GoReSym)は、Go runtime由来のコードを使って`pclntab`や`moduledata`などの構造体を特定・解析します。これにより、従来のシンボルテーブルに頼らずに、関数の境界、名前、ソースパス、型、ビルド情報を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

難読化ツールは、復元された名前を置き換えながら、これらの構造を利用可能な状態に保つことがあります。たとえば Garble は識別子とパッケージパスをハッシュ化し、build、module、debug の情報を削除します。<sup>[[12]](#references)</sup> 難読化されたパッケージトークンは、そのパッケージ内の関数間で一貫している必要があります。関数を繰り返し現れるトークンでグループ化し、呼び出し先、文字列、API からパッケージを1つ推定して、そのパッケージ名をグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolver で Garble の名前を復元する

[GoResolver](https://github.com/volexity/GoResolver) は、実行時シンボルの抽出、クリーンな参照バイナリの生成、control-flow graph（CFG）のマッチングを組み合わせます。次の手順で進めます。<sup>[[10]](#references)[[13]](#references)</sup>

1. **コンパイラのバージョンを特定する。** まず `BuildInfo` と埋め込みバージョン文字列を確認します。難読化ツールによって削除されている場合は、バンドルされた Go runtime の一部を、バージョン別の参照 runtime と比較します。Volexity のテストでは、runtime の約 `2%` で Go のメジャーバージョンを判別できました。これは実証に基づく最適化として扱い、普遍的な閾値とはみなさないでください。<sup>[[13]](#references)</sup>
2. **照合用の参照を作成する。** 特定した Go バージョン、対象アーキテクチャ、使用されている可能性の高いライブラリに合わせて、難読化されていないバイナリを生成します。toolchain を一致させることで、コンパイラが生成する CFG の差異を抑えられます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapher は関数の CFG を照合し、`0.0` から `1.0` の正規化スコアを出力します。basic block の照合は、類似した命令の重み付き比較に基づいています。信頼度の高い一致は、ランダム化された関数をクリーンな実装に対応付けます。信頼度が低い一致でも、パッケージやモジュールの特定に役立つ場合があります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** 呼び出し関係、定数、文字列、副作用を使って提案された名前を確認し、GoResolver の IDA または Ghidra 用 plugin で JSON レポートをインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

toolchain をインストールし、抽出ツールとグラフマッチャーをまとめて実行します。<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

デフォルトの有意な一致のしきい値は `0.9` です。`--extract` と `--graph` スイッチを使うと、どちらか一方の段階だけを実行できます。デフォルトでは、復元されたランタイムメタデータとCFGの証拠が互いを補完するため、両方を実行します。<sup>[[10]](#references)</sup> CFGのスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わることがあるため、信頼度の低い名前を無理に割り当てず、解決できない関数はそのまま残してください。<sup>[[13]](#references)</sup>

## コンパイル済みPython

このページでは、ELF/EXEのPythonコンパイル済みバイナリからPythonコードを取得する方法を説明します。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBAゲームの**バイナリ**を入手した場合は、さまざまなツールを使って**エミュレート**や**デバッグ**ができます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_デバッグ版をダウンロード_) - インターフェース付きのデバッガーを搭載
- [**mgba** ](https://mgba.io)- CLIデバッガーを搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidraプラグイン
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidraプラグイン

[**no$gba**](https://problemkaputt.de/gba.htm)の_**Options --> Emulation Setup --> Controls**_** **では、Game Boy Advanceの**ボタン**の押し方を確認できます。

![Game Boy Advanceのボタン割り当てを示すno$gbaのコントロール設定画面](<../../images/image (581).png>)

押すと、各**キーには識別用の値が割り当てられます**。

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

この種のプログラムでは、注目すべき点は**プログラムがユーザー入力をどのように扱うか**です。アドレス **0x4000130** に、よく見られる関数 **KEYINPUT** があります。

![アドレス 0x4000130 で KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ と _0x080017ac_）から呼び出されていることがわかります。

この関数では、初期化処理（特に重要ではありません）の後に:

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

最後の if は、**`uVar4`** が **last Keys** に含まれていて、現在のキーではないことを確認しています。これはボタンを離した状態を表します（現在のキーは **`uVar1`** に格納されています）。

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

前のコードでは、**押されたボタンの値**が格納されている場所である**uVar1**を、いくつかの値と比較していることがわかります。

- まず、**値 4**（**SELECT**ボタン）と比較します。このチャレンジでは、このボタンを押すと画面がクリアされます。
- 次に、**値 8**（**START**ボタン）と比較します。このチャレンジでは、この分岐で入力されたコードが有効かどうかを確認します。
  - この場合、var **`DAT_030000d8`**が0xf3と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが8未満の間、押されたキーの値が`DAT_030000d8`に累積されます。

つまり、このチャレンジでは、ボタンの値を把握したうえで、長さが8未満で、合計が0xf3になる組み合わせを**押す必要がありました。**

**このチュートリアルの参考資料:** [アーカイブされたNostalgiaチャレンジのwriteup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binaryのdeobfuscation)

## References

- [1] [MBA obfuscationをCoBRAで簡略化する](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRAリポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rustの文字列をデコードする - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversingチュートリアル（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AIを活用したReverse Engineeringを打ち破る、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matchingに基づくControl Flow Graph比較手法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garbleのobfuscationメカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graphの類似性を使ってGolangバイナリを自動的にdeobfuscateする](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
