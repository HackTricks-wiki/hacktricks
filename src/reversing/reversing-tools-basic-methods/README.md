# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui ベースのリバースツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows カーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm デコンパイラー / Wat コンパイラー

オンライン:

- wasm（バイナリ）から wat（プレーンテキスト）に**デコンパイル**するには、[https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用します。
- wat から wasm に**コンパイル**するには、[https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用します。
- デコンパイルには、[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 キャッシュ済みバイトコード

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET デコンパイラー

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、**ライブラリ**（.dll）、**Windowsメタデータファイル**（.winmd）、**実行ファイル**（.exe）など、複数の形式を**デコンパイルして調査**できるデコンパイラーです。デコンパイル後、アセンブリをVisual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、この機能を使えば時間を節約できます。さらに、dotPeekはデコンパイルされたコード内を簡単に移動できるため、**Xamarinのアルゴリズム分析**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供する幅広いリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内のデータの流れを把握できます
- .NET言語やフレームワークの実装と使い方を把握できます
- ドキュメント化されていない機能や公開されていない機能を見つけ、使用中のAPIやテクノロジーをさらに活用できます
- 依存関係や各種アセンブリを見つけます
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な位置を特定します
- 使用しているすべての.NETコードのソースをデバッグできます

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): どのOSでも使用できます（VSCodeから直接インストールできるため、gitをダウンロードする必要はありません。**Extensions**をクリックして、**ILSpy**を検索してください）。\
**デコンパイル**、**変更**、再度**コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または現在も保守されているフォークの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内の何かを変更するには、**右クリック -> Modify Method**を選択します）。

### DNSpy Logging

**DNSpyでファイルに情報をログ出力**するには、次のスニペットを使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpyのデバッグ

DNSpyを使用してコードをデバッグするには、次の操作が必要です。

まず、**デバッグ**に関連する**Assembly属性**を変更します。

![DNSpy Logging - DNSpyのデバッグ: まず、デバッグに関連するAssembly属性を変更します](<../../images/image (973).png>)

変更前：

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

そして、**compile** をクリックします。

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これを行う必要があるのは、行わないと**実行時**にコードにいくつかの**最適化**が適用され、デバッグ中に**ブレークポイントで停止しない**、または**変数が存在しない**といったことが起こり得るためです。

.NET アプリケーションが **IIS** によって**実行**されている場合は、次のコマンドで**再起動**できます。

```
iisreset /noforce
```

次に、debuggingを開始するには、開いているファイルをすべて閉じ、**Debug Tab**で**Attach to Process...**を選択します。

![DNSpy Logging - DNSpy Debugging: 次に、debuggingを開始するには、開いているファイルをすべて閉じ、Debug TabでAttach to Processを選択します](<../../images/image (318).png>)

次に、**w3wp.exe**を選択して**IIS server**にattachし、**attach**をクリックします。

![DNSpy Logging - DNSpy Debugging: 次に、w3wp.exeを選択してIIS serverにattachし、attachをクリックします](<../../images/image (113).png>)

プロセスをdebuggingしているので、次は実行を停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、続けて _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしているので、次は実行を停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、続けてDebug Windows Modulesをクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしているので、次は実行を停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、続けてDebug Windows Modulesをクリックします](<../../images/image (834).png>)

**Modules**内の任意のモジュールをクリックし、**Open All Modules**を選択します。

![DNSpy Logging - DNSpy Debugging: Modules内の任意のモジュールをクリックし、Open All Modulesを選択します](<../../images/image (922).png>)

**Assembly Explorer**内の任意のモジュールを右クリックし、**Sort Assemblies**をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer内の任意のモジュールを右クリックし、Sort Assembliesをクリックします](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのdebugging

### IDAを使用する

- **rundll32を読み込む** (64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debuggerを選択する
- "**Suspend on library load/unload**"を選択する

![Debugging DLLs - Using IDA: "Suspend on library load/unload"を選択します](<../../images/image (868).png>)

- 実行の**parameters**を設定し、**DLLへのpath**と呼び出す関数を指定します。

![Debugging DLLs - Using IDA: 実行のparametersを設定し、DLLへのpathと呼び出す関数を指定します](<../../images/image (704).png>)

debuggingを開始すると、**各DLLが読み込まれたときに実行が停止します**。そのため、rundll32がDLLを読み込むと、実行が停止します。

この方法ではモジュール読み込みイベントで停止しますが、読み込まれたDLLのentry pointに到達するには、以下のx64dbgの手順を使う方法がより直接的です。

### x64dbg/x32dbgを使用する

- **rundll32を読み込む** (64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe)
- **Command Lineを変更** ( _File --> Change Command Line_ ) し、dllのpathと呼び出す関数を設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**"を選択します。
- **実行を開始**すると、debuggerは各dll mainで停止します。やがて、対象dllの**dll Entryで停止**します。そこから、breakpointを設定したい箇所を探します。

win64dbgで何らかの理由により実行が停止した場合、**win64dbgウィンドウ上部**を見ると、**どのコード内にいるか**を確認できます。

![Using IDA - Using x64dbg/x32dbg: win64dbgで何らかの理由により実行が停止した場合、win64dbgウィンドウ上部を見ると、どのコード内にいるかを確認できます](<../../images/image (842).png>)

この表示により、debugging対象のDLL内で実行が停止したことを確認できます。

## GUIアプリ / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのmemory内で重要な値が保存されている場所を特定し、変更するのに便利なプログラムです。詳しくは以下を参照してください。


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)は、ゲームに特化したGNU Project Debugger (GDB)用のfront-end/reverse engineering toolです。ただし、reverse engineering関連のさまざまな用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/)は、複数のdecompilerを利用できるweb front-endです。このweb serviceを使うと、小さな実行ファイルに対する各decompilerの出力を比較できます。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerを使ったshellcodeのdebugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は、**shellcode**をメモリに割り当て、**memory address**を表示して、実行を一時停止します。\
IDAやx64dbgなどのdebuggerをattachし、表示されたアドレスにbreakpointを設定してから実行を再開すると、shellcodeをdebuggingできます。

GitHubのreleasesページには、コンパイル済みのreleaseを含むzipがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のlinkから、少し変更を加えたBlobrunnerを入手できます。コンパイルするには、**Visual Studio CodeでC/C++ projectを作成し、コードをコピーして貼り付け、buildします**。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itを使ったshellcodeのdebugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerに似ています。shellcodeをメモリに割り当て、無限ループに入ります。debuggerをattachし、**2～5秒**実行を再開してから、そのループ内で一時停止し、割り当てられたshellcodeに実行を移す次のcallまでstep実行します。

![割り当てられたshellcodeへのcall直前、jmp2itの無限ループ内でdebuggerが一時停止している状態](<../../images/image (509).png>)

コンパイル済みの[jmp2itはreleasesページ](https://github.com/adamkramer/jmp2it/releases/)からダウンロードできます。

### Cutterを使ったshellcodeのdebugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使ってshellcodeをemulateし、動的に調査できます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。私の場合、shellcodeをfileとして開くと正しくdecompileされましたが、shellcodeとして開くと正しく処理されませんでした。

![同じバイト列をfileとして開いた場合とshellcodeとして開いた場合の分析結果の違いを表示するCutter](<../../images/image (562).png>)

目的の場所からemulationを開始するには、その場所にbpを設定します。すると、Cutterはそこから自動的にemulationを開始するようです。

![Cutterのemulation開始前に、目的のshellcode entryにbreakpointを設定している状態](<../../images/image (589).png>)

![選択したshellcode breakpointで一時停止しているCutter emulator](<../../images/image (387).png>)

たとえば、hex dumpでstackを確認できます。

![Cutterのhex dumpでemulateされたshellcodeのstackを表示](<../../images/image (186).png>)

### shellcodeのdeobfuscationと実行された関数の特定

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してみてください。\
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

![shellcodeのエミュレーションとトレースのオプションを選択するscDbgのグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump**オプションを使うと、メモリ内でshellcodeが動的に変更された場合に、変更後のshellcodeをdumpできます（デコードされたshellcodeのダウンロードに便利です）。**start offset**は、特定のオフセットからshellcodeを開始する場合に便利です。**Debug Shell**オプションを使うと、scDbgのターミナルでshellcodeをデバッグできます（ただし、この目的には前述した他のオプションのほうが便利です。Idaまたはx64dbgを使用できるためです）。

### CyberChefを使用した逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします：[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationの難読化解除

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、算術演算（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた数式で、`x + y`のような単純な式を隠します。重要なのは、こうした恒等式が通常、**固定幅の剰余演算**でのみ成り立つことです。そのため、桁上がりとオーバーフローが重要になります。

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用の代数ツールで簡約すると、ビット幅の意味論が無視されているため、簡単に誤った結果が得られます。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトしたコード／IR／デコンパイラの出力における**元のビット幅**（`8/16/32/64` bits）を維持する。
2. 簡約を試みる前に、式を**分類**する。
   - **線形**: ビット演算のアトムの重み付き和
   - **半線形**: 線形式に `x & 0xFF` のような定数マスクを加えたもの
   - **多項式**: 積が含まれる
   - **混合**: 積とビット演算が交互に現れ、部分式が繰り返されることが多い
3. 候補となる書き換えをすべて、ランダムテストまたはSMT証明で検証する。同値性を証明できない場合は、推測せず元の式を維持する。

### 実行スライスを絞ってフラット化された制御フローを回避する

完全な制御フローグラフを復元する必要がない場合はよくあります。control-flow flattening、opaque predicate、大規模なdispatcher、またはMBA-heavyなコードでは、暗号化されたblobや出力バッファから参照をたどり、それらを変換する最小のルーチンを特定します。その後、そのデータフロースライスだけを再現するか、単独で実行します。関連する状態を直接初期化できるなら、dispatcherは必要な解決策に含める必要はありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocation、相互参照を一覧化する。候補となるテーブルを `.rodata` からダンプし、バイト順と要素幅を保持する。
2. plaintextまたは出力バッファに最後に書き込むルーチンを特定する。その入力、参照するテーブル、importされた呼び出し、必要なグローバル状態を記録する。
3. それらの操作だけを固定幅のPythonモデルにリフトする。スライスが依然として過剰な状態に依存する場合は、プログラム全体をエミュレートする代わりに、Unicorn、QEMU、またはdebugger上でルーチンを呼び出し、無関係なimportをhookする。
4. extractorが与えられたbinaryから実際に出力を導出していることを検証する。暗黙のfallbackを削除し、埋め込みの答えを検索し、文字列、鍵、識別子、レイアウト、obfuscation seedを変更した未見のbuildで実行する。

最初に役立つコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装した MBA expressions を検出する

一見すると入力に依存しているように見える byte 式でも、入力が完全に相殺されることがあります。テーブルを抽出した後、8-bit の全領域で式を評価します。出力集合が単一要素なら、周囲の状態機械を復元しなくても、その byte が定数であると証明できます。<sup>[[7]](#references)</sup>

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

元の加算はバイト幅でラップアラウンドするため、最後のマスクは残してください。より広い領域では、同じ幅の2つのシンボリック入力について、`f(x1) != f(x2)` が充足可能かSMT solverに問い合わせます。`unsat`なら不変性が証明され、`sat`なら反例が得られるため、その入力は破棄できません。<sup>[[7]](#references)</sup>

#### 環境依存のデコードを見分ける

Anti-analysisチェックは、分岐やクラッシュを伴うとは限りません。デコーダはセンサーの結果を鍵ビット、不透明述語の定数、またはフラット化されたディスパッチャの状態に混ぜ込み、正常に処理を続けながら、エミュレーター内でもっともらしいが誤った平文を生成することがあります。そのため、目に見える失敗分岐だけをパッチするのでは不十分です。環境プローブからデコーダの状態へのデータ依存関係を追跡し、実機とエミュレーターで同じ処理範囲を比較し、各センサーの結果を強制的に変更したときに最終バッファがどう変わるかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)は、マルウェア解析や保護されたバイナリのリバースに実用的なMBA簡略化ツールです。すべてに汎用の書き換えパスを適用するのではなく、式を分類し、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

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

有用的ケース:

- **Linear MBA**: CoBRA は Boolean 入力で式を評価して signature を導出し、pattern matching、ANF 変換、係数補間など複数の復元方法を並行して実行します。
- **Semilinear MBA**: 定数マスクされた atom は、マスク領域が正しく保たれるよう、bit 分割による再構築で復元します。
- **Polynomial/Mixed MBA**: 積を core に分解し、簡略化の前に繰り返し出現する部分式を temporary に切り出せます。

よく復元を試す価値のある mixed identity の例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のように簡略化できます:

```c
x * y
```

### リバースエンジニアリングのメモ

- CoBRAは、**lifted IR式**または、正確な計算を切り分けた後のdecompiler出力に対して実行するのがおすすめです。
- 式がマスク演算や狭いレジスタに由来する場合は、`--bitwidth`を明示的に指定してください。
- より強力な証明手順が必要な場合は、こちらのZ3メモを確認してください。

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRAは**LLVM pass plugin**（`libCobraPass.so`）としても提供されており、後続の解析パスにかける前に、MBAを多用するLLVM IRを正規化したい場合に便利です。
- carryに依存する、サポート対象外の混合ドメイン残差は、元の式を保持してcarryの経路を手作業で追うべきサインとして扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

このobfuscatorは、プログラムの演算を`mov`ベースの命令列に置き換え、signal/exception handlingを使って制御フローを変更します。詳細はこちら：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応するバイナリであれば、[demovfuscator](https://github.com/kirschju/demovfuscator)で結果をdeobfuscateできます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）。

**CTFをプレイしている場合、この回避策でflagを見つけられる可能性があり、とても役立ちます**: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリーポイント**を見つけるには、次のように`::main`で関数を検索します。

![関数名をダブルコロン付きのmainで検索して、GhidraでRustのエントリーポイントを見つける](<../../images/image (1080).png>)

この場合、バイナリの名前はauthenticatorだったので、どのmain関数に注目すべきかは明らかです。\
呼び出されている**関数**の**名前**が分かったら、それらの**入力**と**出力**を調べるために**インターネット**で検索します。

### ELFファームウェアからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列はC形式のNUL終端ポインターから参照されていません。一般的な`rustc`のレイアウトでは、**`.data.rel.ro`**内の**ポインター/長さタプル**が、実際の文字列データが格納された**`.rodata`**内を指しています。

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

つまり、`strings`やGhidraのデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりすることがあります。<sup>[[3]](#references)</sup>

簡単なワークフロー:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得します。
2. **`.data.rel.ro`** を1ワードずつ列挙します。
3. `.rodata` のアドレス範囲内にある値を文字列ポインター候補として扱います。
4. 次のワードを長さ候補として扱います。
5. 妥当性フィルターを適用します（例: 長さが **4**〜**100** バイトのものを残す）。
6. `0x00` までスキャンするのではなく、`.rodata` から `length` バイトを正確に読み取ります。

最小限の抽出ロジック:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

これは firmware reversing で特に役立ちます。復元された Rust の文字列から、**HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth-related logic** が見つかることがよくあります。

Ghidra がこれらの文字列を検出できない場合は、同じヒューリスティックを適用し、参照先の `.rodata` オフセットに string data を作成するカスタムスクリプトやプラグインを実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` は、このアイデアを他の **word sizes、endianness、section layouts** に応用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi のコンパイル済みバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi バイナリを reverse する場合は、IDA plugin の [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) を使用することをお勧めします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin ファイルを選択します。

この plugin はバイナリを実行し、debugging の開始時に function names を動的に解決します。debugging を開始したら、もう一度 Start ボタン（緑色のボタンまたは f9）を押すと、実際のコードの先頭で breakpoint が発生します。

グラフィカルアプリケーションでボタンを押すと、debugger はそのボタンによって呼び出された function で停止することがあります。

## Golang

Golang バイナリを reverse する場合は、IDA plugin の [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使用することをお勧めします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin ファイルを選択します。

これにより、function names が解決されます。

## Compiled Python

このページでは、ELF/EXE のコンパイル済み Python バイナリから Python コードを取得する方法を説明しています。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの **binary** を入手した場合は、**emulate** および **debug** するためのさまざまなツールを使用できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version をダウンロード_) - インターフェース付き debugger を搭載
- [**mgba** ](https://mgba.io)- CLI debugger を搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **buttons** の押し方を確認できます。

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

各 **key には、それを識別するための value** があります。

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

この種のプログラムでは、興味深いのは**プログラムがユーザー入力をどのように処理するか**です。アドレス **0x4000130** には、よく見られる関数 **KEYINPUT** があります。

![アドレス 0x4000130 で KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ と _0x080017ac_）から呼び出されていることがわかります。

この関数では、いくつかの初期化処理（重要ではありません）の後に、次の処理が行われます。

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

次のコードが見つかりました：

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

最後のifは、**`uVar4`**が**最後のKeys**に含まれていて、現在のキーではないことを確認しています。つまり、ボタンを離す操作です（現在のキーは**`uVar1`**に格納されています）。

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

前のコードでは、**押されたボタンの値**が格納されている場所である **uVar1** が、いくつかの値と比較されていることがわかります。

- まず、**値 4**（**SELECT**ボタン）と比較されます。このチャレンジでは、このボタンを押すと画面がクリアされます。
- 次に、値が **8**（**START**ボタン）と比較されます。このチャレンジでは、この分岐で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが 8 未満の間、押されたキーの値が `DAT_030000d8` に加算されます。

つまり、このチャレンジではボタンの値を把握したうえで、長さが 8 未満で、合計が 0xf3 になる組み合わせを**押す必要がありました。**

**このチュートリアルの参考資料:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリの難読化解除）

## References

- [1] [CoBRAを使ったMBA難読化の簡素化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRAリポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rust文字列のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBAリバースエンジニアリングチュートリアル（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI支援リバースエンジニアリングを打ち破る、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
