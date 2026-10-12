# Reversingツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのReversingツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windowsカーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasmデコンパイラ / Watコンパイラ

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使って、wasm（バイナリ）からwat（プレーンテキスト）に**デコンパイル**します。
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使って、watからwasmに**コンパイル**します。
- デコンパイルには、[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8のキャッシュ済みバイトコード

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 仮想化されたpayloadとカスタムVM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NETデコンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、ライブラリ（.dll）、Windowsメタデータファイル（.winmd）、実行ファイル（.exe）など、複数の形式を**デコンパイルして調査する**デコンパイラです。デコンパイル後、アセンブリをVisual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、この機能によって時間を節約できます。さらに、dotPeekはデコンパイルされたコード内を簡単に移動できるため、**Xamarinのアルゴリズム解析**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、開発の時間を節約し、効率化します。このツールが提供する多彩なリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内でのデータの流れを把握できます。
- .NET言語やフレームワークの実装と使用方法を確認できます。
- ドキュメント化されていない機能や公開されていない機能を見つけ、使用しているAPIやテクノロジーをさらに活用できます。
- 依存関係や各種アセンブリを特定できます。
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な発生箇所を追跡できます。
- 使用している.NETコードのソースをデバッグできます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): どのOSでも利用できます（VSCodeから直接インストールできるため、gitをダウンロードする必要はありません。**Extensions**をクリックして、**ILSpy**を検索してください）。\
**デコンパイル**、**変更**、再度**コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または活発にメンテナンスされているforkの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内のコードを変更するには、**Right Click -> Modify Method**を選択します。）

### DNSpyのログ出力

**DNSpyでファイルに情報をログ出力する**には、次のスニペットを使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpy を使って code を debug するには、次の操作が必要です。

まず、**debugging** に関連する **Assembly attributes** を変更します。

![DNSpy Logging - DNSpy Debugging: まず、debugging に関連する Assembly attributes を変更します](<../../images/image (973).png>)

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

そして、**コンパイル**をクリックします。

![DNSpyのロギング - DNSpyのデバッグ: コンパイルをクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpyのロギング - DNSpyのデバッグ: File Save moduleから新しいファイルを保存](<../../images/image (602).png>)

これを行う必要があるのは、そうしないと**実行時**にコードにいくつかの**最適化**が適用され、デバッグ中に**ブレークポイントに到達しない**、または**変数が存在しない**可能性があるためです。

.NETアプリケーションが**IIS**によって**実行**されている場合は、次のコマンドで**再起動**できます。

```
iisreset /noforce
```

その後、デバッグを開始するには、開いているファイルをすべて閉じ、**Debug Tab** で **Attach to Process...** を選択します。

![DNSpy Logging - DNSpy Debugging: デバッグを開始するには、開いているファイルをすべて閉じ、Debug Tab で Attach to Process を選択します](<../../images/image (318).png>)

次に **w3wp.exe** を選択して **IIS server** にアタッチし、**attach** をクリックします。

![DNSpy Logging - DNSpy Debugging: w3wp.exe を選択して IIS server にアタッチし、attach をクリックします](<../../images/image (113).png>)

プロセスをデバッグ中なので、次は実行を停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグ中なので、実行を停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグ中なので、実行を停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** の任意のモジュールをクリックし、**Open All Modules** を選択します。

![DNSpy Logging - DNSpy Debugging: Modules の任意のモジュールをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のモジュールを右クリックし、**Sort Assemblies** をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のモジュールを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java逆コンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのデバッグ

### IDAを使う

- **rundll32を読み込みます**（64bitsはC:\Windows\System32\rundll32.exe、32 bitsはC:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debuggerを選択します
- 「**Suspend on library load/unload**」を選択します

![Debugging DLLs - Using IDA: 「Suspend on library load/unload」を選択します](<../../images/image (868).png>)

- 実行の**parameters**を設定し、**DLLのパス**と呼び出したい関数を指定します。

![Debugging DLLs - Using IDA: DLLのパスと呼び出したい関数を指定して、実行のparametersを設定します](<../../images/image (704).png>)

その後、デバッグを開始すると、**DLLが読み込まれるたびに実行が停止します**。そのため、rundll32がDLLを読み込むと、実行が停止します。

この方法ではモジュールの読み込みイベントで停止しますが、読み込まれたDLLのentry pointに到達する方法は、以下のx64dbgの手順より直接的ではありません。

### x64dbg/x32dbgを使う

- **rundll32を読み込みます**（64bitsはC:\Windows\System32\rundll32.exe、32 bitsはC:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更**（_File --> Change Command Line_）し、dllのパスと呼び出したい関数を設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、「**DLL Entry**」を選択します。
- その後、**実行を開始**すると、debuggerは各dll mainで停止します。やがて、**対象のdllのEntryで停止**します。そこから、breakpointを設定したい箇所を探します。

win64dbgで何らかの理由により実行が停止したときは、**win64dbgウィンドウの上部**を見ると、**現在どのコードにいるか**を確認できます。

![Using IDA - Using x64dbg/x32dbg: win64dbgで何らかの理由により実行が停止したときは、win64dbgウィンドウの上部を見ると現在どのコードにいるかを確認できます](<../../images/image (842).png>)

この表示で、デバッグ対象のDLL内で実行が停止したことを確認できます。

## GUIアプリ / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内で重要な値が保存されている場所を特定し、値を変更するのに便利なプログラムです。詳細:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)は、ゲームに特化したGNU Project Debugger（GDB）用のフロントエンド/reverse engineering toolです。ただし、reverse engineering関連の用途なら何にでも使えます。

[**Decompiler Explorer**](https://dogbolt.org/)は、複数のdecompilerを利用できるWebフロントエンドです。このWebサービスでは、小さな実行ファイルに対する各種decompilerの出力を比較できます。

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### blobrunnerでshellcodeをデバッグする

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**をメモリに割り当て、**メモリアドレス**を表示して、実行を一時停止します。\
IDAやx64dbgなどのdebuggerをアタッチし、表示されたアドレスにbreakpointを設定してから実行を再開すると、shellcodeをデバッグできます。

releasesのGitHubページには、コンパイル済みリリースを含むzipがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
次のリンクから、少し変更を加えたBlobrunnerを入手できます。コンパイルするには、**Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドするだけです**。

{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itでshellcodeをデバッグする

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerに似ています。shellcodeをメモリに割り当てて無限ループに入ります。debuggerをアタッチし、**2～5秒間**実行を再開してから、そのループ内で一時停止し、割り当てられたshellcodeに実行を移す次のcallまでステップ実行します。

![jmp2itの無限ループ内で、割り当てられたshellcodeへのcallの直前にdebuggerが一時停止している状態](<../../images/image (509).png>)

コンパイル済みのjmp2itは[releasesページ](https://github.com/adamkramer/jmp2it/releases/)からダウンロードできます。

### Cutterを使ってshellcodeをデバッグする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使ってshellcodeをエミュレートし、動的に調査できます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。私の場合、shellcodeをファイルとして開くと正しくdecompileされましたが、shellcodeとして開くとうまくいきませんでした。

![同じバイト列をファイルとして開いた場合とshellcodeとして開いた場合の、Cutterによる分析結果の違い](<../../images/image (562).png>)

目的の位置からエミュレーションを開始するには、その位置にbpを設定します。すると、Cutterはそこから自動的にエミュレーションを開始するようです。

![Cutterでエミュレーションを開始する前に、shellcodeの目的のentryにbreakpointを設定した状態](<../../images/image (589).png>)

![選択したshellcodeのbreakpointで一時停止しているCutter emulator](<../../images/image (387).png>)

たとえば、hex dump内でstackを確認できます。

![Cutterのhex dumpでエミュレートされたshellcodeのstackを表示した状態](<../../images/image (186).png>)

### shellcodeをdeobfuscateして実行された関数を調べる

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してみてください。\
shellcodeが使用している**関数**や、メモリ内でshellcodeが自身を**decode**しているかどうかなどを確認できます。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbgにはグラフィカルランチャーもあり、使用するオプションを選択してshellcodeを実行できます。

![shellcodeのエミュレーションおよびトレースオプションを選択するscDbgのグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump**オプションを使うと、メモリ内でshellcodeが動的に変更された場合に、変更後のshellcodeをダンプできます（デコードされたshellcodeの取得に便利です）。**start offset**を指定すると、特定のオフセットからshellcodeを開始できます。**Debug Shell**オプションを使うとscDbgのターミナルでshellcodeをデバッグできます。ただし、この目的には前述のいずれかのオプションのほうが適していると思います。Idaやx64dbgを使えるためです。

### CyberChefを使った逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationの難読化解除

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、算術演算子（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた式で、`x + y`のような単純な式を隠します。重要なのは、これらの恒等式が通常、**固定幅の剰余演算**でのみ成り立つため、キャリーとオーバーフローが問題になる点です:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用の代数ツールで簡約すると、ビット幅の意味が無視されるため、簡単に誤った結果になります。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトされたコード／IR／逆コンパイラの出力にある**元のビット幅**（`8/16/32/64` bits）を維持します。
2. 簡約を試す前に、式を分類します。
   - **Linear**: ビット演算を含む項の重み付き和
   - **Semilinear**: `x & 0xFF` のような定数マスクを含む linear な式
   - **Polynomial**: 積を含む
   - **Mixed**: 積とビット演算が混在し、同じ部分式が繰り返されることが多い
3. 候補となる変形はすべて、ランダムテストまたは SMT proof で検証します。同値性を証明できない場合は、推測で変形せず、元の式を維持します。

### 狭い実行スライスで flattened control flow を回避する

完全な control-flow graph の復元は、多くの場合必要ありません。control-flow flattening、opaque predicates、大規模な dispatcher、または MBA-heavy なコードの場合、暗号化された blob や出力バッファから参照をたどり、それらを変換する最小のルーチンを特定します。その後、その data-flow slice だけを再現するか、単独で実行します。該当する状態を直接初期化できるなら、dispatcher は解決に必要ありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocation、cross-reference を調べます。候補となるテーブルを `.rodata` からダンプし、バイト順と要素幅を維持します。
2. 平文または出力バッファに最後に書き込むルーチンを特定します。その入力、参照するテーブル、import された呼び出し、必要なグローバル状態を記録します。
3. それらの操作だけを固定幅の Python model にリフトします。そのスライスが依然として大量の状態に依存する場合は、プログラム全体をエミュレートする代わりに、Unicorn、QEMU、または debugger 上でルーチンを呼び出し、無関係な import を hook します。
4. extractor が実際に渡された binary から出力を導出していることを検証します。暗黙の fallback を削除し、埋め込みの回答を検索し、文字列、鍵、識別子、レイアウト、obfuscation seed を変更した未知の build でも実行します。

最初に使えるコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装した MBA expressions の検出

一見すると入力に依存しているように見える byte expression でも、入力が完全に相殺されることがあります。テーブルを抽出した後、8-bit の全領域で式を評価します。出力集合が単一要素なら、周囲の state machine を復元しなくても、その byte が定数であると証明できます。<sup>[[7]](#references)</sup>

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

元の加算ではバイト幅でラップアラウンドするため、最後のマスクは残してください。より広い定義域については、同じ幅の2つの記号入力に対して、`f(x1) != f(x2)` が充足可能かどうかをSMT solverに問い合わせます。`unsat`なら不変性が証明され、`sat`なら反例が得られるため、その入力は破棄できません。<sup>[[7]](#references)</sup>

#### 環境に依存したデコードを見分ける

Anti-analysisチェックは、分岐やクラッシュを伴うとは限りません。デコーダーはセンサーの結果をキーのビット、opaque predicateの定数、またはflattened dispatcherの状態に混ぜ込み、正常に処理を続けながら、emulator内で本物らしいが誤った平文を生成することがあります。そのため、目に見える失敗分岐だけをpatchしても不十分です。環境プローブからデコーダーの状態へのデータ依存関係を追跡し、同じスライスを本物のデバイスとemulatorで比較し、各センサーの結果を強制的に変更したときに最終バッファがどう変わるかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)は、malware analysisや保護されたバイナリのreversingに実用的なMBA simplifierです。すべてに汎用の書き換えパスを適用するのではなく、式を分類して、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRAはBoolean入力に対して式を評価し、シグネチャを導出して、パターンマッチング、ANF変換、係数補間など複数の復元手法を競わせます。
- **Semilinear MBA**: 定数でマスクされたアトムは、マスクされた領域が正しく保たれるよう、ビット分割による再構成で再構築されます。
- **Polynomial/Mixed MBA**: 積はコアに分解され、外側の関係を簡約する前に、繰り返し現れる部分式を一時変数に持ち上げられます。

復元を試す価値がよくある混合恒等式の例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のように簡略化できます：

```c
x * y
```

### Reversing notes

- 正確な計算を切り分けた後、**lifted IR expressions** または decompiler output に対して CoBRA を実行することをおすすめします。
- マスク演算や狭いレジスタに由来する式では、`--bitwidth` を明示的に指定してください。
- より強力な証明手順が必要な場合は、こちらの Z3 notes を確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA には **LLVM pass plugin** (`libCobraPass.so`) も同梱されています。後続の解析 pass の前に、MBA が多用された LLVM IR を正規化したい場合に便利です。
- carry に依存する、サポート対象外の混合ドメインの残余式は、元の式を保持し、carry path を手動で解析する必要があることを示すものとして扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの操作を `mov` ベースの命令シーケンスに置き換え、signal/exception handling を使って control flow を変更します。詳細はこちら:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応するバイナリでは、[demovfuscator](https://github.com/kirschju/demovfuscator) を使って結果を deobfuscate できます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして、[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）。

**CTFをプレイしている場合、この回避策はflagを見つけるのにとても役立つ可能性があります**：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリーポイント**を見つけるには、次のように関数名を`::main`で検索します。

![Ghidraで関数名のダブルコロン付きmainを検索してRustのエントリーポイントを見つける](<../../images/image (1080).png>)

このケースでは、バイナリの名前がauthenticatorだったので、これが興味深いmain関数だということは明らかです。\
呼び出されている**関数**の**名前**が分かったら、**インターネット**で検索して、それらの**入力**と**出力**を確認しましょう。

### ELFファームウェアからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列がCスタイルのNUL終端ポインターとして参照されていません。一般的な`rustc`のレイアウトでは、**`.data.rel.ro`**内の**ポインター/長さのタプル**が、**`.rodata`**に格納された実際の文字列データを指しています。

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

つまり、`strings`やGhidraのデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりすることがあります。<sup>[[3]](#references)</sup>

簡単なワークフロー：

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得します。
2. **`.data.rel.ro`** を1ワードずつ列挙します。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱います。
4. 次のワードを長さの候補として扱います。
5. 妥当性フィルターを適用します（例: 長さが **4** ～ **100** バイトのものを保持します）。
6. `0x00` までスキャンするのではなく、`.rodata` から `length` バイトを正確に読み取ります。

最小限の extractor ロジック:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

これはファームウェアのリバースで特に役立ちます。復元されたRust文字列から、**HTTPルート、RPC名、ログメッセージ、アサーション、ファイル名、設定キー、コマンドハンドラー、認証関連のロジック**が見つかることがよくあります。

Ghidraがこれらの文字列を見つけられない場合は、同じヒューリスティックを適用し、参照されている`.rodata`オフセットに文字列データを作成するカスタムスクリプトやプラグインを実行してください。Pen Test Partnersが公開している`rust-strings`と`RustStrings.py`は、この手法を他の**ワードサイズ、エンディアン、セクションレイアウト**に適用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphiのコンパイル済みバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます。

Delphiバイナリをリバースする必要がある場合は、IDAプラグイン[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)の使用をおすすめします。

IDAで**Alt+F7**を押してPythonプラグインを読み込み、プラグインファイルを選択します。

このプラグインはバイナリを実行し、デバッグ開始時に関数名を動的に解決します。デバッグを開始した後、もう一度Startボタン（緑色のボタン、またはf9）を押すと、実際のコードの冒頭でブレークポイントに到達します。

グラフィカルアプリケーションでボタンを押すと、デバッガーはそのボタンによって呼び出された関数で停止できます。

## Golang

一般的なGoバイナリでは、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使うと、ランタイム構造を復元し、IDAで関数名を改善できます。**Alt+F7**でPythonプラグインを読み込んでください。

### シンボルテーブルなしでメタデータを復元する

stripされたGo実行ファイルでも、プログラムカウンターを関数に対応付けるためにランタイムメタデータが必要です。[GoReSym](https://github.com/mandiant/GoReSym)は、Goランタイムのコードを基に、`pclntab`や`moduledata`などの構造を見つけて解析します。これにより、従来のシンボルテーブルに頼らずに、関数の境界、名前、ソースパス、型、ビルド情報を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

難読化ツールは、復元した名前を置き換えながら、これらの構造を使用可能な状態に保つことがあります。たとえば Garble は識別子と package path をハッシュ化し、build、module、debug 情報を削除します。<sup>[[12]](#references)</sup> 難読化された package token は、その package の関数間で一貫している必要があります。繰り返し現れる token ごとに関数をグループ化し、呼び出し先、文字列、API から package を1つ推測して、その package ラベルをグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolver で Garble の名前を復元する

[GoResolver](https://github.com/volexity/GoResolver) は、runtime-symbol extraction と clean-reference generation、control-flow-graph (CFG) matching を組み合わせます。次の手順で実行します。<sup>[[10]](#references)[[13]](#references)</sup>

1. **compiler version を特定する。** まず `BuildInfo` と埋め込みバージョン文字列を確認します。obfuscator に削除されている場合は、バンドルされた Go runtime の一部を、バージョン別の reference runtime と比較します。Volexity のテストでは、runtime の約 `2%` で Go のメジャーバージョンを識別できました。これは実測に基づく最適化として扱い、普遍的なしきい値とは見なさないでください。<sup>[[13]](#references)</sup>
2. **照合用の reference を作成する。** 特定した Go version、target architecture、可能性の高い libraries に合わせて、難読化されていない binary を生成します。toolchain を一致させると、compiler が生成する CFG の差異を減らせます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapher は関数の CFG を照合し、`0.0` から `1.0` までの正規化されたスコアを出力します。basic block の照合では、類似命令を重み付けして比較します。信頼度の高い照合結果から、ランダム化された関数を難読化されていない実装に対応付けられます。信頼度が低い結果でも、package や module の特定に役立つ場合があります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証して取り込む。** 呼び出し関係、定数、文字列、副作用を使って候補名を確認し、GoResolver plugin を使って IDA または Ghidra に JSON report を取り込みます。<sup>[[10]](#references)[[13]](#references)</sup>

toolchain をインストールし、extractor と graph matcher を組み合わせて実行します。<sup>[[10]](#references)</sup>

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

既定の significant-match threshold は `0.9` です。`--extract` と `--graph` のスイッチを使うと各ステージを個別に実行できます。既定では、復元された runtime metadata と CFG の証拠が互いを補完するため、両方が実行されます。<sup>[[10]](#references)</sup> CFG のスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わる場合があるため、確信度の低い名前を無理に付けず、未解決の関数をそのまま残してください。<sup>[[13]](#references)</sup>

## コンパイル済み Python

このページでは、ELF/EXE の Python コンパイル済みバイナリから Python コードを取得する方法を説明します。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの **binary** を入手した場合、**emulate** および **debug** するために、以下のさまざまなツールを使用できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug版をダウンロード_) - インターフェイス付きの debugger を搭載
- [**mgba** ](https://mgba.io)- CLI debugger を搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** で、Game Boy Advance の **ボタン** の押し方を確認できます。

![Game Boy Advanceのボタン割り当てを表示するno$gbaのコントロール設定](<../../images/image (581).png>)

押すと、各 **キーには識別するための値** が割り当てられます。

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

では、この種のプログラムで注目すべき点は、**プログラムがユーザー入力をどのように処理するか**です。アドレス **0x4000130** には、よく見られる関数 **KEYINPUT** があります。

![アドレス 0x4000130 で KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

この関数では、いくつかの初期化処理（重要ではないため省略）の後に:

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

次のコードが見つかりました:

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

最後のifは、**`uVar4`**が**最後のKeys**に含まれていて、現在のキーではないことを確認しています。つまり、ボタンを離した状態です（現在のキーは**`uVar1`**に格納されています）。

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

前のコードでは、**押されたボタンの値**が格納されている場所である **uVar1** を、いくつかの値と比較していることがわかります。

- まず、**値4**（**SELECT**ボタン）と比較します。このチャレンジでは、このボタンを押すと画面がクリアされます。
- 次に、値を **8**（**START**ボタン）と比較します。このチャレンジでは、この分岐で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が0xf3と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）を確認してインクリメントします。\
  カウンターが8未満の間、押されたキーの値が `DAT_030000d8` に累積されます。

つまり、このチャレンジでは、ボタンの値を把握し、合計が0xf3になる、長さが8未満の組み合わせを**押す必要がありました**。

**このチュートリアルの参考資料:** [アーカイブされたNostalgiaチャレンジのwriteup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリの難読化解除）

## References

- [1] [CoBRAによるMBA難読化の簡素化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRAリポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rust文字列のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBAリバースエンジニアリングチュートリアル（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI支援リバースエンジニアリングを打ち破る、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [基本ブロックマッチングに基づく制御フローグラフ比較手法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garbleの難読化メカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver：制御フローグラフの類似性を利用したGoバイナリの自動難読化解除](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
