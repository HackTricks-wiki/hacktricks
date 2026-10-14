# Reversingツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのReversingツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windowsカーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使うと、wasm（バイナリ）からwat（テキスト）に**decompile**できます。
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使うと、watからwasmに**compile**できます。
- [web-wasmdec](https://wwwg.github.io/web-wasmdec/)を使ったdecompilationも試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8のキャッシュ済みbytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 仮想化されたpayloadとカスタムVM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、ライブラリ（.dll）、**Windows metadata file**（.winmd）、実行ファイル（.exe）など、複数の形式を**decompileして解析**するdecompilerです。decompileしたアセンブリは、Visual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、このツールを使えば時間を節約できます。さらに、dotPeekはdecompileしたコード内をスムーズに移動できるため、**Xamarinのアルゴリズム解析**に最適なツールの一つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ツールをニーズに合わせて拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供する幅広いreverse engineering機能を見てみましょう。

- ライブラリやコンポーネント内でデータがどのように流れるかを把握できます。
- .NET言語やframeworkの実装と使用方法を把握できます。
- ドキュメント化されていない機能や公開されていない機能を見つけ、使用しているAPIや技術をさらに活用できます。
- 依存関係や各種アセンブリを見つけられます。
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な位置を特定できます。
- 作業対象のあらゆる.NETコードのソースをデバッグできます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): どのOSでも利用できます（VSCodeから直接インストールできるため、gitをダウンロードする必要はありません。**Extensions**をクリックして、**ILSpy**を検索してください）。\
**decompile**、**modify**して再度**recompile**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または、現在もメンテナンスされているそのforkである[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内を変更するには、**Right Click -> Modify Method**を選択します）。

### REAによる実行不要のmanaged inspection

**REA**はアセンブリを読み込まずに、PE/CLI metadataとCILを検査できます。まずartifactの識別情報を確認し、次にメンバーと宣言されたnative境界を調べます。これは、decompilerを使ったりプログラムを実行したりする前に、不審な呼び出しを確認する場合に役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン間の差分比較では、`compare_managed_members` はメタデータトークンがビルド間で安定しているものとして扱うのではなく、raw CIL/signature identity と decoded-instruction fingerprints を使用します。P/Invoke 宣言は、native code が実行された証拠にはなりません。この境界を確認するには、`verify_managed_native_boundaries` で対応する native export または function Evidence が必要です。artifact digest、MVID、未解決のマッピングを結果とともに保持してください。<sup>[[17]](#references)</sup>

### DNSpyのログ記録

**DNSpy に情報をファイルへログ出力させる**には、次の snippet を使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpyを使ってコードをデバッグするには、次の手順が必要です。

まず、**デバッグ**に関連する **Assembly attributes** を変更します。

![DNSpy Logging - DNSpy Debugging: まず、デバッグに関連する Assembly attributes を変更します](<../../images/image (973).png>)

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

そして **compile** をクリックします:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これを行う必要があるのは、行わないと **runtime** にコードにいくつかの **最適化** が適用され、デバッグ中に **ブレークポイントに到達しない**、または **変数が存在しない** 可能性があるためです。

.NET アプリケーションが **IIS** によって **実行** されている場合は、次の方法で **再起動** できます:

```
iisreset /noforce
```

その後、debugging を開始するには、開いているファイルをすべて閉じ、**Debug Tab** で **Attach to Process...** を選択します。

![DNSpy Logging - DNSpy Debugging: debugging を開始するには、開いているファイルをすべて閉じ、Debug Tab で Attach to Process を選択します](<../../images/image (318).png>)

次に **w3wp.exe** を選択して **IIS server** にアタッチし、**attach** をクリックします。

![DNSpy Logging - DNSpy Debugging: w3wp.exe を選択して IIS server にアタッチし、attach をクリックします](<../../images/image (113).png>)

プロセスをdebuggingしているので、次はプロセスを停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしているので、次はプロセスを停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしているので、次はプロセスを停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内のモジュールを右クリックし、**Open All Modules** を選択します。

![DNSpy Logging - DNSpy Debugging: Modules 内のモジュールを右クリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内のモジュールを右クリックし、**Sort Assemblies** をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内のモジュールを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java デコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL のdebugging

### IDA を使う

- **rundll32 を読み込む**（64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debugger を選択する
- "**Suspend on library load/unload**" を選択する

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択します](<../../images/image (868).png>)

- 実行時の **parameters** を設定し、**DLL のパス** と呼び出す関数を指定します。

![Debugging DLLs - Using IDA: 実行時の parameters を設定し、DLL のパスと呼び出す関数を指定します](<../../images/image (704).png>)

debugging を開始すると、**DLL が読み込まれるたびに実行が停止します**。そのため、rundll32 が対象の DLL を読み込むと、実行が停止します。

この方法ではモジュールの読み込み時に停止しますが、読み込まれた DLL の entry point に到達するには、以下の x64dbg の手順を使う方法がより直接的です。

### x64dbg/x32dbg を使う

- **rundll32 を読み込む**（64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe）
- **Command Line を変更**し（_File --> Change Command Line_）、dll のパスと呼び出す関数を指定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- **実行を開始**すると、debugger は各 dll main で停止します。いずれ、**対象の dll の Entry で停止します**。そこから、breakpoint を設定したい箇所を探します。

win64dbg で何らかの理由により実行が停止した場合、**win64dbg のウィンドウ上部**を見ると、**どのコード内にいるか**を確認できます。

![Using IDA - Using x64dbg/x32dbg: 実行が何らかの理由で win64dbg により停止した場合、win64dbg のウィンドウ上部を見ると、どのコード内にいるかを確認できます](<../../images/image (842).png>)

この表示により、debugging 対象の DLL 内で実行が停止したことを確認できます。

## GUI アプリ / ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームの memory 内で重要な値が保存されている場所を探し、その値を変更するのに便利なプログラムです。詳しくは次を参照してください。

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、ゲームに特化した GNU Project Debugger (GDB) 用の front-end/reverse engineering ツールです。ただし、reverse engineering 関連のあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数の decompiler を利用できる web front-end です。この web service では、小さな実行ファイルに対する複数の decompiler の出力を比較できます。

## REA を使った、証拠に基づく native 調査

**REA** は、CLI と MCP を通じて Hopper、Ghidra、IDA の解析機能を提供します。Node.js 22.x（少なくとも 22.19）、24.x（少なくとも 24.11）、または 26 以降と、npm が必要です。まず既存の native provider を設定してください。`rea providers --json` を確認し、複数の provider が対象をサポートしている場合は、明示的に provider を選択します。以下の `0x1000` には、inventory から取得した関数名またはアドレスを指定します。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Start from a feature string or symbol, follow references and callers, then inspect the selected function dossier and pseudocode with `rea decompile`. REAは選択したproviderにsessionを紐付け、失敗後に黙って別のproviderへ切り替えることはありません。繰り返しクエリを実行する場合、`--snapshot PATH`はartifact bytes、provider、settings、operation、parametersが一致するものだけを再利用します。snapshotはローカルcacheであり、provider databaseを保存したものではありません。返されたEvidenceと明示的なunknownsを保持し、推測されたpathやdecompilerのテキストを元のsourceとして扱わないでください。<sup>[[16]](#references)[[18]](#references)</sup>

native add-onに至るJavaScript/Electronのentry pointについては、[Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea)を参照してください。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerでshellcodeをデバッグする

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**を割り当て、その**memory address**を表示して実行を一時停止します。\
IDAやx64dbgなどのdebuggerをアタッチし、表示されたaddressにbreakpointを設定して実行を再開すると、shellcodeをデバッグできます。

releasesのgithubページには、コンパイル済みreleaseを含むzipがあります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクからBlobrunnerを少し変更したバージョンを入手できます。コンパイルするには、**Visual Studio CodeでC/C++ projectを作成し、コードをコピー＆ペーストしてbuildする**だけです。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itでshellcodeをデバッグする

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerに似ています。shellcodeを割り当てて無限loopに入ります。debuggerをアタッチし、**2～5秒間**実行を再開してから、そのloop内で一時停止し、割り当てられたshellcodeへ実行を移す次のcallまでstep実行します。

![jmp2itの無限loop内で、割り当てられたshellcodeへのcall直前にdebuggerが一時停止している状態](<../../images/image (509).png>)

コンパイル済みの[jmp2itはreleasesページからダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterでshellcodeをデバッグする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使うとshellcodeをエミュレートし、動的に調査できます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。私の場合、shellcodeをfileとして開くと正しくdecompileされましたが、shellcodeとして開くと正しくdecompileされませんでした。

![同じbytesをfileとして開いた場合とshellcodeとして開いた場合で、異なる解析結果を表示するCutter](<../../images/image (562).png>)

エミュレーションを開始したい位置にbpを設定すると、Cutterはそこから自動的にエミュレーションを開始するようです。

![Cutterでエミュレーションを開始する前に、目的のshellcode entryにbreakpointを設定](<../../images/image (589).png>)

![選択したshellcode breakpointで一時停止しているCutter emulator](<../../images/image (387).png>)

たとえば、hex dump内でstackを確認できます。

![Cutterのhex dumpでエミュレートされたshellcodeのstackを表示](<../../images/image (186).png>)

### shellcodeをdeobfuscateして実行されたfunctionを取得する

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してください。\
shellcodeが使用している**function**や、メモリ内で自身を**decode**しているかどうかなどがわかります。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbgには、必要なオプションを選択してshellcodeを実行できるグラフィカルランチャーもあります。

![shellcodeのエミュレーションおよびトレースのオプションを選択するscDbgグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump** オプションを使うと、メモリ内でshellcodeが動的に変更された場合に、最終的なshellcodeをdumpできます（デコードされたshellcodeのダウンロードに便利です）。**start offset** を指定すると、特定のオフセットからshellcodeを実行できます。**Debug Shell** オプションを使うと、scDbgのターミナルでshellcodeをデバッグできます（ただし、この用途には前述のオプションのほうが適していると思います。Idaやx64dbgを使えるためです）。

### CyberChefを使った逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationのdeobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、`x + y` のような単純な式を、算術演算子（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた式で隠します。重要なのは、こうした恒等式が通常、**固定幅の剰余演算**でのみ成り立つという点です。そのため、桁上がりとオーバーフローが重要になります:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用の代数ツールで簡略化すると、ビット幅の意味論が無視されているため、簡単に誤った結果が得られます。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトしたコード／IR／デコンパイラ出力の**元のビット幅**（`8/16/32/64` bit）を維持する。
2. 簡略化を試みる前に、式を分類する：
   - **線形**：ビット演算の要素の重み付き和
   - **半線形**：`x & 0xFF` のような定数マスクを含む線形式
   - **多項式**：積を含む
   - **混合**：積とビット演算が交互に現れ、部分式が繰り返されることも多い
3. 候補となる書き換えはすべて、ランダムテストまたはSMT証明で検証する。同値性を証明できない場合は、推測で書き換えず、元の式を維持する。

### 狭い実行スライスでフラット化された制御フローをバイパスする

完全な制御フローグラフを復元する必要がないことはよくあります。control-flow flattening、opaque predicate、大規模なディスパッチャー、またはMBAを多用したコードの場合は、暗号化されたblobや出力バッファから参照をたどり、それらを変換する最小のルーチンを特定します。その後、そのデータフロースライスだけを再現するか、独立して実行します。関連する状態を直接初期化できるなら、ディスパッチャーは必要な解法に含める必要はありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、再配置、相互参照を一覧化する。`.rodata`から候補となるテーブルをダンプし、バイト順と要素幅を維持する。
2. 平文または出力バッファに最後に書き込むルーチンを特定する。その入力、参照されるテーブル、インポートされた呼び出し、必要なグローバル状態を記録する。
3. それらの操作だけを固定幅のPythonモデルにリフトする。スライスが依然として過剰な状態に依存する場合は、プログラム全体をエミュレートする代わりに、Unicorn、QEMU、またはデバッガー上でルーチンを呼び出し、無関係なインポートをフックする。
4. エクストラクターが実際に与えられたバイナリから出力を導出していることを検証する。無言のフォールバックを削除し、埋め込み済みの答えを検索し、文字列、キー、識別子、レイアウト、難読化シードを変更した未見のビルドで実行する。

最初に役立つコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装した MBA 式を検出する

一見すると入力に依存するバイト式でも、入力の影響が完全に相殺されている場合があります。テーブルを抽出した後、8 ビットの全領域で式を評価します。出力集合が単一の値であれば、周囲のステートマシンを復元しなくても、そのバイトが定数であると証明できます。<sup>[[7]](#references)</sup>

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

元の加算ではバイト幅でラップアラウンドするため、最後のマスクは残してください。より広い領域では、同じ幅の2つのシンボリック入力について `f(x1) != f(x2)` が充足可能かSMT solverに問い合わせます。`unsat`なら不変性が証明され、`sat`なら反例が得られるため、その入力を除外できないことを意味します。<sup>[[7]](#references)</sup>

#### 環境依存のデコードを見分ける

Anti-analysisチェックは、分岐やクラッシュを伴うとは限りません。デコーダはセンサーの結果をキーのビット、不透明述語の定数、またはフラット化されたディスパッチャの状態に混ぜ込み、正常に処理を続けながら、emulator内でそれらしく見えるが誤った平文を出力することがあります。そのため、目に見える失敗分岐だけをパッチするのでは不十分です。環境プローブからデコーダの状態へのデータ依存関係を追跡し、実機とemulatorで同じスライスを比較し、各センサーの結果を強制的に変えた場合に最終バッファがどう変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)は、malware analysisや保護されたバイナリのreversingに実用的なMBA簡略化ツールです。すべてに単一の汎用書き換え処理を適用するのではなく、式を分類し、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRAはBoolean入力で式を評価してsignatureを導出し、pattern matching、ANF変換、係数補間など複数の復元手法を並行して実行します。
- **Semilinear MBA**: 定数マスクされたatomは、マスク領域が正しく保たれるよう、ビット分割による再構成で復元されます。
- **Polynomial/Mixed MBA**: 積はコアに分解され、外側の関係を単純化する前に、繰り返し現れる部分式を一時変数に持ち上げることができます。

よく復元を試す価値のある、混合型の恒等式の例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のようにまとめられます:

```c
x * y
```

### Reversing notes

- 正確な計算を切り出した後、**lifted IR expressions** または decompiler の出力に対して CoBRA を実行するのがおすすめです。
- 式がマスク演算や狭いレジスタに由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な証明手順が必要な場合は、こちらの Z3 のメモを確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続の解析パスを実行する前に、MBA を多用した LLVM IR を正規化する場合に便利です。
- サポート対象外の、carry に依存する混合ドメインの残差が出た場合は、元の式を維持し、carry の経路を手動で解析する必要があることを示すものとして扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの操作を `mov` ベースの命令シーケンスに置き換え、signal/exception handling を利用して制御フローを変更します。詳細はこちら:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

サポート対象のバイナリであれば、[demovfuscator](https://github.com/kirschju/demovfuscator) で結果を deobfuscate できます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして [keystone をインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）。

**CTF をプレイしている場合、この回避策は flag を見つけるのにとても役立つ可能性があります**：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** を見つけるには、次のように `::main` で関数を検索します。

![Ghidra で関数名の double-colon main を検索して Rust の entry point を見つける](<../../images/image (1080).png>)

この場合、binary の名前は authenticator だったので、これが興味深い main function であることは明らかです。\
呼び出されている**関数**の**名前**が分かったら、**Internet** で検索して、それらの**入力**と**出力**を調べます。

### ELF firmware からの Rust strings の復元

**Rust ELF** binaries では、多くの static strings は C-style の NUL-terminated pointers として参照されません。一般的な `rustc` のレイアウトでは、**`.data.rel.ro`** 内の **pointer/length tuple** が、**`.rodata`** に格納された実際の string blob を指しています。

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

つまり、`strings` や Ghidra のデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりすることがあります。<sup>[[3]](#references)</sup>

簡単なワークフロー：

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得する。
2. **`.data.rel.ro`** を1ワードずつ列挙する。
3. `.rodata` のアドレス範囲内の値を、文字列ポインターの候補として扱う。
4. 次のワードを長さの候補として扱う。
5. 妥当性フィルターを適用する（例：長さが **4** ～ **100** バイトのものを残す）。
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

これは firmware reversing で特に有用です。復元された Rust strings から、**HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth 関連のロジック**が判明することがよくあります。

Ghidra がこれらの strings を見つけられない場合は、同じ heuristic を適用し、参照先の `.rodata` offsets に string data を作成する custom script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` は、このアイデアを他の **word sizes、endianness、section layouts** に応用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi でコンパイルされた binary には、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi binary を reverse する必要がある場合は、IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をおすすめします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin file を選択します。

この plugin は binary を実行し、debugging の開始時に function names を動的に解決します。debugging を開始したら、もう一度 Start ボタン（緑色のボタンまたは f9）を押すと、実際のコードの先頭で breakpoint が発生します。

グラフィカル application 内のボタンを押すと、debugger はそのボタンから呼び出された function で停止できます。

## Golang

一般的な Go binaries では、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使って runtime structures を復元し、IDA で function names を改善できます。**Alt+F7** で Python plugin を読み込みます。

Golang binary を reverse する必要がある場合は、IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をおすすめします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin file を選択します。

これにより function names が解決されます。

### symbol table を使わずに metadata を復元する

stripped Go executable でも、program counter を functions に対応付けるための runtime metadata が必要です。[GoReSym](https://github.com/mandiant/GoReSym) は Go runtime 由来の code を使って、`pclntab` や `moduledata` などの structures を検出して解析します。これにより、従来の symbol table に頼らず、function boundaries、names、source paths、types、build details を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

難読化ツールは、復元された名前を置き換えながら、これらの構造を利用可能な状態に保つことがあります。たとえば Garble は、識別子とパッケージパスをハッシュ化し、ビルド情報、モジュール情報、デバッグ情報を削除します。<sup>[[12]](#references)</sup> 難読化されたパッケージトークンは、そのパッケージ内の関数間で一貫している必要があります。繰り返し現れるトークンごとに関数をグループ化し、呼び出し先、文字列、APIからパッケージを1つ推定したら、そのパッケージ名をグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolverでGarbleの名前を復元する

[GoResolver](https://github.com/volexity/GoResolver)は、ランタイムシンボルの抽出、クリーンな参照バイナリの生成、制御フローグラフ（CFG）の照合を組み合わせます。次の手順を使います。<sup>[[10]](#references)[[13]](#references)</sup>

1. **コンパイラのバージョンを特定する。** まず`BuildInfo`と埋め込みバージョン文字列を確認します。難読化ツールによって削除されている場合は、同梱されたGoランタイムの一部を、バージョン別の参照ランタイムと比較します。Volexityのテストでは、ランタイムの約`2%`でGoのメジャーバージョンを判別できました。これは実験に基づく最適化であり、普遍的な基準ではありません。<sup>[[13]](#references)</sup>
2. **照合用の参照バイナリを用意する。** 特定したGoバージョン、ターゲットアーキテクチャ、使用されている可能性の高いライブラリに合わせて、クリーンなバイナリを生成します。ツールチェーンを一致させると、コンパイラが生成するCFGの差異を減らせます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapherは関数のCFGを照合し、`0.0`から`1.0`までの正規化スコアを出力します。基本ブロックの照合は、類似する命令を重み付けして比較します。信頼度の高い照合では、ランダム化された関数をクリーンな実装に対応付けられます。信頼度が低い照合でも、パッケージやモジュールの特定に役立つことがあります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** 呼び出し関係、定数、文字列、副作用を使って候補の名前を確認し、IDAまたはGhidra用のGoResolverプラグインでJSONレポートをインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

ツールチェーンをインストールし、抽出とグラフ照合をまとめて実行します。<sup>[[10]](#references)</sup>

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

デフォルトの有意一致しきい値は`0.9`です。`--extract`と`--graph`スイッチを使うと、どちらか一方の段階だけを実行できます。デフォルトでは両方を実行します。復元されたランタイムメタデータとCFGの証拠が互いに補完し合うためです。<sup>[[10]](#references)</sup> CFGスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わることがあるため、信頼度の低い名前を無理に付けず、未解決の関数はそのまま残してください。<sup>[[13]](#references)</sup>

### Go文字列テーブルの復元

Goバイナリでは、リンクされたすべてのパッケージの文字列データが1つの連続したテーブルに配置されます。各エントリはNUL終端されておらず、ランタイム構造体からテーブルのベースアドレスやサイズを特定することもできません。しかし、コンパイラはOSやアーキテクチャを問わず、エントリをまず長さ順、次にアルファベット順に並べます。そのため、1つのエントリを見つければ、隣接するエントリを順にたどり、データのクロスリファレンスを使って文字列とコードを関連付けられます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor)は、この作業をIDA ProとGhidraで自動化します。このプラグインはデータセグメントのクロスリファレンスに依存するため、まず自動解析を完了させてください。デフォルトのアンカーはランタイム文字列`entersyscall`です。その後、どちらの方向にもスキャンし、復元した文字列をデータベース内で定義して、文字列と参照元関数を対応付けたJSONを出力できます。<sup>[[14]](#references)</sup>

参照元関数のパッケージでレポートをフィルタリングすると、アプリケーションやマルウェアのコードを、リンクされたライブラリ由来のノイズから分離できます。この手法では、Garbleの`-literals`変換のような難読化によって破棄されたリテラルは復元できません。ただし、難読化されずに残っているランタイム文字列を整理することはできます。<sup>[[14]](#references)[[15]](#references)</sup>

### Goランタイム型の復元

Goには、ガベージコレクションなどの機能で使用されるランタイム型情報が埋め込まれています。ビルド情報が削除されていたり、逆アセンブラがこのメタデータを解析できなかったりすると、命令が任意のデータアドレスを読み込んでいるように見え、対象領域は型が未設定のままになります。メタデータを復元すると、それらのアドレスが読みやすい型参照に変わり、パッケージの機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver)は、シンボルを抽出し、ランタイム型を解析してJSONレポートに出力できます。現在のCLIでは、`resolve`サブコマンドを使用します。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types`オプションを有効にすると、型が解析されます。GoResolverのIDA ProまたはGhidra pluginでレポートをインポートし、復元された型を定義して、解析データベース内でそれらの参照を適用します。この機能で導入されたレポート形式では、`-y`を省略するとRTTIアドレスと復元された型のメンバーはnullになります。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolverはx86、AMD64、ARM、ARM64のPE、ELF、Mach-Oサンプルをサポートしているため、Windows、Linux、macOS向けのGoバイナリにも同じ手順を適用できます。<sup>[[10]](#references)</sup>

## コンパイル済みPython

このページでは、ELF/EXE形式のPythonコンパイル済みバイナリからPythonコードを取得する方法を紹介します:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBAゲームの**binary**を入手した場合、さまざまなツールを使って**emulate**および**debug**できます:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug versionをダウンロード_) - インターフェース付きのdebuggerを搭載
- [**mgba** ](https://mgba.io)- CLI debuggerを搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm)の_**Options --> Emulation Setup --> Controls**_** **では、Game Boy Advanceの**buttons**の押し方を確認できます

![Game Boy Advanceのボタン配置を示すno$gbaのコントロール設定](<../../images/image (581).png>)

押すと、各**keyには識別用の値**が割り当てられます:

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

この種のプログラムでは、注目すべき点は**プログラムがユーザー入力をどのように処理するか**です。アドレス **0x4000130** には、よく見られる関数 **KEYINPUT** があります。

![アドレス 0x4000130 の KEYINPUT を参照する GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることが確認できます。

この関数では、いくつかの初期化処理の後（重要ではないため省略します）：

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

最後のifは、**uVar4**が前回のKeysに含まれており、現在のキーではないことを確認しています。これはボタンを離した状態を表します（現在のキーは**uVar1**に格納されています）。

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

- まず、**値 4**（**SELECT**ボタン）と比較します。このチャレンジでは、このボタンを押すと画面が消去されます。
- 次に、値を **8**（**START**ボタン）と比較します。このチャレンジでは、この経路で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが 8 未満の間、押されたキーの値が `DAT_030000d8` に加算されます。

つまり、このチャレンジでは、**長さが 8 未満で、合計が 0xf3 になる組み合わせを押す必要がありました。**

**このチュートリアルの参考資料:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Rust文字列のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI支援によるReverse Engineeringを打ち破る、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matchingに基づくControl Flow Graphの比較手法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mechanism](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graphの類似性を利用したGoバイナリの自動deobfuscation](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang Toolingのアップデート](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものをReverse Engineerする](https://github.com/morluto/rea)
- [17] [REA managed-code analysis](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI and Evidence guide](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
