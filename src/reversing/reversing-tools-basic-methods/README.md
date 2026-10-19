# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのReversingツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbgのユーザーモード自動化

{{#ref}}
windbg-automation.md
{{#endref}}

## Windowsカーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasmデコンパイラ / Watコンパイラ

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使って、wasm（バイナリ）からwat（プレーンテキスト）に**デコンパイル**できます。
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使って、watからwasmに**コンパイル**できます。
- デコンパイルには[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8のキャッシュ済みバイトコード

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 仮想化されたペイロードとカスタムVM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NETデコンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、**ライブラリ**（.dll）、**Windowsメタデータファイル**（.winmd）、**実行ファイル**（.exe）など、複数の形式を**デコンパイルして調査**できるデコンパイラです。デコンパイルしたアセンブリは、Visual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、この機能によって時間を節約できます。さらにdotPeekは、デコンパイルしたコード内を簡単に移動できるため、**Xamarinのアルゴリズム解析**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を効率化します。このツールが提供する多彩なリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内のデータの流れを把握できます。
- .NET言語やフレームワークの実装と使用方法を確認できます。
- ドキュメント化されていない機能や公開されていない機能を見つけ、使用中のAPIやテクノロジーをさらに活用できます。
- 依存関係や各種アセンブリを見つけられます。
- コード、サードパーティ製コンポーネント、ライブラリで発生したエラーの正確な位置を特定できます。
- 使用しているすべての.NETコードのソースをデバッグできます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) と [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): どのOSでも利用できます（VSCodeから直接インストールできるため、gitをダウンロードする必要はありません。**Extensions**をクリックし、**ILSpy**を検索してください）。\
**デコンパイル**して**変更**し、再度**コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)、または現在もメンテナンスされているそのフォークである[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内を変更するには、**Right Click -> Modify Method**を選択してください。）

### REAによる実行不要のマネージドコード検査

**REA**はアセンブリを読み込まずに、PE/CLIメタデータとCILを検査できます。まずアーティファクトの識別情報を確認し、次にメンバーと宣言されたネイティブ境界を調べます。デコンパイラを使ったりプログラムを実行したりする前に、不審な呼び出しを調査する際に役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン差分比較では、`compare_managed_members` はメタデータトークンがビルド間で安定しているものとして扱わず、生の CIL/シグネチャの同一性とデコード済み命令のフィンガープリントを使用します。P/Invoke 宣言はネイティブコードが実行された証拠にはなりません。その境界を確認するには、`verify_managed_native_boundaries` に一致するネイティブエクスポートまたは関数の Evidence が必要です。アーティファクトのダイジェスト、MVID、未解決のマッピングを結果とともに保持してください。<sup>[[17]](#references)</sup>

### DNSpy のログ記録

**DNSpy にファイルへ情報を記録させる**には、次のスニペットを使用できます。:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy のデバッグ

DNSpy を使ってコードをデバッグするには、次の操作が必要です。

まず、**デバッグ**に関連する **Assembly 属性**を変更します。

![DNSpy Logging - DNSpy のデバッグ: まず、デバッグに関連する Assembly 属性を変更します](<../../images/image (973).png>)

次の状態から：

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これを行う必要があるのは、そうしないと **runtime** にコードに対していくつかの **optimisations** が適用され、デバッグ中に **break-point が一度もヒットしない**、または **一部の変数が存在しない** 可能性があるためです。

次に、.NET アプリケーションが **IIS** によって **実行** されている場合は、次のコマンドで **再起動** できます:

```
iisreset /noforce
```

その後、debuggingを開始するには、開いているファイルをすべて閉じ、**Debug Tab**で**Attach to Process...**を選択します。

![DNSpy Logging - DNSpy Debugging: debuggingを開始するには、開いているファイルをすべて閉じ、Debug TabでAttach to Processを選択します](<../../images/image (318).png>)

次に、**IIS server**にattachするために**w3wp.exe**を選択し、**attach**をクリックします。

![DNSpy Logging - DNSpy Debugging: IIS serverにattachするためにw3wp.exeを選択し、attachをクリックします](<../../images/image (113).png>)

プロセスをdebuggingできる状態になったので、停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingできる状態になったので、停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、次にDebug Windows Modulesをクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingできる状態になったので、停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、次にDebug Windows Modulesをクリックします](<../../images/image (834).png>)

**Modules**内の任意のモジュールをクリックし、**Open All Modules**を選択します。

![DNSpy Logging - DNSpy Debugging: Modules内の任意のモジュールをクリックし、Open All Modulesを選択します](<../../images/image (922).png>)

**Assembly Explorer**内の任意のモジュールを右クリックし、**Sort Assemblies**をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer内の任意のモジュールを右クリックし、Sort Assembliesをクリックします](<../../images/image (339).png>)

## Javaデコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのdebugging

### IDAを使用する

- **rundll32を読み込む**（64bit版はC:\Windows\System32\rundll32.exe、32bit版はC:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debuggerを選択する
- "**Suspend on library load/unload**"を選択する

![Debugging DLLs - Using IDA: " Suspend on library load/unload "を選択します](<../../images/image (868).png>)

- 実行の**parameters**を設定し、**DLLのパス**と呼び出す関数を指定します。

![Debugging DLLs - Using IDA: 実行のparametersを設定し、DLLのパスと呼び出す関数を指定します](<../../images/image (704).png>)

debuggingを開始すると、**各DLLが読み込まれるときに実行が停止します**。そのため、rundll32がDLLを読み込むと、実行が停止します。

この方法ではモジュールの読み込みイベントで停止しますが、読み込まれたDLLのentry pointに到達する手順は、以下のx64dbgの方法より直接的ではありません。

### x64dbg/x32dbgを使用する

- **rundll32を読み込む**（64bit版はC:\Windows\System32\rundll32.exe、32bit版はC:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更する**（_File --> Change Command Line_）。DLLのパスと呼び出す関数を指定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_を変更し、"**DLL Entry**"を選択します。
- **実行を開始すると**、debuggerは各dll mainで停止します。何度か停止した後、**対象DLLのDLL Entryで停止します**。そこから、breakpointを設定したい箇所を探してください。

win64dbgで何らかの理由により実行が停止したときは、**win64dbgウィンドウの上部**を見ると、**どのコード内にいるか**確認できます。

![Using IDA - Using x64dbg/x32dbg: win64dbgで何らかの理由により実行が停止したときは、win64dbgウィンドウの上部を見ると、どのコード内にいるか確認できます](<../../images/image (842).png>)

この表示により、debugging対象のDLL内で実行が停止したことを確認できます。

## GUIアプリ / ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内で重要な値が保存されている場所を探し、その値を変更するのに便利なプログラムです。詳しくは以下を参照してください。

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)は、ゲームに特化したGNU Project Debugger (GDB)用のフロントエンド / reverse engineeringツールです。ただし、reverse engineeringに関連するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/)は、複数のデコンパイラを利用できるWebフロントエンドです。このWebサービスでは、小さな実行ファイルに対する各デコンパイラの出力を比較できます。

## REAを使った、証拠に基づくネイティブ調査

**REA**は、Hopper、Ghidra、IDAの解析機能をCLIおよびMCP経由で利用できるようにします。Node.js 22.x（少なくとも22.19）、24.x（少なくとも24.11）、または26以降と、npmが必要です。まず既存のnative providerを設定してください。`rea providers --json`を確認し、対象をサポートするproviderが複数ある場合は、明示的に選択します。以下では、`0x1000`の代わりに、インベントリで確認した関数名またはアドレスを使用してください。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

機能文字列またはシンボルから始め、参照先や呼び出し元をたどり、選択した関数の dossier と擬似コードを `rea decompile` で確認します。REA は選択した provider にセッションを紐付け、失敗後に provider を黙って切り替えることはありません。クエリを再現可能にするには、`--snapshot PATH` を指定します。これは、artifact bytes、provider、settings、operation、parameters が一致する場合に限り再利用されます。snapshot はローカルキャッシュであり、provider のデータベースを保存するものではありません。返された Evidence と明示された unknowns を保持し、推定されたパスや decompiler のテキストを元のソースとして扱わないでください。<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron のエントリーポイントから native add-on へたどる方法については、[Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) を参照してください。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### BlobRunner を使った shellcode のデバッグ

[**BlobRunner**](https://github.com/OALabs/BlobRunner) は **shellcode** をメモリに割り当て、その **メモリアドレス** を表示して実行を一時停止します。\
IDA や x64dbg などの debugger をアタッチし、表示されたアドレスに breakpoint を設定して実行を再開し、shellcode をデバッグします。

releases の GitHub ページには、コンパイル済みのリリースを含む zip があります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクから、少し変更を加えた Blobrunner を入手できます。コンパイルするには、**Visual Studio Code で C/C++ プロジェクトを作成し、コードをコピーして貼り付け、ビルドしてください**。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it を使った shellcode のデバッグ

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) は BlobRunner と似ています。shellcode をメモリに割り当てて無限ループに入ります。debugger をアタッチし、**2～5 秒間**実行を再開してから、そのループ内で一時停止します。続いて、割り当てられた shellcode に実行を移す次の call までステップ実行します。

![jmp2it の無限ループ内で、割り当てられた shellcode への call の直前に debugger が一時停止している状態](<../../images/image (509).png>)

コンパイル済みの [jmp2it は releases ページからダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutter を使った shellcode のデバッグ

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) は radare の GUI です。Cutter を使うと、shellcode をエミュレートして動的に調査できます。

Cutter では「Open File」と「Open Shellcode」を選べます。同じ shellcode でも、私の環境ではファイルとして開くと正しく decompile されましたが、shellcode として開くと正しく処理されませんでした。

![同じバイト列をファイルまたは shellcode として開いたときに、異なる解析結果を表示する Cutter](<../../images/image (562).png>)

エミュレーションを開始したい場所に breakpoint を設定すると、Cutter はそこから自動的にエミュレーションを開始するようです。

![Cutter のエミュレーションを開始する前に、shellcode の目的のエントリーポイントに breakpoint を設定](<../../images/image (589).png>)

![選択した shellcode の breakpoint で一時停止した Cutter emulator](<../../images/image (387).png>)

たとえば、hex dump 内で stack を確認できます。

![Cutter の hex dump で、エミュレートされた shellcode の stack を表示](<../../images/image (186).png>)

### shellcode の難読化解除と実行された関数の特定

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試してください。\
shellcode が使用している **関数** や、メモリ内で自身を **decode** しているかどうかなどが分かります。

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

**Create Dump**オプションを使うと、メモリ内でshellcodeに動的な変更が加えられた場合、変更後のshellcodeをダンプできます（デコードされたshellcodeの取得に便利です）。**start offset**を指定すると、特定のオフセットからshellcodeを開始できます。**Debug Shell**オプションでは、scDbgのターミナルを使ってshellcodeをデバッグできます（ただし、この用途には前述のオプションのほうが適していると思います。Idaやx64dbgを使用できるためです）。

### CyberChefを使用した逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします。[https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、算術演算子（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた数式で、`x + y`のような単純な式を隠します。重要なのは、こうした恒等式が通常、**固定幅の剰余演算**でのみ正しく成り立つことです。そのため、キャリーとオーバーフローが重要になります。

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用的な代数ツールで簡略化すると、bit-width の意味論が無視され、誤った結果になりやすいです。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. **元の bit-width を維持する**（lift されたコード／IR／decompiler の出力にある `8/16/32/64` bits）。
2. 簡略化を試みる前に、式を分類する:
   - **Linear**: bitwise atom の重み付き和
   - **Semilinear**: `x & 0xFF` のような定数 mask と linear の組み合わせ
   - **Polynomial**: 積が含まれる
   - **Mixed**: 積と bitwise logic が交互に現れ、同じ部分式が繰り返し使われることが多い
3. ランダムテストまたは SMT proof ですべての書き換え候補を検証する。同値性を証明できない場合は、推測で書き換えず、元の式を維持する。

### narrow execution slice で flatten された control flow を回避する

完全な control-flow graph の復元は、多くの場合不要です。control-flow flattening、opaque predicate、大規模な dispatcher、または MBA-heavy code がある場合は、暗号化された blob や output buffer への参照をたどり、それらを変換する最小の routine を特定します。その data-flow slice だけを再現するか、単独で実行します。関連する state を直接初期化できるなら、dispatcher は解決に必要ありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです:<sup>[[7]](#references)</sup>

1. executable と data section、relocation、cross-reference を調べます。byte order と element width を維持しながら、`.rodata` から候補となる table を dump します。
2. plaintext または output buffer に最後に書き込む routine を特定します。その入力、参照される table、import された call、必要な global state を記録します。
3. その操作だけを fixed-width の Python model に lift します。slice が依然として多くの state に依存する場合は、プログラム全体を emulation する代わりに、Unicorn、QEMU、または debugger で routine を呼び出し、不要な import を hook します。
4. extractor が実際に与えられた binary から出力を導出していることを検証します。暗黙の fallback を削除し、埋め込み回答を検索して、string、key、identifier、layout、obfuscation seed が異なる未知の build で実行します。

最初に使えるコマンドは次のとおりです:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装した MBA 式を検出する

一見入力に依存するバイト式でも、入力が完全に相殺されることがあります。テーブルを抽出した後、式を 8 ビットの全領域で評価します。出力集合が単一要素なら、周囲の状態機械を復元せずに、そのバイトが定数であると証明できます。<sup>[[7]](#references)</sup>

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

元の加算では byte 幅のラップアラウンドが発生するため、最後のマスクは残してください。より広い領域では、同じ幅の記号入力 `x1` と `x2` に対して `f(x1) != f(x2)` が充足可能か SMT solver に問い合わせます。`unsat` なら不変性が証明され、`sat` なら反例が得られるため、その入力は除外できません。<sup>[[7]](#references)</sup>

#### 環境に依存するデコードを見分ける

Anti-analysis チェックは、分岐やクラッシュを起こすとは限りません。decoder はセンサーの結果を鍵ビット、不透明述語の定数、または平坦化された dispatcher の状態に混ぜ、正常に処理を続けながら、emulator 内でそれらしく見える偽の平文を生成することがあります。そのため、目に見える失敗分岐だけを patch しても不十分です。環境プローブから decoder の状態に至るデータ依存関係を追跡し、実機と emulator で同じスライスを比較し、各センサーの結果を強制的に変えたときに最終バッファがどう変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis や保護された binary の reversing に実用的な MBA simplifier です。式を分類し、すべてに同じ汎用の書き換えパスを適用するのではなく、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA は Boolean 入力で式を評価して signature を導出し、pattern matching、ANF 変換、係数補間など複数の復元手法を並行して実行します。
- **Semilinear MBA**: 定数マスクされた atom は bit-partitioned reconstruction で再構築され、マスクされた領域が正しく保たれます。
- **Polynomial/Mixed MBA**: 積を core に分解し、繰り返し現れる部分式を一時変数に置き換えてから、外側の関係を簡約できます。

復元を試す価値がある、よくある mixed identity の例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のように簡略化できます:

```c
x * y
```

### Reversing のメモ

- CoBRA は、正確な計算箇所を特定した後の **lifted IR expressions** または decompiler の出力に対して実行するのがおすすめです。
- 式がマスク演算または narrow registers 由来の場合は、`--bitwidth` を明示的に指定してください。
- より強力な証明ステップが必要な場合は、こちらの Z3 のメモを確認してください。


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA には **LLVM pass plugin** (`libCobraPass.so`) も付属しており、後続の解析パスの前に MBA を多用する LLVM IR を正規化したい場合に便利です。
- 未対応の carry-sensitive mixed-domain residuals が見つかった場合は、元の式を維持し、carry path を手動で解析する必要があるというサインとして扱ってください。

## XOR-state control-flow flattening の復元

OLLVM-style flattener は、現在の basic-block state を2つの64-bit registersに保持し、dispatcher で XOR を使って再構築することがあります。各元ブロックは次の state のペアを書き込み、dispatcher に戻ります。条件付きブロックでは、CPU flags に応じてペアの片方を置き換えるために `CMOVcc` を使用することがあり、目に見える branch instructions だけを追うと2つの successor を見落とします。indirect-jump dispatcher とは異なり、この形式では全体を通じて direct back-edges を使用できます。<sup>[[19]](#references)[[20]](#references)</sup>

グラフを復元するには、dispatcher の比較ツリーと2つの state registers を特定し、比較される各 XOR state を対応する target block にマッピングしてから、各元ブロックで register pair に到達する書き込みを追跡します。条件付き書き込みの場合は、flags を設定する instruction と `CMOVcc` の両方の結果を含めてください。各ブロックの dispatcher への exit を、解決した direct successor または conditional branch に書き換えると、binary を patch せずに dispatcher を到達不能にできます。これは full-CFG アプローチです。特定の decoder だけが対象なら、上記の [narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice) のほうが速い場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) は、この形式を Binary Ninja で自動処理します。`plugins/DispatchThis` を Binary Ninja のユーザー plugin ディレクトリにコピーして、再起動してください。対象の function で **Function Settings** を開き、`OLLVM_XOR_64` を選択します。解析が始まらない場合は、**Analysis → Reanalyze All Functions** を実行してください。この mode は MLIL の control-flow edges を書き換えるもので、ファイルの bytes は変更せず、Z3 も indirect-jump resolver も必要としません。Binary Ninja 5.3.9757+ で動作確認済みです。ブロックごとの不要な state writes は削除されないため、これらを残った live transitions と誤認しないでください。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの演算を `mov` ベースの instruction sequences に置き換え、signal/exception handling を使って control flow を変更します。詳細はこちらを参照してください。

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応する binary であれば、[demovfuscator](https://github.com/kirschju/demovfuscator) を使って結果を deobfuscate できます。いくつかの dependencies が必要です。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）。

**CTFをプレイしている場合、このフラグを見つけるための回避策**が役立つかもしれません：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリポイント**を見つけるには、次のように関数名を`::main`で検索します。

![Ghidraで関数名のダブルコロン付きmainを検索してRustのエントリポイントを見つける](<../../images/image (1080).png>)

この場合、バイナリ名はauthenticatorだったため、注目すべきmain関数は明らかです。\
呼び出されている**関数**の**名前**がわかったら、**インターネット**で検索して、それらの**入力**と**出力**を調べましょう。

### ELFファームウェアからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列がCスタイルのNUL終端ポインタから参照されていません。一般的な`rustc`のレイアウトでは、**`.data.rel.ro`**内の**ポインタと長さのタプル**が、**`.rodata`**に格納された実際の文字列データを指しています。

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

これは、`strings`やGhidraのデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりする可能性があるということです。<sup>[[3]](#references)</sup>

手早い作業手順:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`**の仮想アドレスとサイズを取得します。
2. **`.data.rel.ro`**を1ワードずつ列挙します。
3. `.rodata`のアドレス範囲内にある値を、文字列ポインタの候補として扱います。
4. 次のワードを、候補の長さとして扱います。
5. 妥当性フィルターを適用します（例：長さが**4**～**100**バイトのものを残します）。
6. `0x00`までスキャンするのではなく、`.rodata`から`length`バイトを正確に読み取ります。

最小限の抽出ロジック:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

これは、復元された Rust 文字列から **HTTP ルート、RPC 名、ログメッセージ、アサーション、ファイル名、設定キー、コマンドハンドラー、認証関連のロジック**が見つかることが多いため、ファームウェアのリバースエンジニアリングで特に役立ちます。

Ghidra がこれらの文字列を見つけられない場合は、同じヒューリスティックを適用し、参照先の `.rodata` オフセットに文字列データを作成するカスタムスクリプト／プラグインを実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` は、このアイデアを他の **ワードサイズ、エンディアン、セクションレイアウト**に適用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi でコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi バイナリをリバースエンジニアリングする場合は、IDA プラグイン [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をおすすめします。

IDA で **Alt+F7** を押して Python プラグインを読み込み、プラグインファイルを選択します。

このプラグインはバイナリを実行し、デバッグ開始時に関数名を動的に解決します。デバッグを開始した後、もう一度 Start ボタン（緑色のボタン、または f9）を押すと、実際のコードの先頭でブレークポイントにヒットします。

グラフィカルアプリケーション内のボタンを押すと、デバッガーがそのボタンによって呼び出された関数で停止することがあります。

## Golang

通常の Go バイナリでは、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使ってランタイム構造を復元し、IDA で関数名を改善できます。**Alt+F7** で Python プラグインを読み込みます。

Golang バイナリをリバースエンジニアリングする場合は、IDA プラグイン [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をおすすめします。

IDA で **Alt+F7** を押して Python プラグインを読み込み、プラグインファイルを選択します。

これにより、関数名が解決されます。

### シンボルテーブルなしでメタデータを復元する

strip された Go 実行ファイルでも、プログラムカウンターを関数に対応付けるためのランタイムメタデータが必要です。[GoReSym](https://github.com/mandiant/GoReSym) は、Go ランタイム由来のコードを使って `pclntab` や `moduledata` などの構造を特定し、解析します。これにより、従来のシンボルテーブルに依存せずに、関数の境界、名前、ソースパス、型、ビルド情報を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

obfuscatorは、復元された名前を置き換えながら、これらの構造を利用可能な状態に保つことがあります。たとえばGarbleは、識別子とpackage pathをハッシュ化し、build、module、debug情報を削除します。<sup>[[12]](#references)</sup> 難読化されたpackage tokenは、そのpackage内の関数間で一貫している必要があります。繰り返し現れるtokenで関数をグループ化し、そのcallees、文字列、APIからpackageを1つ推定して、そのpackageラベルをグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolverでGarbleの名前を復元する

[GoResolver](https://github.com/volexity/GoResolver)は、runtime symbolの抽出、クリーンな参照バイナリの生成、control-flow graph（CFG）の照合を組み合わせます。次の手順を使います。<sup>[[10]](#references)[[13]](#references)</sup>

1. **compilerのバージョンを特定する。** まず`BuildInfo`と埋め込みのバージョン文字列を確認します。obfuscatorによって削除されている場合は、同梱されたGo runtimeの一部を、バージョンが分かっている参照runtimeと比較します。Volexityのテストでは、runtimeの約`2%`でGoのメジャーバージョンを識別できました。これは経験に基づく最適化であり、普遍的な閾値ではない点に注意してください。<sup>[[13]](#references)</sup>
2. **照合用の参照バイナリを作成する。** 特定したGoのバージョン、target architecture、可能性の高いlibrary向けに、クリーンなバイナリを生成します。toolchainを一致させることで、compilerが生成するCFGの差異を抑えられます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapherは関数のCFGを照合し、`0.0`から`1.0`の正規化されたスコアを出力します。basic blockの照合は、類似した命令の重み付き比較に基づいています。信頼度の高い照合結果は、ランダム化された関数をクリーンな実装に対応付けます。信頼度が低い照合結果でも、packageまたはmoduleの特定に役立つ場合があります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** call relationship、定数、文字列、副作用を使って推定された名前を確認し、その後、IDAまたはGhidra用のGoResolver pluginでJSONレポートをインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

toolchainをインストールし、extractorとgraph matcherを組み合わせて実行します。<sup>[[10]](#references)</sup>

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

デフォルトの有意一致しきい値は `0.9` です。`--extract` と `--graph` スイッチを使うと、どちらか一方のステージだけを実行できます。デフォルトでは、復元された runtime metadata と CFG の証拠が互いを補完するため、両方を実行します。<sup>[[10]](#references)</sup> CFG のスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わる可能性があるため、信頼度の低い名前を無理に割り当てず、未解決の関数はそのままにしてください。<sup>[[13]](#references)</sup>

### Go string table の復元

Go バイナリでは、リンクされたすべてのパッケージの文字列バイトが、1つの連続したテーブルに格納されます。各エントリは NUL 終端ではなく、runtime の構造体からテーブルのベースアドレスやサイズを取得することもできません。しかし、コンパイラは OS やアーキテクチャを問わず、まず長さ順、次にアルファベット順でエントリを並べます。そのため、1つのエントリを見つければ、アナリストは隣接するエントリをたどり、データの cross-reference を使って文字列とコードを関連付けられます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) は、IDA Pro と Ghidra でこの作業を自動化します。このプラグインはデータセグメントの cross-reference に依存するため、まず自動解析を完了させてください。デフォルトのアンカーは runtime 文字列 `entersyscall` です。そこからどちらの方向にもスキャンし、復元した文字列をデータベースに定義して、文字列と参照元の関数を対応付けた JSON をエクスポートできます。<sup>[[14]](#references)</sup>

参照元の関数のパッケージでレポートを絞り込み、アプリケーションやマルウェアのコードと、リンクされたライブラリ由来のノイズを分離します。この手法では、Garble の `-literals` 変換のような難読化によって破壊されたリテラルは復元できません。ただし、難読化されていない runtime 文字列を整理する用途には引き続き使えます。<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime type の復元

Go には、garbage collection などの機能で使われる runtime type 情報が埋め込まれています。ビルド情報が削除されている場合や、逆アセンブラがこのメタデータを解析できない場合、命令は任意のデータアドレスを読み込んでいるように見え、対象領域も型なしのままになります。メタデータを復元すると、これらのアドレスが読みやすい型参照に変わり、パッケージの機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) は、シンボルを抽出し、runtime type を解析して JSON レポートに出力できます。現在の CLI では `resolve` サブコマンドを使用します。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` オプションを有効にすると、型解析が行われます。GoResolver の IDA Pro または Ghidra plugin でレポートをインポートし、復元された型を定義して、その参照を解析データベースに適用します。この機能で導入されたレポート形式では、`-y` を省略すると RTTI アドレスと復元された型のメンバーは null のままになります。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver は x86、AMD64、ARM、ARM64 の PE、ELF、Mach-O サンプルをサポートしているため、Windows、Linux、macOS の Go バイナリにも同じワークフローを適用できます。<sup>[[10]](#references)</sup>

## コンパイル済み Python

このページでは、ELF/EXE の Python コンパイル済みバイナリから Python コードを取得する方法を紹介します。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの **binary** を入手した場合、さまざまなツールを使って **emulate** および **debug** できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug 版をダウンロード_) - インターフェース付きの debugger を搭載
- [**mgba** ](https://mgba.io)- CLI debugger を搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **ボタン**の押し方を確認できます。

![Game Boy Advance のボタン割り当てを表示する no$gba のコントロール設定](<../../images/image (581).png>)

押すと、それぞれの **key に識別用の値**が割り当てられます。

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

![アドレス 0x4000130 で KEYINPUT を参照している GBA バイナリの Ghidra ビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

この関数では、（特に重要ではない）いくつかの初期化処理の後に:

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

最後のifは、**`uVar4`**が**最後のKeys**に含まれていて、現在のキーではないことを確認しています。これはボタンを離したときの状態です（現在のキーは**`uVar1`**に格納されています）。

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

- まず、**値 4**（**SELECT**ボタン）と比較しています。このチャレンジでは、このボタンを押すと画面がクリアされます。
- 次に、値を **8**（**START**ボタン）と比較しています。このチャレンジでは、この処理経路で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** を 0xf3 と比較し、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）を確認してインクリメントします。\
  カウンターが 8 未満の間は、押されたキーの値が `DAT_030000d8` に加算されます。

つまり、このチャレンジでは、各ボタンの値を把握したうえで、**長さが 8 未満で、合計が 0xf3 になる組み合わせを押す必要がありました。**

**このチュートリアルの参考資料:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (バイナリの難読化解除)

## References

- [1] [CoBRAを使ったMBA難読化の簡素化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRAリポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rust文字列のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBAリバースエンジニアリングチュートリアル（アーカイブ版）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI支援リバースエンジニアリングを打ち破る、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [基本ブロックのマッチングに基づく制御フローグラフ比較手法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolverリポジトリ](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garbleの難読化メカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: 制御フローグラフの類似性を使ってGoバイナリを自動的に難読化解除する](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractorリポジトリ](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: VolexityのGolangツールのアップデート](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものをリバースエンジニアリング](https://github.com/morluto/rea)
- [17] [REAのマネージドコード解析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLIおよびエビデンスガイド](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninjaの制御フロー平坦化解除ワークフロー](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MFのゼロデイ侵入、Javaローダー、Webシェル、AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
{{#include ../../banners/hacktricks-training.md}}
