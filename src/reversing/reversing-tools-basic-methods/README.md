# Reversingツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのReversingツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbgのユーザーモード自動化

{{#ref}}
windbg-automation.md
{{#endref}}

## Windowsの例外駆動型制御フロー

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windowsカーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasmデコンパイラー / Watコンパイラー

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使って、wasm（バイナリ）からwat（読みやすいテキスト）に**逆コンパイル**できます
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使って、watからwasmに**コンパイル**できます
- 逆コンパイルには[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

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

## .NETデコンパイラー

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、**ライブラリ**（.dll）、**Windowsメタデータファイル**（.winmd）、**実行ファイル**（.exe）など、複数の形式を**逆コンパイルして調査**するデコンパイラーです。逆コンパイル後、アセンブリをVisual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、この機能によって時間を節約できます。さらに、dotPeekは逆コンパイルしたコード内を簡単に移動できるため、**Xamarinのアルゴリズム解析**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を効率化します。このツールが提供する豊富なリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内のデータの流れを把握できます
- .NET言語やフレームワークの実装と使い方を把握できます
- ドキュメント化されていない機能や公開されていない機能を見つけ、APIや使用中のテクノロジーをより活用できます。
- 依存関係や異なるアセンブリを見つけます
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な位置を特定します。
- 使用するすべての.NETコードのソースをデバッグできます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): あらゆるOSで利用できます（VSCodeから直接インストールでき、gitをダウンロードする必要はありません。**Extensions**をクリックし、**ILSpy**を検索してください）。\
**逆コンパイル**、**変更**、再度の**コンパイル**が必要な場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または現在もメンテナンスされているフォークの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内を変更するには、**右クリック -> Modify Method**を選択します）。

### REAによる実行不要のマネージドコード検査

**REA**はアセンブリをロードせずに、PE/CLIメタデータとCILを検査できます。まずアーティファクトの識別情報を確認し、次にメンバーと宣言されたネイティブ境界を調べます。デコンパイラーを使ったりプログラムを実行したりする前に、疑わしい呼び出しを調査するのに役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン差分では、`compare_managed_members` は、metadata token がビルド間で安定しているものとして扱うのではなく、raw CIL/signature identity と decoded-instruction fingerprints を使用します。P/Invoke 宣言は native code が実行された証拠にはなりません。境界を確認するには、`verify_managed_native_boundaries` で一致する native export または function Evidence が必要です。artifact digest、MVID、未解決のマッピングを結果とともに保持してください。<sup>[[17]](#references)</sup>

### DNSpy Logging

**DNSpy に情報をファイルへ記録させる**には、次の snippet を使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy デバッグ

DNSpyでコードをデバッグするには、次の操作が必要です。

まず、**デバッグ**に関連する**Assembly属性**を変更します。

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: compile をクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します:

![DNSpy Logging - DNSpy Debugging: File Save module から新しいファイルを保存](<../../images/image (602).png>)

これを行う必要があるのは、そうしないと **runtime** にコードにいくつかの **optimisations** が適用され、デバッグ中に **break-point に到達しない**、または **変数が存在しない**可能性があるためです。

.NET アプリケーションが **IIS** によって **実行**されている場合は、次のコマンドで **再起動**できます:

```
iisreset /noforce
```

その後、デバッグを開始するには、開いているファイルをすべて閉じ、**Debug Tab** で **Attach to Process...** を選択します。

![DNSpy Logging - DNSpy Debugging: デバッグを開始するには、開いているファイルをすべて閉じ、Debug Tab で Attach to Process を選択します](<../../images/image (318).png>)

次に **w3wp.exe** を選択して **IIS server** にアタッチし、**attach** をクリックします。

![DNSpy Logging - DNSpy Debugging: w3wp.exe を選択して IIS server にアタッチし、attach をクリックします](<../../images/image (113).png>)

プロセスをデバッグしているので、停止してすべてのモジュールを読み込む準備ができました。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしているので、停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしているので、停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意のモジュールをクリックし、**Open All Modules** を選択します。

![DNSpy Logging - DNSpy Debugging: Modules 内の任意のモジュールをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のモジュールを右クリックし、**Sort Assemblies** をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のモジュールを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java デコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL のデバッグ

### IDA を使用する

- **rundll32 を読み込む**（64bit 版は C:\Windows\System32\rundll32.exe、32bit 版は C:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debugger を選択する
- "**Suspend on library load/unload**" を選択する

![Debugging DLLs - Using IDA: "Suspend on library load/unload" を選択します](<../../images/image (868).png>)

- 実行の **parameters** を設定し、**DLL のパス** と呼び出したい関数を指定します。

![Debugging DLLs - Using IDA: DLL のパスと呼び出したい関数を指定して、実行の parameters を設定します](<../../images/image (704).png>)

その後、デバッグを開始すると **DLL が読み込まれるたびに実行が停止します**。rundll32 が DLL を読み込むと、実行が停止します。

この方法ではモジュールの読み込みイベントで停止しますが、読み込まれた DLL のエントリポイントに到達する手順は、以下の x64dbg のワークフローより直接的ではありません。

### x64dbg/x32dbg を使用する

- **rundll32 を読み込む**（64bit 版は C:\Windows\System32\rundll32.exe、32bit 版は C:\Windows\SysWOW64\rundll32.exe）
- **Command Line を変更**（_File --> Change Command Line_）し、DLL のパスと呼び出したい関数を設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- **実行を開始**すると、debugger は各 DLL の main で停止します。そのうち、**対象 DLL の DLL Entry で停止**します。そこから、breakpoint を設定したい箇所を探してください。

win64dbg で何らかの理由により実行が停止したとき、**win64dbg ウィンドウの上部**を見ると、**どのコード内にいるか**が分かります。

![Using IDA - Using x64dbg/x32dbg: 何らかの理由で実行が停止したとき、win64dbg ウィンドウの上部を見ると、どのコード内にいるかが分かります](<../../images/image (842).png>)

この表示により、デバッグ対象の DLL 内で実行が停止したことを確認できます。

## GUI アプリ / ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内で重要な値が保存されている場所を探し、値を変更するのに便利なプログラムです。詳しくは以下を参照してください。

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、ゲームに特化した GNU Project Debugger (GDB) のフロントエンド / reverse engineering tool です。ただし、reverse-engineering に関連するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数のデコンパイラを利用できる web フロントエンドです。この web サービスでは、小さな実行ファイルに対する各デコンパイラの出力を比較できます。

## REA を使った、証拠に基づくネイティブ調査

**REA** は、CLI と MCP を通じて Hopper、Ghidra、IDA の解析機能を提供します。Node.js 22.x（少なくとも 22.19）、24.x（少なくとも 24.11）、または 26 以降と npm が必要です。まず既存のネイティブ provider を設定してください。`rea providers --json` を確認し、対象をサポートする provider が複数ある場合は、明示的に選択します。以下の `0x1000` の代わりに、インベントリで確認した関数名またはアドレスを使用してください。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

feature string または symbol から開始し、references と callers をたどってから、選択した関数の dossier と pseudocode を `rea decompile` で調べます。REA は選択した provider に session を紐付け、失敗しても暗黙に別の provider に切り替えません。クエリを再現可能にするには、`--snapshot PATH` を指定すると、一致する artifact bytes、provider、settings、operation、parameters の場合に限って再利用します。snapshot はローカル cache であり、provider database を保存したものではありません。返された Evidence と明示された unknowns を保持し、推定された paths や decompiler のテキストを元の source として扱わないでください。<sup>[[16]](#references)[[18]](#references)</sup>

native add-ons に至る JavaScript/Electron の entry points については、[Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) を参照してください。

## ローカル TCP bridge を使った IDA と Ghidra のスクリプト解析

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) は、**すでに開いている** IDA database または Ghidra CodeBrowser program 内で動作し、別の script からその analysis database を照会・変更できるようにします。IDA の Python CLI から `ID_Server.py`（`import ID_Server`）を実行するか、Ghidra の Script Manager から `Ghidra_Server.py` を実行します。IDA は `127.0.0.1` の port `5073` から bind し、それより大きい port を順にスキャンします。現在の Ghidra script は port `5093` から開始し、`5102` までの10個の port を試します。Java socket は loopback のみに限定せず、wildcard address に bind します。接続前に、その instance が表示する port を確認してください。headless analyzer とは異なり、この bridge は GUI instance で現在開いている program を操作します。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

接続ごとに改行で終わる command を**1つだけ**送信し、改行で終わる response を読み取ります。通常、結果は JSON です。たとえば、入力 path に関係する imported API を見つけた後、`IMPORTXREF` でその call sites を検索し、続いて `DECOMP_XREF` で選択した address の callers をまとめて decompile できます。`FUNC` は関数を調べ、`PCODE` は decompiler の中間表現を返します。別の rebase 済み binary からコピーした address ではなく、active database の address を使ってください。以下の例は IDA の default port を使用しています。Ghidra の場合は、script が表示する port を使ってください。<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

同じチャネルから**解析データベースを変更**することもできます。`RENAME_FUNC`、`RETYPE`、`SETCONV`、`DEFSTRUCT`/`SETFIELD`、`MAKEFUNC`、`PATCH`は、名前、型、構造体定義、関数の境界、または保存されたバイト列を変更します。`PATCH`はデータベースの編集であり、実行中プロセスへのパッチを示すものではありません。どちらのlistenerも認証について記載していません。IDAはloopbackのみですが、Ghidraはネットワークインターフェース経由でアクセスできる可能性があります。Ghidraのlistenerを使用する場合は、アクセスを制限してください。`QUIT`はどちらのlistenerも停止し、IDAでは`ida_bridge_stop()`も利用できます。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### BlobRunnerを使ったshellcodeのデバッグ

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**を割り当て、その**メモリアドレス**を表示してから実行を一時停止します。\
IDAやx64dbgなどのdebuggerをアタッチし、表示されたアドレスにbreakpointを設定してから実行を再開すると、shellcodeをデバッグできます。

releasesのGitHubページには、コンパイル済みリリースを含むzipファイルがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクから、少し変更を加えたバージョンのBlobrunnerを入手できます。コンパイルするには、**Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドするだけです**。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itを使ったshellcodeのデバッグ

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerに似ています。shellcodeを割り当てて、無限ループに入ります。debuggerをアタッチして**2～5秒間**実行を再開し、そのループ内で一時停止してから、割り当てられたshellcodeに実行を移す次のcallまでstepしてください。

![jmp2itの無限ループ内で、割り当てられたshellcodeを呼び出す直前にdebuggerが一時停止している様子](<../../images/image (509).png>)

コンパイル済みバージョンの[jmp2itはreleasesページからダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使ったshellcodeのデバッグ

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使うと、shellcodeをエミュレートして動的に調べることができます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。同じshellcodeを開いた場合、私の環境ではファイルとして開くと正しくdecompileされましたが、shellcodeとして開くと正しく解析されませんでした。

![同じバイト列をファイルまたはshellcodeとして開いたときの解析結果の違いを表示するCutter](<../../images/image (562).png>)

任意の場所からエミュレーションを開始するには、そこにbpを設定してください。すると、Cutterはその場所から自動的にエミュレーションを開始するようです。

![Cutterのエミュレーション開始前に、目的のshellcodeエントリにbreakpointを設定する様子](<../../images/image (589).png>)

![選択したshellcodeのbreakpointで一時停止しているCutter emulator](<../../images/image (387).png>)

たとえば、hex dumpでstackを確認できます。

![Cutterのhex dumpでエミュレート中のshellcodeのstackを表示する様子](<../../images/image (186).png>)

### shellcodeのdeobfuscationと実行された関数の特定

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してください。\
shellcodeが**どの関数**を使用しているか、またメモリ内で自身を**decode**しているかなどを確認できます。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbgには、必要なオプションを選択してshellcodeを実行できるグラフィカルランチャーもあります

![shellcodeのエミュレーションとトレースのオプションを選択するscDbgのグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump** オプションは、メモリ内でshellcodeが動的に変更された場合に、最終的なshellcodeをダンプします（デコードされたshellcodeの取得に便利です）。**start offset** を指定すると、特定のオフセットからshellcodeを開始できます。**Debug Shell** オプションを使うと、scDbgのターミナルでshellcodeをデバッグできます（ただし、この用途には前述のオプションのほうが優れていると思います。Idaやx64dbgを使えるためです）。

### CyberChefを使用した逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationの難読化解除

**Mixed Boolean-Arithmetic（MBA）** obfuscationは、算術演算（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた数式で、`x + y`のような単純な式を隠します。重要なのは、こうした恒等式は通常、**固定幅の剰余演算**でのみ正しく成り立つため、桁上がりとオーバーフローが影響することです:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用的な代数ツールで簡略化すると、ビット幅の意味が無視され、誤った結果になることがあります。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトしたコード、IR、またはデコンパイラの出力にある**元のビット幅**（`8/16/32/64` bits）を維持する。
2. 簡略化を試す前に、式を**分類**する。
   - **Linear**: ビット単位の原子式の重み付き和
   - **Semilinear**: 線形式に `x & 0xFF` のような定数マスクを加えたもの
   - **Polynomial**: 積を含むもの
   - **Mixed**: 積とビット演算ロジックが交互に現れ、部分式が繰り返されることが多いもの
3. 候補となる書き換えはすべて、ランダムテストまたはSMT証明で検証する。同値性を証明できない場合は、推測で書き換えず、元の式を維持する。

### 狭い実行スライスで平坦化された制御フローをバイパスする

完全な制御フローグラフを復元する必要がない場合もよくあります。control-flow flattening、opaque predicates、大規模なdispatcher、またはMBA-heavyなコードでは、暗号化されたblobや出力バッファへの参照をたどり、それらを変換する最小のルーチンを特定します。その後、そのデータフロースライスだけを再現するか、単独で実行します。関連する状態を直接初期化できるなら、dispatcherは解決に必要ありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocation、相互参照を一覧にする。`.rodata` から候補となるテーブルをダンプし、バイト順と要素幅を維持する。
2. 平文または出力バッファに最後に書き込むルーチンを特定する。その入力、参照先のテーブル、importされた呼び出し、必要なグローバル状態を記録する。
3. それらの操作だけを固定幅のPythonモデルにリフトする。スライスが依然として大量の状態に依存する場合は、プログラム全体をエミュレートする代わりに、Unicorn、QEMU、またはデバッガでルーチンを実行し、不要なimportをhookする。
4. extractorが実際に与えられたバイナリから出力を導出していることを検証する。暗黙のfallbackを削除し、バイナリ内に答えが埋め込まれていないか検索する。また、文字列、鍵、識別子、レイアウト、難読化のseedを変更した未知のビルドで実行する。

最初に役立つコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装した MBA 式を検出する

一見入力に依存しているように見えるバイト式でも、入力が完全に相殺されている場合があります。テーブルを抽出した後、8 ビットの全領域にわたって式を評価します。出力集合が単一の値であれば、周囲の状態機械を復元しなくても、そのバイトが定数であると証明できます。<sup>[[7]](#references)</sup>

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

元の加算ではバイト幅で桁あふれが発生するため、最後のマスクは残してください。より広い領域では、同じ幅のシンボリック入力 `x1` と `x2` に対して、SMT solverで `f(x1) != f(x2)` が充足可能かを調べます。`unsat` なら不変性が証明され、`sat` なら反例が得られるため、その入力は破棄できません。<sup>[[7]](#references)</sup>

#### 環境に依存するデコードを見分ける

Anti-analysisチェックは、分岐やクラッシュを伴うとは限りません。デコーダーは、センサーの結果をキーのビット、opaque-predicateの定数、またはflattened-dispatcherの状態に混ぜ、正常に処理を続けながら、エミュレーター内で妥当そうに見える偽の平文を生成することがあります。したがって、目に見える失敗分岐だけをパッチしても不十分です。環境プローブからデコーダーの状態へのデータ依存関係を追跡し、実機とエミュレーターで同じスライスを比較して、各センサー結果を強制的に変更したときに最終バッファがどう変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)は、マルウェア解析や保護されたバイナリのリバースに役立つ、実用的なMBA簡略化ツールです。すべてに汎用の書き換えパスを適用するのではなく、式を分類し、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

簡単な使用例：

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

- **Linear MBA**: CoBRA は Boolean 入力で式を評価して signature を導出し、pattern matching、ANF conversion、coefficient interpolation など複数の復元手法を並行して実行します。
- **Semilinear MBA**: constant-masked atom は bit-partitioned reconstruction で再構築され、マスクされた領域が正しく保たれます。
- **Polynomial/Mixed MBA**: 積をコアに分解し、繰り返し現れる部分式を一時変数に置き換えてから、外側の関係式を簡約できます。

復元を試す価値がよくある mixed identity の例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のようにまとめられます：

```c
x * y
```

### Reversing のメモ

- 正確な計算箇所を特定した後、**lifted IR expressions** または decompiler の出力に対して CoBRA を実行するのがおすすめです。
- masked arithmetic や狭いレジスタに由来する式では、`--bitwidth` を明示的に指定してください。
- より強力な証明が必要な場合は、こちらのローカル Z3 のメモを確認してください。


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続の解析 pass の前に MBA を多用する LLVM IR を正規化する場合に便利です。
- carry に依存する未対応の混合領域の残余式は、元の式を保持し、carry の経路を手動で追うべきという合図として扱ってください。

## XOR-state による control-flow flattening の復元

OLLVM 形式の flattener は、現在の basic-block の state を2つの64-bit registerに保持し、dispatcher で XOR を使って復元する場合があります。元の各 block は次の state の register ペアを書き込み、dispatcher に戻ります。条件付き block は CPU flags に応じてペアの片方を置き換えるために `CMOVcc` を使うことがあり、目に見える branch 命令だけを追っても2つの successor を見落とします。間接 jump を使う dispatcher と異なり、この形式では全体を通じて直接の back-edge を使う場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

graph を復元するには、dispatcher の比較 tree と2つの state register を特定し、比較される各 XOR state を対象 block に対応付けたうえで、元の各 block における register ペアへの reaching write を追跡します。条件付き write では、flag を設定する命令と `CMOVcc` の両方の結果を含めます。各 block の dispatcher への exit を、解決した直接 successor または conditional branch に書き換えます。これにより、binary を patch せずに dispatcher を到達不能にできます。これは full-CFG の手法です。decoder が1つだけ対象なら、上記の [narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice) のほうが速い場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) は Binary Ninja でこの形式を自動化します。`plugins/DispatchThis` を Binary Ninja のユーザープラグインディレクトリにコピーして再起動してください。対象の function で **Function Settings** を開き、`OLLVM_XOR_64` を選択します。解析が始まらない場合は、**Analysis → Reanalyze All Functions** を実行してください。この mode は MLIL の control-flow edge を書き換えるもので、file の byte は変更せず、Z3 や indirect-jump resolver も必要としません。Binary Ninja 5.3.9757+ で動作確認されています。block ごとの不要な state write は削除されないため、それらを有効な遷移が残っていると誤認しないでください。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの操作を `mov` ベースの命令シーケンスに置き換え、signal/exception handling を利用して control flow を変更します。詳細：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応する binary では、[demovfuscator](https://github.com/kirschju/demovfuscator) を使って結果を deobfuscate できます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして [keystone をインストールします](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTFをプレイしている場合、この回避策でflagを見つけられる**かもしれません: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**を見つけるには、次のように関数名を`::main`で検索します:

![関数名のダブルコロン付きmainを検索して、GhidraでRustのentry pointを見つける](<../../images/image (1080).png>)

この場合、バイナリの名前はauthenticatorだったので、これが興味深いmain関数だということは明らかです。\
呼び出されている**関数**の**名前**がわかったら、**Internet**で検索して、それらの**入力**と**出力**について調べます。

### ELF firmwareからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列はC形式のNUL終端ポインターから参照されていません。一般的な`rustc`のレイアウトでは、**`.data.rel.ro`**内の**ポインター/長さのタプル**が、**`.rodata`**に格納された実際の文字列データを指しています:

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
2. **`.data.rel.ro`** を1ワードずつ列挙する。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱う。
4. 次のワードを長さの候補として扱う。
5. 妥当性フィルターを適用する（例：長さが **4**～**100** バイトのものを残す）。
6. `0x00` まで走査するのではなく、`.rodata` から `length` バイトを正確に読み取る。

最小限の抽出ロジック:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

これはファームウェアのリバースエンジニアリングで特に有用です。復元されたRust文字列から、**HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、認証関連のロジック**が判明することがよくあります。

Ghidraでこれらの文字列を検出できない場合は、同じヒューリスティックを適用し、参照先の`.rodata`オフセットに文字列データを作成するカスタムスクリプトやpluginを実行してください。Pen Test Partnersが公開している`rust-strings`と`RustStrings.py`は、このアイデアを他の**ワードサイズ、エンディアン、セクションレイアウト**に応用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphiでコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます。

Delphiバイナリをリバースする場合は、IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)の使用をおすすめします。

IDAで**Alt+F7**を押してPython pluginを読み込み、pluginファイルを選択します。

このpluginはバイナリを実行し、デバッグ開始時に関数名を動的に解決します。デバッグを開始したら、もう一度Startボタン（緑色のボタンまたはf9）を押すと、実際のコードの先頭でブレークポイントに到達します。

グラフィカルアプリケーションでボタンを押すと、デバッガーはそのボタンから呼び出された関数で停止することがあります。

## Golang

通常のGoバイナリでは、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使ってruntime構造体を復元し、IDAで関数名を補完できます。**Alt+F7**でPython pluginを読み込んでください。

Golangバイナリをリバースする場合は、IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)の使用をおすすめします。

IDAで**Alt+F7**を押してPython pluginを読み込み、pluginファイルを選択します。

これにより、関数名が解決されます。

### シンボルテーブルなしでメタデータを復元する

stripされたGo実行ファイルでも、プログラムカウンターを関数に対応付けるためにruntimeメタデータが必要です。[GoReSym](https://github.com/mandiant/GoReSym)はGo runtime由来のコードを使い、`pclntab`や`moduledata`などの構造体を特定して解析します。これにより、従来のシンボルテーブルに依存せずに、関数の境界、名前、ソースパス、型、ビルド情報を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

難読化ツールは、復元した名前を置き換えながら、これらの構造を使用可能な状態に保つことがあります。たとえばGarbleは、識別子とpackage pathをハッシュ化し、build、module、debug情報を削除します。<sup>[[12]](#references)</sup> 難読化されたpackage tokenは、そのpackage内の関数間で一貫している必要があります。繰り返し現れるtokenで関数をグループ化し、そのcallee、文字列、APIからpackageを1つ推定して、グループ全体にそのpackageラベルを適用します。<sup>[[13]](#references)</sup>

### GoResolverでGarbleの名前を復元する

[GoResolver](https://github.com/volexity/GoResolver)は、runtime symbolの抽出と、クリーンな参照バイナリの生成、control-flow graph（CFG）のマッチングを組み合わせます。次の手順で進めます。<sup>[[10]](#references)[[13]](#references)</sup>

1. **コンパイラのバージョンを特定する。** まず`BuildInfo`と埋め込みのバージョン文字列を確認します。難読化ツールによって削除されている場合は、同梱されたGo runtimeの一部を、バージョン別の参照runtimeと比較します。Volexityのテストでは、runtimeの約`2%`でGoのメジャーバージョンを判別できました。これは実験に基づく最適化であり、普遍的なしきい値ではない点に注意してください。<sup>[[13]](#references)</sup>
2. **照合用の参照バイナリを用意する。** 特定したGoバージョン、target architecture、使用されている可能性の高いlibraryに合わせて、クリーンなバイナリを生成します。toolchainを一致させると、コンパイラが生成するCFGの差異を抑えられます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapherは関数のCFGを照合し、`0.0`から`1.0`の範囲で正規化されたスコアを出力します。basic blockの照合には、類似する命令の重み付き比較が使われます。信頼度の高い一致から、ランダム化された関数をクリーンな実装に対応付けられます。信頼度が低い一致でも、packageやmoduleの特定に役立つことがあります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** call relationship、定数、文字列、副作用を使って候補の名前を確認し、GoResolver pluginを使ってIDAまたはGhidraにJSONレポートをインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

toolchainをインストールし、抽出とgraph matchingを組み合わせて実行します。<sup>[[10]](#references)</sup>

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

デフォルトの有意一致しきい値は `0.9` です。`--extract` と `--graph` スイッチを使うと、どちらか一方の段階だけを実行できます。復元されたランタイムメタデータとCFGの情報は互いを補完するため、デフォルトでは両方を実行します。<sup>[[10]](#references)</sup> CFGスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わることがあるため、信頼度の低い名前を無理に割り当てず、未解決の関数はそのまま残してください。<sup>[[13]](#references)</sup>

### Go文字列テーブルの復元

Goバイナリでは、リンクされたすべてのパッケージの文字列バイト列が、1つの連続したテーブルに配置されます。各エントリはNUL終端されておらず、ランタイム構造体からテーブルのベースアドレスやサイズを取得することもできません。しかし、コンパイラはOSやアーキテクチャを問わず、エントリをまず長さ順、次にアルファベット順に並べます。そのため、1つのエントリを見つければ、隣接するエントリをたどり、データのクロスリファレンスを使って文字列とコードを関連付けられます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) は、この作業をIDA ProとGhidraで自動化します。このプラグインはデータセグメントのクロスリファレンスに依存するため、まず自動解析が完了するまで待ちます。デフォルトのアンカーはランタイム文字列 `entersyscall` です。これを起点に、どちらの方向にもスキャンして、復元した文字列をデータベースに定義し、文字列と参照元関数の対応をJSON形式でエクスポートできます。<sup>[[14]](#references)</sup>

参照元関数のパッケージでレポートをフィルタリングすると、アプリケーションやマルウェアのコードを、リンクされたライブラリ由来のノイズから分離できます。この手法では、Garbleの `-literals` 変換などの難読化によって破壊されたリテラルは復元できません。それでも、難読化されずに残ったランタイム文字列を整理するのに役立ちます。<sup>[[14]](#references)[[15]](#references)</sup>

### Goランタイム型の復元

Goは、ガベージコレクションなどの機能で使用されるランタイム型情報を埋め込みます。ビルド情報が削除されている場合や、逆アセンブラがこのメタデータを解析できない場合、命令は任意のデータアドレスを読み込んでいるように見え、対象領域も型情報のないままになります。メタデータを復元すると、これらのアドレスが読みやすい型参照に変わり、パッケージの機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) は、シンボルを抽出し、ランタイム型を解析してJSONレポートを作成できます。現在のCLIでは `resolve` サブコマンドを使います。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types`オプションを指定すると、型の解析が有効になります。レポートをGoResolverのIDA ProまたはGhidraプラグインにインポートすると、復元された型を定義し、解析データベース内でその参照を適用できます。この機能で導入されたレポート形式では、`-y`を省略すると、RTTIアドレスとrecovered-typesメンバーはnullになります。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolverはx86、AMD64、ARM、ARM64のPE、ELF、Mach-Oサンプルに対応しているため、同じワークフローをWindows、Linux、macOSのGoバイナリに適用できます。<sup>[[10]](#references)</sup>

## コンパイル済みPython

このページでは、ELF/EXE形式のPythonコンパイル済みバイナリからPythonコードを取得する方法を説明します。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBAゲームの**バイナリ**を入手した場合、さまざまなツールを使って**エミュレート**および**デバッグ**できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_デバッグ版をダウンロード_) - インターフェース付きのデバッガーを搭載
- [**mgba** ](https://mgba.io)- CLIデバッガーを搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidraプラグイン
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidraプラグイン

[**no$gba**](https://problemkaputt.de/gba.htm)では、_**Options --> Emulation Setup --> Controls**_** **でGame Boy Advanceの**ボタン**の押し方を確認できます。

![Game Boy Advanceのボタン割り当てを示すno$gbaのコントロール設定](<../../images/image (581).png>)

キーを押すと、それぞれを識別するための**値**が割り当てられます。

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

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

この関数では、いくつかの初期化処理（特に重要ではありません）の後に:

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

最後の if は、**`uVar4`** が **最後の Keys** に含まれており、現在のキー（**`uVar1`** に格納）ではないことを確認しています。これは、ボタンを離す操作とも呼ばれます。

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

- 最初に、**値 4**（**SELECT**ボタン）と比較します。このチャレンジでは、このボタンを押すと画面が消去されます。
- 次に、**値 8**（**START**ボタン）と比較します。このチャレンジでは、この分岐で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）を確認してインクリメントします。\
  カウンターが 8 未満である間、押されたキーの値は `DAT_030000d8` に累積されます。

つまり、このチャレンジでは、ボタンの値を把握したうえで、合計が 0xf3 になる、長さが 8 未満の組み合わせを**入力する必要がありました。**

**このチュートリアルの参考資料：** [Nostalgia challenge の writeup（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA を使った MBA obfuscation の簡素化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust の文字列をデコードする - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 支援による Reverse Engineering を阻止する、少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [基本ブロックマッチングに基づく制御フローグラフ比較のアプローチ](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation の仕組み](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: 制御フローグラフの類似性を使って Go バイナリを自動で deobfuscate する](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang ツールのアップデート](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものを Reverse Engineer する](https://github.com/morluto/rea)
- [17] [REA managed-code analysis](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI と Evidence ガイド](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja の制御フロー unflattening ワークフロー](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF のゼロデイ侵入、Java Loader、Web Shell、AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge サーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge サーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) はワイルドカードアドレスにバインドする](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
