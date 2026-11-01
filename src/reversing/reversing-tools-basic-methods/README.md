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

## Wasmデコンパイラ / Watコンパイラ

オンライン:

- wasm（バイナリ）からwat（プレーンテキスト）に**デコンパイル**するには、[https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用します
- watからwasmに**コンパイル**するには、[https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用します
- デコンパイルには[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

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

レガシーアセンブリから失われたソースコードを復元する必要がある場合に、このツールを使えば時間を節約できます。さらに、dotPeekはデコンパイルされたコード内を簡単に移動できるため、**Xamarinのアルゴリズム解析**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供する豊富なリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内でデータがどのように流れるかを把握できます
- .NET言語やフレームワークの実装と使用方法を確認できます
- 使用しているAPIやテクノロジーをより活用するために、文書化されていない機能や公開されていない機能を見つけられます。
- 依存関係や各種アセンブリを見つけられます
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な場所を特定できます。
- 使用しているすべての.NETコードのソースをデバッグできます。

### [ILSpy](https://github.com/icsharpcode/ILSpy) と [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): あらゆるOSで利用できます（VSCodeから直接インストールでき、gitをダウンロードする必要はありません。**Extensions**をクリックして、**ILSpy**を検索してください）。\
**デコンパイル**、**変更**、再度の**再コンパイル**が必要な場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または現在も積極的にメンテナンスされているフォークの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内を変更するには、**右クリック -> Modify Method**を選択します）。

### REAによる実行不要のマネージドコード検査

**REA**はアセンブリを読み込まずに、PE/CLIメタデータとCILを検査できます。まずアーティファクトの識別情報を確認し、次にメンバーと宣言されたネイティブ境界を調べます。これは、デコンパイラを使用したりプログラムを実行したりする前に、不審な呼び出しを調査する際に役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン差分の比較では、`compare_managed_members` はメタデータトークンがビルド間で安定しているものとして扱わず、生の CIL／シグネチャの同一性と、デコード済み命令のフィンガープリントを使用します。P/Invoke 宣言はネイティブコードが実行された証拠にはなりません。その境界を確認するには、`verify_managed_native_boundaries` に対応するネイティブ export または関数の Evidence が必要です。成果物のダイジェスト、MVID、未解決のマッピングも結果に含めてください。<sup>[[17]](#references)</sup>

### DNSpy のログ記録

**DNSpy に情報をファイルへログ出力させる**には、次のスニペットを使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpyでのデバッグ

DNSpyを使ってコードをデバッグするには、次の手順が必要です。

まず、**デバッグ**に関連する **Assembly attributes** を変更します。

![DNSpy Logging - DNSpyでのデバッグ: まず、デバッグに関連するAssembly attributesを変更します](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: そして compile をクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: 次に File Save module から新しいファイルを保存](<../../images/image (602).png>)

これを行う必要があるのは、そうしないと **runtime** にコードにいくつかの**最適化**が適用され、デバッグ中に**ブレークポイントに到達しない**場合や、一部の**変数が存在しない**場合があるためです。

次に、.NET アプリケーションが **IIS** によって**実行**されている場合は、次の方法で**再起動**できます。

```
iisreset /noforce
```

その後、デバッグを開始するには、開いているファイルをすべて閉じ、**Debug Tab** で **Attach to Process...** を選択します。

![DNSpy Logging - DNSpy Debugging: デバッグを開始するには、開いているファイルをすべて閉じ、Debug Tab で Attach to Process を選択します](<../../images/image (318).png>)

次に **w3wp.exe** を選択して **IIS server** にアタッチし、**attach** をクリックします。

![DNSpy Logging - DNSpy Debugging: w3wp.exe を選択して IIS server にアタッチし、attach をクリックします](<../../images/image (113).png>)

プロセスをデバッグしている状態になったら、停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしている状態になったら、停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしている状態になったら、停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内のモジュールを右クリックし、**Open All Modules** を選択します。

![DNSpy Logging - DNSpy Debugging: Modules 内のモジュールを右クリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のモジュールを右クリックし、**Sort Assemblies** をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のモジュールを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Javaデコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのデバッグ

### IDAを使用する

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debuggerを選択する
- "**Suspend on library load/unload**" を選択する

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択します](<../../images/image (868).png>)

- **DLLのパス**と呼び出したい関数を指定して、実行の**parameters**を設定します。

![Debugging DLLs - Using IDA: DLLのパスと呼び出したい関数を指定して、実行のparametersを設定します](<../../images/image (704).png>)

デバッグを開始すると、**DLLがロードされるたびに実行が停止します**。そのため、rundll32がDLLをロードすると、実行が停止します。

この方法ではモジュールのロードイベントで停止しますが、ロードされたDLLのエントリポイントに到達する手順は、以下のx64dbgの方法より直接的ではありません。

### x64dbg/x32dbgを使用する

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更**（_File --> Change Command Line_）し、DLLのパスと呼び出したい関数を設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- **実行を開始**すると、debuggerは各dll mainで停止します。いずれかの時点で、**対象のdllのEntryで停止します**。そこから、breakpointを設定したい箇所を探します。

win64dbgで何らかの理由により実行が停止したとき、**win64dbgのウィンドウ上部**を見ると、**どのコードにいるか**を確認できます。

![Using IDA - Using x64dbg/x32dbg: win64dbgで何らかの理由により実行が停止したとき、win64dbgのウィンドウ上部を見ると、どのコードにいるかを確認できます](<../../images/image (842).png>)

この表示により、デバッグ対象のDLL内で実行が停止したことを確認できます。

## GUIアプリ / ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内で重要な値が保存されている場所を見つけ、変更するのに便利なプログラムです。詳しくは次を参照してください。

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、ゲームに特化した GNU Project Debugger (GDB) のフロントエンド／reverse engineering toolです。ただし、reverse engineeringに関するさまざまな用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数のdecompilerを利用できるWebフロントエンドです。このWebサービスでは、小さな実行ファイルに対する複数のdecompilerの出力を比較できます。

### Godot PCKの復号とプロジェクトの復元

配布されたGodotゲームでは、単独の`.pck`、実行ファイルに追加または埋め込まれたpack、あるいはAPKの`assets`ディレクトリ内からPCKを探します。[gore](https://github.com/figurophobia/gore)でpackを調査・抽出できます。一方、スクリプトとリソースを完全に再構築するにはGDRE Toolsが必要です（`gore setup`でインストールするか、`--gdre`を使用します）。このツールは、このワークフローでGodot 4.xのPCK形式v2～v4をサポートしています。v1のheaderは検出できますが、v1にはキーを指定する必要があります。<sup>[[25]](#references)</sup>

自動キー復元には暗号化されたファイルテーブルが必要です。ファイルの内容のみが暗号化されている場合は、既知のキーを指定してください。復元に失敗しても、packが暗号化されていないとは判断できません。<sup>[[28]](#references)</sup>

キーの検索は、**AES-256 keyspace attackではありません**。暗号化されたファイルテーブルには、平文のMD5、平文の長さ、IV、AES-256-CFB ciphertextが含まれます。<sup>[[27]](#references)</sup> `gore`は、ゲームの実行ファイルまたは近隣のファイルから32-byteの領域を切り出し、候補キーとして検査します。復号されたパスの長さとprefixが妥当かどうかで候補を絞り込み、binary-scanで見つかった候補は、テーブル全体を復号してMD5を確認します。<sup>[[26]](#references)[[28]](#references)</sup> まず初期化済みのPE/ELFデータセクションを検索し、その後、ファイル全体をスキャンします。`--scan`を指定すると、ほかの候補ファイルも検索対象に追加されます。<sup>[[28]](#references)</sup>

埋め込みキーが見つからない場合は、組み込みの短いpassword listが試されます。ほかの候補を指定するには`--wordlist`を使用します。各passwordは、engineがpasswordから導出するキー表現、ゼロ埋めした文字列、または64文字の16進数キーとして検査されます。binary-scanで見つかった候補とは異なり、この実装ではwordlistで見つかった候補はパス構造のフィルターを通過するだけです。packを開き、抽出したassetsを検証して確認してください。<sup>[[26]](#references)[[28]](#references)</sup>

ゲームのartifactをローカルで利用できる場合は、分析に必要な段階を選びます。`recover`はGDREを実行して、開けるプロジェクトを再構築します。一方、`extract`はrawファイルを展開するだけです。`key`は、別のツールで使用する候補キーを出力します。<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## REAを使った証拠に基づくネイティブ調査

**REA** は、Hopper、Ghidra、IDA の解析機能を CLI と MCP 経由で利用できます。Node.js 22.x（22.19 以降）、24.x（24.11 以降）、または 26 以降と、npm が必要です。最初に既存のネイティブプロバイダーを設定してください。`rea providers --json` を確認し、対象をサポートするプロバイダーが複数ある場合は、プロバイダーを明示的に選択してください。以下の `0x1000` には、インベントリーで確認した関数名またはアドレスを指定してください。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

機能文字列またはシンボルから始め、参照先や呼び出し元をたどり、選択した関数の dossier と pseudocode を `rea decompile` で調べます。REA はセッションを選択した provider に紐付け、失敗後に黙って別の provider に切り替えることはありません。クエリを再現可能にするには、`--snapshot PATH` を使います。これは、artifact のバイト列、provider、設定、操作、パラメーターが一致する場合にのみ再利用されます。snapshot はローカルキャッシュであり、保存済みの provider database ではありません。推測されたパスや decompiler のテキストを元のソースとして扱わず、返された Evidence と明示された unknowns を保持してください。<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron のエントリーポイントから native add-on へ進む場合は、[Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) を参照してください。

## ローカル TCP bridge を使った IDA と Ghidra のスクリプト分析

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) は、**すでに開いている** IDA database または Ghidra CodeBrowser の program 内で動作し、別のスクリプトからその分析 database を照会・変更できるようにします。IDA の Python CLI から `ID_Server.py` を実行（`import ID_Server`）するか、Ghidra の Script Manager から `Ghidra_Server.py` を実行します。IDA は `127.0.0.1` のポート `5073` からバインドを開始し、より大きいポートを順に調べます。現在の Ghidra スクリプトはポート `5093` から開始し、`5102` までの10個のポートを試します。Java socket は loopback のみに限らず、ワイルドカードアドレスにバインドします。接続する前に、インスタンスが表示したポートを確認してください。headless analyzer とは異なり、この bridge は GUI インスタンスで現在開いている program を対象に動作します。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

**接続ごとに、改行で終わるコマンドを1つ送信**し、改行で終わる応答を読み取ります。通常、結果は JSON です。たとえば、入力パスに関連する imported API を見つけた後、`IMPORTXREF` でその call site を見つけ、続いて `DECOMP_XREF` で選択したアドレスの呼び出し元をまとめて decompile します。`FUNC` は関数を調べ、`PCODE` は decompiler の中間表現を返します。異なる rebase が適用されたバイナリからコピーしたアドレスではなく、アクティブな database のアドレスを使用してください。以下の例では IDA のデフォルトポートを使用しています。Ghidra の場合は、スクリプトが表示したポートを使用してください。<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

同じチャネルから**解析データベースを変更**することもできます。`RENAME_FUNC`、`RETYPE`、`SETCONV`、`DEFSTRUCT`/`SETFIELD`、`MAKEFUNC`、`PATCH`は、名前、型、構造体定義、関数境界、または保存されたバイト列を変更します。`PATCH`はデータベースの編集であり、実行中プロセスへのpatchの証拠ではありません。どちらのlistenerも認証については記載していません。IDAはloopback限定ですが、Ghidraはネットワークインターフェース経由で到達可能な場合があります。Ghidraのlistenerを使用する場合は、アクセスを制限してください。`QUIT`はどちらのlistenerも停止し、IDAには`ida_bridge_stop()`もあります。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerを使ったshellcodeのデバッグ

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**をメモリに割り当て、その**メモリアドレス**を表示してから、実行を一時停止します。\
IDAやx64dbgなどのdebuggerをアタッチし、表示されたアドレスにbreakpointを設定して実行を再開すると、shellcodeをデバッグできます。

リリースのGitHubページには、コンパイル済みリリースを含むzipファイルがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクから、少し変更を加えたBlobrunnerのバージョンを入手できます。コンパイルするには、**Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドするだけです**。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itを使ったshellcodeのデバッグ

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerに似ています。shellcodeをメモリに割り当て、無限ループに入ります。debuggerをアタッチして**2〜5秒間**実行を再開し、そのループ内で一時停止してから、割り当てられたshellcodeに実行を移す次のcallまでstep実行してください。

![jmp2itの無限ループ内で、割り当てられたshellcodeへのcallの直前にdebuggerが一時停止している様子](<../../images/image (509).png>)

コンパイル済みのバージョンは、[リリースページからjmp2itをダウンロード](https://github.com/adamkramer/jmp2it/releases/)できます。

### Cutterを使ったshellcodeのデバッグ

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使ってshellcodeをエミュレートし、動的に調査できます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。私の場合、shellcodeをファイルとして開くと正しく逆コンパイルされましたが、shellcodeとして開くと正しく処理されませんでした。

![同じバイト列をファイルとして開いた場合とshellcodeとして開いた場合で、異なる解析結果を表示するCutter](<../../images/image (562).png>)

エミュレーションを開始したい場所でbpを設定すると、Cutterはそこから自動的にエミュレーションを開始するようです。

![Cutterのエミュレーション開始前に、目的のshellcodeエントリにbreakpointを設定](<../../images/image (589).png>)

![選択したshellcodeのbreakpointで一時停止したCutterエミュレーター](<../../images/image (387).png>)

たとえば、hex dump内でstackを確認できます。

![Cutterのhex dumpでエミュレートされたshellcodeのstackを表示](<../../images/image (186).png>)

### shellcodeをdeobfuscateして実行された関数を取得する

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

scDbgには、必要なオプションを選択してshellcodeを実行できるグラフィカルランチャーもあります。

![shellcodeのエミュレーションとトレースのオプションを選択するscDbgグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump**オプションを使うと、メモリ内でshellcodeが動的に変更された場合に、最終的なshellcodeをダンプできます（デコードされたshellcodeのダウンロードに便利です）。**start offset**は、特定のオフセットからshellcodeを開始する場合に便利です。**Debug Shell**オプションを使うと、scDbgターミナルでshellcodeをデバッグできます（ただし、この用途では前述のオプションのほうが優れていると思います。Idaやx64dbgを使用できるためです）。

### CyberChefを使った逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationの難読化解除

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、算術演算（`+`、`-`、`*`）とビット演算（`&`、`|`、`^`、`~`、シフト）を組み合わせた式で、`x + y`のような単純な式を隠します。重要なのは、こうした等式が通常、**固定幅の剰余演算**でのみ成立することです。そのため、キャリーとオーバーフローが重要になります:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用的な代数ツールで簡約すると、ビット幅の意味が無視されて誤った結果になりやすいです。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. lifted code/IR/decompiler の出力にある**元のビット幅**（`8/16/32/64` ビット）を維持する。
2. 簡約を試みる前に、式を**分類**する。
   - **Linear**: ビット演算アトムの重み付き和
   - **Semilinear**: `x & 0xFF` のような定数マスクを含む linear
   - **Polynomial**: 積を含む
   - **Mixed**: 積とビット演算ロジックが入り交じり、同じ部分式が繰り返されることが多い
3. ランダムテストまたは SMT 証明で、書き換え候補をすべて**検証**する。同値性を証明できない場合は、推測せず元の式を維持する。

### 狭い実行スライスでフラット化された制御フローを回避する

完全な制御フローグラフの復元は、多くの場合不要です。制御フローの flattening、opaque predicates、大規模な dispatcher、または MBA-heavy なコードがある場合は、暗号化された blob や出力バッファから参照をたどり、それらを変換する最小のルーチンを特定します。その後、そのデータフロースライスだけを再現するか、単独で実行します。関連する状態を直接初期化できるなら、dispatcher は解決に必要ありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocations、cross-references を一覧にする。候補となるテーブルを `.rodata` からダンプし、バイト順と要素幅を維持する。
2. plaintext または出力バッファに最後に書き込むルーチンを特定する。その入力、参照先のテーブル、import された呼び出し、必要なグローバル状態を記録する。
3. 該当する操作だけを、固定幅の Python モデルに lift する。スライスが依然として過剰な状態に依存する場合は、プログラム全体をエミュレートする代わりに、Unicorn、QEMU、または debugger の下でルーチンを呼び出し、無関係な import を hook する。
4. extractor が与えられた binary から実際に出力を導出していることを検証する。暗黙の fallback を削除し、埋め込まれた答えがないか検索し、文字列、キー、識別子、レイアウト、obfuscation seed を変えた未確認の build に対して実行する。

最初に役立つコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装したMBA式を検出する

一見すると入力に依存しているように見えるバイト式でも、入力が完全に相殺されることがあります。テーブルを抽出した後、8ビットの全領域で式を評価します。出力集合が単一要素なら、周囲のステートマシンを復元しなくても、そのバイトが定数であると証明できます。<sup>[[7]](#references)</sup>

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

元の加算にはバイト幅のラップアラウンドがあるため、最後のマスクは残してください。より広い領域では、同じ幅のシンボリック入力 `x1` と `x2` に対して `f(x1) != f(x2)` が充足可能かどうかを SMT ソルバーに問い合わせます。`unsat` なら不変性が証明され、`sat` なら反例が得られるため、その入力は破棄できません。<sup>[[7]](#references)</sup>

#### 環境に依存するデコードを見分ける

Anti-analysis チェックは、必ずしも分岐やクラッシュを伴うとは限りません。デコーダーはセンサーの結果をキーのビット、不透明述語の定数、またはフラット化されたディスパッチャーの状態に混ぜ込み、正常に処理を続けながら、エミュレーター上で妥当に見える偽の平文を生成することがあります。そのため、目に見える失敗分岐だけをパッチしても不十分です。環境プローブからデコーダーの状態までのデータ依存関係を追跡し、実機とエミュレーターで同じスライスを比較し、各センサーの結果を強制的に変えたときに最終バッファーがどう変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis や保護されたバイナリのリバースに実用的な MBA simplifier です。式を分類し、すべてに単一の汎用リライトパスを適用するのではなく、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRAはBoolean入力で式を評価してsignatureを導出し、pattern matching、ANF変換、係数補間など複数の復元手法を並行して試します。
- **Semilinear MBA**: constant-masked atomsをbit-partitioned reconstructionで再構築し、マスクされた領域が正しく保たれるようにします。
- **Polynomial/Mixed MBA**: 積をcoreに分解し、簡約前に繰り返し現れる部分式をtemporaryに切り出せます。

復元を試す価値のある、よくあるmixed identityの例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のように簡略化できます:

```c
x * y
```

### Reversingに関するメモ

- CoBRAは、**lifted IR expressions**または、対象の計算を正確に切り分けた後のdecompiler出力に対して実行するのがおすすめです。
- 式がmasked arithmeticや狭いレジスタに由来する場合は、`--bitwidth`を明示的に指定してください。
- より強力な証明ステップが必要な場合は、こちらのローカルなZ3のメモを確認してください。


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRAには**LLVM pass plugin**（`libCobraPass.so`）も含まれており、後続の解析passの前にMBA-heavyなLLVM IRを正規化したい場合に便利です。
- carryに依存する、未対応のmixed-domain residualsは、元の式を維持し、carry pathを手動で解析する必要があるというサインとして扱ってください。

## XOR-state control-flow flatteningの復元

OLLVM形式のflattenerでは、現在のbasic-block stateを2つの64-bit registerに保持し、dispatcherでXORを使って再構成することがあります。各元ブロックは次のstateに対応するペアを書き込み、dispatcherへ戻ります。条件付きブロックはCPU flagsに応じてペアの片方を`CMOVcc`で置き換えることがあるため、見えているbranch instructionだけを追うと、2つの後続ブロックを見落とします。indirect-jump dispatcherとは異なり、この形式では全体を通してdirect back-edgeを使う場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

グラフを復元するには、dispatcherの比較ツリーと2つのstate registerを特定し、比較される各XOR stateを対象ブロックに対応付けてから、各元ブロックでregisterペアに到達する書き込みを追跡します。条件付きの書き込みでは、flagsを設定する命令と、両方の`CMOVcc`の結果を含めます。各ブロックのdispatcherへのexitを、解決したdirect successorまたはconditional branchに書き換えます。これによりbinaryをpatchしなくても、dispatcherは到達不能になります。これはfull-CFGのアプローチです。1つのdecoderだけが必要なら、上記の[narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice)のほうが速い場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis)は、Binary Ninjaでこの形式を自動処理します。`plugins/DispatchThis`をBinary Ninjaのユーザープラグインディレクトリにコピーして再起動してください。対象の関数で**Function Settings**を開き、`OLLVM_XOR_64`を選択します。解析が始まらない場合は、**Analysis → Reanalyze All Functions**を実行してください。このモードはMLILのcontrol-flow edgeを書き換えるもので、ファイルのバイト列は変更せず、Z3やindirect-jump resolverも必要ありません。Binary Ninja 5.3.9757+で動作を確認しています。ブロックごとの不要なstate書き込みは削除されないため、それらを実行時に有効な遷移と誤認しないでください。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

このobfuscatorは、プログラムの操作を`mov`ベースの命令列に置き換え、signal/exception handlingを使ってcontrol flowを変更します。詳細はこちら：

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応するbinaryでは、[demovfuscator](https://github.com/kirschju/demovfuscator)で結果をdeobfuscateできます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）。

**CTFをプレイしているなら、このflagを見つけるための回避策**が役に立つかもしれません：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**を見つけるには、次のように関数名を`::main`で検索します。

![関数名のダブルコロン付きmainを検索して、GhidraでRustのentry pointを見つける](<../../images/image (1080).png>)

この場合、バイナリ名はauthenticatorだったので、これが注目すべきmain関数であることは明らかです。\
呼び出されている**関数**の**名前**がわかったら、**インターネット**で検索して、その**入力**と**出力**について調べましょう。

### ELFファームウェアからRustの文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列はC形式のNUL終端ポインターから参照されていません。一般的な`rustc`のレイアウトでは、**`.data.rel.ro`**内の**ポインター/長さのタプル**が、**`.rodata`**に格納された実際の文字列領域を指しています。

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

これは、`strings` や Ghidra のデフォルトの解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

簡単なワークフロー:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得する。
2. **`.data.rel.ro`** を1 wordずつ列挙する。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱う。
4. 次の word を候補の長さとして扱う。
5. 妥当性フィルターを適用する（例: 長さが **4**～**100** bytes の範囲内のものを残す）。
6. `0x00` までスキャンするのではなく、`.rodata` から `length` bytes を正確に読み取る。

最小限の extractor ロジック:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

これは firmware reversing で特に役立ちます。復元された Rust 文字列から、**HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth 関連のロジック**が判明することがよくあります。

Ghidra がこれらの文字列を検出できない場合は、同じヒューリスティックを適用し、参照先の `.rodata` オフセットに文字列データを作成するカスタムスクリプトや plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` は、このアイデアを他の **word sizes、endianness、section layouts** に応用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi のコンパイル済みバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi バイナリを reverse する場合は、IDA plugin の [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をおすすめします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin ファイルを選択します。

この plugin はバイナリを実行し、debugging の開始時に関数名を動的に解決します。debugging を開始したら、もう一度 Start ボタン（緑色のボタン、または f9）を押すと、実際のコードの先頭で breakpoint に到達します。

グラフィカルアプリケーションのボタンを押すと、debugger はそのボタンから呼び出された関数で停止することがあります。

## Golang

通常の Go バイナリでは、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使って runtime structures を復元し、IDA の関数名を改善できます。**Alt+F7** で Python plugin を読み込みます。

Golang バイナリを reverse する場合は、IDA plugin の [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をおすすめします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin ファイルを選択します。

これにより、関数名が解決されます。

### symbol table なしで metadata を復元する

stripped Go executable でも、program counter を関数に対応付けるために runtime metadata が必要です。[GoReSym](https://github.com/mandiant/GoReSym) は、Go runtime 由来のコードを使って `pclntab` や `moduledata` などの構造を特定し、解析します。従来の symbol table に頼らず、関数の境界、名前、ソースパス、型、build の詳細を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

難読化ツールは、復元した名前を置き換えながら、これらの構造を利用可能な状態に保つことがあります。たとえば Garble は識別子と package path をハッシュ化し、build、module、debug 情報を削除します。<sup>[[12]](#references)</sup> 難読化された package token は、その package の関数間で一貫している必要があります。繰り返し現れる token ごとに関数をグループ化し、callee、文字列、API から package を推測して、その package label をグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolver で Garble の名前を復元する

[GoResolver](https://github.com/volexity/GoResolver) は、runtime symbol の抽出、クリーンな参照バイナリの生成、control-flow graph（CFG）の照合を組み合わせます。次の手順を実行します。<sup>[[10]](#references)[[13]](#references)</sup>

1. **コンパイラのバージョンを特定する。** まず `BuildInfo` と埋め込みバージョン文字列を確認します。obfuscator がそれらを削除している場合は、同梱された Go runtime の一部を、バージョンごとの参照 runtime と比較します。Volexity のテストでは、runtime の約 `2%` で Go のメジャーバージョンを判別できました。これは実測に基づく最適化であり、普遍的な基準ではありません。<sup>[[13]](#references)</sup>
2. **照合用の参照バイナリを用意する。** 特定した Go バージョン、target architecture、使用されている可能性の高いライブラリに合わせて、クリーンなバイナリを生成します。toolchain を一致させると、コンパイラ生成 CFG の差異を抑えられます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapher は関数 CFG を照合し、`0.0` から `1.0` の正規化スコアを出力します。basic block の照合では、類似する命令を重み付けして比較します。確度の高い照合結果を使って、ランダム化された関数をクリーンな実装に対応付けます。確度が低い結果でも、package または module の特定に役立ちます。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** 提案された名前を、call relationship、定数、文字列、side effect で確認してから、GoResolver plugin を使って IDA または Ghidra に JSON report をインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

toolchain をインストールし、抽出器と graph matcher を組み合わせて実行します。<sup>[[10]](#references)</sup>

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

デフォルトの有意な一致のしきい値は `0.9` です。`--extract` と `--graph` のスイッチを使うと各段階を個別に実行できますが、復元されたランタイムメタデータとCFGの証拠が互いを補完するため、デフォルトでは両方が実行されます。<sup>[[10]](#references)</sup> CFGスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わることがあるため、信頼度の低い名前を無理に付けず、解決できない関数はそのまま残してください。<sup>[[13]](#references)</sup>

### Go string tableの復元

Goバイナリでは、リンクされたすべてのパッケージの文字列バイトが、1つの連続したテーブルに格納されます。各エントリはNUL終端されておらず、ランタイム構造体からテーブルのベースアドレスやサイズを取得することもできません。しかし、コンパイラはOSやアーキテクチャを問わず、まず長さ順、次にアルファベット順でエントリを並べます。そのため、エントリを1つ見つければ、隣接するエントリをたどり、データのクロスリファレンスを使って文字列をコードに関連付けられます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor)は、このワークフローをIDA ProとGhidraで自動化します。このプラグインはデータセグメントのクロスリファレンスに依存するため、先に自動解析を完了させてください。デフォルトのアンカーはランタイム文字列`entersyscall`です。その後、どちらの方向にもスキャンし、復元した文字列をデータベース内で定義して、文字列と参照元関数の対応をJSON形式でエクスポートできます。<sup>[[14]](#references)</sup>

参照元関数のパッケージでレポートをフィルタリングし、アプリケーションやマルウェアのコードと、リンクされたライブラリのノイズを切り分けてください。この手法では、Garbleの`-literals`変換のような難読化によって破壊されたリテラルは復元できません。それでも、難読化されずに残っているランタイム文字列を整理することはできます。<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime typeの復元

Goには、ガベージコレクションなどの機能で使われるランタイム型情報が埋め込まれています。ビルド情報が削除されている場合や、逆アセンブラがこのメタデータを解析できない場合、命令が任意のデータアドレスを読み込んでいるように見え、対象領域に型情報が付与されないことがあります。このメタデータを復元すると、こうしたアドレスが読みやすい型参照に変わり、パッケージの機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver)はシンボルを抽出し、ランタイム型を解析してJSONレポートにできます。現在のCLIでは、`resolve`サブコマンドを使用します。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` オプションを指定すると、型の解析が有効になります。レポートを GoResolver の IDA Pro または Ghidra プラグインでインポートすると、復元された型を定義し、解析データベース内の参照に適用できます。この機能で導入されたレポート形式では、`-y` を省略すると、RTTI アドレスと復元された型のメンバーは null のままになります。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver は x86、AMD64、ARM、ARM64 の PE、ELF、Mach-O サンプルに対応しているため、同じ手順を Windows、Linux、macOS の Go バイナリに適用できます。<sup>[[10]](#references)</sup>

## コンパイル済みPython

このページでは、ELF/EXE の Python コンパイル済みバイナリから Python コードを取得する方法を紹介します:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの**バイナリ**を入手した場合、**エミュレート**や**デバッグ**にさまざまなツールを使用できます:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_デバッグ版をダウンロード_) - インターフェース付きのデバッガーを搭載
- [**mgba** ](https://mgba.io)- CLI デバッガーを搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra プラグイン
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra プラグイン

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の**ボタン**の押し方を確認できます

![Game Boy Advance のボタン割り当てを示す no$gba のコントロール設定](<../../images/image (581).png>)

押すと、各**キーには識別用の値**が割り当てられます:

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

![アドレス0x4000130でKEYINPUTを参照しているGBAバイナリのGhidraビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

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

最後のifは、**`uVar4`**が最後のKeysに含まれており、現在のキーではないことを確認しています。これはボタンを離すことに相当します（現在のキーは**`uVar1`**に格納されています）。

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

- まず、**値 4**（**SELECT**ボタン）と比較します。このチャレンジでは、このボタンを押すと画面がクリアされます。
- 次に、**値 8**（**START**ボタン）と比較します。このチャレンジでは、この分岐で入力したコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** を 0xf3 と比較し、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが 8 未満の間、押されたキーの値が `DAT_030000d8` に加算されていきます。

つまり、このチャレンジでは、ボタンの値がわかれば、合計が 0xf3 になる、長さが 8 未満の組み合わせを**押す必要がありました。**

**このチュートリアルの参考資料:** [アーカイブされた Nostalgia チャレンジの解説](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (バイナリの難読化解除)

## References

- [1] [CoBRA による MBA 難読化の簡略化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA リポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rust の文字列をデコードする - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA リバースエンジニアリングチュートリアル（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 支援リバースエンジニアリングを打ち破る、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [基本ブロックのマッチングに基づく制御フローグラフ比較のアプローチ](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver リポジトリ](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble の難読化メカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: 制御フローグラフの類似性を使って Golang バイナリの難読化を自動的に解除する](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor リポジトリ](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity の Golang ツールに関するアップデート](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものをリバースエンジニアリング](https://github.com/morluto/rea)
- [17] [REA のマネージドコード解析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI とエビデンスのガイド](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja による制御フローのアンフラット化ワークフロー](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF のゼロデイ侵入、Java ローダー、Web シェル、AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA ブリッジサーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra ブリッジサーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) はワイルドカードアドレスにバインドする](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot リバースエンジニアリングツールキット](https://github.com/figurophobia/gore)
- [26] [gore のキー復元実装](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore の暗号化 blob 形式](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore のコマンドおよび復元実装](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
