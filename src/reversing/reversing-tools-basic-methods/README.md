# リバースエンジニアリングツールと基本手法

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのリバースエンジニアリングツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbgのユーザーモード自動化

{{#ref}}
windbg-automation.md
{{#endref}}

## Officeドキュメントのマクロ解析

不審なOfficeドキュメントについては、[VBAマクロのジャンクコードと非表示のUserFormコントロール](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms)を調査してください。

## Windowsの例外駆動型制御フロー

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windowsカーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

オンライン:

- wasm（バイナリ）をwat（プレーンテキスト）に**逆コンパイル**するには、[https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用します
- watをwasmに**コンパイル**するには、[https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用します
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

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、ライブラリ（.dll）、Windowsメタデータファイル（.winmd）、実行ファイル（.exe）など、**複数の形式を逆コンパイルして調査する**decompilerです。逆コンパイルしたアセンブリは、Visual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、この機能によって時間を節約できます。さらに、dotPeekは逆コンパイルされたコード内を簡単に移動できるため、**Xamarinのアルゴリズム解析に最適なツールの1つ**です。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供する豊富なリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内でデータがどのように流れるかを把握できます
- .NET言語やフレームワークの実装と使用方法を把握できます
- ドキュメント化されていない、または公開されていない機能を見つけ、使用中のAPIやテクノロジーをさらに活用できます
- 依存関係やさまざまなアセンブリを見つけられます
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な場所を特定できます
- 使用しているすべての.NETコードのソースをデバッグできます

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): どのOSでも利用できます（VSCodeから直接インストールできるため、gitをダウンロードする必要はありません。**Extensions**をクリックして、**ILSpy**を検索してください）。\
**逆コンパイル**し、**変更**してから再び**再コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または現在もメンテナンスされているフォークの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内の内容を変更するには、**右クリック -> Modify Method**を選択します）。

### REAによる実行不要のマネージドコード検査

**REA**はアセンブリをロードせずに、PE/CLIメタデータとCILを検査できます。まずアーティファクトの識別情報を確認し、次にメンバーと宣言されたネイティブ境界を調べます。decompilerを使ったりプログラムを実行したりする前に、不審な呼び出しを確認する際に役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン間の差分を比較する際、`compare_managed_members` は、metadata token がビルド間で安定しているものとして扱わず、生の CIL／シグネチャの同一性と、デコードされた命令のフィンガープリントを使用します。P/Invoke 宣言だけではネイティブコードが実行された証拠にはなりません。この境界を確認するには、`verify_managed_native_boundaries` で対応するネイティブエクスポートまたは関数の証拠が必要です。アーティファクトのダイジェスト、MVID、未解決のマッピングは結果とともに保持してください。<sup>[[17]](#references)</sup>

### DNSpyのログ出力

**DNSpyに情報をファイルへログ出力させる**には、次のスニペットを使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpyでのデバッグ

DNSpyを使ってコードをデバッグするには、次の操作が必要です。

まず、**デバッグ**に関連する**アセンブリ属性**を変更します。

![DNSpy Logging - DNSpyでのデバッグ: まず、デバッグに関連するアセンブリ属性を変更します](<../../images/image (973).png>)

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

そして **compile** をクリックします。

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これを行う必要があるのは、行わないと **runtime** にコードへ複数の **optimisations** が適用され、デバッグ中に **break-point に到達しない**、または一部の **variables が存在しない**可能性があるためです。

.NET アプリケーションが **IIS** によって **実行**されている場合は、次のコマンドで **再起動**できます：

```
iisreset /noforce
```

次に、debuggingを開始するには、開いているファイルをすべて閉じ、**Debug Tab** から **Attach to Process...** を選択します。

![DNSpy Logging - DNSpy Debugging: 次に、debuggingを開始するには、開いているファイルをすべて閉じ、Debug Tab から Attach to Process を選択します](<../../images/image (318).png>)

次に **w3wp.exe** を選択して **IIS server** にattachし、**attach** をクリックします。

![DNSpy Logging - DNSpy Debugging: 次に、w3wp.exe を選択して IIS server にattachし、attach をクリックします](<../../images/image (113).png>)

processをdebuggingしているので、次は停止してすべてのmoduleを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: processをdebuggingしているので、次は停止してすべてのmoduleを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: processをdebuggingしているので、次は停止してすべてのmoduleを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意のmoduleをクリックし、**Open All Modules** を選択します。

![DNSpy Logging - DNSpy Debugging: Modules 内の任意のmoduleをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のmoduleを右クリックし、**Sort Assemblies** をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のmoduleを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのdebugging

### IDAを使用する

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debuggerを選択します
- "**Suspend on library load/unload**" を選択します

![Debugging DLLs - IDAを使用する: "Suspend on library load/unload" を選択します](<../../images/image (868).png>)

- **parameters** に **DLLのパス** と呼び出したいfunctionを設定します。

![Debugging DLLs - IDAを使用する: parameters にDLLのパスと呼び出したいfunctionを設定します](<../../images/image (704).png>)

debuggingを開始すると、**DLLが読み込まれるたびに実行が停止します**。そのため、rundll32がDLLを読み込むと、実行が停止します。

この方法ではmoduleの読み込みイベントで停止しますが、読み込んだDLLのentry pointに到達する操作は、以下のx64dbgの手順より直接的ではありません。

### x64dbg/x32dbgを使用する

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更**（_File --> Change Command Line_）し、dllのパスと呼び出したいfunctionを設定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- **実行を開始**すると、debuggerは各dll mainで停止します。そのうち、**自分のdllのEntryで停止します**。そこから、breakpointを設定したい箇所を探してください。

win64dbgで何らかの理由により実行が停止したときは、**win64dbgウィンドウの上部**を見ると、**どのcodeにいるか**を確認できます。

![Using IDA - x64dbg/x32dbgを使用する: 実行が何らかの理由で停止したときは、win64dbgウィンドウの上部を見ると、どのcodeにいるかを確認できます](<../../images/image (842).png>)

このindicatorにより、debugしたいDLL内で実行が停止したことを確認できます。

## GUIアプリ / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のgameのmemory内で重要な値が保存されている場所を見つけ、値を変更するのに便利なprogramです。詳細は以下を参照してください。

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、gameに重点を置いたGNU Project Debugger (GDB)向けのfront-end/reverse engineering toolです。ただし、reverse engineeringに関連する用途であれば何にでも使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数のdecompilerを利用できるweb front-endです。このweb serviceでは、小さなexecutableに対する各decompilerの出力を比較できます。

### Godot PCKの復号とprojectの復元

配布されたGodot gameでは、単独の`.pck`、実行ファイルに追加または埋め込まれたpack、あるいはAPKの`assets`ディレクトリからPCKを見つけます。[gore](https://github.com/figurophobia/gore)でpackを検査・展開できます。scriptとresourceを完全に再構築するにはGDRE Toolsが必要です（`gore setup`でインストールするか、`--gdre`を使用します）。このworkflowではGodot 4.xのPCK形式v2～v4に対応しています。v1のheaderは検出できますが、v1にはkeyの指定が必要です。<sup>[[25]](#references)</sup>

自動key復元には暗号化されたfile tableが必要です。fileの内容だけが暗号化されている場合は、既知のkeyを指定してください。復元に失敗しても、packが暗号化されていないとは限りません。<sup>[[28]](#references)</sup>

keyの検索は、**AES-256のkeyspaceに対する攻撃ではありません**。暗号化されたfile tableには、平文のMD5、平文の長さ、IV、AES-256-CFBのciphertextが含まれます。<sup>[[27]](#references)</sup> `gore`は、gameの実行ファイルや隣接するfileから32-byteの範囲を切り出し、candidate keyとして試します。復号したpathの長さとprefixが妥当かどうかでcandidateを絞り込み、binary scanで見つかった候補については、table全体を復号してMD5を確認します。<sup>[[26]](#references)[[28]](#references)</sup> まず初期化済みのPE/ELF data sectionを検索し、その後、file全体をscanします。`--scan`を指定すると、ほかのcandidate fileも検索対象に加わります。<sup>[[28]](#references)</sup>

埋め込みkeyが見つからない場合は、組み込みの小さなpassword listが試されます。ほかの候補を指定するには`--wordlist`を使用します。各passwordは、engineのpassword由来のkey表現、ゼロpaddingした文字列、または64文字のhex keyとして試されます。binary scanで見つかった候補とは異なり、この実装ではwordlistで見つかった候補はpath構造のfilterを通過するだけです。packを開いて、展開されたassetを検証してください。<sup>[[26]](#references)[[28]](#references)</sup>

gameのartifactをローカルで利用できる場合は、分析に必要な段階を選択します。`recover`はGDREを呼び出して、開けるprojectを再構築します。一方、`extract`はraw fileを展開するだけです。`key`は、別のtoolで使用するcandidate keyを出力します。<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## REAによるエビデンスに基づくネイティブ調査

**REA**は、Hopper、Ghidra、IDAの解析機能をCLIおよびMCP経由で利用できます。Node.js 22.x（22.19以上）、24.x（24.11以上）、または26以上とnpmが必要です。まず既存のネイティブプロバイダーを設定してください。`rea providers --json`で確認し、対象をサポートするプロバイダーが複数ある場合は、プロバイダーを明示的に選択します。以下の`0x1000`は、インベントリにある実際に確認済みの関数名またはアドレスに置き換えてください。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

機能文字列またはシンボルから始め、参照先や呼び出し元をたどり、選択した関数の dossier と擬似コードを `rea decompile` で調べます。REA は失敗後に黙って別の provider に切り替えるのではなく、選択した provider にセッションを固定します。クエリを再現可能にするには、`--snapshot PATH` を指定すると、一致する artifact のバイト列、provider、設定、操作、パラメーターに限って再利用します。snapshot はローカルキャッシュであり、provider のデータベースを保存したものではありません。返された Evidence と明示された未知事項を保持し、推定されたパスや decompiler の出力を元のソースとして扱わないでください。<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron のエントリーポイントから native add-on へ至る場合は、[Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) を参照してください。

## ローカルTCPブリッジを使ったIDAとGhidraのスクリプト分析

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) は、**すでに開いている** IDA データベースまたは Ghidra CodeBrowser プログラム内で実行され、別のスクリプトから分析データベースを照会・変更できるようにします。IDA の Python CLI から `ID_Server.py`（`import ID_Server`）を実行するか、Ghidra の Script Manager から `Ghidra_Server.py` を実行します。IDA は `127.0.0.1` のポート `5073` からバインドを開始し、より大きいポートを順にスキャンします。現在の Ghidra スクリプトはポート `5093` から開始し、`5102` までの10個のポートを試します。Java socket は loopback のみに限定せず、ワイルドカードアドレスにバインドします。接続する前に、インスタンスが出力したポートを確認してください。headless analyzer とは異なり、このブリッジはその GUI インスタンスで現在開いているプログラムを操作します。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

接続ごとに、改行で終わるコマンドを**1つ**送信し、改行で終わる応答を読み取ります。結果は通常 JSON です。たとえば、入力パスに関係する imported API を見つけた後、`IMPORTXREF` でその呼び出し箇所を検索し、続いて `DECOMP_XREF` で選択したアドレスの呼び出し元をまとめて逆コンパイルできます。`FUNC` は関数を調べ、`PCODE` は decompiler の中間表現を返します。別の rebase 済みバイナリからコピーしたアドレスではなく、アクティブなデータベースのアドレスを使ってください。以下の例は IDA のデフォルトポートを使用しています。Ghidra の場合は、そのスクリプトが出力したポートを使ってください。<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

同じチャネルから**analysis databaseを変更する**こともできます。`RENAME_FUNC`、`RETYPE`、`SETCONV`、`DEFSTRUCT`/`SETFIELD`、`MAKEFUNC`、`PATCH`は、名前、型、構造体定義、関数境界、または保存されたバイト列を変更します。`PATCH`はdatabaseの編集であり、実行中プロセスへのpatchを示すものではありません。どちらのlistenerも認証について記載していません。IDAはloopback限定ですが、Ghidraはネットワークインターフェース経由でアクセス可能な場合があります。Ghidraのlistenerを使う場合は、アクセスを制限してください。`QUIT`はどちらのlistenerも停止し、IDAでは`ida_bridge_stop()`も利用できます。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerを使ったshellcodeのデバッグ

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**を割り当て、その**メモリアドレス**を表示してから、実行を一時停止します。\
IDAやx64dbgなどのdebuggerをアタッチし、表示されたアドレスにbreakpointを設定して実行を再開すると、shellcodeをデバッグできます。

GitHubのreleasesページには、コンパイル済みリリースを含むzipファイルがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクから、少し変更されたBlobrunnerのバージョンを入手できます。コンパイルするには、**Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドするだけ**です。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itを使ったshellcodeのデバッグ

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerと似ています。shellcodeを割り当てて、無限ループに入ります。debuggerをアタッチし、**2～5秒**間実行を再開してから、そのループ内で一時停止し、割り当てられたshellcodeに実行を移す次のcallまでステップ実行します。

![jmp2itの無限ループ内で、割り当てられたshellcodeへのcall直前にdebuggerが一時停止している状態](<../../images/image (509).png>)

コンパイル済みの[jmp2itはreleasesページからダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使ったshellcodeのデバッグ

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使うと、shellcodeをエミュレートして動的に調べることができます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。同じshellcodeをファイルとして開いた場合は正しく逆コンパイルされましたが、shellcodeとして開いた場合は正しく処理されませんでした。

![同じバイト列をファイルとshellcodeとして開いたときの異なる解析結果を表示するCutter](<../../images/image (562).png>)

指定した場所からエミュレーションを開始するには、その場所にbpを設定します。すると、Cutterはそこから自動的にエミュレーションを開始するようです。

![Cutterでエミュレーションを開始する前に、目的のshellcodeエントリにbreakpointを設定](<../../images/image (589).png>)

![選択したshellcodeのbreakpointで一時停止しているCutterのemulator](<../../images/image (387).png>)

たとえば、hex dumpでstackを確認できます。

![Cutterのhex dumpでエミュレートされたshellcodeのstackを表示](<../../images/image (186).png>)

### shellcodeをdeobfuscateして実行された関数を特定する

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

scDbgには、必要なオプションを選択してshellcodeを実行できるグラフィカルランチャーもあります

![shellcodeのエミュレーションとトレースのオプションを選択するscDbgグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump**オプションを使うと、メモリ上でshellcodeが動的に変更された場合に、最終的なshellcodeをダンプできます（デコードされたshellcodeのダウンロードに便利です）。**start offset**は、特定のオフセットからshellcodeを開始する場合に便利です。**Debug Shell**オプションを使うと、scDbgのターミナルでshellcodeをデバッグできます（ただし、この用途では、前述したいずれかのオプションのほうが優れていると思います。Idaやx64dbgを使用できるためです）。

### CyberChefを使用した逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationの難読化解除

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、`x + y`のような単純な式を、算術演算（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた数式で隠します。重要なのは、こうした恒等式が通常、**固定幅の剰余演算**でのみ成立することです。そのため、キャリーとオーバーフローが重要になります:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用代数ツールで簡略化すると、bit-width のセマンティクスが無視されているため、誤った結果になりやすいです。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. lifted code/IR/decompiler output の**元の bit-width**（`8/16/32/64` bits）を維持する。
2. 簡略化を試す前に、式を**分類する**:
   - **線形**: bitwise atom の加重和
   - **半線形**: `x & 0xFF` のような定数マスクを含む線形式
   - **多項式**: 積を含む
   - **混合**: 積と bitwise logic が入り交じり、同じ部分式が繰り返し現れることが多い
3. ランダムテストまたは SMT proof で、書き換え候補をすべて**検証する**。同値性を証明できない場合は、推測で書き換えず、元の式を維持する。

### 狭い実行スライスでflattened control flowを回避する

完全な control-flow graph を復元する必要はないことがよくあります。control-flow flattening、opaque predicates、大規模な dispatcher、または MBA-heavy なコードでは、暗号化された blob や出力バッファから参照をたどり、それらを変換する最小のルーチンを特定します。その後、その data-flow slice だけを再現するか、単独で実行します。関連する状態を直接初期化できるなら、dispatcher は必要な解法に含まれません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです:<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocation、cross-reference を一覧化する。`.rodata` から候補となるテーブルをdumpし、バイト順と要素幅を維持する。
2. plaintext または出力バッファに最後に書き込むルーチンを特定する。その入力、参照されるテーブル、importされた呼び出し、および必要なグローバル状態を記録する。
3. それらの処理だけを固定幅の Python model に移す。slice が依然として過剰な状態に依存する場合は、プログラム全体をemulateする代わりに、Unicorn、QEMU、またはdebuggerでルーチンを呼び出し、無関係なimportをhookする。
4. extractorが与えられたbinaryから実際に出力を導出していることを検証する。無言のfallbackを削除し、埋め込み済みの答えがないか検索し、文字列、鍵、識別子、レイアウト、難読化seedを変更した未知のbuildでも実行する。

最初に試すとよいコマンドは次のとおりです:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装した MBA 式を検出する

一見すると入力に依存しているように見えるバイト式でも、入力が完全に相殺されることがあります。テーブルを抽出した後、8 ビットの全領域にわたって式を評価します。出力集合が単一の値なら、周囲の状態機械を復元しなくても、そのバイトが定数であると証明できます。<sup>[[7]](#references)</sup>

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

元の加算はバイト幅でラップアラウンドするため、最後のマスクは残してください。より広いドメインでは、同じ幅の記号入力 `x1` と `x2` に対して `f(x1) != f(x2)` が充足可能か SMT solver に問い合わせます。`unsat` は不変性を証明し、`sat` は反例を示すため、その入力を破棄できないことを意味します。<sup>[[7]](#references)</sup>

#### 環境依存のデコードを見分ける

Anti-analysis チェックは、分岐やクラッシュを伴うとは限りません。decoder はセンサーの結果を鍵ビット、不透明述語の定数、または平坦化された dispatcher の状態に混ぜ、正常に処理を続けながら、emulator 上で一見もっともらしい偽の平文を生成することがあります。そのため、目に見える失敗分岐だけをパッチするのでは不十分です。環境プローブから decoder の状態へのデータ依存関係を追跡し、実機と emulator で同じ処理スライスを比較し、各センサー結果を強制的に変更したときに最終バッファがどう変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware analysis と保護された binary の reversing に実用的な MBA simplifier です。すべてに汎用の rewrite pass を適用するのではなく、式を分類し、専用の pipeline に振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA は Boolean 入力で式を評価して signature を導出し、pattern matching、ANF conversion、coefficient interpolation など複数の復元手法を並行して実行します。
- **Semilinear MBA**: constant-masked atom は bit-partitioned reconstruction で再構築され、マスクされた領域が正しく保たれます。
- **Polynomial/Mixed MBA**: 積は cores に分解され、繰り返し現れる部分式は一時変数に持ち上げてから、外側の関係式を簡略化できます。

復元を試す価値がある、一般的な mixed identity の例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次の形にまとめられます:

```c
x * y
```

### リバースに関するメモ

- 正確な計算を特定した後、**lifted IR expressions**またはデコンパイラの出力に対してCoBRAを実行するのが望ましいです。
- 式がマスク演算や狭いレジスタに由来する場合は、`--bitwidth`を明示的に指定してください。
- より強力な証明ステップが必要な場合は、こちらのZ3に関するローカルメモを確認してください。


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRAは**LLVM pass plugin**（`libCobraPass.so`）としても提供されており、後続の解析passの前に、MBAを多用するLLVM IRを正規化したい場合に便利です。
- carryに依存する未対応の混合ドメイン残差がある場合は、元の式を維持し、carryの経路を手作業で推論する必要があるという兆候として扱ってください。

## XOR-stateによるcontrol-flow flatteningの復元

OLLVM形式のflatteningでは、2つの64-bitレジスタに現在のbasic blockのstateを保持し、dispatcherでXORを使って復元することがあります。元の各blockは、次のstateに対応するレジスタペアを書き込み、dispatcherに戻ります。条件付きblockでは、CPU flagsに応じてペアの片方を置き換えるために`CMOVcc`を使うことがあり、目に見える分岐命令だけを追っていると、2つの後続先を見落とします。間接ジャンプを使うdispatcherとは異なり、この形式では全体を通じて直接のback-edgeを使えます。<sup>[[19]](#references)[[20]](#references)</sup>

グラフを復元するには、dispatcherの比較木と2つのstateレジスタを特定し、比較された各XOR stateを対象blockに対応付けてから、元の各blockでレジスタペアに到達する書き込みを追跡します。条件付きの書き込みでは、flagsを設定する命令と、両方の`CMOVcc`の結果を考慮します。各blockのdispatcherへの出口を、解決した直接の後続先または条件分岐に書き換えます。これにより、バイナリをpatchせずにdispatcherを到達不能にできます。これはCFG全体を対象にする方法です。対象となるdecoderが1つだけなら、上記の[narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice)のほうが速い場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis)は、Binary Ninjaでこの形式を自動化します。`plugins/DispatchThis`をBinary Ninjaのユーザープラグインディレクトリにコピーして、再起動してください。対象の関数で**Function Settings**を開き、`OLLVM_XOR_64`を選択します。解析が始まらない場合は、**Analysis → Reanalyze All Functions**を実行してください。このモードはファイルのバイト列ではなくMLILのcontrol-flow edgeを書き換え、Z3や間接ジャンプresolverを必要としません。Binary Ninja 5.3.9757以降で動作確認されています。blockごとの不要なstate書き込みは削除されないため、それらをまだ有効な遷移と誤認しないでください。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

このobfuscatorは、プログラムの操作を`mov`ベースの命令列に置き換え、signal/exception handlingを使ってcontrol flowを変更します。詳細はこちらを参照してください。

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応するバイナリであれば、[demovfuscator](https://github.com/kirschju/demovfuscator)で結果をdeobfuscateできます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）。

**CTFをプレイしている場合、この回避策はflagを見つけるのに非常に役立つ可能性があります**：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリポイント**を見つけるには、次のように関数名に含まれる`::main`を検索します。

![Ghidraで関数名のdouble-colon mainを検索してRustのエントリポイントを見つける](<../../images/image (1080).png>)

このケースでは、バイナリ名がauthenticatorだったため、どれが興味深いmain関数なのかは明らかです。\
呼び出されている**関数**の**名前**がわかったら、**入力**と**出力**を調べるために**インターネット**で検索します。

### ELFファームウェアからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列がCスタイルのNUL終端ポインターとして参照されていません。一般的な`rustc`のレイアウトでは、**`.data.rel.ro`**内の**ポインターと長さのタプル**が、**`.rodata`**に格納された実際の文字列データを指しています：

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

これは、`strings` や Ghidra のデフォルトの解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりする可能性があるということです。<sup>[[3]](#references)</sup>

簡単なワークフロー:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得します。
2. **`.data.rel.ro`** を1ワードずつ列挙します。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱います。
4. 次のワードを候補の長さとして扱います。
5. 妥当性フィルターを適用します（たとえば、長さが **4**〜**100** バイトのものを残します）。
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

これは、復元された Rust の文字列から **HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、auth関連のロジック** が見つかることが多いため、firmwareのreversingで特に役立ちます。

Ghidraがこれらの文字列を検出できない場合は、同じヒューリスティックを適用し、参照先の `.rodata` offsets にstring dataを作成するカスタムscript/pluginを実行してください。Pen Test Partnersが公開している `rust-strings` と `RustStrings.py` は、このアイデアを他の **word sizes、endianness、section layouts** に適用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphiでコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphiバイナリをreversingする場合は、IDA pluginの [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をおすすめします。

IDAで **Alt+F7** を押してPython pluginを読み込み、pluginファイルを選択します。

このpluginはバイナリを実行し、debuggingの開始時にfunction namesを動的に解決します。debuggingを開始した後、もう一度Start button（緑色のボタンまたはf9）を押すと、実際のcodeの先頭でbreakpointがヒットします。

graphical applicationでボタンを押すと、debuggerはそのボタンから呼び出されたfunctionで停止できます。

## Golang

一般的なGoバイナリでは、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使うと、runtime structuresを復元し、IDA上のfunction namesを改善できます。**Alt+F7** でPython pluginを読み込みます。

Golangバイナリをreversingする場合は、IDA pluginの [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をおすすめします。

IDAで **Alt+F7** を押してPython pluginを読み込み、pluginファイルを選択します。

これによりfunction namesが解決されます。

### シンボルテーブルなしでmetadataを復元する

stripされたGo executableでも、program countersをfunctionsに対応付けるためにruntime metadataが必要です。[GoReSym](https://github.com/mandiant/GoReSym) は、Go runtime由来のcodeを使用して `pclntab` や `moduledata` などのstructuresを特定し、解析します。従来のシンボルテーブルに依存せずに、function boundaries、names、source paths、types、build detailsを復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

難読化ツールは、復元された名前を置き換えながら、それらの構造を使用可能な状態に保つことがあります。たとえば Garble は、識別子と package path をハッシュ化し、build、module、debug 情報を削除します。<sup>[[12]](#references)</sup> 難読化された package token は、その package 内の関数間で一貫している必要があります。繰り返し現れる token で関数をグループ化し、callee、文字列、API から package を1つ推定して、その package ラベルをグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolver で Garble の名前を復元する

[GoResolver](https://github.com/volexity/GoResolver) は、runtime symbol の抽出と、クリーンな参照バイナリの生成、control-flow graph（CFG）のマッチングを組み合わせます。次の手順を使用します。<sup>[[10]](#references)[[13]](#references)</sup>

1. **コンパイラのバージョンを特定する。** まず `BuildInfo` と埋め込みバージョン文字列を確認します。obfuscator に削除されている場合は、同梱された Go runtime の一部を、バージョン別の参照 runtime と比較します。Volexity のテストでは、runtime の約 `2%` で Go のメジャーバージョンを識別できました。これは実験に基づく最適化であり、普遍的なしきい値ではありません。<sup>[[13]](#references)</sup>
2. **マッチング用の参照バイナリを作成する。** 特定した Go バージョン、ターゲットアーキテクチャ、使用されている可能性の高いライブラリに合わせて、クリーンなバイナリを生成します。toolchain を一致させることで、コンパイラが生成する CFG の差異を減らせます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapher は関数の CFG をマッチングし、`0.0` から `1.0` までの正規化スコアを出力します。basic block のマッチングは、類似する命令の重み付け比較に基づいています。信頼度の高いマッチは、ランダム化された関数をクリーンな実装に対応付けます。信頼度が低めのマッチでも、package や module の特定に役立ちます。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** call relationship、定数、文字列、side effect を使って候補の名前を確認し、GoResolver の IDA または Ghidra 用 plugin で JSON レポートをインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

toolchain をインストールし、抽出ツールと graph matcher を組み合わせて実行します。<sup>[[10]](#references)</sup>

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

デフォルトの significant-match threshold は `0.9` です。`--extract` と `--graph` のスイッチを使うと各ステージを個別に実行できます。デフォルトでは、復元された runtime metadata と CFG の証拠が互いを補完するため、両方を実行します。<sup>[[10]](#references)</sup> CFG のスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わることがあるため、確信度の低い名前を無理に割り当てず、解決できなかった関数はそのままにしてください。<sup>[[13]](#references)</sup>

### Go の string table の復元

Go バイナリでは、リンクされたすべてのパッケージの文字列バイト列が、連続したテーブルに格納されます。エントリは NUL 終端されておらず、runtime の構造体からテーブルのベースアドレスやサイズを取得することもできません。しかし、コンパイラは OS やアーキテクチャにかかわらず、エントリをまず長さ順、次にアルファベット順に並べます。そのため、1つのエントリを見つければ、隣接するエントリをたどり、データのクロスリファレンスを使って文字列をコードに関連付けられます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) は、この手順を IDA Pro と Ghidra で自動化します。プラグインはデータセグメントのクロスリファレンスに依存するため、まず自動解析を完了させてください。デフォルトのアンカーは runtime 文字列 `entersyscall` です。その後、どちらの方向にもスキャンし、復元した文字列をデータベース内に定義して、文字列と参照元の関数を対応付けた JSON をエクスポートできます。<sup>[[14]](#references)</sup>

参照元の関数が属するパッケージでレポートをフィルタリングすると、アプリケーションやマルウェアのコードを、リンクされたライブラリ由来のノイズから分離できます。この手法では、Garble の `-literals` 変換のような難読化によって破壊されたリテラルは復元できません。ただし、難読化されていない runtime 文字列の整理には引き続き利用できます。<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime の型情報の復元

Go は、ガベージコレクションなどの機能で使用される runtime の型情報を埋め込みます。ビルド情報が削除されていたり、逆アセンブラがこのメタデータを解析できなかったりすると、命令が任意のデータアドレスを読み込んでいるように見え、対象領域に型情報が付与されません。メタデータを復元すると、それらのアドレスが読みやすい型参照に変わり、パッケージの機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) は、シンボルを抽出し、runtime の型情報を解析して JSON レポートに出力できます。現在の CLI では `resolve` サブコマンドを使用します。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` オプションを有効にすると、type parsing が行われます。GoResolver の IDA Pro または Ghidra plugin でレポートをインポートし、復元された型を定義して、分析データベース内でその参照を適用します。この機能で導入されたレポート形式では、`-y` を省略すると、RTTI address と recovered-types members は null のままです。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver は x86、AMD64、ARM、ARM64 の PE、ELF、Mach-O サンプルに対応しているため、同じワークフローを Windows、Linux、macOS の Go バイナリに適用できます。<sup>[[10]](#references)</sup>

## Compiled Python

このページでは、ELF/EXE の Python コンパイル済みバイナリから Python コードを取得する方法を説明します。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの**バイナリ**を入手した場合、さまざまなツールを使って**エミュレート**および**デバッグ**できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_デバッグバージョンをダウンロード_) - インターフェース付きの debugger を搭載
- [**mgba** ](https://mgba.io)- CLI debugger を搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の**ボタン**の押し方を確認できます。

![Game Boy Advance のボタン割り当てを示す no$gba のコントロール設定](<../../images/image (581).png>)

押すと、各**キーには識別用の値**が割り当てられます。

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

次のコードが見つかります：

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

最後の if は、**`uVar4`** が前回の Keys に含まれており、現在のキーではないことを確認しています。つまり、ボタンを離した状態です（現在のキーは **`uVar1`** に格納されています）。

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

前のコードでは、**uVar1**（**押されたボタンの値**が格納されている場所）が、いくつかの値と比較されていることがわかります。

- まず、**値 4**（**SELECT**ボタン）と比較されます。このチャレンジでは、このボタンを押すと画面がクリアされます。
- 次に、値が **8**（**START**ボタン）と比較されます。このチャレンジでは、この経路で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが 8 未満の間、押されたキーの値が `DAT_030000d8` に加算されます。

つまり、このチャレンジでは、ボタンの値を把握したうえで、合計が 0xf3 になる、長さが 8 未満の組み合わせを**押す必要がありました**。

**このチュートリアルの参考資料:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [MBA obfuscation を CoBRA で簡略化する](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA リポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rust 文字列のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reverse engineering チュートリアル（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI 支援による reverse engineering を阻止する、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [基本ブロックマッチングに基づく制御フローグラフ比較のアプローチ](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver リポジトリ](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble の obfuscation メカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: 制御フローグラフの類似性を用いて Golang バイナリを自動的に deobfuscate する](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor リポジトリ](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang ツールのアップデート](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものを reverse engineer する](https://github.com/morluto/rea)
- [17] [REA の managed-code 分析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI と Evidence ガイド](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja の control-flow unflattening ワークフロー](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF のゼロデイ侵入、Java Loader、Web Shell、AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge サーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge サーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) はワイルドカードアドレスにバインドする](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot reverse engineering toolkit](https://github.com/figurophobia/gore)
- [26] [gore の key-recovery 実装](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore の encrypted-blob 形式](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore のコマンドおよびリカバリー実装](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
