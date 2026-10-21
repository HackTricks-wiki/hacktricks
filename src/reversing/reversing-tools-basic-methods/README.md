# リバースエンジニアリングツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのリバースエンジニアリングツール

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

## Wasm逆コンパイラ / Watコンパイラ

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使って、wasm（バイナリ）からwat（プレーンテキスト）に**逆コンパイル**できます
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使って、watからwasmに**コンパイル**できます
- 逆コンパイルには、[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

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

## .NET逆コンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、**ライブラリ**（.dll）、**Windowsメタデータファイル**（.winmd）、**実行ファイル**（.exe）など、複数の形式を**逆コンパイルして調査**できる逆コンパイラです。逆コンパイルしたアセンブリは、Visual Studioプロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、この機能によって時間を節約できるのが利点です。また、dotPeekは逆コンパイルされたコード内を簡単に移動できるため、**Xamarinのアルゴリズム解析**に最適なツールの一つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できるAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供するさまざまなリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内でデータがどのように流れるかを把握できます
- .NET言語やフレームワークの実装と使用方法を確認できます
- ドキュメント化されていない機能や公開されていない機能を見つけ、使用中のAPIやテクノロジーをさらに活用できます
- 依存関係やさまざまなアセンブリを見つけられます
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な位置を特定できます
- 使用するすべての.NETコードのソースをデバッグできます

### [ILSpy](https://github.com/icsharpcode/ILSpy) と [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): どのOSでも使用できます（VSCodeから直接インストールできるため、gitをダウンロードする必要はありません。**Extensions**をクリックして、**ILSpy**を検索してください）。\
**逆コンパイル**、**変更**、再**コンパイル**が必要な場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)、または現在もメンテナンスされているフォークの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（関数内を変更するには、**Right Click -> Modify Method**を選択します）。

### REAによる実行を伴わないマネージドコードの調査

**REA**はアセンブリを読み込まずに、PE/CLIメタデータとCILを調査できます。まず成果物の識別情報を確認し、次にメンバーと宣言されたネイティブ境界を調べます。これは、逆コンパイラを使ったりプログラムを実行したりする前に、不審な呼び出しを確認する際に役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン差分の比較では、`compare_managed_members` は metadata token がビルド間で安定しているものとして扱わず、生の CIL/signature identity と decoded-instruction fingerprints を使用します。P/Invoke 宣言は native code が実行された証拠にはなりません。この境界を確認するには、`verify_managed_native_boundaries` で一致する native export または function Evidence が必要です。artifact digest、MVID、未解決の mappings を結果とともに保持してください。<sup>[[17]](#references)</sup>

### DNSpy Logging

**DNSpy に情報をファイルへ記録させる**には、次のスニペットを使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpyによるデバッグ

DNSpyでコードをデバッグするには、次の手順が必要です。

まず、**デバッグ**に関連する**アセンブリ属性**を変更します。

![DNSpy Logging - DNSpyによるデバッグ: まず、デバッグに関連するアセンブリ属性を変更します](<../../images/image (973).png>)

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

そして、**コンパイル**をクリックします:

![DNSpy Logging - DNSpy Debugging: そして、コンパイルをクリック](<../../images/image (314) (1).png>)

次に、_**ファイル >> モジュールを保存...**_ で新しいファイルを保存します:

![DNSpy Logging - DNSpy Debugging: 次に、ファイルの保存で新しいファイルを保存](<../../images/image (602).png>)

これを行う必要があるのは、そうしないと**実行時**にコードにいくつかの**最適化**が適用され、デバッグ中に**ブレークポイントに到達しない**、または一部の**変数が存在しない**可能性があるためです。

次に、.NET アプリケーションが **IIS** によって**実行**されている場合は、次のコマンドで**再起動**できます:

```
iisreset /noforce
```

その後、debuggingを開始するには、開いているファイルをすべて閉じ、**Debug Tab**で**Attach to Process...**を選択します。

![DNSpy Logging - DNSpy Debugging: その後、debuggingを開始するには、開いているファイルをすべて閉じ、Debug TabでAttach to Processを選択します](<../../images/image (318).png>)

次に、**w3wp.exe**を選択して**IIS server**にattachし、**attach**をクリックします。

![DNSpy Logging - DNSpy Debugging: 次に、w3wp.exeを選択してIIS serverにattachし、attachをクリックします](<../../images/image (113).png>)

プロセスをdebuggingしているので、次は停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしているので、次は停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、次にDebug Windows Modulesをクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをdebuggingしているので、次は停止してすべてのモジュールを読み込みます。まずDebug Break Allをクリックし、次にDebug Windows Modulesをクリックします](<../../images/image (834).png>)

**Modules**内のモジュールをクリックし、**Open All Modules**を選択します。

![DNSpy Logging - DNSpy Debugging: Modules内のモジュールをクリックし、Open All Modulesを選択します](<../../images/image (922).png>)

**Assembly Explorer**内のモジュールを右クリックし、**Sort Assemblies**をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer内のモジュールを右クリックし、Sort Assembliesをクリックします](<../../images/image (339).png>)

## Javaデコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのdebugging

### IDAを使用

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debuggerを選択します
- "**Suspend on library load/unload**"を選択します

![Debugging DLLs - IDAを使用: " Suspend on library load/unload "を選択します](<../../images/image (868).png>)

- 実行の**parameters**を設定し、**DLLのパス**と呼び出す関数を指定します。

![Debugging DLLs - IDAを使用: 実行のparametersを設定し、DLLのパスと呼び出す関数を指定します](<../../images/image (704).png>)

その後、debuggingを開始すると、**各DLLの読み込み時に実行が停止します**。つまり、rundll32がDLLを読み込むと実行が停止します。

この方法ではmodule-loadイベントで停止しますが、読み込まれたDLLのentry pointに到達する手順は、以下のx64dbgの方法より直接的ではありません。

### x64dbg/x32dbgを使用

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更**（_File --> Change Command Line_）し、dllのパスと呼び出す関数を指定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_を変更し、"**DLL Entry**"を選択します。
- **実行を開始**すると、debuggerは各dll mainで停止します。いずれ、**対象dllのDLL Entryで停止します**。そこから、breakpointを設定したい箇所を探します。

win64dbgで何らかの理由により実行が停止したときは、**win64dbgウィンドウの上部**を見ると、**どのコード内にいるか**確認できます。

![IDAを使用 - x64dbg/x32dbgを使用: win64dbgで何らかの理由により実行が停止したときは、win64dbgウィンドウの上部を見ると、どのコード内にいるか確認できます](<../../images/image (842).png>)

この表示により、debugging対象のDLL内で実行が停止したことを確認できます。

## GUIアプリ / ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内で重要な値が保存されている場所を見つけ、値を変更するのに便利なプログラムです。詳細はこちら：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)は、ゲームに特化したGNU Project Debugger（GDB）のフロントエンド / reverse engineeringツールです。ただし、reverse engineeringに関するあらゆる用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/)は、複数のデコンパイラを利用できるWebフロントエンドです。このWebサービスでは、小さな実行ファイルに対する各デコンパイラの出力を比較できます。

## REAを使った証拠に基づくネイティブ調査

**REA**は、CLIとMCPを通じてHopper、Ghidra、IDAの解析機能を提供します。Node.js 22.x（少なくとも22.19）、24.x（少なくとも24.11）、または26+とnpmが必要です。まず既存のネイティブproviderを設定してください。`rea providers --json`を確認し、対象に対応するproviderが複数ある場合は明示的に選択します。以下の`0x1000`には、inventoryで確認した関数名またはアドレスを指定してください。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

機能文字列またはシンボルから始め、参照と呼び出し元をたどってから、選択した関数の詳細情報と疑似コードを `rea decompile` で調べます。REAは、失敗後にプロバイダーを暗黙に切り替えるのではなく、選択したプロバイダーにセッションを紐付けます。クエリを再現可能にするには、`--snapshot PATH` を使うと、一致するアーティファクトのバイト列、プロバイダー、設定、操作、パラメーターに限って再利用されます。スナップショットはローカルキャッシュであり、保存されたプロバイダーデータベースではありません。推定されたパスやデコンパイラーのテキストを元のソースとして扱わず、返されたEvidenceと明示された不明点を保持してください。<sup>[[16]](#references)[[18]](#references)</sup>

ネイティブアドオンにつながるJavaScript/Electronのエントリーポイントについては、[Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea)を参照してください。

## ローカルTCPブリッジを使ったIDAおよびGhidraのスクリプト分析

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)は、**すでに開いている**IDAデータベースまたはGhidra CodeBrowserのプログラム内で動作し、別のスクリプトからその分析データベースを照会・変更できます。IDAのPython CLIから`ID_Server.py`（`import ID_Server`）を実行するか、GhidraのScript Managerから`Ghidra_Server.py`を実行します。IDAは`127.0.0.1`のポート`5073`からバインドを開始し、より大きいポートを順にスキャンします。現在のGhidraスクリプトはポート`5093`から開始し、`5102`までの10個のポートを試します。そのJavaソケットはワイルドカードアドレスにバインドされ、ループバックに限定されません。接続する前に、インスタンスが表示したポートを確認してください。ヘッドレスアナライザーとは異なり、このブリッジはそのGUIインスタンスで現在開いているプログラムを操作します。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

**接続ごとに改行で終わるコマンドを1つ**送信し、改行で終わる応答を読み取ります。結果は通常JSONです。たとえば、入力パスに関係するインポート済みAPIを見つけたら、`IMPORTXREF`でその呼び出し箇所を検索し、続いて`DECOMP_XREF`で選択したアドレスの呼び出し元をまとめてデコンパイルできます。`FUNC`は関数を調べ、`PCODE`はデコンパイラーの中間表現を返します。別のベースアドレスにリベースされたバイナリからコピーしたアドレスではなく、アクティブなデータベース内のアドレスを使ってください。以下の例ではIDAのデフォルトポートを使用しています。Ghidraでは、スクリプトが表示したポートを使用してください。<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

同じチャネルから**解析データベースを変更**することもできます。`RENAME_FUNC`、`RETYPE`、`SETCONV`、`DEFSTRUCT`/`SETFIELD`、`MAKEFUNC`、`PATCH`は、名前、型、構造体の定義、関数の境界、または保存されているバイト列を変更します。`PATCH`はデータベースの編集であり、実行中プロセスへのパッチの証拠ではありません。どちらのlistenerも認証について記載していません。IDAはloopbackのみで待ち受けますが、Ghidraはネットワークインターフェース経由でアクセスできる可能性があります。Ghidraのlistenerを使用する場合は、アクセスを制限してください。`QUIT`はどちらのlistenerも停止し、IDAでは`ida_bridge_stop()`も使用できます。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunnerでshellcodeをデバッグする

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**用のメモリを確保し、その**メモリアドレス**を表示して、実行を一時停止します。\
IDAやx64dbgなどのdebuggerをアタッチし、表示されたアドレスにbreakpointを設定してから実行を再開すると、shellcodeをデバッグできます。

releasesのGitHubページには、コンパイル済みリリースのzipファイルがあります。[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクから、少し変更を加えたBlobrunnerを入手できます。コンパイルするには、**Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドする**だけです。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itでshellcodeをデバッグする

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerに似ています。shellcode用のメモリを確保し、無限ループに入ります。debuggerをアタッチして**2～5秒間**実行を再開し、そのループ内で一時停止してから、確保したshellcodeに実行を移す次のcallまでステップ実行します。

![jmp2itの無限ループ内で、確保したshellcodeへのcallの直前にdebuggerが一時停止している画面](<../../images/image (509).png>)

コンパイル済みの[jmp2itはこちらのreleasesページからダウンロード](https://github.com/adamkramer/jmp2it/releases/)できます。

### Cutterでshellcodeをデバッグする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使うと、shellcodeをエミュレートして動的に調査できます。

Cutterには「Open File」と「Open Shellcode」があります。同じshellcodeを開いたところ、私の環境ではファイルとして開くと正しく逆コンパイルされましたが、shellcodeとして開くと正しく処理されませんでした。

![同じバイト列をファイルとして開いた場合とshellcodeとして開いた場合で、異なる解析結果を表示するCutter](<../../images/image (562).png>)

指定した場所からエミュレーションを開始するには、そこにbpを設定します。するとCutterは自動的にその場所からエミュレーションを開始するようです。

![Cutterのエミュレーションを開始する前に、shellcodeの目的のentryにbreakpointを設定する画面](<../../images/image (589).png>)

![選択したshellcodeのbreakpointで一時停止しているCutterのemulator](<../../images/image (387).png>)

たとえば、hex dump内でstackを確認できます。

![Cutterのhex dumpで、エミュレート中のshellcodeのstackを表示する画面](<../../images/image (186).png>)

### shellcodeをdeobfuscateして実行された関数を取得する

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してください。\
shellcodeが使用している**関数**や、メモリ内でshellcodeが自らを**decode**しているかどうかなどを確認できます。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbgには、必要なオプションを選択してshellcodeを実行できる graphical launcher もあります

![shellcodeのemulationとtracingのオプションを選択するscDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** オプションを使うと、メモリ上でshellcodeが動的に変更された場合、変更後のshellcodeをダンプできます（デコードされたshellcodeの取得に便利です）。**start offset** は、特定のオフセットからshellcodeを開始する場合に便利です。**Debug Shell** オプションを使うと、scDbg terminalでshellcodeをデバッグできます（ただし、この用途では前述のオプションの方が便利です。Idaやx64dbgを使用できるためです）。

### CyberChefを使った逆アセンブル

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA難読化の解除

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、`x + y`のような単純な式を、算術演算子（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた式で隠します。重要なのは、こうした恒等式は通常、**固定幅の剰余演算**でのみ正しいということです。そのため、桁上がりやオーバーフローが重要になります:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用的な代数ツールで単純化すると、ビット幅のセマンティクスが無視されているため、誤った結果になりやすいです。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトしたコード／IR／decompilerの出力にある**元のビット幅**（`8/16/32/64` ビット）を維持する。
2. 単純化する前に、式を**分類**する。
   - **線形**: ビット単位のアトムの重み付き和
   - **半線形**: `x & 0xFF` のような定数マスクと線形項の組み合わせ
   - **多項式**: 積が含まれる
   - **混合**: 積とビット単位のロジックが入り交じり、同じ部分式が繰り返し現れることが多い
3. ランダムテストまたはSMT証明で、候補となる書き換えをすべて検証する。同値性を証明できない場合は、推測せず元の式を維持する。

### 狭い実行スライスでflattened control flowを回避する

完全なcontrol-flow graphの復元は、多くの場合不要です。control-flow flattening、opaque predicates、大規模なdispatcher、またはMBAを多用するコードでは、暗号化されたblobや出力バッファから参照をたどり、それらを変換する最小のルーチンを特定します。その後、そのdata-flow sliceだけを再現するか、単独で実行します。関連するstateを直接初期化できる場合、dispatcherは必要な解法に含まれません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocations、cross-referencesを調査する。`.rodata` から候補となるテーブルを、バイト順と要素幅を保ってダンプする。
2. 平文または出力バッファに最後に書き込むルーチンを特定する。その入力、参照するテーブル、importされた呼び出し、必要なglobal stateを記録する。
3. その操作だけを固定幅のPythonモデルにリフトする。スライスが依然として多くのstateに依存する場合は、プログラム全体をエミュレートするのではなく、Unicorn、QEMU、またはdebuggerでルーチンを呼び出し、不要なimportをhookする。
4. extractorが与えられたbinaryから実際に出力を導出していることを検証する。無言のfallbackを削除し、埋め込まれた回答がないか検索し、文字列、鍵、識別子、レイアウト、obfuscation seedを変更した未知のbuildに対して実行する。

最初に使えるコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装した MBA 式を検出する

一見すると入力に依存しているように見えるバイト式でも、入力の影響が完全に相殺される場合があります。テーブルを抽出した後、8ビットの全領域で式を評価します。出力集合が単一要素であれば、周囲のステートマシンを復元しなくても、そのバイトが定数であることを証明できます。<sup>[[7]](#references)</sup>

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

元の加算ではバイト幅で桁あふれするため、最後のマスクは残してください。より広い領域では、同じ幅のシンボリック入力2つについて、`f(x1) != f(x2)` が充足可能かどうかをSMT solverに問い合わせます。`unsat`なら不変性が証明され、`sat`なら反例が得られるため、その入力は破棄できません。<sup>[[7]](#references)</sup>

#### 環境依存のデコードを見分ける

Anti-analysisチェックは、分岐したりクラッシュしたりするとは限りません。decoderはセンサーの結果をキーのビット、不透明述語の定数、またはフラット化されたディスパッチャーの状態に混ぜ込み、通常どおり処理を続けながら、emulator上で一見もっともらしいが誤った平文を生成することがあります。そのため、目に見える失敗分岐だけをパッチするのでは不十分です。環境プローブからdecoderの状態へのデータ依存関係を追跡し、実機とemulatorで同じスライスを比較し、各センサーの結果を強制的に変更したときに最終バッファがどう変化するかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA)は、マルウェア解析や保護されたバイナリのリバースに実用的なMBA簡略化ツールです。あらゆる式に汎用的な書き換えパスを適用するのではなく、式を分類し、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRAはブール入力で式を評価してシグネチャを導出し、pattern matching、ANF変換、係数補間など複数の復元手法を並行して試します。
- **Semilinear MBA**: 定数マスクされたatomは、マスクされた領域が正しく保たれるよう、ビット分割による再構築で作り直します。
- **Polynomial/Mixed MBA**: 積をコアに分解し、繰り返し現れる部分式を一時変数に持ち上げてから、外側の関係を単純化できます。

よく復元を試す価値のあるmixed identityの例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のように簡略化できます:

```c
x * y
```

### リバースに関するメモ

- 正確な計算処理を特定した後、**リフトされたIR式**またはデコンパイラの出力に対してCoBRAを実行するのがおすすめです。
- マスク演算や狭いレジスタに由来する式では、`--bitwidth`を明示的に指定してください。
- より強力な証明ステップが必要な場合は、こちらのZ3メモを確認してください。


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRAは**LLVM pass plugin**（`libCobraPass.so`）としても提供されており、後続の解析パスの前にMBAを多用したLLVM IRを正規化する場合に便利です。
- carryに依存する、未対応の混合ドメインの残余式がある場合は、元の式を保持し、carryの経路を手動で解析する必要があると判断してください。

## XOR状態による制御フロー平坦化の復元

OLLVM型のフラットナーでは、現在の基本ブロックの状態を2つの64ビットレジスタに保持し、dispatcherでXORを使って再構成する場合があります。元の各ブロックは次の状態を表すレジスタペアを書き込み、dispatcherに戻ります。条件付きブロックでは、CPUフラグに応じてペアの片方を`CMOVcc`で置き換えることがあるため、目に見える分岐命令だけを追うと2つの後続ブロックを見落とします。間接ジャンプを使うdispatcherとは異なり、この形式では一貫して直接の後方分岐を使うことがあります。<sup>[[19]](#references)[[20]](#references)</sup>

グラフを復元するには、dispatcherの比較ツリーと2つの状態レジスタを特定し、比較される各XOR状態を対象ブロックに対応付けたうえで、元の各ブロックにおけるレジスタペアへの到達可能な書き込みを追跡します。条件付きの書き込みでは、フラグを設定する命令と`CMOVcc`の両方の結果を含めます。各ブロックのdispatcherへの出口を、解決した直接の後続ブロックまたは条件分岐に書き換えます。これにより、バイナリをパッチせずにdispatcherを到達不能にできます。これは完全なCFGを扱う方法です。デコーダーが1つだけ対象なら、上記の[狭い実行スライスを使うワークフロー](#bypass-flattened-control-flow-with-a-narrow-execution-slice)のほうが速い場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis)は、Binary Ninjaでこの形式を自動化します。`plugins/DispatchThis`をBinary Ninjaのユーザープラグインディレクトリにコピーして再起動してください。対象の関数で**Function Settings**を開き、`OLLVM_XOR_64`を選択します。解析が始まらない場合は、**Analysis → Reanalyze All Functions**を実行してください。このモードはファイルのバイト列ではなくMLILの制御フローエッジを書き換えるため、Z3や間接ジャンプの解決機能は不要です。Binary Ninja 5.3.9757以降で動作確認されています。ブロックごとの不要な状態書き込みは削除されないため、それらをまだ有効な遷移と誤認しないでください。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この難読化ツールは、プログラムの操作を`mov`ベースの命令列に置き換え、シグナルや例外処理を使って制御フローを変更します。詳細は以下を参照してください。

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応するバイナリであれば、[demovfuscator](https://github.com/kirschju/demovfuscator)で結果を逆難読化できます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

そして[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）。

**CTFをプレイしている場合、このflagを見つけるための回避策**が役立つかもしれません：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリポイント**を見つけるには、次のように関数名を`::main`で検索します。

![関数名のダブルコロン付きmainを検索して、GhidraでRustのエントリポイントを見つける](<../../images/image (1080).png>)

この場合、バイナリ名はauthenticatorだったので、これが注目すべきmain関数だということは明らかです。\
呼び出されている**関数**の**名前**が分かったら、**入力**と**出力**を調べるために**インターネット**で検索します。

### ELFファームウェアからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列はC形式のNUL終端ポインタから参照されていません。一般的な`rustc`のレイアウトでは、**`.data.rel.ro`**内の**ポインタ／長さのタプル**が、**`.rodata`**に格納された実際の文字列データを指しています。

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

これは、`strings` や Ghidra のデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

簡単なワークフロー:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得します。
2. **`.data.rel.ro`** を1ワードずつ列挙します。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱います。
4. 次のワードを候補の長さとして扱います。
5. 妥当性フィルターを適用します（例：長さが **4**〜**100** バイトのものに絞ります）。
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

これは、復元されたRust文字列から **HTTP routes、RPC名、ログメッセージ、アサーション、ファイル名、configキー、コマンドハンドラー、認証関連のロジック**が明らかになることが多いため、firmwareのreversingで特に役立ちます。

Ghidraがこれらの文字列を見つけられない場合は、同じヒューリスティックを適用し、参照先の`.rodata`オフセットに文字列データを作成するカスタムスクリプト/pluginを実行してください。Pen Test Partnersが公開している`rust-strings`と`RustStrings.py`は、このアイデアを他の **word size、エンディアン、セクションレイアウト**に応用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphiでコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます。

Delphiバイナリをreversingする場合は、IDA pluginの[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)の使用をおすすめします。

IDAで**Alt+F7**を押してPython pluginを読み込み、pluginファイルを選択します。

このpluginはバイナリを実行し、debugging開始時に関数名を動的に解決します。debuggingを開始した後、もう一度Startボタン（緑色のボタン、またはf9）を押すと、実際のコードの先頭でbreakpointに到達します。

グラフィカルアプリケーションのボタンを押すと、debuggerはそのボタンから呼び出された関数で停止することがあります。

## Golang

一般的なGoバイナリでは、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使ってruntime構造体を復元し、IDAで関数名を改善できます。**Alt+F7**でPython pluginを読み込んでください。

Golangバイナリをreversingする場合は、IDA pluginの[https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)の使用をおすすめします。

IDAで**Alt+F7**を押してPython pluginを読み込み、pluginファイルを選択します。

これにより、関数名が解決されます。

### シンボルテーブルなしでメタデータを復元する

stripされたGo実行ファイルでも、プログラムカウンターを関数に対応付けるためのruntimeメタデータが必要です。[GoReSym](https://github.com/mandiant/GoReSym)は、Go runtime由来のコードを使って`pclntab`や`moduledata`などの構造体を特定し、解析します。これにより、従来のシンボルテーブルに頼らずに、関数の範囲、名前、ソースパス、型、ビルド情報を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

An obfuscatorは、復元された名前を置き換えながら、これらの構造を利用可能な状態に保つことがあります。たとえばGarbleは、識別子とpackage pathをハッシュ化し、build、module、debug情報を削除します。<sup>[[12]](#references)</sup> 難読化されたpackage tokenは、そのpackage内の関数間で一貫している必要があります。繰り返し現れるtokenで関数をグループ化し、callee、文字列、APIからpackageを1つ推測して、そのpackageラベルをグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolverでGarbleの名前を復元する

[GoResolver](https://github.com/volexity/GoResolver)は、runtime symbolの抽出と、クリーンな参照バイナリの生成、control-flow graph（CFG）のマッチングを組み合わせています。次の手順を使います。<sup>[[10]](#references)[[13]](#references)</sup>

1. **コンパイラのバージョンを特定する。** まず`BuildInfo`と埋め込みバージョン文字列を確認します。obfuscatorによって削除されている場合は、バンドルされたGo runtimeの一部を、バージョン別の参照runtimeと比較します。Volexityのテストでは、runtimeの約`2%`でGoのメジャーバージョンを判別できました。これは実証に基づく最適化として扱い、普遍的な閾値とはみなさないでください。<sup>[[13]](#references)</sup>
2. **照合用の参照バイナリを作成する。** 特定したGoのバージョン、target architecture、使用されている可能性の高いlibraryに合わせて、クリーンなバイナリを生成します。toolchainを一致させることで、コンパイラが生成するCFGの差異を抑えられます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapherは関数のCFGを照合し、`0.0`から`1.0`までの正規化スコアを出力します。basic blockの照合には、類似した命令の重み付き比較を用います。信頼度の高い一致から、ランダム化された関数をクリーンな実装に対応付けます。信頼度が低い一致でも、packageやmoduleの特定に役立つことがあります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** call relationship、定数、文字列、side effectで候補の名前を確認してから、IDAまたはGhidra用のGoResolver pluginでJSONレポートをインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

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

デフォルトの有意一致しきい値は `0.9` です。`--extract` と `--graph` スイッチを使うと、いずれかの段階だけを実行できます。デフォルトでは両方を実行します。これは、復元されたランタイムメタデータとCFGの証拠が互いを補完するためです。<sup>[[10]](#references)</sup> CFGスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わることがあるため、信頼度の低い名前を無理に割り当てず、未解決の関数はそのまま残してください。<sup>[[13]](#references)</sup>

### Go文字列テーブルの復元

Goバイナリでは、リンクされたすべてのパッケージの文字列バイトが、1つの連続したテーブルに配置されます。各エントリはNUL終端されておらず、ランタイム構造体からテーブルのベースアドレスやサイズを取得することもできません。しかし、コンパイラはOSやアーキテクチャを問わず、まず長さ順、次にアルファベット順でエントリを並べます。そのため、エントリを1つ見つければ、隣接するエントリをたどり、データクロスリファレンスを使って文字列とコードを関連付けられます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor)は、IDA ProとGhidraでこのワークフローを自動化します。このプラグインはデータセグメントのクロスリファレンスに依存するため、まず自動解析が完了するのを待ってください。デフォルトのアンカーはランタイム文字列 `entersyscall` です。その後、どちらの方向にもスキャンし、復元した文字列をデータベース内で定義して、文字列と参照元関数の対応を示すJSONを出力できます。<sup>[[14]](#references)</sup>

参照元関数のパッケージでレポートをフィルタリングすると、アプリケーションやマルウェアのコードを、リンクされたライブラリ由来のノイズから切り分けられます。この手法では、Garbleの `-literals` 変換などの難読化によって破壊されたリテラルは復元できません。それでも、難読化されずに残っているランタイム文字列を整理できます。<sup>[[14]](#references)[[15]](#references)</sup>

### Goランタイム型の復元

Goには、ガベージコレクションなどの機能で使われるランタイム型情報が埋め込まれています。ビルド情報が削除されている場合や、逆アセンブラがこのメタデータを解析できない場合、命令は任意のデータアドレスを読み込んでいるように見え、対象領域は型情報のないままになります。メタデータを復元すれば、それらのアドレスを読みやすい型参照に変換でき、パッケージの機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver)はシンボルを抽出し、ランタイム型を解析してJSONレポートに出力できます。現在のCLIでは `resolve` サブコマンドを使用します。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` オプションを有効にすると、型の解析が行われます。レポートを GoResolver の IDA Pro または Ghidra plugin でインポートすると、復元された型を定義し、その参照を解析データベースに適用できます。この機能で導入されたレポート形式では、`-y` を省略すると、RTTI address と recovered-types members は null のままになります。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver は x86、AMD64、ARM、ARM64 の PE、ELF、Mach-O サンプルに対応しているため、同じワークフローを Windows、Linux、macOS の Go バイナリに適用できます。<sup>[[10]](#references)</sup>

## コンパイル済み Python

このページでは、ELF/EXE の Python コンパイル済みバイナリから Python コードを取得する方法を説明します:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの**バイナリ**を入手した場合は、さまざまなツールを使って**エミュレート**および**デバッグ**できます:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version をダウンロード_) - インターフェース付きの debugger が含まれています
- [**mgba** ](https://mgba.io)- CLI debugger が含まれています
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) では、_**Options --> Emulation Setup --> Controls**_** ** から、Game Boy Advance の**ボタン**の押し方を確認できます

![Game Boy Advanceのボタン割り当てを示すno$gbaのコントロール設定画面](<../../images/image (581).png>)

各キーを押すと、そのキーを識別するための**値**が表示されます:

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

![アドレス 0x4000130 で KEYINPUT を参照している GBA バイナリの Ghidra 表示](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ と _0x080017ac_）から呼び出されていることが確認できます。

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

このコードが見つかりました：

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

最後の if は、**`uVar4`** が **最後の Keys** に含まれていて、現在のキーではないことを確認しています。これはボタンを離したときの処理です（現在のキーは **`uVar1`** に格納されています）。

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

- まず、**値 4**（**SELECT**ボタン）と比較されます。この challenge では、このボタンを押すと画面がクリアされます。
- 次に、値を **8**（**START**ボタン）と比較します。この challenge では、この経路で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが 8 未満の場合、押されたキーの値が `DAT_030000d8` に加算されていきます。

つまり、この challenge では、ボタンの値を知ったうえで、合計が 0xf3 になる長さ 8 未満の組み合わせを**押す必要がありました**。

**このチュートリアルの参考資料:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRAによるMBA難読化の簡素化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust文字列のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBAリバースエンジニアリングチュートリアル（アーカイブ版）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI支援リバースエンジニアリングに打ち勝つ方法、あるいは少なくとも試みる方法](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [基本ブロックのマッチングに基づく制御フローグラフ比較手法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garbleの難読化メカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: 制御フローグラフの類似性を利用したGolangバイナリの自動難読化解除](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golangツールのアップデート](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものをリバースエンジニアリング](https://github.com/morluto/rea)
- [17] [REAのマネージドコード解析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLIとEvidenceガイド](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninjaの制御フロー平坦化解除ワークフロー](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MFのゼロデイ侵入、Java Loader、Web Shell、およびAdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridgeサーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridgeサーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int)はワイルドカードアドレスにバインドする](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
