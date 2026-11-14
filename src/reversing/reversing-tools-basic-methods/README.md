# リバースエンジニアリングツールと基本手法

{{#include ../../banners/hacktricks-training.md}}

## ImGui ベースのリバースエンジニアリングツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg のユーザーモード自動化

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows の例外駆動型制御フロー

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows カーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm デコンパイラ / Wat コンパイラ

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) を使うと、wasm（バイナリ）から wat（プレーンテキスト）に**デコンパイル**できます
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) を使うと、wat から wasm に**コンパイル**できます
- デコンパイルには [web-wasmdec](https://wwwg.github.io/web-wasmdec/) も試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 のキャッシュされたバイトコード

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 仮想化されたペイロードとカスタム VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET デコンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek は、ライブラリ（.dll）、**Windows metadata file**（.winmd）、実行ファイル（.exe）など、複数の形式を**デコンパイルして調査**できるデコンパイラです。デコンパイル後、アセンブリを Visual Studio プロジェクト（.csproj）として保存できます。

失われたソースコードをレガシーアセンブリから復元する必要がある場合、この機能を使えば時間を節約できます。また、dotPeek はデコンパイル済みコード内を便利に移動できるため、**Xamarin のアルゴリズム解析**に最適なツールの一つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できる API を備えた .NET Reflector は、時間を節約し、開発を簡素化します。このツールが提供する豊富なリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内のデータフローを把握できます
- .NET の言語やフレームワークの実装と使用方法を把握できます
- ドキュメント化されていない機能や公開されていない機能を見つけ、使用中の API やテクノロジーをさらに活用できます
- 依存関係や各種アセンブリを見つけられます
- コード、サードパーティ製コンポーネント、ライブラリ内のエラーの正確な位置を特定できます
- 使用するすべての .NET コードのソースをデバッグできます

### [ILSpy](https://github.com/icsharpcode/ILSpy) と [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code 用 ILSpy プラグイン](https://github.com/icsharpcode/ilspy-vscode): どの OS でも利用できます（VSCode から直接インストールできるため、git をダウンロードする必要はありません。**Extensions** をクリックして **ILSpy** を検索してください）。\
**デコンパイル**、**変更**、再度**コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases) または活発にメンテナンスされているフォークの [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) を使用できます。（関数内を変更するには **Right Click -> Modify Method** を選択します）。

### REA による実行不要のマネージドコード検査

**REA** はアセンブリを読み込まずに PE/CLI メタデータと CIL を検査できます。まずアーティファクトの識別情報を確認し、次にメンバーと宣言されたネイティブ境界を調べます。デコンパイラを使用したりプログラムを実行したりする前に、疑わしい呼び出しを確認する際に役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン差分の比較では、`compare_managed_members` はメタデータトークンがビルド間で安定しているものとして扱わず、生の CIL／シグネチャの同一性と、デコード済み命令のフィンガープリントを使用します。P/Invoke 宣言はネイティブコードが実行された証拠にはなりません。境界を確認するには、`verify_managed_native_boundaries` に照合できるネイティブエクスポートまたは関数の証拠が必要です。成果物のダイジェスト、MVID、未解決のマッピングを結果とともに保持してください。<sup>[[17]](#references)</sup>

### DNSpy のログ出力

**DNSpy に情報をファイルへ記録させる**には、次のスニペットを使用できます。

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy のデバッグ

DNSpy を使ってコードをデバッグするには、次の手順が必要です。

まず、**デバッグ**に関連する **Assembly attributes** を変更します。

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

そして **compile** をクリックします。

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

これが必要なのは、これを行わないと、**runtime** にコードにいくつかの**最適化**が適用され、デバッグ中に**ブレークポイントに到達しない**場合や、**変数が存在しない**場合があるためです。

.NET アプリケーションが **IIS** によって**実行**されている場合は、次のコマンドで**再起動**できます：

```
iisreset /noforce
```

次に、デバッグを開始するには、開いているファイルをすべて閉じ、**Debug Tab** で **Attach to Process...** を選択します。

![DNSpy Logging - DNSpy Debugging: デバッグを開始するには、開いているファイルをすべて閉じ、Debug Tab で Attach to Process を選択します](<../../images/image (318).png>)

次に、**IIS server** にアタッチするため **w3wp.exe** を選択し、**attach** をクリックします。

![DNSpy Logging - DNSpy Debugging: IIS server にアタッチするため w3wp.exe を選択し、attach をクリックします](<../../images/image (113).png>)

プロセスをデバッグしている状態になったので、処理を一時停止して、すべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしている状態になったので、処理を一時停止して、すべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスをデバッグしている状態になったので、処理を一時停止して、すべてのモジュールを読み込みます。まず Debug Break All をクリックし、次に Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意のモジュールをクリックし、**Open All Modules** を選択します。

![DNSpy Logging - DNSpy Debugging: Modules 内の任意のモジュールをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のモジュールを右クリックし、**Sort Assemblies** をクリックします。

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のモジュールを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java デコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL のデバッグ

### IDA を使用する

- **rundll32 を読み込む**（64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debugger を選択する
- "**Suspend on library load/unload**" を選択する

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択します](<../../images/image (868).png>)

- 実行の **parameters** を設定し、**DLL のパス** と呼び出す関数を指定します。

![Debugging DLLs - Using IDA: 実行の parameters を設定し、DLL のパスと呼び出す関数を指定します](<../../images/image (704).png>)

デバッグを開始すると、**各 DLL が読み込まれるたびに実行が停止します**。そのため、rundll32 が DLL を読み込むと、実行が停止します。

この方法ではモジュールの読み込みイベントで停止しますが、読み込まれた DLL のエントリポイントに到達する手順は、以下の x64dbg の方法よりも直接的ではありません。

### x64dbg/x32dbg を使用する

- **rundll32 を読み込む**（64bits は C:\Windows\System32\rundll32.exe、32 bits は C:\Windows\SysWOW64\rundll32.exe）
- **Command Line を変更**（_File --> Change Command Line_）し、DLL のパスと呼び出す関数を指定します。例: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- **実行を開始**すると、デバッガは各 DLL の main で停止します。いずれかの時点で、**自分の DLL の Entry で停止します**。そこから、ブレークポイントを設定したい箇所を探します。

win64dbg では、何らかの理由で実行が停止した際、**win64dbg ウィンドウの上部**を見ると、**どのコード内にいるか**を確認できます。

![Using IDA - Using x64dbg/x32dbg: 何らかの理由で実行が停止した際、win64dbg ウィンドウの上部を見ると、どのコード内にいるかを確認できます](<../../images/image (842).png>)

このインジケーターで、デバッグ対象の DLL 内で実行が停止したことを確認できます。

## GUI アプリ / ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内で重要な値が保存されている場所を見つけ、変更するのに便利なプログラムです。詳しくは以下を参照してください。

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、ゲームに特化した GNU Project Debugger (GDB) 用のフロントエンド／reverse engineering ツールです。ただし、reverse engineering 関連のさまざまな用途に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数のデコンパイラを利用できる Web フロントエンドです。この Web サービスでは、小さな実行ファイルに対する各デコンパイラの出力を比較できます。

### Godot PCK の復号とプロジェクトの復元

配布された Godot ゲームの場合、PCK の場所は、単体の `.pck`、実行ファイルに追加または埋め込まれたパック、あるいは APK の `assets` ディレクトリです。[gore](https://github.com/figurophobia/gore) でパックを検査・展開できます。一方、スクリプトとリソースを完全に再構築するには GDRE Tools が必要です（`gore setup` でインストールするか、`--gdre` を使用します）。このワークフローでは Godot 4.x の PCK 形式 v2～v4 をサポートしています。v1 ヘッダーは検出できますが、v1 ではキーの指定が必要です。<sup>[[25]](#references)</sup>

自動キー復元には暗号化されたファイルテーブルが必要です。ファイルの内容のみが暗号化されている場合は、既知のキーを指定してください。復元に失敗したからといって、パックが暗号化されていないとは限りません。<sup>[[28]](#references)</sup>

キー検索は **AES-256 の鍵空間を総当たりする攻撃ではありません**。暗号化されたファイルテーブルには、平文の MD5、平文の長さ、IV、AES-256-CFB の ciphertext が含まれています。<sup>[[27]](#references)</sup> `gore` はゲームの実行ファイルまたは近隣のファイルから 32 バイトのウィンドウを取り出し、候補キーとして検証します。復号したパスの長さとプレフィックスが妥当かどうかで候補を絞り込み、バイナリスキャンで見つかった候補は、テーブル全体を復号して MD5 を照合します。<sup>[[26]](#references)[[28]](#references)</sup> まず初期化済みの PE/ELF データセクションを検索し、その後、ファイル全体をスキャンします。`--scan` を指定すると、ほかの候補ファイルも追加されます。<sup>[[28]](#references)</sup>

埋め込みキーが見つからない場合は、組み込みの短い password リストを試します。ほかの候補を指定するには `--wordlist` を使います。各 password は、エンジンが password から導出するキー表現、ゼロでパディングしたリテラル、または 64 文字の 16 進数キーとして検証されます。バイナリスキャンで見つかった候補とは異なり、この実装で wordlist から見つかった候補は、パス構造のフィルターを通過するだけです。パックを開き、展開したアセットを検証して確認してください。<sup>[[26]](#references)[[28]](#references)</sup>

ゲームのファイルをローカルで利用できる場合は、分析に必要な段階を選択します。`recover` は GDRE を呼び出して、開けるプロジェクトを再構築します。一方、`extract` は生ファイルを展開するだけです。`key` は、別のツールで使用する候補キーを出力します。<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## REAを使った、根拠に基づくネイティブ調査

**REA**は、CLIとMCPを通じてHopper、Ghidra、IDAによる解析を提供します。Node.js 22.x（22.19以上）、24.x（24.11以上）、または26以上とnpmが必要です。まず既存のネイティブプロバイダーを設定してください。`rea providers --json`を確認し、複数のプロバイダーが対象をサポートしている場合は、プロバイダーを明示的に選択してください。以下では、インベントリにある実際に確認された関数名またはアドレスを`0x1000`の代わりに使用してください。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

機能文字列またはシンボルから始め、参照先や呼び出し元をたどり、選択した関数の dossier と疑似コードを `rea decompile` で確認します。REA は選択した provider にセッションを紐付け、失敗後に黙って別の provider に切り替えることはありません。クエリを再現可能にするには、`--snapshot PATH` を指定します。このオプションは、artifact のバイト列、provider、設定、操作、パラメーターが一致する場合に限り再利用します。snapshot はローカルキャッシュであり、provider のデータベースを保存したものではありません。返された Evidence と明示された不明点を保持し、推定されたパスや decompiler のテキストを元のソースとして扱わないでください。<sup>[[16]](#references)[[18]](#references)</sup>

ネイティブ add-on につながる JavaScript/Electron のエントリーポイントについては、[Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) を参照してください。

## ローカル TCP ブリッジを使った IDA と Ghidra のスクリプト分析

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) は、**すでに開いている** IDA database または Ghidra CodeBrowser program 内で動作し、別のスクリプトからその分析データベースをクエリおよび変更できるようにします。IDA の Python CLI から `ID_Server.py` を実行（`import ID_Server`）するか、Ghidra の Script Manager から `Ghidra_Server.py` を実行します。IDA は `127.0.0.1` のポート `5073` からバインドを開始し、より大きいポート番号を順に確認します。現在の Ghidra スクリプトはポート `5093` から開始し、`5102` までの 10 個のポートを試します。Java socket は loopback だけでなく、ワイルドカードアドレスにバインドします。接続する前に、インスタンスが表示したポートを確認してください。headless analyzer とは異なり、このブリッジは GUI インスタンスで現在開いている program を対象に動作します。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

**接続ごとに、改行で終わるコマンドを1つ送信し、改行で終わる応答を読み取ります。** 通常、結果は JSON です。たとえば、入力パスに関係する imported API を見つけた後、`IMPORTXREF` でその呼び出し箇所を検索し、`DECOMP_XREF` で選択したアドレスの呼び出し元をまとめて逆コンパイルできます。`FUNC` は関数を調べ、`PCODE` は decompiler の中間表現を返します。異なる rebase 済みバイナリからコピーしたアドレスではなく、アクティブな database のアドレスを使用してください。以下の例では IDA のデフォルトポートを使用しています。Ghidra の場合は、そのスクリプトが表示したポートを使用してください。<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

同じチャネルから**解析データベースを変更**することもできます。`RENAME_FUNC`、`RETYPE`、`SETCONV`、`DEFSTRUCT`/`SETFIELD`、`MAKEFUNC`、`PATCH`は、名前、型、構造体の定義、関数の境界、または保存されたバイト列を変更します。`PATCH`はデータベースの編集であり、実行中プロセスへのパッチを示すものではありません。どちらのリスナーも認証については記載していません。IDAはloopback限定ですが、Ghidraはネットワークインターフェース経由でアクセスできる場合があります。Ghidraのリスナーを使用する際は、アクセスを制限してください。`QUIT`はどちらのリスナーも停止し、IDAでは`ida_bridge_stop()`も利用できます。<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### BlobRunnerを使ったshellcodeのデバッグ

[**BlobRunner**](https://github.com/OALabs/BlobRunner)は**shellcode**を割り当て、その**メモリアドレス**を表示してから、実行を一時停止します。\
IDAやx64dbgなどのデバッガをアタッチし、表示されたアドレスにブレークポイントを設定して実行を再開すると、shellcodeをデバッグできます。

GitHubのリリースページには、コンパイル済みリリースを含むzipファイルがあります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクから、わずかに変更されたバージョンのBlobRunnerを入手できます。コンパイルするには、**Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドするだけです**。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2itを使ったshellcodeのデバッグ

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobRunnerと似ています。shellcodeを割り当てて無限ループに入ります。デバッガをアタッチし、**2～5秒間**実行を再開した後、そのループ内で一時停止し、割り当てられたshellcodeに実行を移す次のcallまでステップ実行します。

![jmp2itの無限ループ内で、割り当てられたshellcodeを呼び出す直前にデバッガが一時停止している画面](<../../images/image (509).png>)

コンパイル済みの[jmp2itはリリースページからダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使ったshellcodeのデバッグ

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使うと、shellcodeをエミュレートして動的に調査できます。

Cutterでは「Open File」と「Open Shellcode」を選択できます。同じshellcodeを試したところ、ファイルとして開くと正しく逆コンパイルされましたが、shellcodeとして開くと正しく処理されませんでした。

![同じバイト列をファイルとして開いた場合とshellcodeとして開いた場合の異なる解析結果を表示するCutter](<../../images/image (562).png>)

指定した場所からエミュレーションを開始するには、そこにbpを設定します。どうやらCutterはその場所から自動的にエミュレーションを開始します。

![Cutterのエミュレーション開始前に、shellcodeの目的のエントリポイントにブレークポイントを設定した画面](<../../images/image (589).png>)

![選択したshellcodeのブレークポイントで一時停止したCutterエミュレーター](<../../images/image (387).png>)

たとえば、hex dumpでスタックを確認できます。

![Cutterのhex dumpでエミュレートされたshellcodeのスタックを表示した画面](<../../images/image (186).png>)

### shellcodeの難読化解除と実行された関数の特定

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してください。\
shellcodeが使用している**関数**や、メモリ内で自身を**デコード**しているかどうかなどを確認できます。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbgには、必要なオプションを選択してshellcodeを実行できるグラフィカルランチャーも付属しています。

![shellcodeのエミュレーションとトレースのオプションを選択するscDbgのグラフィカルランチャー](<../../images/image (258).png>)

**Create Dump** オプションを使うと、メモリ上でshellcodeが動的に変更された場合に、変更後のshellcodeをダンプできます（デコード済みのshellcodeを取得するのに便利です）。**start offset** は、指定したオフセットからshellcodeを開始する場合に便利です。**Debug Shell** オプションを使うと、scDbgのターミナルでshellcodeをデバッグできます（ただし、この用途には前述のオプションのほうが適していると思います。IDAやx64dbgを使えるためです）。

### CyberChefを使ったDisassembling

shellcodeファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscationのdeobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscationは、算術演算子（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた式で、`x + y`のような単純な式を隠します。重要なのは、こうした恒等式が通常、**固定幅の剰余演算**でのみ成立する点です。そのため、キャリーとオーバーフローが重要になります:

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用的な代数ツールで簡略化すると、ビット幅のセマンティクスが無視されているため、誤った結果になりやすいです。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトしたコード/IR/decompilerの出力にある**元のビット幅**（`8/16/32/64` bits）を維持する。
2. 簡略化を試みる前に、式を**分類**する:
   - **Linear**: ビット演算の要素の加重和
   - **Semilinear**: `x & 0xFF` のような定数マスクを含む線形式
   - **Polynomial**: 積を含む式
   - **Mixed**: 積とビット演算ロジックが混在し、部分式が繰り返されることも多い
3. 候補となる書き換えはすべて、ランダムテストまたはSMT証明で検証する。同値性を証明できない場合は、推測で書き換えず、元の式を維持する。

### 狭い実行スライスで平坦化された制御フローを回避する

制御フローグラフ全体を復元する必要がない場合もよくあります。control-flow flattening、opaque predicates、大規模なdispatcher、またはMBAを多用したコードでは、暗号化されたblobや出力バッファから参照をたどり、それらを変換する最小のルーチンを特定します。その後、そのデータフロースライスだけを再現するか、単独で実行します。関連するstateを直接初期化できるなら、dispatcherは必要な解決策に含まれません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocations、cross-referencesを一覧化する。`.rodata`から候補となるテーブルをダンプし、バイト順と要素幅を維持する。
2. plaintextまたは出力バッファに最後に書き込むルーチンを特定する。その入力、参照するテーブル、importされた呼び出し、必要なglobal stateを記録する。
3. それらの操作だけを固定幅のPythonモデルにリフトする。スライスが依然として多くのstateに依存する場合は、プログラム全体をエミュレートする代わりに、Unicorn、QEMU、またはdebugger上でルーチンを呼び出し、無関係なimportsをhookする。
4. extractorが与えられたbinaryから実際に出力を導出していることを検証する。暗黙のfallbackをなくし、埋め込まれた回答を検索し、文字列、鍵、識別子、layout、obfuscation seedを変更した未知のbuildで実行する。

最初に試すとよいコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数に見せかけたMBA式を検出する

一見すると入力に依存しているように見えるバイト式でも、入力が完全に相殺されることがあります。テーブルを抽出した後、8ビットの全領域で式を評価します。出力集合が単一の値なら、周囲のステートマシンを復元しなくても、そのバイトが定数だと証明できます。<sup>[[7]](#references)</sup>

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

元の加算にはbyte幅のwraparoundがあるため、最後のmaskは残してください。より広い領域では、同じ幅の2つのシンボリック入力について、SMT solverで `f(x1) != f(x2)` が充足可能かどうかを調べます。`unsat` なら不変性が証明され、`sat` なら反例が得られるため、その入力を除去できないことを意味します。<sup>[[7]](#references)</sup>

#### 環境に依存するデコードを見分ける

Anti-analysisチェックは、分岐やクラッシュを引き起こすとは限りません。decoderはセンサーの結果をキーのビット、不透明述語の定数、またはflattened dispatcherの状態に混ぜ、正常に処理を続けながら、emulator上で妥当に見えるものの誤った平文を生成することがあります。そのため、目に見える失敗分岐だけをpatchしても不十分です。環境プローブからdecoderの状態へのデータ依存関係を追跡し、実機とemulatorで同じスライスを比較し、各センサーの結果を強制的に変更したときに最終バッファがどう変わるかをテストしてください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、malware解析や保護されたbinaryのreversingに使える実用的なMBA simplifierです。式を分類し、すべてに汎用のrewrite passを適用するのではなく、専用のpipelineに振り分けます。<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRAはBoolean入力で式を評価し、signatureを導出して、pattern matching、ANF変換、係数補間など複数の復元手法を並行して実行します。
- **Semilinear MBA**: constant-masked atomはbit-partitioned reconstructionで再構築され、マスクされた領域の正確さが保たれます。
- **Polynomial/Mixed MBA**: 積はcoreに分解され、外側の関係を簡略化する前に、繰り返し現れる部分式をtemporaryに持ち上げられます。

復元を試す価値がある、よくあるmixed identityの例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のようにまとめられます:

```c
x * y
```

### Reversing のメモ

- CoBRA は、正確な計算処理を特定した後の **lifted IR expressions** または decompiler の出力に対して実行するのがおすすめです。
- 式がマスク演算や狭いレジスタに由来する場合は、`--bitwidth` を明示的に指定してください。
- より強力な証明手順が必要な場合は、こちらの Z3 のメモを確認してください。


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA には **LLVM pass plugin** (`libCobraPass.so`) も含まれており、後続の解析 pass の前に MBA が多用された LLVM IR を正規化する場合に便利です。
- carry に依存する、サポート対象外の混合ドメインの残余式がある場合は、元の式を維持して carry の経路を手動で解析する目印としてください。

## XOR-state による制御フロー平坦化の復元

OLLVM 形式の flattener は、現在の basic block の state を2つの64ビットレジスタに保持し、dispatcher で XOR を使って再構成する場合があります。元の各 block は、次の state に対応するペアを書き込み、dispatcher に戻ります。条件付き block は `CMOVcc` を使って CPU flags に応じてペアの一方を書き換えることがあるため、目に見える branch 命令だけを追うと、2つの後続 block を見落とします。間接ジャンプを使う dispatcher とは異なり、この形式では全体を通して直接の後方分岐を使うことがあります。<sup>[[19]](#references)[[20]](#references)</sup>

グラフを復元するには、dispatcher の比較ツリーと2つの state レジスタを特定し、比較された各 XOR state を対象 block に対応付けたうえで、元の各 block でレジスタペアに書き込む到達可能な命令を追跡します。条件付き書き込みでは、flags を設定する命令と `CMOVcc` の両方の結果を考慮します。各 block の dispatcher への exit を、解決した直接の後続 block または条件分岐に書き換えます。すると、binary にパッチを当てなくても dispatcher は到達不能になります。これは CFG 全体を扱う方法です。対象の decoder が1つだけなら、上記の[狭い実行スライスのワークフロー](#bypass-flattened-control-flow-with-a-narrow-execution-slice)のほうが速い場合があります。<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) は、Binary Ninja でこの形式を自動処理します。`plugins/DispatchThis` を Binary Ninja のユーザープラグインディレクトリにコピーして再起動してください。対象の関数で **Function Settings** を開き、`OLLVM_XOR_64` を選択します。解析が開始されない場合は、**Analysis → Reanalyze All Functions** を実行してください。このモードは MLIL の制御フローエッジを書き換えるもので、ファイルのバイト列は変更せず、Z3 や indirect-jump resolver も必要ありません。Binary Ninja 5.3.9757+ で動作確認されています。block ごとに残る不要な state 書き込みは削除されないため、それらを有効な遷移と誤認しないでください。<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator は、プログラムの操作を `mov` ベースの命令シーケンスに置き換え、signal/exception handling を使って制御フローを変更します。詳細はこちら:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応する binary であれば、[demovfuscator](https://github.com/kirschju/demovfuscator) で結果を deobfuscate できます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTFをプレイしている場合、この回避策を使ってflagを見つけられるかもしれません**: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリポイント**を見つけるには、次のように関数名を `::main` で検索します。

![関数名をダブルコロン付きのmainで検索して、GhidraでRustのエントリポイントを見つける](<../../images/image (1080).png>)

このケースでは、バイナリの名前はauthenticatorだったため、これが注目すべきmain関数であることは明らかです。\
呼び出されている**関数**の**名前**がわかったら、**Internet**で検索して、それらの**入力**と**出力**を調べましょう。

### ELFファームウェアからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列は、CスタイルのNUL終端ポインタとして参照されていません。一般的な `rustc` のレイアウトでは、**`.data.rel.ro`** 内の**ポインタ/長さのタプル**が、**`.rodata`** に格納された実際の文字列データを指しています。

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
3. `.rodata` のアドレス範囲内にある値を、文字列ポインター候補として扱います。
4. 次のワードを長さ候補として扱います。
5. 妥当性フィルターを適用します（例: **4**〜**100** バイトの長さに限定）。
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

これはファームウェアのリバースエンジニアリングで特に役立ちます。復元された Rust の文字列から、**HTTP routes、RPC names、log messages、assertions、filenames、config keys、command handlers、認証関連のロジック**が明らかになることがよくあります。

Ghidra がこれらの文字列を見つけられない場合は、同じヒューリスティックを適用し、参照先の `.rodata` オフセットに文字列データを作成するカスタムスクリプトやプラグインを実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` は、このアイデアを他の**ワードサイズ、エンディアン、セクションレイアウト**に応用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi コンパイル済みバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます。

Delphi バイナリをリバースする必要がある場合は、IDA plugin の[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)の使用をおすすめします。

IDA で**Alt+F7**を押して Python plugin を読み込み、plugin ファイルを選択します。

この plugin はバイナリを実行し、デバッグ開始時に関数名を動的に解決します。デバッグを開始したら、もう一度 Start ボタン（緑色のボタン、または f9）を押すと、実際のコードの先頭でブレークポイントに到達します。

グラフィカルアプリケーションのボタンを押すと、デバッガーはそのボタンから呼び出された関数で停止することがあります。

## Golang

一般的な Go バイナリでは、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使ってランタイム構造を復元し、IDA の関数名を改善できます。**Alt+F7**で Python plugin を読み込みます。

Golang バイナリをリバースする必要がある場合は、IDA plugin の[https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)の使用をおすすめします。

IDA で**Alt+F7**を押して Python plugin を読み込み、plugin ファイルを選択します。

これにより、関数名が解決されます。

### シンボルテーブルなしでメタデータを復元する

strip された Go 実行ファイルでも、プログラムカウンターを関数に対応付けるためにランタイムメタデータが必要です。[GoReSym](https://github.com/mandiant/GoReSym)は、Go runtime 由来のコードを使って、`pclntab`や`moduledata`などの構造を特定して解析します。これにより、従来のシンボルテーブルに頼らずに、関数の境界、名前、ソースパス、型、ビルド情報を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

obfuscatorは、復元された名前を置き換えながら、これらの構造を利用可能な状態に保つことがあります。たとえばGarbleは、識別子とpackage pathをハッシュ化し、build、module、debug情報を削除します。<sup>[[12]](#references)</sup> obfuscated package tokenは、そのpackageの関数間で一貫している必要があります。繰り返し現れるtokenで関数をグループ化し、callee、文字列、APIから1つのpackageを推定して、そのpackageラベルをグループ全体に適用します。<sup>[[13]](#references)</sup>

### GoResolverでGarbleの名前を復元する

[GoResolver](https://github.com/volexity/GoResolver)は、runtime symbolの抽出、クリーンな参照バイナリの生成、control-flow graph（CFG）のマッチングを組み合わせます。次の手順で進めます。<sup>[[10]](#references)[[13]](#references)</sup>

1. **compilerのversionを特定する。** まず`BuildInfo`と埋め込みversion文字列を確認します。obfuscatorがそれらを削除している場合は、バンドルされたGo runtimeの一部を、version別の参照runtimeと比較します。Volexityのテストでは、runtimeの約`2%`でGoのメジャーversionを識別できました。これは経験的な最適化であり、普遍的な閾値ではないことに注意してください。<sup>[[13]](#references)</sup>
2. **マッチング用の参照バイナリを作成する。** 特定したGo version、target architecture、使用が見込まれるlibrary向けに、クリーンなバイナリを生成します。toolchainを一致させることで、compilerが生成するCFGの差異を減らせます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapherは関数のCFGをマッチングし、`0.0`から`1.0`までの正規化されたスコアを出力します。basic blockのマッチングは、類似した命令を重み付けして比較します。信頼度の高いマッチは、ランダム化された関数をクリーンな実装に対応付けます。信頼度の低いマッチでも、packageやmoduleを特定できる場合があります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** call関係、定数、文字列、副作用を使って候補名を確認し、GoResolver pluginを使ってJSONレポートをIDAまたはGhidraにインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

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

デフォルトの有意な一致のしきい値は `0.9` です。`--extract` と `--graph` のスイッチを使うと、どちらか一方の段階だけを実行できます。デフォルトでは、復元された runtime metadata と CFG の証拠が互いを補完するため、両方が実行されます。<sup>[[10]](#references)</sup> CFG のスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わる可能性があるため、信頼度の低い名前を無理に割り当てず、未解決の関数はそのまま残してください。<sup>[[13]](#references)</sup>

### Go string table の復元

Go バイナリでは、リンクされたすべてのパッケージの文字列データが、1つの連続したテーブルに配置されます。エントリは NUL 終端ではなく、runtime 構造体からテーブルのベースアドレスやサイズを取得することもできません。しかし、コンパイラは OS やアーキテクチャにかかわらず、エントリをまず長さ順、次にアルファベット順に並べます。そのため、1つのエントリを見つければ、隣接するエントリをたどり、データのクロスリファレンスを使って文字列とコードを関連付けられます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) は、IDA Pro と Ghidra でこの作業を自動化します。プラグインはデータセグメントのクロスリファレンスに依存するため、先に自動解析を完了させてください。デフォルトのアンカーは runtime の文字列 `entersyscall` です。この文字列を基準にどちらの方向にもスキャンでき、復元した文字列をデータベースに定義し、文字列とそれを参照する関数の対応を JSON 形式でエクスポートできます。<sup>[[14]](#references)</sup>

参照元の関数のパッケージでレポートを絞り込むと、アプリケーションやマルウェアのコードを、リンクされたライブラリ由来のノイズから分けられます。この手法では、Garble の `-literals` 変換のような難読化によって破壊されたリテラルは復元できません。それでも、難読化されずに残っている runtime 文字列を整理することはできます。<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime の型情報の復元

Go には、ガベージコレクションなどの機能で使われる runtime の型情報が埋め込まれています。ビルド情報が削除されている場合や、逆アセンブラがこのメタデータを解析できない場合、命令が任意のデータアドレスを読み込んでいるように見え、対象の領域は型情報のないままになります。このメタデータを復元すると、それらのアドレスを読みやすい型参照に変換でき、パッケージが持つ機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) は、シンボルを抽出し、runtime の型情報を解析して JSON レポートに出力できます。現在の CLI では `resolve` サブコマンドを使います。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` オプションを有効にすると、型の解析が行われます。GoResolver の IDA Pro または Ghidra plugin でレポートをインポートし、復元された型を定義して、その参照を解析データベースに適用します。この機能で導入されたレポート形式では、`-y` を省略すると、RTTI アドレスと復元された型のメンバーは null になります。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver は x86、AMD64、ARM、ARM64 の PE、ELF、Mach-O サンプルに対応しているため、同じ手順を Windows、Linux、macOS の Go バイナリに適用できます。<sup>[[10]](#references)</sup>

## コンパイル済み Python

このページでは、ELF/EXE の Python コンパイル済みバイナリから Python コードを取得する方法を紹介します。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの**バイナリ**を入手した場合は、さまざまなツールを使って**エミュレート**および**デバッグ**できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_デバッグ版をダウンロード_) - インターフェース付きの debugger を搭載
- [**mgba** ](https://mgba.io)- CLI debugger を搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** で、Game Boy Advance の**ボタン**の押し方を確認できます。

![Game Boy Advance のボタン割り当てを表示する no$gba のコントロール設定](<../../images/image (581).png>)

押すと、各**キーには値**が割り当てられ、識別に使われます。

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

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることが確認できます。

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

最後のifは、**uVar4**が**最後のKeys**に含まれていて、現在のキーではないことを確認しています。これはボタンを離すことを意味します（現在のキーは**uVar1**に格納されています）。

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

前述のコードでは、**uVar1**（**押されたボタンの値**が格納されている場所）をいくつかの値と比較していることがわかります。

- まず、**値 4**（**SELECT**ボタン）と比較します。このチャレンジでは、このボタンを押すと画面が消去されます。
- 次に、値を **8**（**START**ボタン）と比較します。このチャレンジでは、この処理経路で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが 8 未満の場合、押されたキーの値が `DAT_030000d8` に累積されます。

つまり、このチャレンジでは、ボタンの値を把握したうえで、合計が 0xf3 になる、長さが 8 未満の組み合わせを**押す必要がありました**。

**このチュートリアルの参考資料:** [アーカイブされた Nostalgia challenge の writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary の難読化解除)

## References

- [1] [CoBRAによるMBA難読化の簡素化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA リポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rust の文字列をデコードする - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing チュートリアル（アーカイブ版）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI支援による Reverse Engineering を阻止する、あるいは少なくとも試みる](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matching に基づく Control Flow Graph 比較手法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver リポジトリ](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble の難読化メカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graph の類似性を利用して Golang バイナリを自動的に難読化解除する](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor リポジトリ](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang ツールのアップデート](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものを Reverse Engineer する](https://github.com/morluto/rea)
- [17] [REA による managed-code の解析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI と Evidence ガイド](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja の control-flow unflattening ワークフロー](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF の Zero-Day Intrusion、Java Loader、Web Shell、AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge サーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge サーバーの実装](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) はワイルドカードアドレスに bind する](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot Reverse Engineering ツールキット](https://github.com/figurophobia/gore)
- [26] [gore の key-recovery 実装](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore の encrypted-blob 形式](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore のコマンドおよびリカバリ実装](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
