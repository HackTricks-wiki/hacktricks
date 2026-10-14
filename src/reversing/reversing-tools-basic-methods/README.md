# リバースツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGui ベースのリバースツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg ユーザーモードの自動化

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows カーネルデバッグ

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm デコンパイラ / Wat コンパイラ

オンライン:

- wasm（バイナリ）から wat（テキスト）に**デコンパイル**するには、[https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用します
- wat から wasm に**コンパイル**するには、[https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用します
- デコンパイルには[web-wasmdec](https://wwwg.github.io/web-wasmdec/)も試せます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 のキャッシュ済みバイトコード

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## 仮想化されたペイロードとカスタム VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET デコンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek は、ライブラリ（.dll）、Windows メタデータファイル（.winmd）、実行ファイル（.exe）など、複数の形式を**デコンパイルして調査**できるデコンパイラです。デコンパイルしたアセンブリは、Visual Studio プロジェクト（.csproj）として保存できます。

レガシーアセンブリから失われたソースコードを復元する必要がある場合、この機能によって時間を節約できるのが利点です。また、dotPeek はデコンパイルしたコード内を簡単に移動できるため、**Xamarin のアルゴリズム解析に最適なツールの1つ**です。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ニーズに合わせてツールを拡張できる API を備えた .NET Reflector は、時間を節約し、開発を簡素化します。このツールが提供する幅広いリバースエンジニアリング機能を見てみましょう。

- ライブラリやコンポーネント内でのデータの流れを把握できる
- .NET 言語やフレームワークの実装と使用方法を把握できる
- 使用している API やテクノロジーをより活用するため、文書化されていない機能や公開されていない機能を見つけられる
- 依存関係や異なるアセンブリを見つけられる
- 自分のコード、サードパーティ製コンポーネント、ライブラリにおけるエラーの正確な場所を特定できる
- 使用しているすべての .NET コードのソースをデバッグできる

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code 用 ILSpy プラグイン](https://github.com/icsharpcode/ilspy-vscode): どの OS でも利用できます（VSCode から直接インストールできるため、git をダウンロードする必要はありません。**Extensions** をクリックして、**ILSpy** を検索してください）。\
**デコンパイル**、**変更**、再度の**コンパイル**が必要な場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)または、現在もメンテナンスされているフォークである[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます（関数内を変更するには、**右クリック -> Modify Method**）。

### REA による実行不要のマネージドコード検査

**REA** はアセンブリを読み込まずに、PE/CLI メタデータと CIL を検査できます。まずアーティファクトの識別情報を確認し、次にメンバーと宣言されたネイティブ境界を調べます。デコンパイラを使用したり、プログラムを実行したりする前に、不審な呼び出しを確認する際に役立ちます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

バージョン間の差分比較では、`compare_managed_members` はメタデータトークンがビルド間で安定しているものとして扱わず、生の CIL／シグネチャの同一性とデコード済み命令のフィンガープリントを使用します。P/Invoke 宣言があっても、ネイティブコードが実行された証拠にはなりません。この境界を確認するには、`verify_managed_native_boundaries` で一致するネイティブ export または関数 Evidence が必要です。アーティファクトの digest、MVID、未解決のマッピングも結果とともに保持してください。<sup>[[17]](#references)</sup>

### DNSpy のログ記録

**DNSpy に情報をファイルへ記録させる**には、次のスニペットを使用できます：

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy デバッグ

DNSpyを使ってコードをデバッグするには、次の操作が必要です。

まず、**デバッグ**に関連する**アセンブリ属性**を変更します。

![DNSpy Logging - DNSpy デバッグ: まず、デバッグに関連するアセンブリ属性を変更します](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: compile をクリック](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_ から新しいファイルを保存します。

![DNSpy Logging - DNSpy Debugging: File Save module から新しいファイルを保存](<../../images/image (602).png>)

これが必要なのは、これを行わないと**実行時**にコードに複数の**最適化**が適用され、デバッグ中に**ブレークポイントに到達しない**場合や、一部の**変数が存在しない**場合があるためです。

.NET アプリケーションが **IIS** によって**実行**されている場合は、次のコマンドで**再起動**できます。

```
iisreset /noforce
```

Then、デバッグを開始するには、開いているファイルをすべて閉じ、**Debug Tab** 内で **Attach to Process...** を選択します：

![DNSpy Logging - DNSpy Debugging: デバッグを開始するには、開いているファイルをすべて閉じ、Debug Tab 内で Attach to Process を選択します](<../../images/image (318).png>)

次に、**IIS server** にアタッチするため **w3wp.exe** を選択し、**attach** をクリックします：

![DNSpy Logging - DNSpy Debugging: IIS server にアタッチするため w3wp.exe を選択し、attach をクリックします](<../../images/image (113).png>)

プロセスのデバッグを開始したら、停止してすべてのモジュールを読み込みます。まず _Debug >> Break All_ をクリックし、続けて _**Debug >> Windows >> Modules**_ をクリックします：

![DNSpy Logging - DNSpy Debugging: プロセスのデバッグを開始したら、停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、続けて Debug Windows Modules をクリックします](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: プロセスのデバッグを開始したら、停止してすべてのモジュールを読み込みます。まず Debug Break All をクリックし、続けて Debug Windows Modules をクリックします](<../../images/image (834).png>)

**Modules** 内の任意のモジュールをクリックし、**Open All Modules** を選択します：

![DNSpy Logging - DNSpy Debugging: Modules 内の任意のモジュールをクリックし、Open All Modules を選択します](<../../images/image (922).png>)

**Assembly Explorer** 内の任意のモジュールを右クリックし、**Sort Assemblies** をクリックします：

![DNSpy Logging - DNSpy Debugging: Assembly Explorer 内の任意のモジュールを右クリックし、Sort Assemblies をクリックします](<../../images/image (339).png>)

## Java逆コンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのデバッグ

### IDAを使用する

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Windbg** debuggerを選択する
- "**Suspend on library load/unload**" を選択する

![Debugging DLLs - Using IDA: " Suspend on library load/unload " を選択します](<../../images/image (868).png>)

- 実行の**parameters**を設定し、**DLLのパス**と呼び出したい関数を指定します：

![Debugging DLLs - Using IDA: 実行のparametersを設定し、DLLのパスと呼び出したい関数を指定します](<../../images/image (704).png>)

その後、デバッグを開始すると、**各DLLが読み込まれるたびに実行が停止します**。したがって、rundll32がDLLを読み込むと、実行が停止します。

この方法ではモジュールのロードイベントで停止しますが、読み込まれたDLLのエントリーポイントに到達するには、以下のx64dbgの手順のほうが直接的です。

### x64dbg/x32dbgを使用する

- **rundll32を読み込む**（64bits版はC:\Windows\System32\rundll32.exe、32 bits版はC:\Windows\SysWOW64\rundll32.exe）
- **Command Lineを変更**し（_File --> Change Command Line_）、dllのパスと呼び出したい関数を設定します。例："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ を変更し、"**DLL Entry**" を選択します。
- その後、**実行を開始**すると、debuggerは各dll mainで停止します。やがて、**対象dllのEntryで停止します**。そこから、breakpointを設定したい箇所を探します。

win64dbgで何らかの理由により実行が停止したときは、**win64dbgウィンドウ上部**を見ると、**どのコード上にいるか**を確認できます：

![Using IDA - Using x64dbg/x32dbg: 何らかの理由により実行が停止したときは、win64dbgウィンドウ上部を見ると、どのコード上にいるかを確認できます](<../../images/image (842).png>)

この表示により、デバッグ対象のDLL内で実行が停止したことを確認できます。

## GUIアプリ / ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内で重要な値が保存されている場所を探し、値を変更するのに便利なプログラムです。詳細はこちら：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) は、ゲームに特化したGNU Project Debugger (GDB)用のフロントエンド/reverse engineering toolです。ただし、reverse engineering関連の用途全般に使用できます。

[**Decompiler Explorer**](https://dogbolt.org/) は、複数のdecompilerを利用できるWebフロントエンドです。このWebサービスを使うと、小さな実行ファイルに対する各decompilerの出力を比較できます。

## REAを使った証拠に基づくネイティブ調査

**REA** は、CLIとMCPを通じてHopper、Ghidra、IDAによる解析機能を提供します。Node.js 22.x（少なくとも22.19）、24.x（少なくとも24.11）、または26以降と、npmが必要です。まず既存のネイティブproviderを設定してください。`rea providers --json` を確認し、複数のproviderが対象をサポートしている場合は、providerを明示的に選択します。以下の `0x1000` の代わりに、inventoryから確認した関数名またはアドレスを指定します。<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

機能文字列またはシンボルから始め、参照先や呼び出し元をたどり、選択した関数の dossier と疑似コードを `rea decompile` で調べます。REA は選択した provider にセッションを紐付けるため、失敗後に黙って別の provider に切り替わることはありません。クエリを再現可能にするには、`--snapshot PATH` を指定します。このオプションは、artifact のバイト列、provider、設定、操作、パラメーターが一致する場合にのみ再利用します。snapshot はローカルキャッシュであり、provider のデータベースを保存するものではありません。返された Evidence と明示された不明点を保持し、推測されたパスや decompiler のテキストを元のソースとして扱わないでください。<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron のエントリポイントから native add-on に至る経路については、[Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) を参照してください。

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner を使った shellcode のデバッグ

[**BlobRunner**](https://github.com/OALabs/BlobRunner) は **shellcode** を割り当て、**memory address** を表示して実行を一時停止します。\
IDA や x64dbg などの debugger をアタッチし、表示されたアドレスに breakpoint を設定してから実行を再開し、shellcode をデバッグします。

releases の github ページには、コンパイル済みリリースを含む zip があります: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクから、少し改変された Blobrunner を入手できます。コンパイルするには、**Visual Studio Code で C/C++ project を作成し、コードをコピーして貼り付け、ビルドする**だけです。


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it を使った shellcode のデバッグ

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) は BlobRunner に似ています。shellcode を割り当てて無限ループに入ります。debugger をアタッチし、**2〜5 秒間**実行を再開してから、そのループ内で一時停止し、割り当てられた shellcode に実行を移す次の call までステップ実行します。

![jmp2it の無限ループ内で、割り当てられた shellcode を呼び出す直前に debugger が一時停止している画面](<../../images/image (509).png>)

コンパイル済みの [jmp2it は releases ページからダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutter を使った shellcode のデバッグ

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) は radare の GUI です。Cutter を使うと、shellcode をエミュレートして動的に調査できます。

Cutter では「Open File」と「Open Shellcode」を選べます。私の場合、shellcode を file として開くと正しく逆コンパイルされましたが、shellcode として開くと正しく処理されませんでした。

![同じバイト列を file として開いた場合と shellcode として開いた場合で、異なる解析結果を表示する Cutter](<../../images/image (562).png>)

エミュレーションを開始したい場所で bp を設定すると、Cutter はそこから自動的にエミュレーションを開始するようです。

![Cutter のエミュレーション開始前に、目的の shellcode entry に breakpoint を設定](<../../images/image (589).png>)

![選択した shellcode breakpoint で一時停止している Cutter emulator](<../../images/image (387).png>)

たとえば、hex dump 内で stack を確認できます。

![Cutter の hex dump でエミュレートされた shellcode の stack を表示](<../../images/image (186).png>)

### shellcode の deobfuscation と実行された関数の特定

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) を試してください。\
shellcode が使用している **関数**や、メモリ内で自身を **decode** しているかどうかなどが分かります。

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg には、必要なオプションを選択して shellcode を実行できるグラフィカルランチャーもあります。

![shellcode のエミュレーションとトレースのオプションを選択する scDbg グラフィカルランチャー](<../../images/image (258).png>)

**Create Dump** オプションを使うと、メモリ上で shellcode が動的に変更された場合に、最終的な shellcode をダンプできます（デコードされた shellcode のダウンロードに便利です）。**start offset** は、特定のオフセットから shellcode を開始する場合に便利です。**Debug Shell** オプションを使うと、scDbg ターミナルで shellcode をデバッグできます（ただし、この用途では、前に説明したオプションのほうが優れていると思います。Ida や x64dbg を使えるためです）。

### CyberChef を使った逆アセンブル

shellcode ファイルを入力としてアップロードし、次のレシピを使って逆アセンブルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation の難読化解除

**Mixed Boolean-Arithmetic (MBA)** obfuscation は、算術演算（`+`、`-`、`*`）とビット演算子（`&`、`|`、`^`、`~`、シフト）を組み合わせた数式で、`x + y` のような単純な式を隠します。重要なのは、こうした恒等式が通常、**固定幅の剰余演算**でのみ正しいということです。そのため、キャリーとオーバーフローが重要になります。

```c
(x ^ y) + 2 * (x & y) == x + y
```

この種の式を汎用の代数ツールで簡約すると、ビット幅の意味が無視されるため、誤った結果になりやすいです。<sup>[[1]](#references)</sup>

### 実践的なワークフロー

1. リフトしたコード／IR／decompiler の出力にある**元のビット幅**（`8/16/32/64` bits）を維持します。
2. 簡約を試す前に、式を**分類**します。
   - **線形**: ビット演算のアトムの重み付き和
   - **半線形**: 線形式に `x & 0xFF` のような定数マスクを加えたもの
   - **多項式**: 積を含むもの
   - **混合**: 積とビット演算ロジックが入り交じり、部分式が繰り返されることが多いもの
3. 候補となる書き換えは、すべてランダムテストまたは SMT 証明で検証します。同値性を証明できない場合は、推測で書き換えず、元の式を維持します。

### 狭い実行スライスで flatten された制御フローを回避する

完全な制御フローグラフを復元する必要がない場合はよくあります。control-flow flattening、opaque predicate、大規模な dispatcher、または MBA-heavy なコードでは、暗号化された blob と出力バッファから参照をたどり、それらを変換する最小のルーチンを見つけます。そのデータフロースライスだけを再現するか、独立して実行します。関連する状態を直接初期化できるなら、dispatcher は解決に必要ありません。<sup>[[7]](#references)</sup>

実践的なワークフローは次のとおりです。<sup>[[7]](#references)</sup>

1. 実行可能セクションとデータセクション、relocation、相互参照を調べます。`.rodata` から候補となるテーブルを、バイト順と要素幅を維持してダンプします。
2. 平文または出力バッファに最後に書き込むルーチンを特定します。その入力、参照するテーブル、import された呼び出し、必要なグローバル状態を記録します。
3. それらの操作だけを固定幅の Python モデルに移します。スライスが依然として過剰な状態に依存する場合は、プログラム全体をエミュレートする代わりに、Unicorn、QEMU、または debugger でルーチンを呼び出し、不要な import を hook します。
4. extractor が実際に与えられた binary から出力を導出していることを検証します。暗黙の fallback を削除し、埋め込み済みの答えがないか調べ、文字列、鍵、識別子、レイアウト、難読化 seed を変えた未知の build でも実行します。

最初に使えるコマンドは次のとおりです。<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### 定数を偽装したMBA式を検出する

一見すると入力に依存しているように見えるバイト式でも、入力が完全に相殺されることがあります。テーブルを抽出した後、8ビットの全領域で式を評価します。出力集合が単一要素なら、周囲のステートマシンを復元せずに、そのバイトが定数だと証明できます。<sup>[[7]](#references)</sup>

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

最終的なマスクは残してください。元の加算では、バイト幅でのオーバーフローが発生するためです。より広いドメインでは、同じ幅のシンボリック入力 `x1` と `x2` に対して `f(x1) != f(x2)` が充足可能か SMT solver に問い合わせます。`unsat` なら不変性が証明され、`sat` なら反例が得られるため、その入力は破棄できません。<sup>[[7]](#references)</sup>

#### 環境依存のデコードを見分ける

Anti-analysis checks は、分岐やクラッシュを起こす必要はありません。デコーダーは、センサーの結果を鍵のビット、不透明述語の定数、またはフラット化されたディスパッチャーの状態に混ぜ込み、正常に処理を続けながら、エミュレーター上で一見もっともらしい偽の平文を生成できます。そのため、目に見える失敗分岐だけをパッチするのでは不十分です。環境プローブからデコーダーの状態へのデータ依存関係をトレースし、実機とエミュレーターで同じスライスを比較し、各センサーの結果を強制的に変更したときに最終バッファがどう変わるかを確認してください。<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) は、マルウェア解析や保護されたバイナリのリバース解析に実用的な MBA simplifier です。すべてに単一の汎用的な書き換え処理を適用するのではなく、式を分類し、専用のパイプラインに振り分けます。<sup>[[2]](#references)</sup>

クイックな使い方：

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
- **Semilinear MBA**: 定数でマスクされたatomは、マスク領域の正しさを保つため、ビット分割による再構成で再構築されます。
- **Polynomial/Mixed MBA**: 積をcoreに分解し、繰り返し現れる部分式を一時変数に持ち上げてから、外側の関係を単純化できます。

よく復元を試す価値がある、mixed identityの例:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

これは次のように簡約できます:

```c
x * y
```

### Reversing notes

- 正確な計算を切り分けた後、**lifted IR expressions** または decompiler output に対して CoBRA を実行するのがおすすめです。
- マスク演算や narrow registers に由来する式では、`--bitwidth` を明示的に指定してください。
- より強力な証明手順が必要な場合は、こちらのローカル Z3 notes を確認してください:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA は **LLVM pass plugin** (`libCobraPass.so`) としても提供されており、後続の analysis passes の前に MBA を多用した LLVM IR を正規化する場合に便利です。
- サポートされていない、carry に依存する mixed-domain residuals は、元の式を保持し、carry path を手動で解析する必要があることを示すサインとして扱ってください。

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この obfuscator はプログラムの処理を `mov` ベースの命令シーケンスに置き換え、signal/exception handling を使って制御フローを変更します。詳細はこちら:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

対応するバイナリであれば、[demovfuscator](https://github.com/kirschju/demovfuscator) を使って結果を deobfuscate できます。いくつかの依存関係があります。

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTFをプレイしている場合、このフラグを見つけるための回避策**が役立つかもしれません: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリポイント**を見つけるには、次のように関数名を `::main` で検索します:

![Ghidraで関数名の二重コロン付きmainを検索してRustのエントリポイントを見つける](<../../images/image (1080).png>)

この場合、バイナリ名はauthenticatorだったため、どれが興味深いmain関数かは明らかです。\
呼び出されている**関数**の**名前**がわかったら、**入力**と**出力**を知るために**インターネット**で検索しましょう。

### ELFファームウェアからRust文字列を復元する

**Rust ELF**バイナリでは、多くの静的文字列はCスタイルのNUL終端ポインタから参照されていません。一般的な `rustc` の配置では、**`.data.rel.ro`** 内の**ポインタと長さのタプル**が、**`.rodata`** に格納された実際の文字列データを指しています:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

これは、`strings`やGhidraのデフォルト解析では、隣接する文字列が結合されたり、クロスリファレンスが完全に見落とされたりする可能性があることを意味します。<sup>[[3]](#references)</sup>

簡単なワークフロー：

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** の仮想アドレスとサイズを取得します。
2. **`.data.rel.ro`** を1ワードずつ列挙します。
3. `.rodata` のアドレス範囲内にある値を、文字列ポインターの候補として扱います。
4. 次のワードを、候補の長さとして扱います。
5. 妥当性フィルターを適用します（例：長さが **4**～**100** バイトの範囲内であること）。
6. `0x00` まで走査するのではなく、`.rodata` から `length` バイトを正確に読み取ります。

最小限の抽出ロジック：

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

これは firmware reversing で特に役立ちます。復元された Rust 文字列から、**HTTP routes、RPC 名、ログメッセージ、assertion、ファイル名、config キー、command handler、認証関連のロジック**が判明することがよくあります。

Ghidra がこれらの文字列を検出できない場合は、同じ heuristic を適用し、参照先の `.rodata` オフセットに string data を作成するカスタム script/plugin を実行してください。Pen Test Partners が公開している `rust-strings` と `RustStrings.py` は、このアイデアを他の**word size、endianness、section layout**に適用する際の参考になります。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi でコンパイルされた binary には、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) を使用できます。

Delphi binary を reverse する場合は、IDA plugin の [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) の使用をおすすめします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin file を選択します。

この plugin は binary を実行し、debugging の開始時に function 名を動的に解決します。debugging を開始した後、もう一度 Start ボタン（緑色のボタン、または f9）を押すと、実際の code の先頭で breakpoint にヒットします。

グラフィカル application のボタンを押すと、debugger はそのボタンから呼び出される function で停止できます。

## Golang

一般的な Go binary では、[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) を使って runtime structures を復元し、IDA で function 名を改善できます。**Alt+F7** を押して Python plugin を読み込んでください。

Golang binary を reverse する場合は、IDA plugin の [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) の使用をおすすめします。

IDA で **Alt+F7** を押して Python plugin を読み込み、plugin file を選択します。

これにより function 名が解決されます。

### symbol table を使わずに metadata を復元する

stripped Go executable でも、program counter と function の対応付けには runtime metadata が必要です。[GoReSym](https://github.com/mandiant/GoReSym) は Go runtime 由来の code を使って、`pclntab` や `moduledata` などの structure を特定・解析します。これにより、従来の symbol table に頼らず、function の境界、名前、source path、型、build 情報を復元できます。<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

難読化ツールは、復元された名前を置き換えながら、これらの構造を使用可能な状態に保つことがあります。たとえば Garble は、識別子とパッケージパスをハッシュ化し、build、module、debug 情報を削除します。<sup>[[12]](#references)</sup> 難読化されたパッケージトークンは、そのパッケージ内の関数間で一貫している必要があります。繰り返し出現するトークンごとに関数をグループ化し、その関数の呼び出し先、文字列、API からパッケージを推定して、グループ全体にそのパッケージ名を適用します。<sup>[[13]](#references)</sup>

### GoResolver で Garble の名前を復元する

[GoResolver](https://github.com/volexity/GoResolver) は、runtime-symbol の抽出と、クリーンな参照バイナリの生成、control-flow-graph（CFG）の照合を組み合わせます。次の手順で進めます。<sup>[[10]](#references)[[13]](#references)</sup>

1. **コンパイラのバージョンを特定する。** まず `BuildInfo` と埋め込みのバージョン文字列を調べます。難読化ツールによって削除されている場合は、バンドルされた Go runtime の一部を、バージョンごとの参照 runtime と比較します。Volexity のテストでは、runtime の約 `2%` で Go のメジャーバージョンを判別できました。これは実証に基づく最適化であり、普遍的な基準ではありません。<sup>[[13]](#references)</sup>
2. **照合用の参照バイナリを用意する。** 特定した Go バージョン、ターゲットアーキテクチャ、使用されている可能性の高いライブラリに合わせて、クリーンなバイナリを生成します。ツールチェーンを一致させることで、コンパイラが生成する CFG の差異を抑えられます。<sup>[[10]](#references)[[13]](#references)</sup>
3. **関数を比較する。** GoGrapher は関数の CFG を照合し、`0.0` から `1.0` までの正規化スコアを出力します。基本ブロックの照合は、類似命令を重み付けして比較します。信頼度の高い照合結果から、ランダム化された関数とクリーンな実装を対応付けます。信頼度が低い照合結果でも、パッケージやモジュールの特定に役立つ場合があります。<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **検証してインポートする。** 提案された名前を、呼び出し関係、定数、文字列、副作用を使って確認してから、IDA または Ghidra 用の GoResolver plugin で JSON レポートをインポートします。<sup>[[10]](#references)[[13]](#references)</sup>

toolchain をインストールし、抽出ツールとグラフ照合ツールをまとめて実行します。<sup>[[10]](#references)</sup>

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

デフォルトの有意一致しきい値は `0.9` です。`--extract` と `--graph` のスイッチを使うと各ステージを個別に実行できます。デフォルトでは、復元されたランタイムメタデータとCFGの証拠が互いを補完するため、両方が実行されます。<sup>[[10]](#references)</sup> CFGスコアはヒューリスティックです。インライン化、ビルドフラグ、アーキテクチャ、ライブラリのバージョンの違いによってグラフの形状が変わることがあるため、信頼度の低い名前を無理に割り当てず、未解決の関数はそのまま残してください。<sup>[[13]](#references)</sup>

### Goの文字列テーブルの復元

Goバイナリでは、リンクされたすべてのパッケージの文字列データが、1つの連続したテーブルに配置されます。各エントリはNUL終端されておらず、ランタイム構造体からテーブルのベースアドレスやサイズを取得することもできません。しかし、コンパイラはOSやアーキテクチャを問わず、エントリをまず長さ順、次にアルファベット順に並べます。そのため、1つのエントリを見つければ、隣接するエントリをたどり、データのクロスリファレンスを使って文字列とコードを関連付けることができます。<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) は、この作業を IDA Pro と Ghidra で自動化します。このプラグインはデータセグメントのクロスリファレンスに依存するため、最初に自動解析が完了するのを待ってください。デフォルトのアンカーはランタイム文字列 `entersyscall` です。その後、どちらの方向にもスキャンし、復元した文字列をデータベース内で定義して、文字列と参照元関数の対応を示すJSONをエクスポートできます。<sup>[[14]](#references)</sup>

レポートを参照元関数のパッケージでフィルタリングすると、アプリケーションやマルウェアのコードを、リンクされたライブラリ由来のノイズから分離できます。この手法では、Garbleの `-literals` 変換のような難読化によって破壊されたリテラルは復元できません。一方、難読化されずに残ったランタイム文字列を整理することはできます。<sup>[[14]](#references)[[15]](#references)</sup>

### Goランタイム型の復元

Goには、ガベージコレクションなどの機能で使われるランタイム型情報が埋め込まれています。ビルド情報が削除されていたり、逆アセンブラがこのメタデータを解析できなかったりすると、命令が任意のデータアドレスを読み込んでいるように見え、対象領域に型が付かないままになります。このメタデータを復元すると、これらのアドレスを読みやすい型参照に変換でき、パッケージの機能を把握しやすくなります。<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) は、シンボルを抽出し、ランタイム型を解析してJSONレポートに出力できます。現在のCLIでは、`resolve` サブコマンドを使用します。<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` オプションを有効にすると、型が解析されます。GoResolver の IDA Pro または Ghidra plugin でレポートをインポートすると、復元された型を定義し、解析データベース内でその参照を適用できます。この機能で導入されたレポート形式では、`-y` を省略すると、RTTI アドレスと復元された型のメンバーは null になります。<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver は x86、AMD64、ARM、ARM64 の PE、ELF、Mach-O サンプルに対応しているため、同じワークフローを Windows、Linux、macOS の Go バイナリに適用できます。<sup>[[10]](#references)</sup>

## コンパイル済み Python

このページでは、コンパイルされた ELF/EXE Python バイナリから Python コードを取得する方法を説明します。


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

GBA ゲームの **バイナリ** を入手した場合、さまざまなツールを使って **emulate** および **debug** できます。

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version をダウンロード_) - インターフェース付きの debugger を搭載
- [**mgba** ](https://mgba.io)- CLI debugger を搭載
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) の _**Options --> Emulation Setup --> Controls**_** ** では、Game Boy Advance の **ボタン** の押し方を確認できます。

![Game Boy Advance のボタン割り当てを示す no$gba の操作設定](<../../images/image (581).png>)

押すと、各 **キーには識別用の値があります**。

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

つまり、この種のプログラムでは、興味深いのは**プログラムがユーザー入力をどのように処理するか**です。アドレス **0x4000130** に、よく見られる関数 **KEYINPUT** があります。

![アドレス0x4000130でKEYINPUTを参照しているGBAバイナリのGhidraビュー](<../../images/image (447).png>)

前の画像では、この関数が **FUN_080015a8**（アドレス: _0x080015fa_ および _0x080017ac_）から呼び出されていることがわかります。

この関数では、いくつかのinit処理（重要ではありません）の後に、次の処理が行われます。

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

最後の if は、**`uVar4`** が **last Keys** に含まれ、現在のキーではないことを確認しています。これはボタンを離した状態とも呼ばれます（現在のキーは **`uVar1`** に格納されています）。

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

- まず、**値 4**（**SELECT**ボタン）と比較されます。このチャレンジでは、このボタンを押すと画面がクリアされます。
- 次に、値が **8**（**START**ボタン）と比較されます。このチャレンジでは、この経路で入力されたコードが有効かどうかを確認します。
  - この場合、変数 **`DAT_030000d8`** が 0xf3 と比較され、値が一致するとコードが実行されます。
- それ以外の場合は、カウンター（`DAT_030000d4`）が確認され、インクリメントされます。\
  カウンターが 8 未満の間、押されたキーの値が `DAT_030000d8` に累積されます。

つまり、このチャレンジでは、ボタンの値を把握したうえで、合計が 0xf3 になる、長さが 8 未満の組み合わせを**押す必要がありました**。

**このチュートリアルの参考資料:** [Nostalgiaチャレンジのwriteup（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)。<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRAによるMBA難読化の簡素化](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRAリポジトリ](https://github.com/trailofbits/CoBRA)
- [3] [Rust文字列のデコード - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversingチュートリアル（アーカイブ）](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI支援によるreverse engineeringへの対抗、あるいは少なくともその試み](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [基本ブロックマッチングに基づく制御フローグラフの比較手法](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolverリポジトリ](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garbleの難読化メカニズム](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: 制御フローグラフの類似性を使ってGolangバイナリを自動的にdeobfuscateする](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractorリポジトリ](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: VolexityのGolangツール群の更新](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: あらゆるものをreverse engineerする](https://github.com/morluto/rea)
- [17] [REAのmanaged-code解析](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLIとEvidenceガイド](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
