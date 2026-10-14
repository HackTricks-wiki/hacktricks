# WinDbgによる対象を絞った instrumentation の自動化

{{#include ../../banners/hacktricks-training.md}}

WinDbgとWinDbgXは、起動時、例外発生時、breakpoint に到達したときに debugger コマンドを実行できます。これにより、各イベントで手動停止する代わりに、入力によって実行されるパスの周辺だけで状態を収集する fuzzing や reversing のセッションを実行できます。<sup>[[1]](#references)</sup>

## 有用な例外で開始する

`-c` は debugger の初回停止時にコマンドを実行します。セットアップ後に再開するには、末尾に `;g` を付けます。WinDbg Classic を unattended で実行する場合、`-logo` はコマンドウィンドウをログに記録し、`-Q` は workspace の自動保存を無効にし、`-G` は最後の breakpoint を無視して、target の終了時にセッションを終了します。WinDbgX も `-c` を受け付け、設定済みの Startup commands はその後に実行されます。<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

アクセス違反では、**`sxe av` は first chance で中断し、`sxd av` は first chance をスキップして、未処理の second chance で中断し、`sxi av` はどちらの chance も無視します**。この記事の `sxi` / `sxd` の説明は逆です。Microsoft のドキュメントでは、`sxd` は second-chance filter、`sxi` は無視として定義されています。first-chance コマンドには `-c` を、second-chance コマンドには `-c2` を使用してください。filter が `sxd` だからといって、first-chance の `-c` handler が second-chance handler になるわけではありません。`sx` で有効な filter を確認してください。<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

最初のコマンドは、未処理の access violation が発生した場合に限り、レジスタ、スタックトレース、例外解析情報を収集します。2つ目のコマンドは、モジュールの読み込み時に `lm` を実行します。Breakpoint (`bp`)、モジュール読み込み (`ld`)、access-violation (`av`) イベントはそれぞれライフサイクルが異なるため、デバッガの breakpoint を使う場合は、`bp` を全体的に無視しないでください。<sup>[[1]](#references)[[2]](#references)</sup>

## 制御可能なトリガーで高負荷な breakpoint を有効化する

対象の処理の直前に呼び出せる、スクリプトから参照可能な関数、または入力で制御できる関数を選びます。調査対象の allocator、parser、API 呼び出しに **action breakpoint** を設定します。`bd` で ID を指定して無効化します。コマンドを付加した **trigger breakpoint** を設定し、その ID を `be` で有効化してから `g` で再開します。別の制御可能なトリガーを使えば、再び無効化できます。トリガーを設定する前に `bl` で ID を確認してください。ID は breakpoint の作成順に依存するためです。こうすることで、負荷の低い制御ポイントと負荷の高いトレースを分離し、対象のタイミングやヒープレイアウトへの影響を抑えられます。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

2つのシンボルを解決したら、以下のコマンドパターンを使います。角括弧で囲まれたシンボルと、`bl` が返した action breakpoint ID を置き換えてください。ID が 0 だと決めつけないでください。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Action breakpoint コマンドでは、`@$ip` と `%y`（シンボル化されたアドレス）を表示したり、選択した引数やメモリをダンプしたりしてから、実行を続行できます。条件付き breakpoint で特定の範囲内のポインターだけを記録する場合は、まずその範囲がテスト入力を実際にカバーしていることを確認してください。条件が誤っていると、証拠が黙って失われます。<sup>[[1]](#references)</sup>

### シンボルを使ってトリガーを見つける

実装モジュールが不明な場合は、読み込まれているすべてのモジュールを検索します。`bm` は一致するすべてのシンボルに breakpoint を設定します。スクリプトから呼び出し可能な関数を実行し、どの breakpoint が発火するかを調べます。たとえば、ソースコードが実行するのは、デバッグ対象の renderer 内の `Math.cos(0)` であり、単に任意のブラウザープロセス内のものではありません。<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

ヒットによって正確な関数が特定できたら、`lm a <symbol>` を使ってその関数を含むイメージを解決し、`? <symbol> - <module>` でモジュール相対オフセットを計算します。WinDbg は実行ファイルと DLL に同じ短いモジュール名を表示することがあるため、別のプロセスでオフセットを使う前にイメージパスを確認してください。オーバーヘッドを避けるため、ワイルドカードブレークポイントを確認済みのシンボルに絞り込みます。<sup>[[1]](#references)</sup>

### シンボルなしで候補を探す

Corelan の Frida ベースの `corelan_trigscan.py` は、選択したプロセスモジュールをスキャンし、浮動小数点、SSE、AVX、三角関数の命令パターンを探します。WinDbg のブレークポイントコマンドを `corelan_trigscan.bps` と、番号付きのより小さな `.bps` ファイルに出力します。別のデバッガーをアタッチ**せずに**、Python と `frida-tools` を使って対象に対して実行します。その後、WinDbg を同じプロセス／モジュールにアタッチし、扱いやすい数のブレークポイントを読み込みます。<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

既知のモジュール相対オフセットについて、出力されたすべてのブレークポイントをインポートする前に、しきい値を通過することを確認します:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` は関連命令の密度、`--min-relevant` と `--min-total` は命令数の下限を設定し、`--min-trig` は trig に似た強いシグナルを要求します。既知の関数が見つからない場合は、その関数の**モジュール相対**オフセットを `--check-offset` に渡して、プロローグ、密度、カウント、間接呼び出しを調べます。薄いラッパーは密度が低く、trig 命令がないことがあります。しきい値を下げ、ラッパーを検索する場合はスクリプトの実際の `--min-icall 1` オプション（`--min-ical` ではなく）を使用してください。直接呼び出し先は解析されますが、間接呼び出しのターゲットを確実に追跡することはできません。生成されたブレークポイントが多く、WinDbg の動作が遅くなる場合は、`--splitsize` のバッチを小さくします。対象の入力によってブレークポイントが発火するまでは、候補は検証済みとは言えません。<sup>[[1]](#references)[[6]](#references)</sup>

## 小さなデバッガープログラムと PyKD

条件が信頼できる場合は `.if` を、空白区切りの出力を反復処理するには `.foreach` を、メモリや構造体をたどるには疑似レジスターを使った `.for` を使用します。`.foreach` は列を保持**しません**。たとえば、幅が一定でない `lm` の出力は入力として適しませんが、`lm 1m` ならトークンごとにモジュール名が出力されます。推測した条件によって失敗する経路が隠れる可能性がある場合は、まずフィルターをかけずにデータをログに記録します。<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

`as name value`で作成するエイリアスは、型付き変数ではなくテキスト置換です。`al`で一覧表示し、`ad name`で削除できます。また、`${name}`を使うと曖昧さなく展開できます。エイリアスが組み込みコマンドを隠す可能性があるため、`bp`、`x`、`r`などの名前は避けてください。MASM式は`poi(@$t0)`のようなポインター演算に適しています。シンボルがあれば、`@@c++(...)`で型付きフィールドにアクセスでき、構造体オフセットをハードコードせずに済みます。<sup>[[1]](#references)</sup>

長いコマンドシーケンスはコマンドファイルに記述してください。`$$><filename`は行を1つのコマンドブロックにまとめ、後続にセミコロン区切りのデバッガーコマンドを記述できます。複数行の制御構造は不安定な場合があるため、各`.if`文または`.for`文は1行に収めてください。同じファイルは起動時に`-c`から実行できます。<sup>[[1]](#references)[[8]](#references)</sup>

コマンド言語では扱いにくい処理には、PyKDを使うと、Pythonから型付き構造体、レジスター、メモリー、デバッガー出力にアクセスできます。たとえば、`pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())`でPEBフィールドにアクセスし、`pykd.loadBytes(address, size)`でメモリーを読み取り、`pykd.dbgCommand("lm")`で解析用のデバッガー出力を取得できます。終端されていない可能性があるデータには、上限のない文字列読み取りではなく、上限付きの`loadChars`/`loadWChars`を優先してください。PyKDの`disasm(address).asm(instruction)`は、そのアドレスにアセンブル済みバイトを書き込みます。実行中のプロセスでopcodeを取得するために使う場合は、元のメモリーを保存して復元してください。<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: デバッグ - WinDBG(X)の自動化とスクリプティング - パート1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx、sxd、sxe、sxi、sxn、sxr、sx-（例外の設定）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be（ブレークポイントの有効化）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd（ブレークポイントの無効化）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp、bu、bm（ブレークポイントの設定）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscanのソース](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: WinDbgのコマンドラインオプション](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: スクリプトファイルの実行](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
