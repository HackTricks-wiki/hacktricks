# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**では、入力は**文法的に有効な状態**を保ちながら変異されます。coverage-guidedモードでは、**新たなcoverage**を引き起こしたサンプルのみがcorpus seedとして保存されます。**言語を対象とするもの**（parser、interpreter、engine）では、ある構文の出力が別の構文の入力になるような**semantic/dataflow chain**を必要とするバグを見逃す可能性があります。<sup>[[1]](#references)</sup>

**失敗パターン:** fuzzerは、個別に`document()`や`generate-id()`（または類似のプリミティブ）を実行するseedを見つけても、**連鎖したdataflowを維持できない**ため、「バグに近づく」サンプルがcoverageを増やさないという理由で破棄されます。依存するステップが**3つ以上**あると、ランダムな再結合はコストが高くなり、coverage feedbackも探索の指針になりません。<sup>[[1]](#references)</sup>

**示唆:** 依存関係の多い文法では、**mutational phaseとgenerative phaseを組み合わせる**か、coverageだけでなく**function chaining**パターンを優先して生成することを検討してください。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutationは**貪欲**です。新たなcoverageをもたらしたサンプルはすぐに保存され、多くの場合、変更されていない大きな領域がそのまま残ります。時間が経つにつれ、corpusは構造的多様性の低い**ほぼ重複したサンプル**で埋まります。過度なminimizationは有用なコンテキストを取り除く可能性があるため、実用的な妥協策は、**最小トークン数に達したら停止する**grammar-aware minimizationです（ノイズを減らしつつ、mutationしやすい状態を保てるだけの周辺構造を残します）。<sup>[[1]](#references)</sup>

mutational fuzzingにおける実用的なcorpusの原則は、ほぼ重複したサンプルを大量に集めるより、coverageを最大化する構造の異なるseedを少数選ぶことです。実際には、通常、次のようにします。<sup>[[1]](#references)[[3]](#references)</sup>

- **実環境のサンプル**（公開corpus、クローリングで収集したデータ、取得したtraffic、対象エコシステムのファイル群）から始める。
- 有効なサンプルをすべて残すのではなく、**coverage-based corpus minimization**を使って絞り込む。
- 無関係なbyteに大半のサイクルを費やさず、意味のあるfieldにmutationが当たるよう、seedを**十分小さく**保つ。
- harnessやinstrumentationを大幅に変更した後は、corpus minimizationを再実行する。到達可能な範囲が変わると、「最適な」corpusも変わるためです。

## Comparison-Aware Mutation For Magic Values

fuzzerが頭打ちになる一般的な原因は、syntaxではなく**厳密な比較**です。magic byte、length check、enum string、checksum、または`memcmp`、switch table、連続した比較によって判定されるparserのdispatch値がこれに当たります。純粋なランダムmutationでは、これらの値をbyte単位で推測しようとしてサイクルを浪費します。

このような対象には、**comparison tracing**（たとえばAFL++の`CMPLOG`やRedqueen形式のworkflow）を使い、失敗した比較のoperandをfuzzerが観測できるようにして、それらを満たす値へmutationを誘導します。<sup>[[3]](#references)</sup>

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**実践的な注意点:**

- ターゲットが**file signatures**、**protocol verbs**、**type tags**、または**version-dependent feature bits**の背後に深いロジックを隠している場合に特に有効です。
- 実際のサンプル、プロトコル仕様、デバッグログから抽出した**辞書**と組み合わせましょう。文法トークン、チャンク名、verb、区切り文字を含む小さな辞書のほうが、汎用の大規模wordlistより役立つことがよくあります。
- ターゲットが連続したチェックを多数実行する場合は、最初の「magic」比較を先に解決し、その後、得られたコーパスを再度minimizeして、後続の段階がすでに有効なprefixから始まるようにします。

## ファイル名の言語を隠しているファイルAPIのFuzzing

`filename`、`path`、`URL`という名前のパラメータは、単なるファイル検索ではなく、インタプリタのエントリーポイントかもしれません。たとえば、CFITSIO Extended Filename Syntax (EFS)は、開いたオブジェクトを返す前に、角括弧で囲まれたselector、行/ピクセル式、計算列、ヒストグラム、変換を評価します。一部の形式では一時的なコピーも作成します。攻撃対象領域をマッピングする際は、各open/import APIを**literal-path**または**interpreted-path**に分類し、アプリケーションが実際に呼び出す本番のエントリーポイントをFuzzingします。<sup>[[20]](#references)[[22]](#references)</sup>

その結果得られるSSRF、file-copy、protocol-handlerのプリミティブと、より安全なliteral-path APIについては、[Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)を参照してください。<sup>[[20]](#references)</sup>

### バックエンドのオブジェクトをFuzzing対象のプログラムから分離する

文法がファイル名のsuffixに含まれている場合、参照先ファイルのbytesだけを変更してもパーサーを見逃します。代わりに、小さなハーネスでテストケースを文字列として読み込み、それを解釈型のopen APIに渡せます。CFITSIOのキャンペーンでは、`fits_open_file()`をread-onlyモードで呼び出すことで、ほとんどのEFSパーサーと評価器に到達しました。有効なバックエンドファイルは別途用意しておき、ベースパスを繰り返し壊すのではなく、selector/式の言語に変更を集中させましょう。<sup>[[22]](#references)</sup>

それぞれ異なる文法ファミリーに到達するseedを使い、仕様書とlexer/parserのソースの両方からコンパクトな辞書を作成します。coverageが頭打ちになり、入力が同じ構文エラーの経路で繰り返し失敗する場合は、有効なprefixを保持し、ランダム変更の時間を増やすだけでなく、区切り文字、演算子、keyword、関数名、代表的なフィールド名を追加します。<sup>[[22]](#references)</sup>

たとえば、文法辞書を指定してハーネスを実行します。<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 「read-only」ハーネスの副作用を抑える

ライブラリの read-only フラグがあっても、テストケースで副作用が発生しないとは限りません。ファイル名の言語仕様によって入力が書き換えられたり、出力ファイルが作成されたり、一時オブジェクトが実体化されたりする可能性があります。CFITSIO のキャンペーンでは、シードファイルが最初に破壊され、ファイルシステム全体に予期しないファイルが残ったため、クリーンアップと分離が必要になりました。<sup>[[22]](#references)</sup>

- 各ワーカーに使い捨ての作業ディレクトリと専用の一時ディレクトリを割り当てる。
- 正規のバックアップファイルはコピーを公開し、ターゲットがコーパス唯一のコピーを変更できないようにする。
- リモートバックエンドが対象でない限りネットワークアクセスを無効にし、コンテナ、マウント名前空間、または同等のサンドボックスで書き込み可能なパスを制限する。
- 実行ごと、またはワーカーバッチごとにディレクトリをリセットし、予期しないファイルシステムの変更も追加の発見事項として扱う。

### クラッシュからパッチ、ファジングへ回すループ

修正前にクラッシュを分類し、何千もの成果物が何千ものパッチ作業にならないようにします。CFITSIO の評価では、AFLTriage によって最初のクラッシュ群が少数の根本原因に絞り込まれました。その結果のアドバイザリでは、宛先サイズのチェックミス、`realloc()` 後の古いポインター、算術エラー、安全でないパーサーのクリーンアップ処理など、複数の異なる不具合が示されています。<sup>[[21]](#references)[[22]](#references)</sup>

1. 各クラスタから代表的な入力を最小化し、AddressSanitizer の下で再現する。
2. 不正な状態になった不変条件、その原因となった正確なアクセス、ソース位置、割り当て／解放履歴、パーサーの状態を記録する。
3. 対象を絞った候補パッチを1つ適用し、同じカバレッジ計測とサニタイザー計測を有効にして再ビルドする。
4. 元の再現入力と**そのクラスタ内のすべての入力**を再実行する。また、メモリー安全性の修正によってエラーパスでの所有権が損なわれる可能性があるため、leak detection も有効にする。
5. 実ファイルを使って機能テストを実行し、その後、蓄積したキューから再開する（または、バイナリ変更後にエンジンが新しい出力ディレクトリを必要とする場合は、そのキューを再インポートする）。
6. 繰り返す。最初の浅いクラッシュを取り除くことで、既存のシードがより深いパーサー状態まで進むことがよくあります。

LLM にクラッシュ入力、サニタイザーのレポート、ハーネス、関連ソースを与えれば、ステップ2を効率化し、ステップ3のパッチ案を作成させることができます。ただし、そのパッチは信頼できるものとして扱ってはいけません。修正を受け入れるかどうかを決めるのは、モデルの説明ではなく、サニタイザーによる再実行と回帰テストのゲートです。<sup>[[22]](#references)</sup>

## エッジカバレッジで異なるパスが区別されない場合の、より豊かなフィードバック

通常のエッジカバレッジでは、同じヘルパーを異なる呼び出し元から通る実行や、関数内で異なる分岐の組み合わせを通る実行を区別できません。共有デコーダー、プロトコルディスパッチャー、インタープリターヘルパーでは、エッジまでの**経路**によってライブ状態が決まるため、これは重要です。すべての呼び出しコンテキストを素朴に追跡すると、カバレッジマップやキューが爆発する危険もあります。そのため、コンテキスト依存型ファジングの研究では、呼び出しグラフ全体をコンテキスト依存として扱うのではなく、有望なコンテキストだけを段階的に細分化することが推奨されています。<sup>[[14]](#references)</sup>

最近の AFL++ ビルドでは、通常のエッジカバレッジに加えて、**関数ごとの Ball-Larus パスカバレッジ**が利用できます。関数内の非巡回パスごとに特徴量を割り当てます。ループのバックエッジは除外されるため、このフィードバックで分岐の組み合わせは区別できますが、**ループの反復回数は区別できません**。まずは緩いレベル `1` から始め、パス数が指数関数的に増える可能性があるため、厳しいモードは疑わしいパーサー／状態機械コードに限定します。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

多くのセキュリティ上重要な箇所から呼び出される helper では、LTO mode により各関数パスを直近の呼び出し箇所と組み合わせられます:<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

**キャンペーンの指針:** より豊富なフィードバックは慎重に適用し、coverage-map/queue のコストを監視してください。<sup>[[13]](#references)[[14]](#references)</sup>

- 通常の edge-coverage インスタンスも並行して実行してください。追加の queue/map コストによって executions per second が損なわれない場合に限り、より豊富なフィードバックが有用です。
- 大規模な template-heavy ライブラリや汎用 utility code が map の大部分を占める場合は、`AFL_LLVM_ALLOWLIST` を使って path/caller instrumentation の対象を絞り込んでください。
- 非巡回パスが過剰に多い関数は AFL++ でスキップできます。コンパイル中の警告は、対象に allowlisting を適用するか、より低いレベルにする必要があることを示しています。
- Caller + path coverage がサポートする caller の深さは 1 つだけです。より深い context stack と組み合わせないでください。
- Path ID は LLVM のメジャーバージョン間で変わる可能性があります。キャンペーン中は toolchain を固定し、PATH-based corpus の feature ID がビルド間で安定しているものとして同期しないでください。
- このフィードバックは `CMPLOG` を補完します。comparison tracing は**ガードを通過する値**を特定し、path/caller feedback は**その値に到達した経路と分岐の組み合わせ**を保持します。

## Stateful Fuzzing: シーケンスを seed にする

**protocols**、**authenticated workflows**、**multi-stage parsers** では、興味深い単位は単一の blob ではなく、**メッセージシーケンス**であることがよくあります。トランスクリプト全体を 1 つのファイルに連結して盲目的に変異させる方法は、通常、効率がよくありません。脆弱な状態に到達するのが後続のメッセージだけでも、fuzzer はすべてのステップを均等に変異させるためです。<sup>[[4]](#references)</sup>

より効果的な方法は、**シーケンス自体を seed として扱い**、**観測可能な状態**（応答コード、protocol の状態、parser の段階、返されたオブジェクト型）を追加のフィードバックとして使うことです。<sup>[[4]](#references)</sup>

- **有効なプレフィックスメッセージ**は安定させ、**遷移を引き起こす**メッセージの変異に集中してください。
- 次のステップがそれらに依存する場合は、先行する応答から得られた識別子やサーバー生成値をキャッシュしてください。
- シリアライズされたトランスクリプト全体を不透明な blob として変異させるのではなく、メッセージ単位の変異や splice を優先してください。
- protocol が意味のある応答コードを公開する場合は、それらを**低コストな状態オラクル**として使い、より深く進行するシーケンスを優先してください。

authenticated bugs、隠れた遷移、または「handshake の後にのみ発生する」parser bugs が vanilla file-style fuzzing で見逃されやすいのも、同じ理由です。fuzzer は構造だけでなく、**順序、状態、依存関係**も維持する必要があります。<sup>[[4]](#references)</sup>

### Android Binder: マルチクライアントの driver fuzzing

高い edge coverage を達成しても、coverage では**オブジェクトの所有権、参照カウント、保留中のメッセージ、クリーンアップの順序、スレッドのインターリーブ**が把握できないため、IPC-driver bugs を見逃すことがあります。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) ページでは driver のオブジェクトモデルを説明しています。この例では fuzzer harness に焦点を当てます。Android Binder は有用なモデルです。複数のプロセスが同じ kernel object を必要な順序で操作できなければ、allocation と free の両方のパスに到達するだけでは不十分です。<sup>[[15]](#references)</sup>

#### 個別の `ioctl` バッファではなく protocol をモデル化する

テストケースは、**クライアント ID + 操作 + 構造化引数**からなる順序付き grammar として表現します。Binder LKL fuzzer は protobuf と `libprotobuf-mutator` を使用し、永続的な context-manager client 1 つと通常の client 2 つを使います。semantic harness により、盲目的な byte mutation では壊れてしまう関係性を維持します。<sup>[[15]](#references)</sup>

- 先行する操作が返した値をキャッシュします。たとえば、`BC_FREE_BUFFER` では、以前の `ioctl` が返した transaction-buffer pointer を再利用する必要があります。
- 同期 transaction が完了し、後続の操作にも到達できるよう、有効なデフォルト応答を生成します。
- self-transaction や、同一の target への複数の保留中 transaction など、成立しない遷移は拒否します。
- singleton の初期化状態は、入力ごとのリセット対象から外してください。Binder では 1 回の boot につき `BINDER_SET_CONTEXT_MGR` の登録は 1 回しか許可されないため、その client を繰り返し破棄して再作成すると、後続の入力が無効になります。

有用な lifetime-race のテンプレートでは、あるクライアントにオブジェクトを転送させ、スレッドまたはプロセスのクリーンアップを開始し、受信側のクライアントが同時に transaction buffer を解放するようにします。CVE-2020-0423 の例では、`BINDER_TYPE_WEAK_BINDER` の転送後に `BINDER_THREAD_EXIT` と `BC_FREE_BUFFER` を競合させることで、終了するスレッドのクリーンアップパスがまだ使用中の embedded `binder_work` を解放できました。<sup>[[15]](#references)</sup>

#### userspace kernel に制御されたインターリーブを再導入する

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) は実際の kernel code を userspace harness にリンクし、`lkl_syscall` を通じて syscall interface を公開します。これにより、1 つのプロセス内で protobuf の状態、coverage、KASAN を簡単に連携できます。ただし通常、LKL は別の kernel thread に中断されることなく syscall を実行します。race campaign では、選択した lock/unlock と lifetime の境界に `schedule()` ポイントを挿入し、各 yield 時に harness が次のクライアントをランダムに選べるようにします。各ポイントを追加するたびに scheduling の探索空間が増えるため、対象を絞ってください。研究者が説明した randomized scheduler は、upstream Binder fuzzer の一部ではありません。<sup>[[15]](#references)</sup>

#### シリアライズされた回帰 seed をビルドして再生する

upstream harness は、互換性のある `libprotobuf-mutator` のバージョンを固定し、`LKL_FUZZING=1` で LKL fuzzing instrumentation と KASAN を有効にし、`MMU=1` で Binder 用の `CONFIG_MMU` を有効にします。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

意図的に脆弱なリビジョンをチェックアウトするか、上流で文書化されたロールバックパッチを適用すると、シリアライズされたシードを使って、場当たり的なCの概念実証を作成して状態遷移を再構築することなく、マルチクライアントの状態遷移全体を再現できます:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

生成された KASAN use-after-free は、seed が脆弱な lifetime path に到達したことの確認として扱ってください。これは、kernel code execution や privilege escalation に必要な後続の primitive を実証するものではありません。<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** と **coverage reuse** をハイブリッド化する実用的な方法は、永続的なサーバーに対して短命の worker を再起動することです。各 worker は空の corpus から開始し、`T` 秒後に同期し、結合された corpus でさらに `T` 秒実行して再度同期し、その後終了します。これにより、蓄積された coverage を活用しながら、各 generation で**新しい構造**を生成できます。<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequential workers（ループの例）：**

<details>
<summary>Jackalope worker の再起動ループ</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Notes:**

- `-in empty` は各 generation で**新しい corpus**を強制します。
- `-server_update_interval T` は**遅延 sync**（最初は novelty を優先し、その後 reuse）を近似します。
- grammar fuzzing mode では、デフォルトで**初回の server sync はスキップされます**（`-skip_initial_server_sync` は不要）。
- 最適な `T` は**target に依存**します。worker が「簡単な」coverage の大半を見つけた後に切り替えると、最もうまくいく傾向があります。

## Harness化が難しいtarget向けのSnapshot Fuzzing

テストしたいコードに到達するまでに大きなセットアップコスト（VM の起動、ログインの完了、packet の受信、container の parse、service の初期化）がかかる場合、便利な代替手段が**snapshot fuzzing**です。準備が完了した process または VM の状態を取得し、各 test case を target の input path に注入して、crash/timeout まで実行し、snapshot を復元します。これにより初期化や protocol prefix の繰り返しを避けられ、**network service**、**firmware**、**認証後の攻撃対象領域**、**binary-only target**に有用です。<sup>[[9]](#references)[[10]](#references)</sup>

1. 対象の興味深い状態が準備できるまで実行します。
2. その時点の**memory + registers**を snapshot します。
3. 各 test case について、mutated input を該当する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. snapshot を復元します。VM target では、サポートされている場合は**dirty page**のみを復元してから繰り返します。

snapshot は、最初のコストの高い parse/dispatch 処理に可能な限り近い位置、たとえば `recv`/`read` の後や packet の deserialize 処理の時点に置き、target が使用する input buffer を記録してください。これは、処理の繰り返しを避けるために snapshot を input 処理のより深い位置へ移動するという、adaptive placement の原則に沿っています。<sup>[[11]](#references)</sup>

## MAccConcによるLinux Kernel Raceの探索

[MAccConc](https://github.com/googleprojectzero/MAccConc) は、タイミングに左右される Linux kernel race を、再現可能な memory-access schedule に変換します。2つの context による **A-B-A** 実行を自動で列挙することも、terminal UI/GUI で analyst が順序制約を指定することもできます。これは完全な concurrency fuzzer ではなく、実験的な研究用ツールです。現時点では LLVM 23 以降とプロジェクト独自の patch を適用した kernel が必要で、command-line tool が対応する test thread は2つです。また、提案されている userspace fuzzing layer は実装されていません。<sup>[[17]](#references)[[18]](#references)</sup>

### Context間の通信ポイントを収集する

KASAN outline callback と、patch 適用済み KCOV の memory-record support を有効にして、instrumented kernel を build します。プロジェクトの README では、call stack を利用可能な状態に保つため、sibling-call optimization を無効にすることも推奨しています。<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）は、計測対象のアクセスを helper calls に変換します。MAccConc の kernel patches は `asan-opt-same-temp` を無効にして、連続するアクセスがマージされないようにします。global-variable races を検出する必要がある場合は、`asan-opt-globals` の最適化も無効にします。KCOV は生成された記録を userspace に渡します。異なる実行コンテキストからのアクセスを比較し、バイト範囲が重なり、少なくとも一方が書き込みを行うペアを残します。`kfree()` は書き込みとしてモデル化し、ライフタイムの遷移も候補に含めます。<sup>[[17]](#references)</sup>

packet processing や RCU callbacks など、開始元のタスクから外れる処理では、subsystem が KCOV remote-coverage handle を伝播させる必要があります。Upstream remote KCOV は opt-in であり、任意のバックグラウンド処理で自動的に利用できるわけではありません。そのため、伝播が欠けると、実際の相互作用が検出されない可能性があります。<sup>[[17]](#references)[[19]](#references)</sup>

### 実行ごとに同じ動的アクセスを特定する

割り当てのたびに変わる可能性がある具体的なヒープアドレスや、`memcpy()` や `spin_lock()` などの helper 内では曖昧になる命令アドレスだけを使って再生しないでください。MAccConc は **count-augmented stack trace** を使用します。各フレームは、呼び出し先と呼び出し元の中での呼び出し回数を識別し、最後の要素はメモリアクセス命令を識別します。SanitizerCoverage の関数 entry/exit 記録を使って userspace がこの動的識別子を再構築するため、アドレスの変化や無関係な制御フローのノイズがあっても安定します。<sup>[[17]](#references)</sup>

### 候補ペアを強制スケジュールに変換する

パッチ適用済みの `KCOV_SET_DI` ioctl は、count-augmented access identifier を shared-flag action に関連付けます。<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 選択したアクセスの直前に flag *N* を設定します。 |
| `DI_STACK_WAIT` | 選択したアクセスの直前に、flag *N* が設定されるか、設定された上限に達するまで spin します。 |
| `DI_STACK_WAKE_POST` | 選択したアクセスの直後に flag *N* を設定します。 |

部分的な **A-happens-before-B** 制約では、A に `DI_STACK_WAKE_POST` を、B に同じ flag を使う `DI_STACK_WAIT` を設定します。2つのコンテキストのスケジュールを完全に指定する場合は、B をブロックした状態で開始し、最初の実行権移譲ポイントで A が B を起こして待機するようにします。次の実行権移譲では、B が逆の操作を行います。後者は決定的なコンテキスト切り替えのように動作し、自動 A-B-A explorer が使用する方式です。<sup>[[17]](#references)</sup>

最小限のキャンペーンでは、4つの hook（`test_setup`、2つの thread functions、`test_end`）を含むテストケースを shared library としてコンパイルし、制約なしの trace を収集してから、A-B-A 候補を列挙するか、疑わしいアクセスの周囲に手動で制約を追加します。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

タイムアウトは、成功した順序変更とは別に解釈してください。ロックや初期化／公開の依存関係によって、2つ目のコンテキストが注入ポイントに到達できず、要求した順序を実現できない場合があります。また、KASANの検出範囲の限界にも注意してください。範囲外アクセスの可能性がない限り、直接的なスタックアクセスは通常フックされません。デフォルトの最適化ではグローバル変数は対象外であり、現在のコンパイラはASANとTSANのフックを同時に出力できません。さらに、このプロトタイプではゲストがpanicするとKCOVバッファが失われるため、独立したクラッシュコンソール／オラクルを用意してください。<sup>[[17]](#references)</sup>

今後の並行性ガイド付きfuzzingでは、入力ごと、またはシステムコールごとにメモリアクセスの概要を記録し、コンテキスト間の通信ポイントを形成する操作を組み合わせてから、その組み合わせだけを探索します。VMスナップショットを使うと、グローバル状態とアドレスを安定させられます。スナップショットがない場合は、割り当て位置のメタデータを使って、実行間でオブジェクトを抽象化できます。これは提案されている拡張であり、現在のMAccConcユーザー空間ツールの機能ではありません。<sup>[[17]](#references)</sup>

## Harnessのイントロスペクション：浅いfuzzerを早期に見つける

fuzzing campaignが停滞したとき、問題はmutatorではなく、**harness**にあることがよくあります。**到達可能性／coverageのイントロスペクション**を使い、fuzz targetから静的には到達可能でも、動的にはほとんど、あるいはまったくcoverageされていない関数を見つけてください。こうした関数は通常、次の3つの問題のいずれかを示しています。<sup>[[12]](#references)</sup>

- harnessがtargetに入るタイミングが早すぎる、または遅すぎる。
- seed corpusに機能ファミリーがまるごと欠けている。
- 大きな「何でもする」harnessを1つ用意するのではなく、**2つ目のharness**が本当に必要である。

OSS-Fuzz／ClusterFuzz形式のワークフローを使う場合、Fuzz Introspectorは静的な到達可能性と実行時のcoverageを比較し、時間を区切った実行や公開corpusからレポートを生成できます。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

レポートを使って、未テストのパーサーパス用に新しいハーネスを追加するか、特定の機能のコーパスを拡張するか、モノリシックなハーネスを小さなエントリーポイントに分割するかを判断します。

## グラフ優先のファズターゲット選定とミューテーションのトリアージ

すでに**静的解析の検出結果**、**ミューテーションテストで生き残った変異**、**カバレッジレポート**がある場合、それらを独立したリストとしてトリアージしないでください。まず**コールグラフ**を作成し、ノードに**循環的複雑度**、**エントリーポイント／信頼できない入力からの到達可能性**、外部の検出結果を注釈として付けてから、グラフに関する問いを検討します。<sup>[[5]](#references)[[6]](#references)</sup>

- 信頼できない入力から到達可能な、高複雑度の関数はどれか？
- パーサー／ハンドラーからセキュリティ上重要なコードへのパス上にある、ミューテーションテストで生き残った変異はどれか？
- 異常に大きな**影響範囲**を持つ、アーキテクチャ上の要所となる関数はどれか？

こうすることで、単に「カバレッジが最も低い」ものを選ぶより、優れたファズターゲットが見つかることがよくあります。**複雑度が高く**、外部からの到達可能性が確認されたパーサー／デコーダーは、カバレッジが低くても攻撃者が制御できる経路がない、孤立した内部ヘルパーよりも、ハーネスを作成する有力候補です。

### 実践的なトリアージのワークフロー

1. コードベースから**コードグラフ**を作成し、関数ごとの複雑度／分岐メトリクスを抽出します。
2. 攻撃者が制御する入力を受け付ける**エントリーポイント**を列挙します。例：リクエストハンドラー、デコーダー、インポーター、プロトコルパーサー、CLI／ファイルリーダー。
3. エントリーポイントから候補関数への**パスクエリ**を実行し、到達可能な攻撃対象領域と、到達不能または内部限定のコードを切り分けます。
4. 次の条件が重なるノードを優先します。
   - **循環的複雑度**が高い
   - **信頼できない入力からの到達可能性**が確認されている
   - **影響範囲**が大きい、または下流の依存先が多い
   - **SARIF**の検出結果、監査メモ、ミューテーションテストで生き残った変異など、裏付けとなる証拠がある
5. スコアの高いノードから、対象を絞ったハーネスを作成します。特に、hex／Base64／IP／メッセージのデコーダーなどの**パーサー／コーデック**を優先します。

### ミューテーションテストで生き残った変異：等価変異か、対処すべきものか

ミューテーションテストでは、ノイズの多い生き残り変異のリストが生成されることがよくあります。すべての生き残り変異をセキュリティ上の問題とみなす前に、グラフを使って次の点を確認します。

- 変異させた関数は、攻撃者が制御するエントリーポイントから到達可能か？
- すべての呼び出しパスは、変異させたチェックよりも強い不変条件によって制約されているか？
- そのノードは、到達不能なコード、書式設定だけのロジック、または影響の大きい算術／パーサーパスのいずれに位置するか？

到達不能なまま、または構造上の制約を受けている生き残り変異は、多くの場合**等価変異**です。一方、**到達可能**なままで、**境界条件**、**オーバーフロー／キャリーパス**、または**セキュリティ上重要な算術処理／パース処理**に関わる変異は、次の項目に反映してください。

- 新しいファズハーネス
- 直接的なプロパティ／不変条件テスト
- 対象を絞ったエッジケースのテストベクター

### 外部の検出結果をグラフに対応付ける

SASTパイプラインが**SARIF**を出力する場合、**ファイル名＋行範囲**を使って検出結果をグラフのノードに対応付け、グラフを使って影響範囲を広げて確認します。<sup>[[6]](#references)</sup>

- 検出された関数の**影響範囲**を算出する
- 検出結果がエントリーポイントからのいずれかのパス上にあるか確認する
- 近接する検出結果を、同じ要所に集約できるか確認する

これは、特定の関数にファジングの時間を割くか判断するときに役立ちます。**到達可能**で、**複雑度が高く**、すでに**SASTの検出結果**があるノードは、攻撃経路のない、単に複雑なだけのノードより、優れたターゲットであることがよくあります。

Trailmarkを使ったワークフローの例。<sup>[[6]](#references)</sup>

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

重要な方法論は、その交差点にあります。**複雑さ x 露出度 x 影響度**です。グラフを使って、期待されるセキュリティ上の価値が最も高い fuzz 対象を選び、ミューテーションを生き残ったケースを参考に、ハーネスで重点的に検証すべき境界や不変条件を決めます。<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: より強力なエンジン、型付き入力、差分チェック

Go の対象にネイティブな `testing.F` ハーネスがすでにある場合は、[gosentry](https://github.com/trailofbits/gosentry) を使って同じハーネスを実行するのが実用的なアップグレード方法です。gosentry は、`go test -fuzz` を維持しながら、バックエンドを **LibAFL** に置き換えた Go toolchain のフォークです。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

これは、native Go fuzzerが**難しい比較**、**型付き入力**、または**parserを多用する形式**で停滞した場合に有用です。方法論は変わりません。

- seedには引き続き`f.Add(...)`を、callbackには`f.Fuzz(...)`を使用します。
- 同じharnessを再利用し、stock toolchainの代わりにgosentryの`go` binaryで実行します。
- 結果のcampaignは通常のcoverage-guided runとして扱いますが、LibAFLのスケジューリングとmutation、およびより優れた周辺detectorを利用できます。

### サイレントな失敗をfuzz findingに変える

Goのassessmentで繰り返し起きる問題は、危険な動作がデフォルトでは**crashしない**ことです。gosentryでは、「問題があるがサイレント」な状態をいくつかfindingに変えられます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`を使うと、指定したlogging/error pathをcrashのように動作させられます（通常はログを出して処理を続けるだけの、`log.Fatal`形式のcode pathに有用です）。
- `--catch-races=true`を使うと、新たに見つかったqueue entryをGo race detectorで再実行できます。
- `--catch-leaks=true`を使うと、新しいqueue entryを`goleak`で再実行し、goroutine leakがあれば停止します。
- LibAFLのhang処理により、**無限ループや非常に遅い入力**をtimeoutとして消失させず、fuzz findingとして保持できます。
- デフォルトで組み込みの算術overflowチェックを行い、さらにgo-panikint形式のinstrumentationによるtruncationチェックも任意で利用できます。

これは、security impactがmemory corruptionではなく、**panicしないparser failure**、**concurrency bug**、または**DoSのみを引き起こすhang**であるtargetで特に有用です。

### 型付きGo API向けのstruct-aware fuzzing

native Go fuzzingは主に`[]byte`、`string`、数値などのscalarを想定しています。テスト対象のcodeが型付きobjectを受け取る場合、gosentryでは内部で引き続きbyteをmutationしながら、struct、slice、array、pointerなどの**composite value**を直接fuzzできます。<sup>[[7]](#references)[[8]](#references)</sup>

```go
type Input struct {
    Data []byte
    S    string
    N    int
}

func FuzzStructInput(f *testing.F) {
    f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
    f.Fuzz(func(t *testing.T, in Input) {
        Process(in)
    })
}
```

fuzzing専用の偽のwire formatを構築すると、harness内だけで使われるパースコードの背後にロジックバグが隠れてしまいます。差分テストやgrammar-basedのキャンペーンでは、harnessの入力を単一の`[]byte`または`string`にして、代わりにcallback内でパースしてください。

### パーサーとプロトコル入力のgrammar-based fuzzing

パーサー、フォーマット、入力言語に対して、gosentryはLibAFL上で**Nautilus grammar fuzzing**を実行できます。grammarはproduction ruleのJSON配列で、harnessは通常、単一の`[]byte`または`string`引数を受け取るようにします。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- byte-level mutationsが初期の構文チェックでほとんど失敗する場合は、grammar modeを使う。
- grammarは、言語やプロトコルの仕様全体ではなく、**セキュリティに関係するサブセット**に絞る。
- terminal/nonterminalで大きな境界値を使い、整数、長さ、状態機械の境界をストレステストする。
- grammar modeでは入力の文法的な妥当性が保たれるが、ターゲットが受け取るのは**bytes/strings**である。そのため、パースやセマンティックチェックは引き続きハーネス対象のコード内で行われる。

### Differential fuzzing: クラッシュだけでなく実装を比較する

Goエコシステムで有効なパターンは、**grammar-based differential fuzzing**である。有効な構造化入力を生成し、2つのparser、client、または状態遷移エンジンに渡す。<sup>[[7]](#references)[[8]](#references)</sup>

```go
f.Fuzz(func(t *testing.T, data []byte) {
    gotA, errA := ParseA(data)
    gotB, errB := ParseB(data)
    if (errA == nil) != (errB == nil) {
        t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
    }
    _ = gotA
    _ = gotB
})
```

以下を検出結果として扱います。

- 一方の実装は panic し、もう一方は正常に拒否する
- 入力の受理／拒否に不一致がある
- parse tree またはデコードされたオブジェクトが異なる
- state transition、nonce、balance、または state root に相違がある

これは、純粋な crash fuzzing では見逃されがちな**コンセンサスの不一致**、**parser の曖昧さ**、**仕様と実装の乖離**を見つける実践的な方法です。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### coverage 報告に campaign corpus を再利用する

campaign の後、保存した queue corpus を再生すれば、別の corpus を手動でエクスポートせずに Go coverage report を生成できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

同じパッケージから、同じ `-fuzz` ターゲットを指定してコマンドを実行し、gosentry が適切なキャッシュ済みキャンペーン状態を解決できるようにしてください。



## References

- [1] [ミューテーション文法ファジング](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ファジングの詳細](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet登場から5年：カバレッジガイド型プロトコルファジングについて](https://arxiv.org/abs/2412.20324)
- [5] [Trailmarkがコードをグラフに変換](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Goのファジングにはツールキットの半分が欠けていた。ツールチェーンをフォークして修正した。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：スナップショットを用いたステートフルネットワークプロトコル向け高速グレーボックスファザー](https://arxiv.org/abs/2202.03643)
- [10] [文法がなくても問題なし：システムコール記述なしでLinuxカーネルをファジングする取り組み](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：適応型・可変型スナップショットによる効率的なファジング](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVMインストルメンテーション：パスおよび呼び出し元のカバレッジ](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [予測型コンテキスト依存ファジング](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binderファジング](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binderファザー - ビルドおよび回帰シードのドキュメント](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：メモリアクセスのインターリービングを制御してLinuxカーネルの競合状態を調査](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：ファジング向けコードカバレッジ](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO拡張ファイル名構文](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensecアドバイザリ：CFITSIO 2025年第4四半期](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO拡張ファイル名構文のファジング：16件のメモリ安全性脆弱性とCodexを活用したトリアージ](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
