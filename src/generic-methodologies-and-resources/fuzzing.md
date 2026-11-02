# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**では、入力を**文法的に有効な状態**に保ちながら変異させます。coverage-guidedモードでは、**新たなcoverage**を発生させたサンプルのみがcorpus seedとして保存されます。**言語を対象とする場合**（パーサー、インタープリター、エンジン）、ある構文の出力を別の構文の入力として使うような**意味的なデータフローチェーン**を必要とするバグを見逃す可能性があります。<sup>[[1]](#references)</sup>

**失敗パターン:** fuzzerが`document()`や`generate-id()`（または同様のプリミティブ）を個別に実行するseedを見つけても、**連鎖したデータフローを維持できない**ため、coverageを増やさない「よりバグに近い」サンプルが破棄されます。依存するステップが**3つ以上**ある場合、ランダムな再結合は高コストになり、coverage feedbackも探索の手掛かりになりません。<sup>[[1]](#references)</sup>

**示唆:** 依存関係の多い文法では、**mutational phaseとgenerative phaseを組み合わせる**か、（coverageだけでなく）**function chaining**のパターンが優先されるよう生成にバイアスをかけることを検討してください。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutationは**貪欲**です。新たなcoverageを生むサンプルはすぐに保存され、変更されていない大きな領域が残ることもよくあります。その結果、時間とともにcorpusが**構造的多様性の低いほぼ重複したサンプル**で埋まります。過度なminimizationは有用なコンテキストを取り除くことがあるため、実用的な妥協策は、**最小token数に達したら停止する**grammar-aware minimizationです（ノイズを減らしつつ、変異に適した周辺構造を十分に残します）。<sup>[[1]](#references)</sup>

mutational fuzzingで実用的なcorpusを作るには、大量のほぼ重複したサンプルよりも、**coverageを最大化する構造の異なる少数のseedを優先**します。実際には、通常次のようにします。<sup>[[1]](#references)[[3]](#references)</sup>

- **実世界のサンプル**（公開corpus、クローリングで収集したデータ、キャプチャしたトラフィック、対象エコシステムのファイルセット）から始める。
- 有効なサンプルをすべて残すのではなく、**coverageベースのcorpus minimization**で絞り込む。
- 変異の大半が無関係なbyteに費やされず、意味のあるフィールドに当たるよう、seedを**十分に小さく**保つ。
- harnessやinstrumentationを大きく変更した後は、corpus minimizationを再実行する。reachabilityが変われば、「最適な」corpusも変わるため。

## Comparison-Aware Mutation For Magic Values

fuzzerが停滞する一般的な原因は構文ではなく、**厳密な比較**です。たとえば、magic byte、長さチェック、enum文字列、checksum、`memcmp`、switchテーブル、または連続した比較でガードされたパーサーのdispatch値などです。純粋なランダム変異では、こうした値をbyte単位で推測しようとして、実行サイクルを無駄にします。

このような対象には、**comparison tracing**（たとえば、AFL++ `CMPLOG` / Redqueen形式のワークフロー）を使い、fuzzerが失敗した比較のオペランドを観察できるようにして、比較を満たす値へ変異を誘導します。<sup>[[3]](#references)</sup>

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

- ターゲットが **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** の背後に深いロジックを隠している場合に、特に有用です。
- 実際のサンプル、プロトコル仕様、デバッグログから抽出した **dictionaries** と組み合わせてください。文法トークン、チャンク名、動詞、区切り文字を含む小さな辞書は、巨大な汎用ワードリストよりも有効なことがよくあります。
- ターゲットが連続して多くのチェックを行う場合は、最初に現れる「magic」比較を先に解決し、その後、生成されたコーパスを再度最小化して、後続の段階がすでに有効なプレフィックスから開始できるようにします。

## ファイル名言語を隠し持つファイル API の Fuzzing

`filename`、`path`、`URL` という名前のパラメーターは、単なるファイル検索ではなく、インタープリターのエントリーポイントである場合があります。たとえば、CFITSIO Extended Filename Syntax (EFS) は、開いたオブジェクトを返す前に、角括弧で囲まれたセレクター、行/ピクセル式、計算列、ヒストグラム、変換を評価します。また、一部の形式では一時コピーも作成されます。攻撃対象領域をマッピングする際は、各 open/import API を **literal-path** または **interpreted-path** に分類し、アプリケーションが実際に呼び出す本番環境のエントリーポイントを fuzz してください。<sup>[[20]](#references)[[22]](#references)</sup>

その結果得られる SSRF、ファイルコピー、プロトコルハンドラーのプリミティブと、より安全な literal-path API については、[SSRF/ファイルプリミティブとしてのファイル名ミニ言語](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)を参照してください。<sup>[[20]](#references)</sup>

### バッキングオブジェクトを fuzz 対象のプログラムと分離する

文法がファイル名のサフィックスに含まれる場合、参照先ファイルのバイト列だけを変異させてもパーサーを検査できません。代わりに、小さなハーネスで各テストケースを文字列として読み込み、interpreted open API に渡すことができます。CFITSIO のキャンペーンでは、読み取り専用モードで `fits_open_file()` を呼び出すことで、EFS のほとんどのパーサーと評価器に到達しました。有効なバッキングファイルは別途用意し、ベースパスを繰り返し壊すのではなく、セレクター/式の言語に変異を集中できるようにしてください。<sup>[[22]](#references)</sup>

それぞれ異なる文法ファミリーに到達するシードを使い、仕様と lexer/parser のソースの両方からコンパクトな辞書を作成してください。同じ構文エラーの経路で入力が繰り返し失敗し、カバレッジが頭打ちになった場合は、有効なプレフィックスを保持し、ランダム変異の時間を増やすだけではなく、区切り文字、演算子、キーワード、関数名、代表的なフィールド名を追加してください。<sup>[[22]](#references)</sup>

次のように、文法辞書を使ってハーネスを実行します。<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 「read-only」ハーネスの副作用を封じ込める

ライブラリの read-only フラグがあっても、テストケースで副作用が発生しないとは限りません。ファイル名の言語仕様によって入力が書き換えられたり、出力ファイルが作成されたり、一時オブジェクトが実体化されたりすることがあります。CFITSIO のキャンペーンでは、シードファイルが当初破壊され、ファイルシステム上の予期しない場所にファイルが残されたため、クリーンアップと隔離が必要になりました。<sup>[[22]](#references)</sup>

- 各ワーカーに、使い捨ての作業ディレクトリと専用の一時ディレクトリを割り当てる。
- 正規のバックアップファイルはコピーを公開し、コーパスの唯一のコピーをターゲットに変更させない。
- リモートバックエンドがテスト対象でない限り、ネットワークアクセスを無効にし、コンテナ、マウント名前空間、または同等のサンドボックスで書き込み可能なパスを制限する。
- 実行ごと、またはワーカーバッチごとにディレクトリをリセットし、予期しないファイルシステムの変更も追加の発見事項として扱う。

### クラッシュからパッチ、ファジングへのループ

修正前にクラッシュをクラスタリングし、何千ものアーティファクトが何千ものパッチ作業にならないようにします。CFITSIO の評価では、AFLTriage により初期クラッシュ群が少数の根本原因に絞り込まれました。結果として公開されたアドバイザリには、宛先サイズのチェックミス、`realloc()` 後の古いポインター、算術エラー、安全でないパーサーのクリーンアップ処理など、異なる障害が示されています。<sup>[[21]](#references)[[22]](#references)</sup>

1. 各クラスタの代表的な入力を最小化し、AddressSanitizer の下で再現する。
2. 不変条件が破られる原因となった、正確なアクセス、ソース位置、割り当て／解放の履歴、パーサーの状態を記録する。
3. 範囲を絞った候補パッチを1つ適用し、同じカバレッジ計測とサニタイザー計測を有効にして再ビルドする。
4. 元の再現入力と、クラスタ内のすべての入力を再実行する。メモリ安全性の修正によってエラーパスでの所有権処理が壊れることがあるため、リーク検出も有効にする。
5. 実ファイルを使って機能テストを実行し、蓄積したキューから再開する（または、バイナリ変更後にエンジンで新しい出力ディレクトリが必要なら、そのキューを再インポートする）。
6. これを繰り返す。最初の浅いクラッシュを取り除くと、既存のシードがより深いパーサー状態まで進めることがよくあります。

クラッシュ入力、サニタイザーのレポート、ハーネス、関連ソースを与えれば、LLM はステップ2を効率化し、ステップ3の草案を作成できますが、そのパッチは信頼できるものではありません。修正を受け入れるかどうかは、モデルの説明ではなく、サニタイザーでの再実行と回帰テストのゲートで判断します。<sup>[[22]](#references)</sup>

## エッジカバレッジでは異なるパスを区別できない場合の、より豊富なフィードバック

通常のエッジカバレッジでは、異なる呼び出し元から同じヘルパーを通る実行や、関数内で異なる分岐の組み合わせを通る実行を区別できません。共有デコーダー、プロトコルディスパッチャー、インタープリターのヘルパーでは、エッジに至るまでの**経路**によって、現在の状態が変わるため重要です。すべての呼び出しコンテキストを単純に追跡するのも危険です。カバレッジマップとキューが爆発的に増える可能性があります。そのため、コンテキスト依存ファジングの研究では、呼び出しグラフ全体をコンテキスト依存として扱うのではなく、有望なコンテキストだけを絞り込むことが推奨されています。<sup>[[14]](#references)</sup>

最近の AFL++ ビルドでは、通常のエッジカバレッジに加えて、**関数ごとの Ball-Larus パスカバレッジ**が利用できます。関数内の各非巡回パスに特徴量を割り当てます。ループの後方エッジは取り除かれるため、このフィードバックで分岐の組み合わせは区別できますが、**ループの反復回数は区別できません**。まずは緩やかなレベル `1` から始め、パス数が指数関数的に増える可能性があるため、より厳しいモードは疑わしいパーサーや状態機械のコードに絞って適用します。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

セキュリティ上重要な多数の箇所から呼び出されるヘルパーの場合、LTOモードでは各関数パスを直近の呼び出し元と組み合わせられます:<sup>[[13]](#references)</sup>

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

- 通常の edge-coverage インスタンスも並行して実行してください。追加の queue/map コストによって1秒あたりの実行数が損なわれるなら、より豊富なフィードバックは有用ではありません。
- 大規模なテンプレート主体のライブラリや汎用ユーティリティコードが map の大半を占める場合は、`AFL_LLVM_ALLOWLIST` を使って path/caller instrumentation の対象を絞ってください。
- 非巡回パスが過剰に多い関数は AFL++ でスキップされることがあります。コンパイル時の警告は、対象に allowlisting またはより厳格でないレベルが必要であることを示しています。
- Caller + path coverage がサポートする caller depth は1段階のみです。より深い context stack と組み合わせないでください。
- Path ID は LLVM のメジャーバージョン間で変わることがあります。キャンペーン中は toolchain を固定し、ビルド間で feature ID が安定しているかのように PATH ベースの corpus を同期しないでください。
- このフィードバックは `CMPLOG` を補完します。comparison tracing が解決するのは**ガードを通過する値**であり、path/caller feedback が保持するのは、**どの経路と分岐の組み合わせで到達したか**です。

## Stateful Fuzzing: シーケンスが Seed

**プロトコル**、**認証されたワークフロー**、**複数段階のパーサー**では、興味深い単位は単一の blob ではなく、**メッセージシーケンス**であることがよくあります。トランスクリプト全体を1つのファイルに連結して無差別に変異させる方法は、通常効率的ではありません。ファザーは各ステップを均等に変異させますが、脆弱な状態に到達するのが後続メッセージだけの場合もあるためです。<sup>[[4]](#references)</sup>

より効果的な方法は、**シーケンス自体を seed として扱い**、**観測可能な状態**（レスポンスコード、プロトコル状態、パーサーのフェーズ、返されたオブジェクト型）を追加のフィードバックとして使うことです。<sup>[[4]](#references)</sup>

- **有効な先行メッセージ**は安定させ、変異は**状態遷移を引き起こす**メッセージに集中させます。
- 次のステップが以前のレスポンスに依存する場合は、識別子やサーバーが生成した値をキャッシュします。
- シリアライズされたトランスクリプト全体を不透明な blob として変異させるより、メッセージ単位での変異や splice を優先します。
- プロトコルが意味のあるレスポンスコードを公開している場合は、それを**低コストの状態オラクル**として使い、より深く進行するシーケンスを優先します。

これが、認証が必要なバグ、隠れた状態遷移、「ハンドシェイク後にのみ発生する」パーサーのバグが、通常のファイル形式の fuzzing では見逃されがちな理由です。ファザーは構造だけでなく、**順序、状態、依存関係**を維持する必要があります。<sup>[[4]](#references)</sup>

### Android Binder: マルチクライアントのドライバ fuzzing

edge coverage が高くても、coverage では**オブジェクトの所有権、参照カウント、保留中のメッセージ、クリーンアップ順序、スレッドのインターリーブ**が分からないため、IPC ドライバのバグを見逃すことがあります。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) のページではドライバのオブジェクトモデルを説明しています。この例ではファザーハーネスに焦点を当てます。Android Binder は有用なモデルです。必要な順序で複数のプロセスに同じカーネルオブジェクトを操作させられなければ、割り当てと解放の両方のパスに到達するだけでは不十分です。<sup>[[15]](#references)</sup>

#### 個々の `ioctl` バッファではなくプロトコルをモデル化する

テストケースは、**クライアント ID + 操作 + 構造化引数**からなる順序付き文法として表現します。Binder LKL fuzzer は protobuf と `libprotobuf-mutator` を使い、永続的な context-manager クライアント1つと通常のクライアント2つを用意します。意味を考慮するハーネスを使うことで、無差別なバイト変異では壊れてしまう関係を維持できます。<sup>[[15]](#references)</sup>

- 以前の操作で返された値をキャッシュします。たとえば、`BC_FREE_BUFFER` では、以前の `ioctl` が返したトランザクションバッファポインターを再利用する必要があります。
- 同期トランザクションを完了させ、後続の操作にも到達できるよう、有効なデフォルト応答を生成します。
- 自分自身へのトランザクションや、同じ対象への複数の保留中トランザクションなど、成立しない状態遷移は拒否します。
- シングルトンの初期化状態は入力ごとのリセット対象から外します。Binder では起動ごとに `BINDER_SET_CONTEXT_MGR` の登録が1回しか許可されないため、そのクライアントを繰り返し破棄して再作成すると、後続の入力が無効になります。

有用なライフタイム競合のテンプレートは、あるクライアントにオブジェクトを転送させ、スレッドまたはプロセスのクリーンアップを開始し、同時に受信側のクライアントにトランザクションバッファを解放させることです。CVE-2020-0423 の例では、`BINDER_TYPE_WEAK_BINDER` の転送後に、`BINDER_THREAD_EXIT` と `BC_FREE_BUFFER` を競合させることで、終了するスレッドのクリーンアップパスがまだ使用中の埋め込み `binder_work` を解放できました。<sup>[[15]](#references)</sup>

#### userspace kernel で制御されたインターリーブを再導入する

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) は実際のカーネルコードを userspace ハーネスにリンクし、`lkl_syscall` を通じて syscall インターフェースを公開します。これにより、protobuf の状態、coverage、KASAN を1つのプロセス内で簡単に連携できます。ただし、LKL では通常、syscall の実行中に別のカーネルスレッドが割り込むことはありません。競合キャンペーンでは、選択した lock/unlock 箇所やライフタイム境界の前後に `schedule()` ポイントを挿入し、各 yield でハーネスが次のクライアントをランダムに選ぶようにします。ポイントを1つ追加するごとにスケジューリングの探索空間が広がるため、対象を絞ってください。研究者が説明しているランダムスケジューラーは、upstream Binder fuzzer の一部ではありません。<sup>[[15]](#references)</sup>

#### シリアライズされた回帰 seed をビルドして再生する

upstream ハーネスは互換性のある `libprotobuf-mutator` のバージョンを固定し、`LKL_FUZZING=1` で LKL fuzzing instrumentation と KASAN を有効にし、`MMU=1` で Binder 用の `CONFIG_MMU` を有効にします。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

意図的に脆弱なリビジョンをチェックアウトするか、upstreamで文書化されたロールバックパッチを適用すれば、シリアライズ済みシードで、場当たり的なCの概念実証を作成して再構築することなく、マルチクライアントの状態遷移全体を再現できます:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

生成されたKASANのuse-after-freeは、seedが脆弱なライフタイム経路に到達したことの確認として扱ってください。これは、カーネルコード実行や権限昇格に必要となる後続のプリミティブを実証するものではありません。<sup>[[16]](#references)</sup>

## 単一マシンで多様性を得るテクニック（Jackalope方式）

**生成による新規性**と**カバレッジの再利用**を組み合わせる実用的な方法は、永続サーバーに対して短命のworkerを再起動することです。各workerは空のcorpusから開始し、`T`秒後に同期し、統合されたcorpusでさらに`T`秒実行して再度同期した後、終了します。これにより、蓄積されたカバレッジを活用しながら、世代ごとに**新しい構造**を生成できます。<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**順次ワーカー（ループ例）:**

<details>
<summary>Jackalope ワーカー再起動ループ</summary>

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

**メモ:**

- `-in empty` は各生成で**新しい corpus**を強制します。
- `-server_update_interval T` は**遅延同期**（まず新規入力を優先し、その後再利用）を近似します。
- grammar fuzzing モードでは、デフォルトで**初回のサーバー同期がスキップされます**（`-skip_initial_server_sync` は不要です）。
- 最適な `T` は**対象に依存**します。worker が「簡単な」coverageの大部分を見つけた後に切り替えると、うまくいく傾向があります。

## Snapshot Fuzzing：ハーネス化が難しい対象向け

テストしたいコードに到達するまでに大きなセットアップコスト（VMの起動、ログインの完了、パケットの受信、コンテナの解析、サービスの初期化など）がかかる場合、有効な代替手段は**snapshot fuzzing**です。準備が整ったプロセスまたはVMの状態を保存し、各テストケースを対象の入力経路に注入して、クラッシュまたはタイムアウトまで実行した後、スナップショットを復元します。これにより初期化やプロトコルのプレフィックスを繰り返す必要がなくなり、**ネットワークサービス**、**firmware**、**認証後の攻撃対象領域**、**バイナリのみの対象**に有効です。<sup>[[9]](#references)[[10]](#references)</sup>

1. 対象を、調査対象の状態が整うまで実行します。
2. その時点の**メモリ + レジスタ**をスナップショットに保存します。
3. 各テストケースについて、変異させた入力を関連するゲストまたはプロセスのバッファに直接書き込みます。
4. クラッシュ、タイムアウト、またはリセットまで実行します。
5. スナップショットを復元します。VMを対象とする場合は、サポートされていれば**dirty page**のみを復元してから繰り返します。

スナップショットは、`recv`/`read` の後やパケットのデシリアライズ時点など、最初のコストの高い解析またはディスパッチ処理にできるだけ近い位置に設定し、対象が使用する入力バッファを記録してください。これは、処理を繰り返さずに済むよう、入力処理のさらに奥へスナップショット位置を移動させる適応的配置の原則に従っています。<sup>[[11]](#references)</sup>

## MAccConc による Linux Kernel の Race 探索

[MAccConc](https://github.com/googleprojectzero/MAccConc) は、タイミングに左右される Linux kernel の race を、再現可能なメモリアクセススケジュールに変換します。2つのコンテキストによる **A-B-A** 実行を自動で列挙できるほか、アナリストが terminal UI/GUI で順序制約を設定することもできます。これは完全な concurrency fuzzer ではなく、実験的な研究ツールです。現時点では LLVM 23 以降とプロジェクトがパッチを適用した kernel が必要で、コマンドラインツールがサポートするテストスレッドは2つです。また、提案されている userspace fuzzing 層は実装されていません。<sup>[[17]](#references)[[18]](#references)</sup>

### コンテキスト間の通信ポイントを収集する

KASAN outline callbacks と、パッチ適用済みの KCOV memory-record サポートを使って、計測対象の kernel をビルドします。プロジェクトの README では、call stackを利用できる状態に保つため、sibling-call optimization を無効にすることも推奨しています。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）は、計測対象のアクセスをヘルパー呼び出しに変換します。MAccConc の kernel patches は `asan-opt-same-temp` を無効にして連続するアクセスが統合されないようにします。グローバル変数の race も検出する必要がある場合は、`asan-opt-globals` 最適化も無効にします。KCOV は生成された記録を userspace に渡します。異なる実行コンテキストからのアクセスを比較し、バイト範囲が重なり、少なくとも一方が書き込みを行うペアを保持します。ライフタイムの遷移も候補になるよう、`kfree()` は書き込みとしてモデル化します。<sup>[[17]](#references)</sup>

処理が開始元の task から外れる場合（パケット処理や RCU callback など）、サブシステムは KCOV remote-coverage handle を伝播させる必要があります。upstream の remote KCOV は opt-in であり、任意のバックグラウンド処理で自動的に利用できるわけではありません。そのため、伝播が欠けると実際の相互作用が見えなくなることがあります。<sup>[[17]](#references)[[19]](#references)</sup>

### 実行ごとに同じ動的アクセスを識別する

各割り当ての後に変わる可能性がある具体的な heap address に対して再生したり、`memcpy()` や `spin_lock()` などの helper 内では曖昧になる instruction address だけを使ったりしてはいけません。MAccConc は **count-augmented stack trace** を使用します。各 frame は callee と、その caller 内での呼び出し回数を識別し、最後の要素は memory-access instruction を識別します。SanitizerCoverage の function-entry/exit 記録を使うと、userspace でこの動的識別子を再構築できます。この識別子は、address の変化や無関係な制御フローのノイズがあっても安定しています。<sup>[[17]](#references)</sup>

### 候補ペアを強制スケジュールに変換する

パッチ適用済みの `KCOV_SET_DI` ioctl は、count-augmented access identifier を shared-flag action に関連付けます。<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 選択したアクセスの直前に flag *N* を設定します。 |
| `DI_STACK_WAIT` | 選択したアクセスの前に、flag *N* が設定されるか、設定済みの上限時間が経過するまで spin します。 |
| `DI_STACK_WAKE_POST` | 選択したアクセスの直後に flag *N* を設定します。 |

部分的な **A が B に happens-before する**制約では、同じ flag を使って A に `DI_STACK_WAKE_POST` を、B に `DI_STACK_WAIT` を設定します。完全に指定した 2-context schedule では、B をブロック状態で開始し、最初の transfer point で A が B を wake して wait するようにします。次の transfer point では、B が逆の操作を行います。後者は決定的な context switching のように動作し、自動 A-B-A explorer が使用する方式です。<sup>[[17]](#references)</sup>

最小限の campaign では、4 つの hook（`test_setup`、2 つの thread function、`test_end`）を含むテストケースを shared library としてコンパイルし、制約なしの trace を収集した後、A-B-A 候補を列挙するか、疑わしいアクセスの周辺に手動で制約を追加します。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

タイムアウトと、順序の入れ替えに成功したケースは分けて解釈してください。ロックや初期化／公開の依存関係により、2つ目のコンテキストが注入ポイントに到達できず、要求した順序を実現できない場合があります。また、KASANの検出対象外にも注意してください。直接のスタックアクセスは、範囲外アクセスのおそれがない限り通常フックされず、デフォルトの最適化ではグローバル変数は対象外です。また、現在のコンパイラではASANとTSANのフックを同時に生成できません。さらに、このプロトタイプではゲストがパニックを起こすとKCOVバッファが失われるため、独立したクラッシュコンソール／オラクルを用意してください。<sup>[[17]](#references)</sup>

今後の並行性ガイド付きファジングでは、入力またはシステムコールごとのメモリアクセス要約を記録し、コンテキスト間の通信ポイントとなる操作の組み合わせを特定して、その組み合わせだけを探索します。VMスナップショットを使うと、グローバル状態とアドレスを安定させられます。スナップショットを使わない場合は、割り当てサイトのメタデータによって、実行間でオブジェクトを抽象化できます。これは提案されている拡張であり、現在のMAccConcユーザースペースツールの機能ではありません。<sup>[[17]](#references)</sup>

## ハーネスのイントロスペクション: 浅いファザーを早期に見つける

ファジングキャンペーンが停滞したとき、問題はミューテーターではなく、**ハーネス**にあることがよくあります。**到達可能性／カバレッジのイントロスペクション**を使い、ファズターゲットから静的には到達可能でも、動的にはほとんど、あるいはまったくカバーされない関数を見つけてください。そうした関数は、通常、次の3つの問題のいずれかを示しています。<sup>[[12]](#references)</sup>

- ハーネスがターゲットに入るのが早すぎる、または遅すぎる。
- シードコーパスに機能群が丸ごと欠けている。
- 「何でもこなす」巨大なハーネス1つではなく、**2つ目のハーネス**が本当に必要である。

OSS-Fuzz / ClusterFuzz形式のワークフローを使っている場合、Fuzz Introspectorは静的な到達可能性と実行時カバレッジを比較し、一定時間の実行や公開コーパスからレポートを生成できます。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

レポートを使って、未テストの parser path 用に新しい harness を追加するか、特定の機能の corpus を拡充するか、モノリシックな harness を小さな entry point に分割するかを判断します。

## グラフを起点とする fuzz target の選定と mutation のトリアージ

すでに **static-analysis findings**、**mutation-testing survivors**、**coverage reports** がある場合、それらを独立したリストとしてトリアージしないでください。まず **call graph** を作成し、ノードに **cyclomatic complexity**、**entrypoint／untrusted-input からの到達可能性**、外部の findings を注釈として付けてから、グラフに関する問いを検討します。<sup>[[5]](#references)[[6]](#references)</sup>

- **untrusted input** から到達可能な、高い複雑度を持つ関数はどれか？
- parser／handler からセキュリティ上重要なコードへの経路上にある mutation survivor はどれか？
- 異常に大きな **blast radius** を持つ、アーキテクチャ上のボトルネックとなる関数はどれか？

これにより、単に「coverage が最も低い箇所」を選ぶより、優れた fuzz target が見つかることがよくあります。**複雑度が高く**、外部から到達可能であることが確認された parser／decoder は、coverage が低くても攻撃者が制御できる経路がない、孤立した内部 helper よりも強力な harness 候補です。

### 実践的なトリアージのワークフロー

1. codebase から **code graph** を作成し、関数ごとの複雑度／branch metrics を抽出します。
2. 攻撃者が制御する入力を受け取る **entrypoint** を列挙します。例：request handler、decoder、importer、protocol parser、CLI／file reader。
3. それらの entrypoint から候補関数への **path query** を実行し、到達可能な attack surface と、到達不能または内部のみで使われるコードを区別します。
4. 以下の要素を組み合わせて持つノードを優先します。
   - 高い **cyclomatic complexity**
   - **untrusted input からの到達可能性**が確認されている
   - 大きな **blast radius**、または多数の下流依存関係
   - **SARIF** findings、audit notes、mutation survivor などの裏付けとなる証拠
5. スコアの高いノードから順に、対象を絞った harness を作成します。特に、hex／Base64／IP／message decoder などの **parser／codec** を優先します。

### Mutation survivor：equivalent と対処すべきもの

Mutation testing では、ノイズの多い survivor list が生成されることがよくあります。すべての survivor をセキュリティ上の問題とみなす前に、グラフを使って次の点を確認します。

- 変異した関数は、攻撃者が制御する entrypoint から到達可能か？
- すべての call path は、変異した check より強い invariant によって制約されているか？
- そのノードは dead code、formatting のみを担うロジック、または影響の大きい arithmetic／parser path のいずれに位置しているか？

到達不能なままか、構造的に制約されている survivor は、多くの場合 **equivalent mutant** です。**到達可能**なままで、**境界条件**、**overflow／carry path**、または**セキュリティ上重要な arithmetic／parsing** に関わる survivor は、以下に追加する必要があります。

- 新しい fuzz harness
- 直接的な property／invariant test
- 対象を絞った edge-case vector

### 外部 findings をグラフに紐付ける

SAST pipeline が **SARIF** を出力する場合、**file + line range** を使って findings をグラフのノードに紐付け、グラフを使って影響範囲を広げて確認します。<sup>[[6]](#references)</sup>

- 該当関数の **blast radius** を算出する
- finding が entrypoint からのいずれかの path 上にあるか確認する
- 同じボトルネックに集約される近接した findings をクラスタ化する

これは、特定の関数に fuzzing の時間を割くか判断する際に役立ちます。**到達可能**で、**複雑**であり、すでに **SAST hits** があるノードは、攻撃経路がない単に複雑なノードより、優れたターゲットであることがよくあります。

Trailmark を使ったワークフローの例。<sup>[[6]](#references)</sup>

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

重要な方法論は、**複雑さ x 露出度 x 影響度**の交差です。グラフを使って、期待されるセキュリティ価値が最も高いファジング対象を選び、その後、ミューテーションを生き残った入力を参考に、ハーネスで重点的に検証すべき境界と不変条件を判断します。<sup>[[5]](#references)</sup>

## 暗号鍵エンコーディングの差分ファジング

有効なシリアライズ済み鍵または標準テストベクトルから始めます。インポートや操作の経路に到達するために必要な長さと構造を保ちながら、エンコードされたフィールドをミューテーションし、同じバイト列を独立した実装に送信します。受理結果とエラーを比較します。ランダム化される署名や暗号文には、バイト単位の比較ではなく、正当性オラクルが必要です。署名を検証するか、カプセル化／デカプセル化の往復処理で共有秘密を比較してください。テストベクトルは既知のケースに対する適合性を確認し、差分ミューテーションはそれを超える不正なエンコーディングを調査します。<sup>[[23]](#references)[[26]](#references)</sup>

これらの鍵形式には、形式固有のオラクルを使用します。<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** 鍵をパース可能な状態に保ちながら、パックされた `s1` または `s2` の係数を `[-η, η]` の範囲外に変更します。インポートまたは署名が拒否されるか、生成された署名が検証に通るかを確認します。FIPS 204 は追加の秘密鍵チェックを義務付けていないため、受理結果の違いだけでは標準違反とはなりません。[conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)を参照してください。
- **ML-KEM key pairs:** 必須のカプセル化鍵チェックおよびデカプセル化入力チェックと、インポートした鍵ペアに対する任意のペアワイズ整合性チェック（PCT）を区別します。公開鍵でカプセル化し、秘密鍵でデカプセル化して、共有秘密を比較します。個々の鍵が入力チェックを通過していても、不一致があれば暗号化通信が破綻する可能性があります。API が操作中に入力を検証するのか、別の呼び出しで検証するのかを確認してください。libcrux の `validate_public_key(pk)` と `validate_private_key(sk, ct)` は、PCT の代わりにはなりません。
- **XMSS/XMSSMT raw keys:** メモリ上の鍵を使った操作だけでなく、パラメータセットをまたいだシリアライズ済み**署名鍵と検証鍵**のラウンドトリップをテストします。XMSS と XMSSMT は別々の4バイト OID 名前空間を持つため、XMSS を先に試す OID のみを使ったパーサーは、OID が衝突する XMSSMT 鍵を誤分類してインポートを拒否する可能性があります。報告された RustCrypto のパーサーは、署名偽造ではなく、相互運用性／可用性の障害を示しています。

## gosentry による Go ファジング: より強力なエンジン、型付き入力、差分チェック

Go のターゲットにネイティブな `testing.F` ハーネスがすでにある場合、実用的なアップグレード方法は、[gosentry](https://github.com/trailofbits/gosentry) を使って同じハーネスを実行することです。これは `go test -fuzz` を維持しながら、バックエンドを **LibAFL** に置き換えるフォーク版の Go ツールチェーンです。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

これは、ネイティブの Go fuzzer が**比較の難しい条件**、**型付き入力**、または**パーサー中心のフォーマット**で停滞した場合に有効です。手法は同じです。

- シードには引き続き `f.Add(...)` を、コールバックには `f.Fuzz(...)` を使います。
- 同じ harness を再利用し、標準の toolchain ではなく gosentry の `go` バイナリで実行します。
- その実行を通常の coverage-guided ファジングとして扱います。ただし、LibAFL のスケジューリング／ミューテーションと、より優れた周辺 detector を利用します。

### サイレントな失敗をファジング検出結果に変える

Go のセキュリティ評価で繰り返し問題となるのは、危険な動作がデフォルトでは**クラッシュしない**ことです。gosentry を使うと、「問題はあるがサイレント」な状態をいくつか検出結果として扱えます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` を指定すると、選択した logging/error の経路をクラッシュのように動作させられます（通常はログを出して処理を続けるだけの `log.Fatal` 形式のコードパスで有効です）。
- `--catch-races=true` を指定すると、新たに見つかった queue のエントリーを Go の race detector で再実行します。
- `--catch-leaks=true` を指定すると、新しい queue のエントリーを `goleak` で再実行し、goroutine の leak があれば停止します。
- LibAFL の hang 処理により、**無限ループ／非常に遅い入力**を timeout として消失させず、ファジング検出結果として保持します。
- 算術オーバーフローのチェックはデフォルトで組み込まれており、go-panikint 形式の instrumentation を使った切り捨てチェックも任意で有効にできます。

これは、セキュリティ上の影響がメモリー破壊ではなく、**panic を起こさないパーサーの失敗**、**並行処理のバグ**、または**DoS のみを引き起こす hang**であるターゲットで、特に有効です。

### 型付き Go API のための構造体対応ファジング

ネイティブの Go ファジングが主に想定しているのは、`[]byte`、`string`、数値などのスカラー値です。テスト対象のコードが型付きオブジェクトを受け取る場合、gosentry では、内部のバイト列をミューテーションしながら、複合値（struct、slice、array、pointer）を直接ファジングできます。<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing専用の偽のwire formatを作ると、harness内だけで行うパース処理の背後にロジックバグが隠れてしまう場合に使用してください。differentialまたはgrammar-basedのcampaignでは、harnessの入力を単一の`[]byte`または`string`にして、代わりにcallback内でパースしてください。

### パーサーとプロトコル入力のgrammar-based fuzzing

パーサー、フォーマット、入力言語には、gosentryを使ってLibAFL上で**Nautilus grammar fuzzing**を実行できます。grammarはproduction ruleのJSON配列で、通常、harnessは単一の`[]byte`または`string`引数を受け取ります。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- byte-level mutation の大半が初期の構文チェックで失敗する場合は、grammar mode を使う。
- grammar は、言語/プロトコルの仕様全体をモデル化するのではなく、**セキュリティに関係するサブセット**に絞る。
- 端子/非終端記号で大きな境界値を使い、整数、長さ、状態機械の境界を刺激する。
- grammar mode では入力の文法的な妥当性が保たれるが、ターゲットが受け取るのは引き続き **bytes/strings** である。そのため、パース処理とセマンティックチェックはハーネス化されたコード内に残る。

### Differential fuzzing: クラッシュだけでなく実装を比較する

Go エコシステムで有効なパターンは、**grammar-based differential fuzzing** である。妥当な構造化入力を生成し、それを2つのパーサー、クライアント、または状態遷移エンジンに与える。<sup>[[7]](#references)[[8]](#references)</sup>

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

次のようなケースを検出対象とします。

- 一方の実装はpanicするが、もう一方は正常に拒否する
- 入力の受理／拒否が一致しない
- parse treeやデコードされたオブジェクトが異なる
- state transition、nonce、balance、state rootに差異がある

これは、純粋なクラッシュ fuzzingでは見逃しやすい**コンセンサスの不一致**、**parserの曖昧さ**、**仕様と実装の乖離**を見つける実践的な方法です。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### coverageレポートの生成にcampaign corpusを再利用する

campaign後に保存されたqueue corpusを再生すれば、corpusを別途手動でエクスポートすることなく、Goのcoverageレポートを生成できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

同じ package から、同じ `-fuzz` target を指定してコマンドを実行し、gosentry が正しいキャッシュ済み campaign state を解決できるようにします。

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: スナップショットを用いたステートフルネットワークプロトコル向け高速 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar がなくても問題なし: System Call の記述なしで Linux Kernel を Fuzzing する方法に向けて](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive and Mutable Snapshots による効率的な Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path と caller の coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build と regression-seed のドキュメント](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: 制御された Memory-Access Interleavings による Linux Kernel Race Condition の調査](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Fuzzing のための code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Extended Filename Syntax](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO Extended Filename Syntax の Fuzzing: 16 件の Memory-Safety Vulnerability と Codex を活用したトリアージ](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [暗号技術の Differential Fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID parsing bug - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Post-Quantum Cryptography 実装の現状](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
