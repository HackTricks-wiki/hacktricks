# Fuzzingの方法論

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: カバレッジと意味論

**mutational grammar fuzzing**では、入力を**文法的に有効**な状態に保ちながら変異させます。カバレッジガイドモードでは、**新しいカバレッジ**を生み出したサンプルだけがコーパスのシードとして保存されます。**言語を対象とするターゲット**（パーサー、インタープリター、エンジン）では、ある構造の出力が別の構造の入力になるような、**意味論的なデータフローの連鎖**を必要とするバグを見逃すことがあります。<sup>[[1]](#references)</sup>

**失敗パターン:** fuzzerが`document()`や`generate-id()`（または類似のプリミティブ）を個別に実行するシードを見つけても、**連鎖したデータフローを維持できない**ため、「バグにより近い」サンプルがカバレッジを増やさず破棄されることがあります。依存するステップが**3つ以上**になると、ランダムな再結合にはコストがかかり、カバレッジフィードバックも探索の指針になりません。<sup>[[1]](#references)</sup>

**示唆:** 依存関係の多い文法では、**mutational phaseとgenerative phaseを組み合わせる**か、カバレッジだけでなく**関数連鎖**のパターンが優先されるよう生成を調整することを検討してください。<sup>[[1]](#references)</sup>

## コーパスの多様性に関する落とし穴

カバレッジガイド型の変異は**貪欲**です。新しいカバレッジを生むサンプルはすぐに保存され、変更されていない大きな領域がそのまま残ることがよくあります。時間が経つと、コーパスは構造的な多様性の低い**ほぼ重複したサンプル**で埋まります。過度な最小化は有用なコンテキストを取り除く可能性があるため、実用的な妥協案は、**最小トークン数に達したら停止する****文法を考慮した最小化**です（ノイズを減らしつつ、変異しやすい状態を保てるだけの周辺構造を残します）。<sup>[[1]](#references)</sup>

mutational fuzzingで実用的なコーパスを作る際のルールは、ほぼ重複した大量のサンプルよりも、**カバレッジを最大化する、構造の異なる少数のシードを優先する**ことです。通常、具体的には次のようにします。<sup>[[1]](#references)[[3]](#references)</sup>

- **実世界のサンプル**（公開コーパス、クローリングで収集したデータ、キャプチャしたトラフィック、対象エコシステムのファイルセット）から始めます。
- 有効なサンプルをすべて残すのではなく、**カバレッジに基づくコーパス最小化**で絞り込みます。
- 変異が無関係なバイトに大半のサイクルを費やさず、意味のあるフィールドに適用されるよう、シードを**十分に小さく**保ちます。
- ハーネスや計装を大きく変更した後は、コーパスの最小化を再実行します。到達可能性が変われば、「最適な」コーパスも変わるためです。

## 大きな生成プログラムとタイムアウトの偏り

コンパイラーやインタープリターのfuzzingでは、入力が新しいパーサーブランチではなく、**生成コードのサイズしきい値**を超える必要がある場合があります。V8の[exception-handler offsetの例](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size)では、切り詰められたハンドラーオフセットが問題になる前に、テストケースのバイトコードサイズが256 MiBを超える必要がありました。`yield*`構文を繰り返せばその境界に達しますが、debug buildではテストケースのコンパイルに数秒かかりました。入力を小さく保つ設定や短い実行タイムアウトは、文法カバレッジが高くても、この種のケースを不利にすることがあります。パックされたオフセットや、長さに依存するその他のメタデータを監査する場合は、サイズしきい値とタイムアウトのポリシーを分けて検討してください。このキャンペーンに関する助言は、報告された失敗パターンからの推論です。<sup>[[29]](#references)</sup>

## マジック値に対する比較を考慮した変異

fuzzerが停滞する一般的な理由は構文ではなく、**厳密な比較**です。たとえば、マジックバイト、長さチェック、enum文字列、チェックサム、`memcmp`やswitchテーブル、連続した比較によって判定されるパーサーのディスパッチ値などです。純粋なランダム変異では、これらの値をバイト単位で推測しようとしてサイクルを浪費します。

このようなターゲットには、**比較トレース**（たとえばAFL++の`CMPLOG`やRedqueen形式のワークフロー）を使い、fuzzerが失敗した比較のオペランドを観測し、それを満たす値に向けて変異を誘導できるようにします。<sup>[[3]](#references)</sup>

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

- これは、ターゲットが **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** の背後に深いロジックを隠している場合に特に有効です。
- 実際のサンプル、プロトコル仕様、またはデバッグログから抽出した **dictionaries** と組み合わせてください。文法トークン、チャンク名、verb、区切り文字を含む小さな辞書のほうが、汎用の巨大なワードリストより役立つことがよくあります。
- ターゲットが多数の逐次チェックを行う場合は、最初の「magic」比較をまず解決し、その後、後続のステージがすでに有効なプレフィックスから始まるよう、生成されたコーパスを再度最小化してください。

## ファイル名言語を隠しているファイル API の Fuzzing

`filename`、`path`、または `URL` という名前のパラメーターは、単なるファイル検索ではなく、インタープリターのエントリーポイントである可能性があります。たとえば、CFITSIO Extended Filename Syntax (EFS) は、開いたオブジェクトを返す前に、角括弧で囲まれたセレクター、行/ピクセル式、計算列、ヒストグラム、変換を評価します。また、一部の形式では一時コピーも作成されます。攻撃対象領域をマッピングする際は、各 open/import API を **literal-path** または **interpreted-path** に分類し、アプリケーションが実際に呼び出す本番のエントリーポイントを fuzz してください。<sup>[[20]](#references)[[22]](#references)</sup>

結果として得られる SSRF、ファイルコピー、プロトコルハンドラーのプリミティブと、より安全な literal-path API については、[Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs) を参照してください。<sup>[[20]](#references)</sup>

### バックエンドのオブジェクトを fuzz 対象のプログラムから分離する

文法がファイル名のサフィックスに含まれている場合、参照先のファイルのバイト列だけを変更しても、パーサーを検査できません。代わりに、小さなハーネスで各テストケースを文字列として読み込み、interpreted open API に渡せます。CFITSIO のキャンペーンでは、読み取り専用モードで `fits_open_file()` を呼び出すことで、EFS のパーサーと評価器の大半に到達しました。ベースとなるパスを繰り返し壊すのではなく、セレクター/式の言語に変更を集中できるよう、有効なバックエンドファイルを別途用意しておきましょう。<sup>[[22]](#references)</sup>

それぞれ異なる文法ファミリーに到達するシードを使い、仕様と lexer/parser のソースの両方からコンパクトな辞書を作成してください。同じ構文エラーの経路で入力が繰り返し失敗して coverage が頭打ちになった場合は、ランダム変異の時間を増やすだけでなく、有効なプレフィックスを維持し、区切り文字、演算子、キーワード、関数名、代表的なフィールド名を追加してください。<sup>[[22]](#references)</sup>

たとえば、文法辞書を使ってハーネスを実行します:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 「read-only」ハーネスの副作用を抑える

ライブラリの read-only フラグがあっても、テストケースに副作用がないとは限りません。ファイル名の言語仕様によって入力が書き換えられたり、出力ファイルが作成されたり、一時オブジェクトが実体化されたりする可能性があります。CFITSIO のキャンペーンでは、初期状態でシードファイルが破壊され、ファイルシステム上の予期しない場所にファイルが残ったため、クリーンアップと分離が必要になりました。<sup>[[22]](#references)</sup>

- 各 worker に使い捨ての作業ディレクトリと専用の一時ディレクトリを割り当てる。
- 正規のバックアップファイルはコピーを公開し、ターゲットがコーパス唯一のコピーを変更できないようにする。
- リモートバックエンドが対象の場合を除き、ネットワークアクセスを無効にする。また、コンテナ、マウント名前空間、または同等のサンドボックスで書き込み可能なパスを制限する。
- 各実行後または worker バッチ後にディレクトリを初期化し、予期しないファイルシステムの変更も追加の発見事項として扱う。

### クラッシュからパッチ、そして fuzz へ

修正前にクラッシュをクラスタ化し、何千ものアーティファクトが何千ものパッチ作業になるのを防ぎます。CFITSIO の評価では、AFLTriage により初期クラッシュ群を少数の根本原因に絞り込めました。結果のアドバイザリでは、宛先サイズのチェックミス、`realloc()` 後の古いポインター、算術エラー、安全でないパーサーのクリーンアップ処理など、個別の障害が示されています。<sup>[[21]](#references)[[22]](#references)</sup>

1. 各クラスタから代表的な入力を最小化し、AddressSanitizer で再現する。
2. 不変条件が崩れた原因となった正確なアクセス、ソース位置、確保／解放の履歴、パーサーの状態を記録する。
3. 範囲を限定した候補パッチを1つ適用し、同じカバレッジ計測と sanitizer 計測を有効にして再ビルドする。
4. 元の再現入力と**そのクラスタ内のすべての入力**を再生する。また、メモリ安全性の修正によってエラーパスの所有権処理が壊れる可能性があるため、leak detection も有効にする。
5. 実ファイルを使って機能テストを実行し、その後、蓄積したキューから再開する（または、バイナリ変更後にエンジンが新しい出力ディレクトリを必要とする場合は、そのキューを再インポートする）。
6. 繰り返す。最初の浅いクラッシュを取り除くと、既存のシードがより深いパーサー状態まで進めることがよくあります。

LLM にクラッシュ入力、sanitizer レポート、ハーネス、関連ソースを与えれば、ステップ2を効率化し、ステップ3の案を作成できます。ただし、そのパッチは信頼できないものとして扱います。修正を受け入れるかどうかは、モデルの説明ではなく、sanitizer による再生と回帰テストのゲートで判断します。<sup>[[22]](#references)</sup>

## Edge Coverage では異なる経路を区別できない場合の、より豊富なフィードバック

通常の edge coverage では、同じヘルパーを異なる呼び出し元から通る実行や、関数内で異なる分岐の組み合わせをたどる実行を区別できません。共有デコーダー、プロトコルディスパッチャー、インタープリターヘルパーでは、エッジに至る**経路**によって生存状態が決まるため、これは重要です。一方で、すべての呼び出しコンテキストを単純に追跡するのも危険です。カバレッジマップやキューが爆発的に増える可能性があります。そのため、コンテキスト依存 fuzzing の研究では、コールグラフ全体をコンテキスト依存として扱うのではなく、有望なコンテキストだけを段階的に絞り込むことが推奨されています。<sup>[[14]](#references)</sup>

最近の AFL++ ビルドでは、通常の edge coverage に加えて、**関数ごとの Ball-Larus パスカバレッジ**が利用できます。関数内の非巡回パスごとに特徴を割り当てます。ループの back-edge は取り除かれるため、このフィードバックで区別できるのは分岐の組み合わせであり、**ループの反復回数ではありません**。まずは緩やかなレベル `1` から始め、パス数が指数関数的に増える可能性があるため、より厳しいモードは疑わしいパーサーやステートマシンのコードに限定して使います。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

多くのセキュリティ上重要な箇所から呼び出されるヘルパーでは、LTO mode によって各関数のパスを直近の呼び出し元と組み合わせられます。<sup>[[13]](#references)</sup>

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

- 通常の edge-coverage インスタンスを並行して実行してください。追加の queue/map コストによって実行速度（1 秒あたりの実行回数）が損なわれない場合に限り、より豊富なフィードバックが有用です。
- 大規模なテンプレート依存ライブラリや汎用ユーティリティコードが map の大部分を占める場合は、`AFL_LLVM_ALLOWLIST` を使って path/caller instrumentation の対象を絞り込んでください。
- 非循環パスが過剰な関数は AFL++ でスキップされることがあります。コンパイル時の警告は、allowlisting または制限の緩いレベルが必要であることを示しています。
- Caller + path coverage がサポートする caller の深さは 1 つだけです。より深い context stack と併用しないでください。
- Path ID は LLVM のメジャーバージョン間で変わることがあります。キャンペーン中は toolchain を固定し、ビルド間で feature ID が安定しているかのように PATH ベースの corpus を同期しないでください。
- このフィードバックは `CMPLOG` を補完します。比較トレースが **guard を通過する値**を解決する一方、path/caller feedback は **どの経路と分岐の組み合わせが到達したか**を保持します。

## Stateful Fuzzing: シーケンスを Seed として扱う

**protocols**、**authenticated workflows**、**multi-stage parsers** では、興味深い単位は単一の blob ではなく、**message sequence** であることがよくあります。transcript 全体を 1 つのファイルに連結してやみくもに mutate する方法は、通常は効率的ではありません。脆弱な状態に到達するのが後続のメッセージだけでも、fuzzer は各ステップを同じように mutate するためです。<sup>[[4]](#references)</sup>

より効果的な方法は、**シーケンス自体を seed** として扱い、**観測可能な状態**（response code、protocol state、parser phase、返された object type）を追加のフィードバックとして利用することです。<sup>[[4]](#references)</sup>

- **有効な prefix message** は安定した状態に保ち、**遷移を引き起こす**メッセージを重点的に mutate します。
- 次のステップが以前のレスポンスに依存する場合は、識別子とサーバー生成値をキャッシュします。
- シリアライズ済み transcript 全体を不透明な blob として mutate するより、メッセージ単位での mutation/splicing を優先します。
- protocol が意味のある response code を公開する場合は、それを**低コストな状態オラクル**として使い、より深く進行するシーケンスを優先します。

これが、認証が必要なバグ、隠れた遷移、「handshake 後にのみ発生する」parser バグなどが通常のファイル形式の fuzzing では見逃されがちな理由です。fuzzer は構造だけでなく、**順序、状態、依存関係**も維持する必要があります。<sup>[[4]](#references)</sup>

### Android Binder: 複数クライアントの driver fuzzing

高い edge coverage でも IPC driver のバグを見逃すことがあります。coverage は**オブジェクトの所有権、参照カウント、保留中メッセージ、クリーンアップ順序、スレッドのインターリーブ**を表さないためです。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) のページでは driver のオブジェクトモデルを解説しています。この例では fuzzer の harness に焦点を当てます。Android Binder は参考になるモデルです。割り当てパスと解放パスの両方に到達できても、必要な順序で複数のプロセスに同じ kernel object を操作させられなければ十分ではありません。<sup>[[15]](#references)</sup>

#### 個別の `ioctl` buffer ではなく protocol をモデル化する

テストケースは、**クライアント識別情報 + 操作 + 構造化引数**からなる順序付きの文法として表現します。Binder LKL fuzzer は protobuf と `libprotobuf-mutator` を使い、1 つの永続的な context-manager client と 2 つの通常の client を用います。semantic harness によって、バイト列の盲目的な mutation では壊れてしまう関係性を維持します。<sup>[[15]](#references)</sup>

- 以前の操作で返された値をキャッシュします。たとえば `BC_FREE_BUFFER` では、以前の `ioctl` が返した transaction-buffer pointer を再利用する必要があります。
- 同期 transaction が完了し、後続の操作にも到達できるよう、有効なデフォルト reply を生成します。
- 自分自身への transaction や、同じ target に対する複数の保留中 transaction など、成立しない遷移は拒否します。
- singleton の bootstrap state は、入力ごとの reset の対象外にします。Binder では 1 回の boot につき `BINDER_SET_CONTEXT_MGR` の登録は 1 つだけ許可されるため、その client を繰り返し破棄して作り直すと、後続の入力が無効になります。

有効な lifetime race のテンプレートとして、ある client にオブジェクトを転送させ、thread または process の cleanup を開始し、同時に受信側 client に transaction buffer を解放させる方法があります。CVE-2020-0423 の例では、`BINDER_TYPE_WEAK_BINDER` の転送後、`BINDER_THREAD_EXIT` と `BC_FREE_BUFFER` が競合すると、終了中の thread の cleanup path が使用中の埋め込み `binder_work` が解放される可能性がありました。<sup>[[15]](#references)</sup>

#### userspace kernel で制御されたインターリーブを再導入する

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) は実際の kernel code を userspace harness にリンクし、`lkl_syscall` を通じて syscall interface を公開します。これにより、protobuf state、coverage、KASAN を 1 つの process 内で簡単に連携できます。ただし LKL では通常、syscall の実行中に別の kernel thread が割り込むことはありません。race campaign では、選択した lock/unlock および lifetime 境界の周辺に `schedule()` のポイントを挿入し、各 yield で harness が次の client をランダムに選ぶようにします。各ポイントはスケジューリングの探索空間を拡大するため、対象を絞ってください。研究者が説明したランダムスケジューラは、upstream Binder fuzzer の一部では**ありません**。<sup>[[15]](#references)</sup>

#### シリアライズ済み regression seed をビルドして再生する

upstream harness では、互換性のある `libprotobuf-mutator` を固定し、`LKL_FUZZING=1` で LKL fuzzing instrumentation と KASAN を有効にし、`MMU=1` で Binder 用の `CONFIG_MMU` を有効にします。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

意図的に脆弱なリビジョンをチェックアウトするか、upstream に記載されたロールバックパッチを適用すれば、シリアライズされたシードを使って、場当たり的な C の proof of concept で再構築することなく、複数クライアント間の状態遷移全体を再現できます:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

生成された KASAN use-after-free は、seed が脆弱なライフタイム経路に到達したことの確認として扱ってください。これは、カーネルコード実行や権限昇格に必要な後続のプリミティブを実証するものでは**ありません**。<sup>[[16]](#references)</sup>

## 単一マシンでの多様性の工夫（Jackalope 方式）

**生成による新規性**と**coverage の再利用**を組み合わせる実用的な方法は、永続サーバーに対して短命な worker を再起動することです。各 worker は空の corpus から開始し、`T` 秒後に同期し、統合された corpus でさらに `T` 秒実行してから再度同期し、その後終了します。これにより、蓄積された coverage を活用しながら、**世代ごとに新しい構造**を得られます。<sup>[[1]](#references)[[2]](#references)</sup>

**サーバー:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**逐次ワーカー（ループの例）：**

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
- `-server_update_interval T` は**遅延同期**（まず新規性を優先し、その後再利用）を近似します。
- grammar fuzzing モードでは、デフォルトで**初期 server sync はスキップされます**（`-skip_initial_server_sync` は不要）。
- 最適な `T` は**target に依存**します。worker が「簡単な」coverage の大半を見つけた後に切り替えるのが、最も効果的です。

## Harness 化が難しい target の Snapshot Fuzzing

テスト対象のコードに到達するまでに**大きなセットアップコスト**（VM の起動、ログインの完了、packet の受信、container の解析、service の初期化）がかかる場合、代替手段として有用なのが **snapshot fuzzing** です。準備済みの process または VM の状態をキャプチャし、各 test case を target の入力経路に注入して、crash/timeout まで実行した後、snapshot を復元します。これにより初期化や protocol prefix の繰り返しを避けられ、**network service**、**firmware**、**認証後の attack surface**、**binary-only target** に有効です。<sup>[[9]](#references)[[10]](#references)</sup>

1. 興味のある状態が準備できるまで target を実行します。
2. その時点の**memory + registers**を snapshot に保存します。
3. 各 test case について、変異させた入力を関連する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. snapshot を復元します。VM target では、対応している場合は**dirty page**のみ復元してから繰り返します。

snapshot は、`recv`/`read` の後や packet の deserialization 時点など、最初にコストのかかる parse/dispatch 処理が始まる位置のできるだけ近くに置き、target が使用する入力 buffer を記録します。これは、繰り返し処理を避けるために snapshot を入力処理の奥へ移動する、adaptive-placement の原則に従っています。<sup>[[11]](#references)</sup>

### Protocol state 用の Incremental snapshot

固定 snapshot はセットアップコストを回避しますが、複数の有効な message を必要とする遷移を、それだけで探索できるわけではありません。LibAFL-Qemu harness は protocol-state field への書き込みを監視し、state が変化したときに新しい snapshot を保存できます。[libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) は `tcpcb.t_state` を監視し、state と response flag を hash 化して snapshot を重複排除し、dirty page を親 snapshot との差分として保存します。次の構造化 message を変異させる前に、親の chain をたどって選択した snapshot を復元します。testcase には `SnapshotId` と生成された入力 bytes（`gen_bytes`）が保持され、snapshot manager は replay に必要な親子関係を追跡します。<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu の user-mode `SnapshotModule` は mapping と target memory を保存しますが、CPU registers は保存しません。必要に応じて別途保持してください。説明されている manager は単一の root snapshot tree のみをサポートし、worker 間で snapshot ID を共有できません。また、multi-snapshot モードでは QASAN shadow state を直接再利用できません。offline triage では、別の instrumented process で入力 chain を再構築してください。`AsanHostModule` と `DrCovModule` を使用する場合、`fuzzer.evaluate_input` は必要な `pre_exec`/`post_exec` callback を実行しますが、`qemu.run` 単独では実行しません。<sup>[[27]](#references)[[28]](#references)</sup>

### 論理的な ring-buffer overread の検出

buffer の *valid-data count* を超えた読み取りは、host allocation の範囲内に収まり、通常の ASAN をすり抜けることがあります。[libslirp urgent-data の例](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes)では、unsigned byte count の underflow も発生します。source が利用できる場合、signed/unsigned integer-overflow instrumentation でその副作用を検出できます。report を抑制する前に、意図的な TCP sequence-number wrap と区別してください。より強力な oracle として提案されているのは、custom ring allocation を poison し、internal allocator の進行に合わせて有効な範囲だけを unpoison し、解放した範囲を再度 poison する方法です。LibAFL-Qemu は、source instrumentation の実用が難しい target 向けに ASAN poisoning API を提供しています。<sup>[[27]](#references)</sup>

## MAccConc による Linux Kernel Race の探索

[MAccConc](https://github.com/googleprojectzero/MAccConc) は、タイミングに敏感な Linux kernel race を、再現可能な memory-access schedule に変換します。2 context の **A-B-A** execution を自動で列挙することも、terminal UI/GUI で analyst が順序制約を指定することもできます。これは完全な concurrency fuzzer ではなく、実験的な研究用 tool です。現時点では LLVM 23+ とプロジェクト独自の patched kernel が必要で、command-line tool は2つの test thread をサポートし、提案されている userspace fuzzing layer は未実装です。<sup>[[17]](#references)[[18]](#references)</sup>

### Context 間の通信ポイントを収集する

KASAN outline callback と patched KCOV memory-record support を有効にして、instrumented kernel を build します。プロジェクトの README では、call stack を利用可能な状態に保つため sibling-call optimization を無効にすることも推奨しています。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）は、instrumented accessをhelper callに変換します。MAccConcのkernel patchは`asan-opt-same-temp`を無効にし、連続するaccessが統合されないようにします。global variableのraceを検出する必要がある場合は、`asan-opt-globals` optimizationも無効にしてください。KCOVは生成されたrecordをuserspaceに渡します。異なるexecution contextからのaccessを比較し、byte rangeが重なり、少なくとも片方がwriteを行うpairを保持します。`kfree()`もwriteとして扱うことで、lifetimeの遷移も候補になります。<sup>[[17]](#references)</sup>

initiating taskから処理が引き継がれる場合（packet processingやRCU callbackなど）、subsystemはKCOV remote-coverage handleを引き継ぐ必要があります。upstream remote KCOVはopt-inであり、任意のbackground workで自動的に利用できるわけではありません。そのため、引き継ぎが欠けると、実際に発生した相互作用を検出できないことがあります。<sup>[[17]](#references)[[19]](#references)</sup>

### 実行ごとに同じ動的accessを特定する

allocationごとに変わる可能性のある具体的なheap addressや、`memcpy()`や`spin_lock()`などのhelper内では曖昧になるinstruction addressだけを使ってreplayしないでください。MAccConcは**count-augmented stack trace**を使用します。各frameはcalleeと、そのcaller内での呼び出し回数を識別し、最後の要素はmemory-access instructionを識別します。SanitizerCoverageのfunction-entry/exit recordにより、userspaceはこの動的identifierを再構成できます。このidentifierは、addressの変化や無関係なcontrol-flowの揺らぎがあっても安定しています。<sup>[[17]](#references)</sup>

### 候補pairを強制scheduleに変換する

patch適用済みの`KCOV_SET_DI` ioctlは、count-augmented access identifierをshared-flag actionに関連付けます。<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 選択したaccessの直前にflag *N*を設定します。 |
| `DI_STACK_WAIT` | 選択したaccessの直前に、flag *N*が設定されるか、設定されたlimitに達するまでspinします。 |
| `DI_STACK_WAKE_POST` | 選択したaccessの直後にflag *N*を設定します。 |

部分的な**A-happens-before-B**制約を設定するには、Aに`DI_STACK_WAKE_POST`を、Bに`DI_STACK_WAIT`を同じflagで指定します。2つのcontextのscheduleを完全に指定する場合は、Bをblockした状態で開始し、AがBをwakeして最初のtransfer pointで待機するようにします。次のtransferでは、Bが逆の操作を行います。後者はdeterministic context switchingのように動作し、自動A-B-A explorerが使用する方式です。<sup>[[17]](#references)</sup>

最小限のcampaignでは、4つのhook（`test_setup`、2つのthread function、`test_end`）を含むtest caseをshared libraryとしてcompileし、制約なしのtraceを収集してから、A-B-Aの候補を列挙するか、疑わしいaccessの周辺に手動で制約を追加します。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

タイムアウトは、正常な順序変更とは別に扱ってください。ロックや初期化／公開の依存関係により、2つ目のコンテキストが注入ポイントに到達できず、要求した順序を実現できない場合があります。また、KASANの検出漏れにも注意してください。直接のスタックアクセスは、範囲外アクセスの可能性がない限り通常はフックされず、デフォルトの最適化ではグローバル変数も対象外です。さらに、現在のコンパイラはASANとTSANのフックを同時に生成できません。最後に、ゲストがパニックになるとプロトタイプはKCOVバッファを失うため、独立したクラッシュコンソール／オラクルを維持してください。<sup>[[17]](#references)</sup>

将来の並行性ガイド付きファジングでは、入力またはシステムコールごとのメモリアクセス概要を記録し、コンテキスト間の通信ポイントとなる操作を組み合わせてから、その組み合わせのみを探索します。VMスナップショットを使うと、グローバル状態とアドレスを安定させられます。スナップショットを使わない場合は、割り当て箇所のメタデータを使って、実行間でオブジェクトを抽象化できます。これは提案されている拡張であり、現在のMAccConcユーザー空間ツールの機能ではありません。<sup>[[17]](#references)</sup>

## Harness Introspection: 浅いファザーを早期に見つける

ファジングキャンペーンが停滞したとき、問題はミューテーターではなく**ハーネス**にあることがよくあります。**到達可能性／カバレッジの内省**を使い、ファジングターゲットから静的には到達可能でも、動的にはほとんど、あるいはまったくカバーされない関数を見つけてください。こうした関数は通常、次の3つの問題のいずれかを示しています。<sup>[[12]](#references)</sup>

- ハーネスがターゲットに入るタイミングが早すぎる、または遅すぎる。
- シードコーパスに機能群が丸ごと欠けている。
- 1つの巨大な「何でもする」ハーネスではなく、**2つ目のハーネス**が本当に必要である。

OSS-Fuzz／ClusterFuzz形式のワークフローを使っている場合、Fuzz Introspectorは静的な到達可能性と実行時カバレッジを比較し、時間を区切った実行または公開コーパスからレポートを生成できます。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

レポートを参考に、未テストのパーサーパスに新しい harness を追加するか、特定の機能向けにコーパスを拡充するか、モノリシックな harness を小さなエントリーポイントに分割するかを判断します。

## グラフ優先の fuzz ターゲット選定と mutation トリアージ

すでに**静的解析の検出結果**、**mutation testing の生き残り**、**カバレッジレポート**がある場合、それらを独立したリストとしてトリアージしないでください。まず**コールグラフ**を作成し、ノードに**サイクロマティック複雑度**、**エントリーポイント／信頼できない入力からの到達可能性**、および外部の検出結果を注記してから、グラフに関する問いを検討します。<sup>[[5]](#references)[[6]](#references)</sup>

- 信頼できない入力から到達可能な、複雑度の高い関数はどれか？
- パーサー／ハンドラーからセキュリティ上重要なコードへのパス上にある mutation の生き残りはどれか？
- 異常に大きな**影響範囲**を持つ、アーキテクチャ上の要所となる関数はどれか？

この方法で見つかる fuzz ターゲットは、単に「カバレッジが最も低いもの」を選ぶより適切なことが多くあります。**複雑度が高く**、外部から到達可能であることが確認されたパーサー／デコーダーは、カバレッジが低くても攻撃者が制御できるパスがない、孤立した内部ヘルパーよりも有力な harness 候補です。

### 実践的なトリアージの手順

1. コードベースから**コードグラフ**を作成し、関数ごとの複雑度／分岐メトリクスを抽出します。
2. 攻撃者が制御できる入力を受け取る**エントリーポイント**を列挙します。例：リクエストハンドラー、デコーダー、インポーター、プロトコルパーサー、CLI／ファイルリーダー。
3. これらのエントリーポイントから候補関数へのパスクエリを実行し、到達可能な攻撃対象領域と、到達不能または内部からしか使われないコードを切り分けます。
4. 次の条件を組み合わせて満たすノードを優先します。
   - 高い**サイクロマティック複雑度**
   - 信頼できない入力から到達可能であることの確認
   - 大きな**影響範囲**、または多数の下流依存先
   - **SARIF** の検出結果、監査メモ、mutation の生き残りなど、裏付けとなる証拠
5. スコアの高いノードから、対象を絞った harness を作成します。特に、hex／Base64／IP／メッセージデコーダーなどの**パーサー／codec**を優先します。

### Mutation の生き残り：等価か、対処すべきか

Mutation testing では、ノイズの多い生き残りリストが生成されることがよくあります。すべての生き残りをセキュリティ上の問題とみなす前に、グラフを使って次の点を確認します。

- 変異させた関数は、攻撃者が制御できるエントリーポイントから到達可能か？
- すべての呼び出しパスは、変異させたチェックより強い不変条件によって制約されているか？
- そのノードは、到達不能なコードや整形のみを行うロジックにあるのか、それとも影響の大きい算術／パーサーパスにあるのか？

到達不能なまま、または構造上の制約を受けている生き残りは、**等価ミュータント**であることがよくあります。一方、**到達可能**なままで、**境界条件**、**オーバーフロー／キャリーパス**、または**セキュリティ上重要な算術／パース処理**に関わる生き残りは、次の対象に加えるべきです。

- 新しい fuzz harness
- 直接的なプロパティ／不変条件テスト
- 対象を絞ったエッジケースのテストベクター

### 外部の検出結果をグラフに対応付ける

SAST パイプラインが**SARIF**をエクスポートする場合、**ファイルと行範囲**を使って検出結果をグラフのノードに対応付け、グラフを利用して影響範囲を広げて確認します。<sup>[[6]](#references)</sup>

- 検出対象の関数の**影響範囲**を計算する
- その検出結果がエントリーポイントからのいずれかのパス上にあるか確認する
- 近接する検出結果を、同じ要所に集約されるものごとにグループ化する

これは、特定の関数に fuzzing の時間を割くか判断するときに役立ちます。**到達可能**で、**複雑度が高く**、すでに**SAST の検出結果がある**ノードは、攻撃者からのパスがない単に複雑なだけのノードよりも有力なターゲットであることが多くあります。

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

重要なのは、**複雑さ x 露出度 x 影響度**の交差です。グラフを使って期待されるセキュリティ価値が最も高い fuzz 対象を選び、mutation を通過した入力をもとに、ハーネスで重点的に検証すべき境界と不変条件を判断します。<sup>[[5]](#references)</sup>

## 暗号鍵エンコーディングの差分 fuzzing

有効なシリアライズ済み鍵または標準テストベクターから始めます。import と操作の処理経路に到達するために必要な長さと構造を保ちながら、エンコードされたフィールドを変更し、同じバイト列を独立した実装に送信します。受理結果とエラーを比較します。ランダム化された署名や暗号文は、バイト単位の比較ではなく正当性オラクルが必要です。署名を検証するか、カプセル化／デカプセル化の往復で共有秘密を比較します。テストベクターは既知のケースへの準拠を確認し、差分 mutation はそれらの範囲外にある不正なエンコーディングを調べます。<sup>[[23]](#references)[[26]](#references)</sup>

これらの鍵形式では、形式ごとのオラクルを使います。<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** 鍵をパース可能な状態に保ちながら、パックされた `s1` または `s2` の係数を `[-η, η]` の範囲外に変更します。import または signing が拒否するか、生成された署名が検証に通るかを確認します。受理結果の違いだけでは標準違反とは言えません。FIPS 204 は追加の秘密鍵チェックを義務付けていないためです。[conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)を参照してください。
- **ML-KEM key pairs:** 必須のカプセル化鍵チェックとデカプセル化入力チェックを、import された鍵ペアに対する任意の pairwise-consistency check (PCT) と分けて確認します。公開鍵でカプセル化し、秘密鍵でデカプセル化して、共有秘密を比較します。不一致があれば、個々の鍵が入力チェックに合格していても、暗号化通信が壊れる可能性があります。API が操作時に入力を検証するのか、別の呼び出しで検証するのかを確認します。libcrux は `validate_public_key(pk)` と `validate_private_key(sk, ct)` を公開していますが、これらは PCT の代わりにはなりません。
- **XMSS/XMSSMT raw keys:** メモリ内鍵を使った操作だけでなく、パラメータセットをまたいだシリアライズ済み**署名鍵と検証鍵**の往復をテストします。XMSS と XMSSMT は別々の4バイト OID 名前空間を使用するため、XMSSMT と衝突する OID を持つ鍵を、XMSS を先に試す OID のみのパーサーが誤分類し、import を拒否することがあります。報告された RustCrypto パーサーの問題は、署名偽造ではなく、相互運用性／可用性の失敗を示しています。

## gosentry による Go Fuzzing: より強力なエンジン、型付き入力、差分チェック

Go のターゲットにネイティブな `testing.F` ハーネスがすでにある場合、実用的なアップグレード方法は、[gosentry](https://github.com/trailofbits/gosentry) を使って同じハーネスを実行することです。これは `go test -fuzz` を維持しながら、バックエンドを **LibAFL** に置き換える Go toolchain の fork です。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

これは、native Go fuzzer が**難しい比較**、**型付き入力**、または**パーサー負荷の高い形式**で停滞するときに役立ちます。手法は変わりません。

- シードには引き続き `f.Add(...)` を使い、コールバックには `f.Fuzz(...)` を使います。
- 同じハーネスを再利用し、標準のツールチェーンではなく gosentry の `go` バイナリで実行します。
- 実行結果は通常の coverage-guided fuzzing と同様に扱いますが、LibAFL のスケジューリング／ミューテーションと、より優れた周辺検出機能を利用できます。

### サイレントな失敗を fuzzing の検出結果にする

Go のアセスメントでよくある問題は、危険な動作がデフォルトでは**クラッシュしない**ことです。gosentry を使うと、「問題はあるがサイレント」な状態を複数の種類の検出結果にできます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` を使うと、指定したログ／エラー処理をクラッシュとして扱えます（通常はログを出して処理を続けるだけの `log.Fatal` 型のコードパスに便利です）。
- `--catch-races=true` を使うと、新たに検出したキューエントリーを Go の race detector で再実行できます。
- `--catch-leaks=true` を使うと、新しいキューエントリーを `goleak` で再実行し、goroutine のリークが発生した時点で停止できます。
- LibAFL のハング処理により、**無限ループ／極端に遅い入力**をタイムアウトとして消失させず、fuzzing の検出結果として保持できます。
- 算術オーバーフローのチェックはデフォルトで組み込まれており、go-panikint 形式のインストルメンテーションによる切り詰めチェックもオプションで利用できます。

これは、セキュリティ上の影響がメモリ破損ではなく、**panic を伴わないパーサーの失敗**、**並行処理のバグ**、または**DoS のみを引き起こすハング**であるターゲットで特に有用です。

### 型付き Go API 向けの構造体対応 fuzzing

native Go fuzzing では主に `[]byte`、`string`、数値などのスカラー値を想定します。テスト対象のコードが型付きオブジェクトを受け取る場合、gosentry ではバイト列を引き続きミューテーションしながら、構造体、スライス、配列、ポインターなどの**複合値**を直接 fuzzing できます。<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing専用の偽のwire formatを構築すると、harness専用のパーサーコードによってロジックバグが隠れてしまいます。差分テストやgrammar-basedのcampaignでは、harnessの入力を単一の`[]byte`または`string`にし、代わりにcallback内でパースしてください。

### パーサーとプロトコル入力のgrammar-based fuzzing

パーサー、フォーマット、入力言語の場合、gosentryはLibAFL上で**Nautilus grammar fuzzing**を実行できます。grammarはproduction ruleのJSON配列で、harnessは通常、単一の`[]byte`または`string`引数を受け取るようにします。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法論のメモ:

- バイトレベルの変異が初期の構文チェックでほとんど弾かれる場合は、grammar modeを使う。
- 文法は仕様全体をモデル化するのではなく、言語/プロトコルの**セキュリティに関係する部分集合**に絞る。
- 整数、長さ、状態機械の境界を試すため、terminal/nonterminalには大きな境界値を使う。
- grammar modeでは入力の文法が有効に保たれるが、対象に渡されるのは引き続き**バイト列/文字列**である。そのため、パース処理とセマンティックチェックはハーネスで実行されるコード内に残る。

### Differential fuzzing: クラッシュだけでなく実装同士を比較する

Goエコシステムで有効な手法は、**grammar-based differential fuzzing**である。有効な構造化入力を生成し、2つのparser、client、または状態遷移エンジンに渡す。<sup>[[7]](#references)[[8]](#references)</sup>

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

- 一方の実装はpanicするが、もう一方は適切に拒否する
- 入力の受理・拒否に不一致がある
- parse treeやデコードされたオブジェクトが異なる
- state transition、nonce、balance、state rootに差異がある

これは、純粋なクラッシュfuzzingでは見逃されがちな**consensus mismatch**、**parser ambiguity**、**仕様と実装の乖離**を見つける実践的な方法です。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### coverageレポートの作成にcampaign corpusを再利用する

campaign後、保存済みのqueue corpusを再実行すると、別途corpusを手動でエクスポートせずにGo coverageレポートを作成できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

同じ package から、同じ `-fuzz` target を指定してコマンドを実行し、gosentry が適切なキャッシュ済み campaign state を解決できるようにしてください。

## References

- [1] [ミューテーション文法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing の詳細](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 5 年後：カバレッジガイド型プロトコル fuzzing について](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark がコードをグラフに変換](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go の fuzzing にはツールキットの半分が欠けていた。修正するために toolchain を fork した。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：snapshot を使用したステートフルネットワークプロトコル向け高速 greybox fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [文法がなくても問題ない：システムコールの記述なしで Linux kernel を fuzzing する試み](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：適応型・変更可能な snapshot による効率的な fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation：path と caller の coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [予測型コンテキスト依存 fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build と regression seed のドキュメント](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：制御されたメモリアクセスのインターリーブによる Linux kernel の race condition の調査](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：fuzzing のための code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO の拡張ファイル名構文](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Advisory：CFITSIO 2025 年第 4 四半期](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO の拡張ファイル名構文の fuzzing：16 件のメモリ安全性脆弱性と Codex を活用したトリアージ](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [暗号技術の differential fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203：モジュール格子ベースの鍵カプセル化メカニズム標準](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID parsing bug - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [耐量子暗号実装の現状](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [snapshot による CVE-2026-9539 への到達](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - fuzzer 対 AI：JavaScript engine における Fuzzilli と BigSleep の比較](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
