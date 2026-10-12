# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**では、入力を**文法的に有効な状態**に保ちながら変異させます。coverage-guidedモードでは、**新たなcoverage**を発生させたサンプルのみがcorpus seedとして保存されます。**言語を対象とするもの**（parser、interpreter、engine）では、ある構文の出力が別の構文の入力になるような**意味上のデータフロー連鎖**を必要とするバグを見逃すことがあります。<sup>[[1]](#references)</sup>

**失敗モード:** fuzzerが`document()`と`generate-id()`（または同様のプリミティブ）を個別に実行するseedを見つけても、**連鎖したデータフローが保持されない**ため、coverageが増えない「バグに近い」サンプルは破棄されます。**3つ以上の依存するステップ**があると、ランダムな再結合は高コストになり、coverage feedbackも探索の指針になりません。<sup>[[1]](#references)</sup>

**示唆:** 依存関係の多い文法では、**mutationalフェーズとgenerativeフェーズを組み合わせる**か、（coverageだけでなく）**関数連鎖**パターンを優先的に生成することを検討してください。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutationは**貪欲**です。新たなcoverageを得たサンプルはすぐに保存され、多くの場合、大きな未変更領域もそのまま残ります。時間が経つと、corpusは構造的な多様性の低い**ほぼ重複したサンプル**で埋まります。過度な最小化は有用なコンテキストを削除することがあるため、実用的な妥協策として、**最小token数に達したら停止する**文法を考慮した最小化があります（ノイズを減らしつつ、変異させやすい十分な周辺構造を保つ）。<sup>[[1]](#references)</sup>

mutational fuzzingで実用的なcorpusを作るには、ほぼ重複したサンプルを大量に集めるよりも、coverageを最大化する構造の異なる少数のseedを**優先**します。通常、具体的には次のようにします。<sup>[[1]](#references)[[3]](#references)</sup>

- **実環境のサンプル**（公開corpus、クロールデータ、取得したtraffic、対象エコシステムのファイルセット）から始める。
- 有効なサンプルをすべて保持するのではなく、**coverageベースのcorpus最小化**で絞り込む。
- 変異が無関係なbyteの処理に大半のサイクルを費やさず、意味のあるfieldに作用するよう、seedを**十分小さく**保つ。
- harnessやinstrumentationを大幅に変更した後はcorpusを再度最小化する。到達可能性が変わると、「最適な」corpusも変わるため。

## Comparison-Aware Mutation For Magic Values

fuzzerが停滞するよくある理由は、構文ではなく**厳密な比較**です。たとえば、magic byte、length check、enum string、checksum、`memcmp`、switch table、または連続した比較によって判定されるparserのdispatch値です。純粋なランダム変異では、こうした値をbyte単位で推測しようとしてサイクルを無駄にします。

このような対象では、**comparison tracing**（たとえばAFL++の`CMPLOG`やRedqueen方式のworkflow）を使い、失敗した比較のoperandをfuzzerが観測できるようにして、それを満たす値へ変異を誘導します。<sup>[[3]](#references)</sup>

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

- これは、対象が **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** によって深いロジックへのアクセスを制限している場合に特に有用です。
- 実際のサンプル、プロトコル仕様、デバッグログから抽出した **辞書** と組み合わせてください。文法トークン、チャンク名、動詞、区切り文字を含む小さな辞書のほうが、汎用的なワードリストよりも役立つことがよくあります。
- 対象が多くの逐次チェックを行う場合は、まず最初の「magic」比較を解決し、その後、結果として得られたコーパスを再度最小化して、後続の段階がすでに有効なプレフィックスから始まるようにしてください。

## エッジカバレッジでは異なるパスを区別できない場合の、より豊富なフィードバック

通常のエッジカバレッジでは、同じヘルパーを異なる呼び出し元から通過する実行や、関数内で異なる分岐の組み合わせをたどる実行を区別できません。これは、エッジに至る **経路** によって有効な状態が決まる、共有デコーダー、プロトコルディスパッチャー、インタープリターヘルパーで重要です。すべての呼び出しコンテキストを単純に追跡するのも危険です。カバレッジマップとキューが爆発的に増大する可能性があります。そのため、コンテキストセンシティブなファジングの研究では、呼び出しグラフ全体をコンテキストセンシティブとして扱うのではなく、有望なコンテキストだけを絞り込むことが推奨されています。<sup>[[14]](#references)</sup>

最近の AFL++ ビルドでは、通常のエッジカバレッジに加えて **Ball-Larus 関数ごとのパスカバレッジ** を利用できます。関数内の非巡回パスごとにフィーチャーを割り当てます。ループのバックエッジは取り除かれるため、このフィードバックで分岐の組み合わせは区別できますが、**ループの反復回数は区別できません**。まずは緩いレベル `1` から始め、パス数が指数関数的に増える可能性があるため、より厳しいモードは疑わしいパーサーやステートマシンのコードに限定してください。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

多くのセキュリティ関連箇所から呼び出されるヘルパーの場合、LTO modeでは各関数パスを直近の呼び出し箇所と組み合わせることができます:<sup>[[13]](#references)</sup>

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

- 通常の edge-coverage インスタンスを並行して実行してください。追加の queue/map コストによって executions per second が大きく低下しない場合に限り、より豊富なフィードバックが有効です。
- 大規模な template-heavy ライブラリや汎用ユーティリティコードが map の大部分を占める場合は、`AFL_LLVM_ALLOWLIST` を使って path/caller instrumentation の対象を絞ってください。
- 非常に多くの非巡回パスを持つ関数は AFL++ でスキップできます。コンパイル時の警告は、対象に allowlisting またはより低い厳格度が必要であることを示しています。
- Caller + path coverage がサポートする caller depth は 1 段階のみです。より深い context stack と組み合わせないでください。
- Path ID は LLVM の major version 間で変わる場合があります。キャンペーン中は toolchain を固定し、PATH ベースの corpus を、ビルド間で feature ID が安定しているかのように同期しないでください。
- このフィードバックは `CMPLOG` を補完します。comparison tracing は **guard を通過する値**を特定し、path/caller feedback は **どの経路と分岐の組み合わせでそこに到達したか**を保持します。

## Stateful Fuzzing: シーケンスを seed にする

**protocol**、**認証済みワークフロー**、**複数段階の parser**では、興味深い単位は単一の blob ではなく、**message sequence** であることがよくあります。transcript 全体を 1 つのファイルに連結して無差別に mutation する方法は、通常は効率的ではありません。壊れやすい状態に到達するのが後続の message だけであっても、fuzzer はすべてのステップを同じように mutation するためです。<sup>[[4]](#references)</sup>

より効果的な方法は、**sequence 自体を seed として扱い**、**観測可能な状態**（response code、protocol state、parser phase、返された object type）を追加のフィードバックとして使うことです。<sup>[[4]](#references)</sup>

- **有効な prefix message**を維持し、mutation は**遷移を引き起こす**message に集中させます。
- 次のステップが以前の応答に依存する場合は、identifier とサーバーが生成した値を cache します。
- シリアライズされた transcript 全体を不透明な blob として mutation するより、message ごとの mutation/splicing を優先します。
- protocol が意味のある response code を提供する場合は、それを**低コストの状態 oracle**として使い、より深く進む sequence を優先します。

認証関連の bug、隠れた遷移、または「handshake 後にのみ発生する」parser bug が通常の file-style fuzzing で見逃されがちなのも、同じ理由です。fuzzer は構造だけでなく、**順序、状態、依存関係**を維持しなければなりません。<sup>[[4]](#references)</sup>

### Android Binder: マルチクライアント driver fuzzing

edge coverage が高くても、coverage では**object ownership、reference count、保留中の message、cleanup の順序、thread の interleaving**が表現されないため、IPC-driver bug を見逃すことがあります。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) のページでは driver の object model を説明しています。この例では fuzzer harness に焦点を当てます。Android Binder は有用なモデルです。複数のプロセスに同じ kernel object を必要な順序で操作させられなければ、allocation と free の両方の path に到達するだけでは不十分です。<sup>[[15]](#references)</sup>

#### 個別の `ioctl` buffer ではなく protocol をモデル化する

test case は、**client identity + operation + structured arguments**からなる順序付き grammar として表現します。Binder LKL fuzzer は protobuf と `libprotobuf-mutator` を使い、永続的な context-manager client 1 つと通常の client 2 つを用います。semantic harness によって、無差別な byte mutation では壊れてしまう関係性を維持します。<sup>[[15]](#references)</sup>

- 先行する operation が返した値を cache します。たとえば `BC_FREE_BUFFER` では、以前の `ioctl` が返した transaction-buffer pointer を再利用する必要があります。
- 有効な default reply を生成し、同期 transaction が完了して後続の operation にも到達できるようにします。
- self-transaction や、同じ target に対する複数の保留中 transaction など、不可能な遷移を拒否します。
- singleton bootstrap state は入力ごとの reset の対象外にします。Binder では boot ごとに `BINDER_SET_CONTEXT_MGR` の登録は 1 回だけ許可されるため、その client を何度も破棄して再作成すると、後続の入力が無効になります。

有用な lifetime-race のテンプレートは、ある client に object を転送させ、thread または process の cleanup を開始し、それと並行して受信側の client に transaction buffer を解放させる方法です。CVE-2020-0423 の例では、`BINDER_TYPE_WEAK_BINDER` の転送後、`BINDER_THREAD_EXIT` と `BC_FREE_BUFFER` を race させることで、終了中の thread の cleanup path が使用している最中に埋め込みの `binder_work` が free される可能性がありました。<sup>[[15]](#references)</sup>

#### userspace kernel で制御された interleaving を再導入する

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) は実際の kernel code を userspace harness にリンクし、`lkl_syscall` を通じて syscall interface を公開します。これにより、1 つの process 内で protobuf state、coverage、KASAN を簡単に連携できます。ただし、LKL は通常、別の kernel thread に割り込まれることなく syscall を実行します。race campaign では、選択した lock/unlock および lifetime の境界に `schedule()` point を挿入し、yield ごとに harness が次の client をランダムに選ぶようにします。各 point は scheduling search space を拡大するため、対象を絞ってください。研究者が説明しているランダム化 scheduler は、upstream Binder fuzzer の一部では**ありません**。<sup>[[15]](#references)</sup>

#### シリアライズした regression seed をビルドして再実行する

upstream harness は互換性のある `libprotobuf-mutator` を固定し、`LKL_FUZZING=1` で LKL fuzzing instrumentation と KASAN を有効にし、Binder 用に `MMU=1` で `CONFIG_MMU` を有効にします。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

意図的に脆弱なリビジョンをチェックアウトするか、upstreamで文書化されたロールバックパッチを適用した後なら、シリアライズ済みシードによって、その場しのぎのC proof of conceptで再構築することなく、複数クライアントの状態遷移全体を再現できます:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

得られた KASAN の use-after-free は、seed が脆弱な lifetime path に到達したことの確認として扱ってください。これは、kernel code execution や privilege escalation に必要な後続の primitive を実証するものではありません。<sup>[[16]](#references)</sup>

## 単一マシンの多様性テクニック (Jackalope-Style)

**generative novelty** と **coverage reuse** を組み合わせる実用的な方法は、永続サーバーに対して短命な worker を再起動することです。各 worker は空の corpus から開始し、`T` 秒後に同期し、統合された corpus でさらに `T` 秒実行して再度同期した後、終了します。これにより、蓄積された coverage を活用しながら、世代ごとに**新しい構造**を生成できます。<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**逐次ワーカー（ループの例）:**

<details>
<summary>Jackalopeワーカー再起動ループ</summary>

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
- `-server_update_interval T` は**遅延同期**（最初は新規性を優先し、その後に再利用）を近似します。
- grammar fuzzing mode では、デフォルトで**初期 server sync はスキップされます**（`-skip_initial_server_sync` は不要です）。
- 最適な `T` は**target によって異なります**。worker が大部分の「簡単な」coverageを見つけた後に切り替えるとうまくいく傾向があります。

## Snapshot Fuzzing：ハーネス化が難しい Target 向け

テストしたいコードに到達するまでに**大きなセットアップコスト**（VM の起動、ログインの完了、パケットの受信、コンテナの解析、サービスの初期化など）がかかる場合、便利な代替手段として**snapshot fuzzing**があります。準備が完了したプロセスまたは VM の状態をキャプチャし、各テストケースを target の入力経路に注入して、crash/timeout まで実行した後、snapshot を復元します。これにより初期化やプロトコルのプレフィックスを繰り返す必要がなくなり、**network service**、**firmware**、**認証後の攻撃対象領域**、**binary-only target**に役立ちます。<sup>[[9]](#references)[[10]](#references)</sup>

1. 興味のある状態になるまで target を実行します。
2. その時点で**メモリとレジスタ**を snapshot します。
3. 各テストケースについて、mutated input を関連する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. snapshot を復元します。VM target では、対応している場合は**dirty page**のみを復元してから繰り返します。

`recv`/`read` の後やパケットのデシリアライズ時点など、最初の高コストな parse/dispatch 処理のできるだけ近くに snapshot を配置し、target が使用する input buffer を記録します。これは、処理を繰り返さないよう snapshot を入力処理のより深い位置へ移動するという、適応的配置の原則に従っています。<sup>[[11]](#references)</sup>

## MAccConc による Linux Kernel の Race 探索

[MAccConc](https://github.com/googleprojectzero/MAccConc) は、タイミングに敏感な Linux kernel の race を、再現可能なメモリアクセスのスケジュールに変換します。2つのコンテキスト間での **A-B-A** 実行を自動的に列挙するか、アナリストが terminal UI/GUI で順序制約を指定できます。これは完全な concurrency fuzzer ではなく、実験的な研究用ツールです。現時点では LLVM 23 以降とプロジェクト独自の patch を適用した kernel が必要で、コマンドラインツールがサポートする test thread は2つであり、提案されている userspace fuzzing 層は実装されていません。<sup>[[17]](#references)[[18]](#references)</sup>

### コンテキスト間の通信ポイントを収集する

KASAN outline callback と、patch を適用した KCOV memory-record support を有効にして instrumented kernel をビルドします。プロジェクトの README では、call stack を利用可能な状態に保つため、sibling-call optimization を無効にすることも推奨しています。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）は、instrumented accessをhelper callに変換します。MAccConcのkernel patchでは`asan-opt-same-temp`を無効化し、連続するaccessがマージされないようにします。global variableのraceを検出する必要がある場合は、`asan-opt-globals` optimizationも無効化します。KCOVは生成されたrecordをuserspaceに渡します。異なるexecution contextからのaccessを比較し、byte rangeが重なり、少なくとも片方がwriteを行うpairを保持します。また、lifetime transitionも候補となるよう、`kfree()`をwriteとして扱います。<sup>[[17]](#references)</sup>

packet processingやRCU callbackなど、開始元のtaskから処理が引き継がれる場合、subsystemはKCOV remote-coverage handleを伝播させる必要があります。upstreamのremote KCOVはopt-inであり、任意のbackground workで自動的に利用できるわけではありません。そのため、伝播が行われないと、実際に起きている処理が検出されない可能性があります。<sup>[[17]](#references)[[19]](#references)</sup>

### 毎回同じdynamic accessを特定する

allocationごとに変わる可能性がある具体的なheap addressや、`memcpy()`や`spin_lock()`のようなhelper内では曖昧になるinstruction addressだけを使ってreplayしないでください。MAccConcは**count-augmented stack trace**を使います。各frameは、calleeとcaller内での呼び出し回数を識別し、最後の要素はmemory-access instructionを識別します。SanitizerCoverageのfunction-entry/exit recordを使うと、userspaceでこのdynamic identifierを再構築できます。このidentifierは、addressの変化や無関係なcontrol-flowのノイズがあっても安定しています。<sup>[[17]](#references)</sup>

### 候補pairを強制的なscheduleに変換する

patch適用済みの`KCOV_SET_DI` ioctlは、count-augmented access identifierをshared-flag actionに関連付けます。<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 選択したaccessの直前にflag *N*をセットします。 |
| `DI_STACK_WAIT` | 選択したaccessの直前に、flag *N*がセットされるか設定したlimitを超えるまでspinします。 |
| `DI_STACK_WAKE_POST` | 選択したaccessの直後にflag *N*をセットします。 |

部分的な**A-happens-before-B**制約を設定するには、同じflagを使い、Aに`DI_STACK_WAKE_POST`を、Bに`DI_STACK_WAIT`を設定します。2つのexecution contextのscheduleを完全に指定するには、まずBをblocked状態にし、最初のtransfer pointでAがBをwakeしてwaitするようにします。次のtransferでは、Bが逆の操作を行います。後者はdeterministic context switchingのように動作し、自動A-B-A explorerが使用します。<sup>[[17]](#references)</sup>

最小限のcampaignでは、4つのhook（`test_setup`、2つのthread function、`test_end`）を含むtest caseをshared libraryとしてcompileし、制約なしのtraceを収集してから、A-B-A候補を列挙するか、疑わしいaccessの前後に手動で制約を追加します。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

タイムアウトは、順序の入れ替えが成功した場合と分けて解釈してください。ロックや初期化／公開の依存関係によって、2つ目のコンテキストが注入ポイントに到達できず、要求した順序を実現できない場合があります。また、KASANの検出漏れにも注意してください。スタックへの直接アクセスは、範囲外アクセスの可能性がない限り通常フックされません。デフォルトの最適化ではグローバル変数は対象外となり、現在のコンパイラはASANとTSANのフックを同時に出力できません。さらに、このプロトタイプではゲストがpanicするとKCOVバッファが失われるため、独立したクラッシュコンソール／オラクルを用意してください。<sup>[[17]](#references)</sup>

将来のconcurrency-guided fuzzingでは、入力またはsyscallごとのメモリアクセスの要約を記録し、コンテキスト間通信ポイントを形成する操作を組み合わせてから、それらの組み合わせだけを探索します。VM snapshotはグローバル状態とアドレスを安定させます。snapshotを使わない場合は、allocation-site metadataを使って実行間でオブジェクトを抽象化できます。これは提案されている拡張であり、現在のMAccConc userspace toolsの機能ではありません。<sup>[[17]](#references)</sup>

## Harness Introspection: 浅いfuzzerを早期に見つける

fuzzing campaignが停滞した場合、原因はmutatorではなく、**harness**にあることがよくあります。**到達可能性／coverageのイントロスペクション**を使い、fuzz targetから静的に到達可能でありながら、動的にはほとんど、あるいはまったくcoverageされていない関数を見つけましょう。そのような関数は通常、次の3つの問題のいずれかを示しています。<sup>[[12]](#references)</sup>

- harnessがtargetに入るタイミングが早すぎる、または遅すぎる。
- seed corpusに機能群がまるごと不足している。
- targetには、巨大な「何でも実行する」harnessひとつではなく、**2つ目のharness**が本当に必要である。

OSS-Fuzz／ClusterFuzz形式のワークフローを使っている場合、Fuzz Introspectorは静的な到達可能性と実行時coverageを比較し、時間を区切った実行または公開corpusからレポートを生成できます。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

レポートを使って、未テストのパーサーパス向けに新しい harness を追加するか、特定の機能の corpus を拡張するか、モノリシックな harness をより小さなエントリーポイントに分割するかを判断します。

## Graph-First Fuzz Target Selection And Mutation Triage

すでに **static-analysis findings**、**mutation-testing survivors**、**coverage reports** がある場合は、それらを独立したリストとしてトリアージしないでください。まず **call graph** を構築し、ノードに **cyclomatic complexity**、**entrypoint/untrusted-input reachability**、外部の指摘事項を注釈として付けてから、グラフに関する問いを投げかけます。<sup>[[5]](#references)[[6]](#references)</sup>

- 高い複雑度を持ち、信頼できない入力から到達可能な関数はどれか？
- parser/handler からセキュリティ上重要なコードへのパス上にある mutation survivors はどれか？
- **blast radius** が特に大きい、アーキテクチャ上の要所となる関数はどれか？

こうすることで、通常は「coverage が最も低いもの」だけを見るよりも、優れた fuzz target が見つかります。**complexity** が高く、外部入力から到達可能であることが確認された parser/decoder は、coverage が低くても攻撃者が制御するパスがない孤立した内部 helper より、強力な harness 候補です。

### 実践的なトリアージのワークフロー

1. コードベースから **code graph** を構築し、関数ごとの複雑度/分岐メトリクスを抽出します。
2. 攻撃者が制御する入力を受け取る **entrypoint** を列挙します。例: request handler、decoder、importer、protocol parser、CLI/file reader。
3. これらの entrypoint から候補関数への **path query** を実行し、到達可能な攻撃対象領域と、dead/internal-only のコードを切り分けます。
4. 次の条件を組み合わせて満たすノードを優先します。
   - 高い **cyclomatic complexity**
   - 信頼できない入力から到達可能であることが確認されている
   - 大きな **blast radius**、または多数の下流依存関係
   - **SARIF** findings、監査メモ、mutation survivors など、裏付けとなる証拠
5. 最もスコアの高いノードから優先して、対象を絞った harness を作成します。特に hex/Base64/IP/message decoder などの **parser/codec** が対象です。

### Mutation survivors: equivalent と対応が必要なもの

Mutation testing では、ノイズの多い survivor list が生成されることがよくあります。すべての survivor をセキュリティ上の問題とみなす前に、グラフを使って次の点を確認します。

- 変異させた関数は、攻撃者が制御する entrypoint から到達可能か？
- すべての call path は、変異させたチェックより強い不変条件によって制約されているか？
- そのノードは dead code、書式設定だけのロジック、または影響の大きい算術/パーサーパスのいずれにあるか？

到達不能、または構造的に制約されている survivor は、多くの場合 **equivalent mutants** です。一方、**reachable** のままで、**boundary conditions**、**overflow/carry paths**、またはセキュリティ上重要な算術/パース処理に関わる survivor は、次の項目に引き上げるべきです。

- 新しい fuzz harness
- 直接的な property/invariant test
- 対象を絞った edge-case vector

### 外部の指摘事項をグラフに関連付ける

SAST pipeline が **SARIF** をエクスポートする場合は、**file + line range** によって指摘事項をグラフのノードに対応付け、グラフを使って影響範囲を広げて分析します。<sup>[[6]](#references)</sup>

- 指摘された関数の **blast radius** を計算する
- その指摘事項が entrypoint からのパス上にあるか確認する
- 近接した指摘事項のうち、同じ choke point に集約されるものをまとめる

これは、特定の関数に fuzzing の時間をかけるか判断する際に役立ちます。**reachable** で **complex**、さらに **SAST hits** もあるノードは、攻撃者からのパスがない、単に複雑なだけのノードより優れた対象であることがよくあります。

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

重要な方法論は、その交差点にあります。**複雑さ x 露出度 x 影響度**。グラフを使って、期待されるセキュリティ価値が最も高い fuzz target を選び、その後、mutation を生き残った入力を基に、harness で重点的に検証すべき境界と不変条件を決めます。<sup>[[5]](#references)</sup>

## gosentry による Go Fuzzing: より強力なエンジン、型付き入力、差分チェック

Go の target にネイティブの `testing.F` harness がすでにある場合、実用的なアップグレード方法は、同じ harness を [gosentry](https://github.com/trailofbits/gosentry) で実行することです。これは `go test -fuzz` を維持しつつ、バックエンドを **LibAFL** に置き換えた fork 版の Go toolchain です。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

これは、native Go fuzzer が**難しい比較条件**、**型付き入力**、または**パーサー処理の多い形式**で停滞する場合に有用です。手法は変わりません。

- seed には引き続き `f.Add(...)`、コールバックには `f.Fuzz(...)` を使います。
- 同じ harness を再利用し、標準の toolchain ではなく gosentry の `go` バイナリで実行します。
- 結果の campaign は通常の coverage-guided run として扱います。ただし、LibAFL のスケジューリング/ミューテーションと、より優れた周辺 detector を利用できます。

### サイレントな失敗を fuzzing の検出結果に変える

Go の assessment で繰り返し問題になるのは、危険な動作がデフォルトでは**クラッシュしない**ことです。gosentry を使うと、「問題はあるがサイレント」な状態を複数の種類の検出結果にできます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` を指定すると、選択した logging/error の経路をクラッシュと同様に扱えます（通常はログを出して処理を続けるだけの `log.Fatal` 形式のコードパスに有用です）。
- `--catch-races=true` を指定すると、新たに検出された queue entry を Go race detector で再実行します。
- `--catch-leaks=true` を指定すると、新しい queue entry を `goleak` で再実行し、goroutine leak があれば停止します。
- LibAFL の hang 処理により、**無限ループや極端に遅い入力**を timeout として消失させず、fuzzing の検出結果として扱えます。
- デフォルトで算術オーバーフローを組み込みチェックし、go-panikint 形式の instrumentation による truncation check も任意で利用できます。

これは、セキュリティへの影響がメモリ破損ではなく、**panic を起こさないパーサーの失敗**、**並行処理のバグ**、または**DoS につながる hang**である target で、特に有用です。

### 型付き Go API 向けの struct-aware fuzzing

native Go fuzzing は主に `[]byte`、`string`、数値などの scalar を想定しています。テスト対象のコードが型付きオブジェクトを受け取る場合、gosentry では下層の bytes を mutation しながら、struct、slice、array、pointer などの**複合値**を直接 fuzzing できます。<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing専用の偽のwire formatを作ると、harness専用のパースコードの背後にロジックバグが隠れてしまいます。差分テストやgrammar-basedのcampaignでは、harnessの入力を単一の`[]byte`または`string`として受け取り、代わりにcallback内でパースしてください。

### パーサーとプロトコル入力のgrammar-based fuzzing

パーサー、フォーマット、入力言語には、gosentryを使ってLibAFL上で**Nautilus grammar fuzzing**を実行できます。grammarはproduction ruleのJSON配列で、harnessは通常、単一の`[]byte`または`string`引数を受け取ります。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- byte-level mutations の大半が初期の構文チェックで失敗する場合は、grammar mode を使います。
- grammar は、言語やプロトコルの仕様全体ではなく、**セキュリティに関係するサブセット**に絞ります。
- terminal/nonterminal では大きな境界値を使い、整数、長さ、状態機械の境界をストレステストします。
- grammar mode では入力の文法的な妥当性が保たれますが、ターゲットに渡されるのは依然として **bytes/strings** です。そのため、パースと意味チェックはハーネス化したコード内で行われます。

### Differential fuzzing: クラッシュだけでなく実装を比較する

Go エコシステムで有効な手法は、**grammar-based differential fuzzing** です。構造的に妥当な入力を生成し、2つのパーサー、クライアント、または状態遷移エンジンに渡します。<sup>[[7]](#references)[[8]](#references)</sup>

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

- 一方の実装はpanicし、もう一方は正常に拒否する
- 入力の受理／拒否結果が異なる
- parse treeまたはデコードされたオブジェクトが異なる
- state transition、nonce、balance、state rootが異なる

これは、純粋なクラッシュ fuzzingでは見逃されがちな **consensus mismatches**、**parser ambiguity**、**spec-vs-implementation drift** を見つける実践的な方法です。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### カバレッジレポートにキャンペーンのcorpusを再利用する

キャンペーン後、保存されたqueue corpusを再生して、corpusを別途手動でエクスポートせずにGoのカバレッジレポートを生成できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

同じパッケージから同じ `-fuzz` ターゲットを指定してコマンドを実行し、gosentry が適切なキャッシュ済みキャンペーン状態を解決できるようにしてください。



## References

- [1] [変異文法ファジング](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ファジングの詳細](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 5年後：カバレッジガイド型プロトコルファジングについて](https://arxiv.org/abs/2412.20324)
- [5] [Trailmarkがコードをグラフに変換](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Goのファジングにはツールキットの半分が欠けていた。ツールチェーンをフォークして修正した。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：スナップショットを用いたステートフルなネットワークプロトコル向け高速グレーボックスファザー](https://arxiv.org/abs/2202.03643)
- [10] [文法がなくても問題なし：システムコール記述なしでLinuxカーネルをファジングする方法に向けて](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：適応型・可変スナップショットによる効率的なファジング](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVMインストルメンテーション：パスと呼び出し元のカバレッジ](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [予測的コンテキスト依存ファジング](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binderファジング](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binderファザー - ビルドと回帰シードのドキュメント](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：メモリアクセスのインターリーブを制御してLinuxカーネルの競合状態を調査](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：ファジング向けコードカバレッジ](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
