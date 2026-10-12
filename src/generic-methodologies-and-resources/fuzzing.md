# Fuzzingの方法論

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: カバレッジとセマンティクス

**mutational grammar fuzzing**では、入力を**文法的に有効な状態**に保ちながら変異させます。coverage-guidedモードでは、**新たなカバレッジ**を引き起こしたサンプルだけがcorpus seedsとして保存されます。**言語を対象とするもの**（パーサー、インタープリター、エンジン）では、ある構文の出力が別の構文の入力となるような**セマンティクス／データフローの連鎖**を必要とするバグを見逃すことがあります。<sup>[[1]](#references)</sup>

**失敗パターン:** fuzzerは、個別には`document()`や`generate-id()`（または類似のプリミティブ）を実行するseedを見つけても、**連鎖したデータフローを維持できず**、「バグにより近い」サンプルがカバレッジを増やさないために破棄されます。**3つ以上の依存するステップ**があると、ランダムな再結合はコストが高くなり、カバレッジのフィードバックも探索の指針になりません。<sup>[[1]](#references)</sup>

**示唆:** 依存関係の多い文法では、**mutationalとgenerativeの各フェーズを組み合わせる**か、（カバレッジだけでなく）**関数チェーン**のパターンを優先するよう生成にバイアスをかけることを検討してください。<sup>[[1]](#references)</sup>

## Corpusの多様性に関する落とし穴

Coverage-guided mutationは**貪欲**です。新たなカバレッジを得たサンプルは、多くの場合、大きな変更されていない領域を残したまま、すぐに保存されます。時間が経つと、corpusは構造的な多様性が低い**ほぼ重複したサンプル**で埋まります。過度な最小化は有用なコンテキストを取り除く可能性があるため、実用的な妥協策は、**最小トークン数に達したら停止する**文法を考慮した最小化です（ノイズを減らしつつ、変異させやすい状態を保てるだけの周辺構造を残します）。<sup>[[1]](#references)</sup>

mutational fuzzingにおける実用的なcorpusのルールは、重複に近いサンプルを大量に集めるより、**カバレッジを最大化する構造の異なる少数のseedを優先する**ことです。通常、次のようにします。<sup>[[1]](#references)[[3]](#references)</sup>

- **実世界のサンプル**（公開corpus、クローリングデータ、取得したトラフィック、対象エコシステムのファイル群）を出発点にする。
- 有効なサンプルをすべて保持するのではなく、**カバレッジベースのcorpus最小化**で絞り込む。
- 変異の大半が無関係なバイトに費やされず、意味のあるフィールドに当たるよう、seedを**十分小さく**保つ。
- ハーネスや計装に大きな変更を加えた後はcorpusの最小化を再実行する。到達可能性が変われば、「最適な」corpusも変わるため。

## Magic Valueに対する比較認識型の変異

fuzzerが頭打ちになる一般的な原因は、構文ではなく**厳密な比較**です。たとえば、magic bytes、長さチェック、enum文字列、チェックサム、`memcmp`、switchテーブル、または連鎖した比較によって保護されたパーサーのディスパッチ値などです。純粋なランダム変異では、これらの値をバイトごとに推測しようとしてサイクルを無駄にします。

このような対象には、**比較トレース**（たとえばAFL++ `CMPLOG` / Redqueen方式のワークフロー）を使用し、失敗した比較のオペランドをfuzzerが観察できるようにして、比較を満たす値に向けて変異を誘導します。<sup>[[3]](#references)</sup>

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
- 実際のサンプル、プロトコル仕様、デバッグログから抽出した **dictionaries** と組み合わせてください。文法トークン、チャンク名、verb、区切り文字を含む小さな辞書は、多くの場合、巨大な汎用ワードリストよりも価値があります。
- ターゲットが逐次的なチェックを多数行う場合は、まず最初の「magic」比較を通過させ、その後、得られたコーパスを再度最小化して、後続の段階がすでに有効な prefix から開始するようにします。

## エッジカバレッジでは異なるパスを区別できない場合の、より豊富なフィードバック

通常のエッジカバレッジでは、異なる caller から同じ helper を通る実行や、関数内で異なる分岐の組み合わせを通る実行を区別できません。共有デコーダー、プロトコルディスパッチャー、インタープリターの helper では、エッジに至る **経路** によって有効な状態が変わるため、これは重要です。すべての呼び出しコンテキストを単純に追跡するのも危険です。カバレッジマップとキューが爆発的に増える可能性があります。そのため、コンテキストセンシティブな fuzzing の研究では、コールグラフ全体をコンテキストセンシティブに扱うのではなく、有望なコンテキストだけを絞り込むことが推奨されています。<sup>[[14]](#references)</sup>

最近の AFL++ ビルドでは、通常のエッジカバレッジに加えて、関数ごとの **Ball-Larus パスカバレッジ** が利用できます。関数内の各非巡回パスに feature を割り当てます。ループのバックエッジは除外されるため、このフィードバックでは分岐の組み合わせを区別できますが、**ループの反復回数は区別できません**。まずは緩やかなレベル `1` から始め、パス数が指数関数的に増える可能性があるため、厳しいモードは疑わしい parser/state-machine のコードに限定してください。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

多くのセキュリティ関連箇所から呼び出されるヘルパーの場合、LTOモードでは各関数パスを直近の呼び出し元と組み合わせることができます。<sup>[[13]](#references)</sup>

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

**Campaign guidance:** richer feedbackは控えめに適用し、そのcoverage-map/queueコストを監視してください。<sup>[[13]](#references)[[14]](#references)</sup>

- 通常のedge-coverageインスタンスを並行して実行してください。追加のqueue/mapコストによって1秒あたりの実行数が損なわれない場合に限り、richer feedbackは有用です。
- 大規模なtemplate-heavyライブラリや汎用ユーティリティコードがmapの大部分を占める場合は、`AFL_LLVM_ALLOWLIST`を使ってpath/caller instrumentationの範囲を絞ってください。
- 非常に多くのacyclic pathを持つ関数はAFL++でスキップされる場合があります。コンパイル時の警告は、対象にallowlistingまたはより厳しくないレベルが必要であることを示しています。
- Caller + path coverageがサポートするcaller depthは1つだけです。より深いcontext stackと組み合わせないでください。
- Path IDはLLVMのmajor version間で変わることがあります。campaign中はtoolchainを固定し、PATHベースのcorpusを、ビルド間でfeature IDが安定しているかのように同期しないでください。
- このfeedbackは`CMPLOG`を補完します。comparison tracingは**guardを通過する値**を特定する一方、path/caller feedbackは**どの経路と分岐の組み合わせでそこに到達したか**を保持します。

## Stateful Fuzzing: シーケンスをseedとして扱う

**protocol**、**認証済みworkflow**、**multi-stage parser**では、興味深い単位は単一のblobではなく、**メッセージシーケンス**であることがよくあります。transcript全体を1つのファイルに連結して無差別にmutateする方法は、通常効率がよくありません。壊れやすい状態に到達するのが後続のメッセージだけでも、fuzzerは各ステップを同じようにmutateするためです。<sup>[[4]](#references)</sup>

より効果的な方法は、**シーケンス自体をseed**として扱い、**観測可能な状態**（response code、protocol state、parser phase、返されるobject type）を追加のfeedbackとして使うことです。<sup>[[4]](#references)</sup>

- **有効なprefix message**は維持し、**遷移を引き起こす**メッセージのmutateに集中します。
- 次のステップが以前のresponseに依存する場合は、identifierやserverが生成した値をcacheします。
- シリアライズ済みtranscript全体を不透明なblobとしてmutateするより、メッセージ単位のmutate/spliceを優先します。
- protocolが意味のあるresponse codeを公開している場合は、それを**低コストのstate oracle**として使い、より深く進むシーケンスを優先します。

認証が必要なバグ、隠れた遷移、または「handshake後にのみ発生する」parser bugが通常のファイル形式のfuzzingで見逃されがちなのも、これと同じ理由です。fuzzerは構造だけでなく、**順序、状態、依存関係**を維持する必要があります。<sup>[[4]](#references)</sup>

### Android Binder: マルチクライアントのdriver fuzzing

edge coverageが高くても、coverageでは**objectの所有権、reference count、保留中のメッセージ、cleanup順序、threadのinterleaving**が分からないため、IPC driverのbugを見逃すことがあります。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md)のページではdriverのobject modelを解説しています。この例ではfuzzer harnessに焦点を当てます。Android Binderは参考になるモデルです。必要な順序で複数のprocessに同じkernel objectを操作させられない場合、allocation pathとfree pathの両方に到達するだけでは不十分です。<sup>[[15]](#references)</sup>

#### 孤立した`ioctl` bufferではなく、protocolをモデル化する

test caseは、**client identity + operation + structured arguments**からなる順序付きgrammarとして表現します。Binder LKL fuzzerはprotobufと`libprotobuf-mutator`を使い、永続的なcontext-manager client 1つと通常のclient 2つを使用します。semantic harnessによって、無差別なbyte mutationでは壊れてしまう関係性を維持します。<sup>[[15]](#references)</sup>

- 以前のoperationが返した値をcacheします。たとえば、`BC_FREE_BUFFER`では、以前の`ioctl`が返したtransaction-buffer pointerを再利用する必要があります。
- 有効なdefault replyを生成し、同期transactionが完了して後続のoperationにも到達できるようにします。
- self-transactionや、同じtargetへの複数の保留中transactionなど、不可能な遷移を拒否します。
- singletonのbootstrap stateは、入力ごとのresetの対象外にします。Binderでは起動ごとに`BINDER_SET_CONTEXT_MGR`を1回しか登録できないため、このclientを繰り返し破棄して再作成すると、後続の入力が無効になります。

有用なlifetime raceのテンプレートでは、あるclientにobjectを転送させ、threadまたはprocessのcleanupを開始し、受信側clientにtransaction bufferを同時に解放させます。CVE-2020-0423の例では、`BINDER_TYPE_WEAK_BINDER`の転送後に`BINDER_THREAD_EXIT`と`BC_FREE_BUFFER`を競合させると、終了するthreadのcleanup pathがまだ使用中の埋め込み`binder_work`が解放される可能性がありました。<sup>[[15]](#references)</sup>

#### userspace kernelで制御されたinterleavingを再導入する

[Linux Kernel Library (LKL)](https://github.com/lkl/linux)は実際のkernel codeをuserspace harnessにリンクし、`lkl_syscall`を通じてsyscall interfaceを公開します。これにより、protobuf state、coverage、KASANを1つのprocess内で簡単に連携できます。ただしLKLでは通常、syscallの実行中に別のkernel threadが割り込むことはありません。race campaignでは、選択したlock/unlockとlifetimeの境界に` schedule()`ポイントを挿入し、各yieldで次に実行するclientをharnessにランダムに選ばせます。各ポイントを増やすとschedulingの探索空間が拡大するため、対象を絞ってください。研究者が説明しているrandomized schedulerは、upstream Binder fuzzerには含まれていません。<sup>[[15]](#references)</sup>

#### シリアライズされたregression seedをbuildしてreplayする

upstream harnessでは、互換性のある`libprotobuf-mutator`のversionを固定し、`LKL_FUZZING=1`でLKL fuzzing instrumentationとKASANを有効にし、Binder用に`MMU=1`で`CONFIG_MMU`を有効にします。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

意図的に脆弱なリビジョンをチェックアウトするか、上流で文書化されたロールバックパッチを適用すると、シリアライズされたシードで、場当たり的なCの概念実証を作成して再構築することなく、複数クライアント間の状態遷移全体を再現できます。<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

結果として生じたKASANのuse-after-freeは、seedが脆弱なライフタイム経路に到達したことの確認として扱ってください。これは、kernel code executionやprivilege escalationに必要な後続のprimitivesを実証するものではありません。<sup>[[16]](#references)</sup>

## 単一マシンで多様性を生み出す手法（Jackalopeスタイル）

**生成による新規性**と**coverageの再利用**を組み合わせる実用的な方法は、稼働し続けるserverに対して、短時間だけ動作するworkerを再起動することです。各workerは空のcorpusから開始し、`T`秒後に同期して、統合されたcorpusを使ってさらに`T`秒間実行し、再度同期して終了します。これにより、蓄積したcoverageを活用しながら、**世代ごとに新しい構造**を生み出せます。<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

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

- `-in empty` は世代ごとに**新しい corpus**を強制します。
- `-server_update_interval T` は**遅延同期**（最初は新規入力を優先し、その後再利用）を近似します。
- grammar fuzzing モードでは、デフォルトで**初期サーバー同期はスキップされます**（`-skip_initial_server_sync` は不要です）。
- 最適な `T` は**target に依存**します。worker が「簡単な」coverage の大半を発見した後に切り替えるのが、一般に最も効果的です。

## ハーネス化が難しいターゲット向けの Snapshot Fuzzing

テスト対象のコードに到達するまでに大きなセットアップコスト（VM の起動、ログインの完了、パケットの受信、コンテナの解析、サービスの初期化など）がかかる場合、便利な代替手段として**snapshot fuzzing**があります。準備が整ったプロセスまたは VM の状態を保存し、各テストケースをターゲットの入力経路に注入して、クラッシュまたはタイムアウトまで実行した後、snapshot を復元します。これにより初期化やプロトコルのプレフィックスを繰り返す必要がなくなり、**ネットワークサービス**、**firmware**、**認証後の攻撃対象面**、**バイナリのみのターゲット**に有効です。<sup>[[9]](#references)[[10]](#references)</sup>

1. 興味のある状態になるまでターゲットを実行します。
2. その時点の**メモリ + レジスタ**を snapshot に保存します。
3. 各テストケースについて、変更した入力を関連する guest/process バッファに直接書き込みます。
4. クラッシュ、タイムアウト、またはリセットまで実行します。
5. snapshot を復元します。VM ターゲットでは、サポートされている場合は**dirty pages**のみを復元し、これを繰り返します。

snapshot は、`recv`/`read` の後やパケットのデシリアライズ地点など、最初の高コストな解析/ディスパッチ処理の直後にできるだけ近づけて配置し、ターゲットが使用する入力バッファを記録します。これは、処理の繰り返しを避けるために snapshot を入力処理のより深い位置へ移動するという、適応配置の原則に従っています。<sup>[[11]](#references)</sup>

## Harness Introspection: 浅い Fuzzer を早期に見つける

campaign が停滞したとき、問題は mutator ではなく**harness**にあることがよくあります。**到達可能性/coverage の introspection**を使って、fuzz target から静的には到達可能でも、動的にはほとんど、またはまったく coverage されていない関数を見つけましょう。通常、こうした関数は次の3つの問題のいずれかを示しています。<sup>[[12]](#references)</sup>

- harness がターゲットに入るのが早すぎる、または遅すぎる。
- seed corpus に機能ファミリー全体が欠けている。
- 大きすぎる「何でも処理する」harness 1つではなく、**2つ目の harness**が本当に必要である。

OSS-Fuzz / ClusterFuzz 形式のワークフローを使用している場合、Fuzz Introspector は静的な到達可能性と実行時の coverage を比較し、時間制限付きの実行または公開 corpus からレポートを生成できます。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

レポートを使って、未テストのパーサーパス向けに新しいハーネスを追加するか、特定の機能のコーパスを拡張するか、モノリシックなハーネスをより小さなエントリーポイントに分割するかを判断します。

## グラフ優先のFuzz Target選定とMutation Triage

**静的解析の指摘事項**、**mutation testingの生存変異**、**カバレッジレポート**がすでにある場合、それらを独立したリストとしてトリアージしないでください。まず**コールグラフ**を構築し、各ノードに**サイクロマティック複雑度**、**エントリーポイント／信頼されていない入力からの到達可能性**、外部からの指摘事項を注釈として付けてから、グラフについて問いかけます。<sup>[[5]](#references)[[6]](#references)</sup>

- 信頼されていない入力から到達可能な、高複雑度の関数はどれか？
- パーサー／ハンドラーからセキュリティ上重要なコードへのパス上にあるmutation survivorはどれか？
- 異例に大きな**blast radius**を持つ、アーキテクチャ上のボトルネック関数はどれか？

この方法では、単に「カバレッジが最も低い」ものを選ぶよりも、優れたFuzz Targetが見つかることがよくあります。**複雑度が高く**、外部入力からの到達性が確認されたパーサー／デコーダーは、カバレッジが低くても攻撃者が制御するパスがない、孤立した内部ヘルパーよりも、ハーネス候補として有望です。

### 実践的なトリアージの手順

1. コードベースから**コードグラフ**を構築し、関数ごとの複雑度／分岐メトリクスを抽出します。
2. 攻撃者が制御する入力を受け取る**エントリーポイント**を列挙します。例：リクエストハンドラー、デコーダー、インポーター、プロトコルパーサー、CLI／ファイルリーダー。
3. それらのエントリーポイントから候補関数へのパスクエリを実行し、到達可能な攻撃対象領域と、到達不能または内部限定のコードを切り分けます。
4. 次の条件を組み合わせて満たすノードを優先します。
   - 高い**サイクロマティック複雑度**
   - 信頼されていない入力からの**到達可能性**が確認されている
   - 大きな**blast radius**、または下流の依存先が多い
   - **SARIF**の指摘事項、監査メモ、mutation survivorなど、裏付けとなる証拠がある
5. スコアの高いノードから、特にhex/Base64/IP／メッセージデコーダーなどの**パーサー／コーデック**を対象に、焦点を絞ったハーネスを作成します。

### Mutation survivor：等価か、対処が必要か

Mutation testingでは、ノイズの多いsurvivorリストが生成されることがよくあります。すべてのsurvivorをセキュリティ上の欠陥とみなす前に、グラフを使って次の点を確認します。

- 変異させた関数は、攻撃者が制御するエントリーポイントから到達可能か？
- すべての呼び出しパスは、変異させたチェックより強い不変条件によって制約されているか？
- そのノードは、デッドコードやフォーマット処理のみのロジックにあるか、それとも影響の大きい算術処理／パーサーパスにあるか？

到達不能なままか、構造的に制約されているsurvivorは、多くの場合**等価ミュータント**です。一方、**到達可能**なままで、**境界条件**、**オーバーフロー／キャリーのパス**、または**セキュリティ上重要な算術処理／パース処理**に関わるsurvivorは、次のテストに追加すべきです。

- 新しいFuzz harness
- 直接的なプロパティ／不変条件テスト
- 対象を絞ったエッジケースのテストベクター

### 外部の指摘事項をグラフに対応付ける

SASTパイプラインが**SARIF**を出力する場合、**ファイル名＋行範囲**を使って指摘事項をグラフのノードに対応付け、グラフを使って影響範囲を拡大して調べます。<sup>[[6]](#references)</sup>

- 指摘された関数の**blast radius**を算出する
- その指摘事項がエントリーポイントからのいずれかのパス上にあるか確認する
- 近接する指摘事項を、同じボトルネックに集約されるものごとに分類する

これは、特定の関数にFuzzingの時間を割くかどうかを判断する際に役立ちます。**到達可能**で、**複雑度が高く**、すでに**SASTの指摘事項**もあるノードは、攻撃者からのパスがない、単に複雑なだけのノードよりも有望なターゲットであることがよくあります。

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

重要な方法論は、**複雑さ x 露出度 x 影響度**の交差点です。グラフを使って期待されるセキュリティ価値が最も高い fuzz 対象を選び、mutation の生き残りを参考に、ハーネスでどの境界や不変条件を重点的に検証すべきか判断します。<sup>[[5]](#references)</sup>

## gosentry を使った Go Fuzzing: より強力なエンジン、型付き入力、差分チェック

Go の対象にネイティブの `testing.F` ハーネスがすでにある場合、実用的なアップグレード方法は、[gosentry](https://github.com/trailofbits/gosentry) で同じハーネスを実行することです。これは `go test -fuzz` を維持しつつ、バックエンドを **LibAFL** に切り替えた、Go toolchain の fork です。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

これは、native Go fuzzer が **hard comparisons**、**typed inputs**、または **parser-heavy formats** で行き詰まる場合に役立ちます。方法論は変わりません。

- seed には引き続き `f.Add(...)` を使い、callback には `f.Fuzz(...)` を使います。
- 同じ harness を再利用し、stock toolchain ではなく gosentry の `go` binary で実行します。
- 生成された campaign は通常の coverage-guided run として扱いますが、LibAFL の scheduling/mutation と、より優れた周辺 detector を利用できます。

### サイレントな失敗を fuzz finding に変える

Go の assessment で繰り返し発生する問題は、危険な挙動がデフォルトでは **crash しない**ことです。gosentry を使うと、「問題はあるがサイレント」な状態を複数の種類の finding に変えられます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` を指定すると、選択した logging/error path を crash として扱えます（通常は log を出して処理を続行するだけの `log.Fatal` 型の code path に便利です）。
- `--catch-races=true` を指定すると、新たに検出された queue entry を Go race detector で再実行します。
- `--catch-leaks=true` を指定すると、新しい queue entry を `goleak` で再実行し、goroutine leak があれば停止します。
- LibAFL の hang handling により、**infinite loop / 非常に遅い input** を timeout として消失させず、fuzz finding として保持できます。
- arithmetic overflow check はデフォルトで組み込まれており、go-panikint 型の instrumentation による truncation check もオプションで利用できます。

これは、security impact が memory corruption ではなく、**panicless parser failure**、**concurrency bug**、または **DoS のみを引き起こす hang** である target に特に有効です。

### typed Go API 向けの struct-aware fuzzing

native Go fuzzing は主に `[]byte`、`string`、数値などの scalar を想定しています。テスト対象の code が typed object を受け取る場合、gosentry は bytes を内部で mutation しながら、composite value（struct、slice、array、pointer）を直接 fuzz できます。<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing専用の偽のwire formatを構築すると、harness内だけで使うパースコードによってロジックバグが隠れてしまいます。差分テストやgrammar-basedのキャンペーンでは、harnessの入力を単一の`[]byte`または`string`にして、代わりにcallback内でパースしてください。

### パーサーとプロトコル入力のgrammar-based fuzzing

パーサー、フォーマット、入力言語に対して、gosentryはLibAFL上で**Nautilus grammar fuzzing**を実行できます。grammarはproduction ruleのJSON配列で、harnessには通常、単一の`[]byte`または`string`引数を渡します。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法論に関するメモ:

- byte-level mutations が初期の構文チェックでほとんど失敗する場合は、grammar mode を使います。
- 文法は、言語やプロトコルの仕様全体ではなく、**セキュリティに関連するサブセット**に絞ります。
- 整数、長さ、状態機械の境界を試すため、terminal/nonterminal には大きな境界値を使います。
- grammar mode では入力の文法が有効に保たれますが、ターゲットが受け取るのは引き続き **bytes/strings** なので、パースとセマンティックチェックはハーネス化したコード内で行われます。

### Differential fuzzing: クラッシュだけでなく実装を比較する

Go ecosystem で有効なパターンは、**grammar-based differential fuzzing** です。有効な構造化入力を生成し、2つのパーサー、クライアント、または状態遷移エンジンに与えます。<sup>[[7]](#references)[[8]](#references)</sup>

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

次のようなものを検出結果として扱います。

- 一方の実装はpanicし、もう一方は正常に拒否する
- 入力の受理・拒否に食い違いがある
- parse treeやデコードされたオブジェクトが異なる
- state transition、nonce、balance、state rootに食い違いがある

これは、クラッシュの検出だけを目的とするfuzzingでは見逃されがちな**consensus mismatch**、**parser ambiguity**、**specと実装のずれ**を見つける実用的な方法です。

### カバレッジレポートの作成にキャンペーンのcorpusを再利用する

キャンペーンの終了後、保存されたqueue corpusを再生すれば、別のcorpusを手動でエクスポートすることなく、Goのカバレッジレポートを作成できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

同じパッケージから、同じ `-fuzz` ターゲットを指定してコマンドを実行し、gosentry が正しいキャッシュ済みキャンペーン状態を解決できるようにしてください。



## References

- [1] [ミューテーション文法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing 詳細ガイド](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 5年後：カバレッジガイド型プロトコル fuzzing について](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark がコードをグラフに変換](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing にはツールキットの半分が欠けていた。ツールチェーンをフォークして修正した。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：スナップショットを使用したステートフルネットワークプロトコル向け高速 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [文法がなくても問題なし：システムコール記述なしで Linux カーネルを fuzzing することを目指して](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：適応型・可変型スナップショットによる効率的な fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM インストルメンテーション：パスおよび呼び出し元カバレッジ](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [予測的なコンテキスト依存型 fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - ビルドおよび回帰シードのドキュメント](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
