# ファジング手法

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: カバレッジとセマンティクス

**mutational grammar fuzzing**では、入力を**文法的に有効な状態**に保ちながら変異させます。カバレッジガイド方式では、**新しいカバレッジ**を発生させたサンプルだけがコーパスのシードとして保存されます。**言語を対象とするもの**（パーサー、インタープリター、エンジン）では、ある構造の出力が別の構造の入力になるような**セマンティクス／データフローの連鎖**を必要とするバグを見逃すことがあります。<sup>[[1]](#references)</sup>

**失敗パターン:** ファザーが `document()` や `generate-id()`（または類似のプリミティブ）を個別に実行するシードを見つけても、**連鎖したデータフローを維持できない**ため、「バグにより近い」サンプルがカバレッジを増やさず、破棄されます。**依存するステップが3つ以上**あると、ランダムな再結合は高コストになり、カバレッジフィードバックも探索の指針になりません。<sup>[[1]](#references)</sup>

**意味するところ:** 依存関係の多い文法では、**mutationalフェーズとgenerativeフェーズを組み合わせる**か、カバレッジだけでなく**関数チェーン**のパターンを優先して生成することを検討してください。<sup>[[1]](#references)</sup>

## コーパスの多様性に関する落とし穴

カバレッジガイド変異は**貪欲**です。新しいカバレッジを生むサンプルはすぐに保存され、変更されていない大きな領域がそのまま残ることもよくあります。その結果、時間の経過とともに、構造的な多様性が低い**ほぼ同一のサンプル**がコーパスに蓄積します。過度な最小化は有用なコンテキストを取り除く可能性があるため、実用的な妥協策として、**最小トークン数に達したら停止する**文法対応の最小化を行います（ノイズを減らしつつ、変異しやすい状態を保つために必要な周辺構造を残します）。<sup>[[1]](#references)</sup>

mutational fuzzingにおける実用的なコーパスの原則は、ほぼ同一のサンプルを大量に集めるより、**構造の異なる少数のシードでカバレッジを最大化する**ことです。通常、具体的には次のようにします。<sup>[[1]](#references)[[3]](#references)</sup>

- **実世界のサンプル**（公開コーパス、クローリングで収集したデータ、キャプチャしたトラフィック、対象エコシステムのファイルセット）を出発点にする。
- 有効なサンプルをすべて残すのではなく、**カバレッジベースのコーパス最小化**でサンプルを絞り込む。
- 変異が無関係なバイトに大半のサイクルを費やさず、意味のあるフィールドに作用するよう、シードを**十分に小さく**保つ。
- ハーネスや計装に大きな変更を加えた後は、コーパスを再度最小化する。到達可能性が変われば、「最適な」コーパスも変わるため。

## Magic Valueに対する比較認識型の変異

ファザーが頭打ちになる一般的な原因は、構文ではなく**厳密な比較**です。たとえば、magic bytes、長さチェック、列挙値の文字列、チェックサム、`memcmp`、switchテーブル、または連鎖した比較によって保護されたパーサーのディスパッチ値などです。純粋なランダム変異では、これらの値をバイト単位で推測しようとしてサイクルを無駄にします。

こうした対象には、**比較トレース**（たとえばAFL++ `CMPLOG` / Redqueen形式のワークフロー）を使い、失敗した比較のオペランドをファザーが確認できるようにして、それらを満たす値に向けて変異を誘導します。<sup>[[3]](#references)</sup>

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
- 実際のサンプル、プロトコル仕様、デバッグログから抽出した **dictionaries** と組み合わせてください。文法トークン、チャンク名、verb、区切り文字を含む小さな辞書のほうが、汎用の巨大なワードリストより役立つことがよくあります。
- ターゲットが順次多くのチェックを行う場合は、最初の「magic」比較から先に解決し、その後、生成されたコーパスを再び最小化して、後続の段階がすでに有効なプレフィックスから始まるようにします。

## ファイル名言語を隠し持つ File API の Fuzzing

`filename`、`path`、`URL` という名前のパラメーターは、単なるファイル検索ではなく、インタープリターのエントリーポイントである可能性があります。たとえば、CFITSIO Extended Filename Syntax (EFS) は、開いたオブジェクトを返す前に、角括弧で囲まれたセレクター、行/ピクセル式、計算列、ヒストグラム、変換を評価します。一部の形式では、一時コピーも作成されます。攻撃対象領域を調査する際は、各 open/import API を **literal-path** と **interpreted-path** に分類し、アプリケーションが実際に呼び出す本番環境のエントリーポイントを fuzzing します。<sup>[[20]](#references)[[22]](#references)</sup>

結果として得られる SSRF、ファイルコピー、protocol handler のプリミティブ、およびより安全な literal-path API については、[Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs) を参照してください。<sup>[[20]](#references)</sup>

### Fuzzing 対象のプログラムと、背後で参照されるオブジェクトを分ける

文法がファイル名のサフィックスにある場合、参照先ファイルのバイト列だけを変更してもパーサーを検査できません。代わりに、小さなハーネスでテストケースを文字列として読み込み、それを interpreted open API に渡すことができます。CFITSIO のキャンペーンでは、`fits_open_file()` を読み取り専用モードで呼び出すことで、ほとんどの EFS パーサーと評価器に到達しました。セレクター/式言語に変更を集中させ、ベースパスを何度も壊さないよう、有効な backing file は別に用意しておきます。<sup>[[22]](#references)</sup>

それぞれ異なる文法ファミリーに到達するシードを使い、仕様と lexer/parser のソースの両方からコンパクトな辞書を作成します。同じ構文エラーの経路で入力が繰り返し失敗し、カバレッジが頭打ちになった場合は、有効なプレフィックスを維持し、ランダムな変更を行う時間を延ばすだけでなく、区切り文字、演算子、キーワード、関数名、代表的なフィールド名を追加します。<sup>[[22]](#references)</sup>

たとえば、文法辞書を使ってハーネスを実行します。<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 「read-only」harnessの副作用を抑える

ライブラリのread-onlyフラグがあっても、testcaseで副作用が発生しないとは限りません。filename languageが入力を書き換えたり、出力ファイルを作成したり、一時オブジェクトを実体化したりすることがあります。CFITSIOのcampaignでは、seedファイルが最初に破壊され、filesystem全体に予期しないファイルが残ったため、cleanupと隔離が必要でした。<sup>[[22]](#references)</sup>

- 各workerに使い捨てのworking directoryと専用のtemporary directoryを割り当てる。
- 正規のbacking fileのコピーを公開し、targetがcorpusの唯一のコピーを変更できないようにする。
- リモートbackendが対象でない限り、network accessを無効にし、container、mount namespace、または同等のsandboxで書き込み可能なpathを制限する。
- 各実行またはworker batchの後にdirectoryをリセットし、予期しないfilesystemの変更も追加のfindingとして扱う。

### Crash-to-patch-to-fuzzのループ

修正前にcrashをcluster化し、何千ものartifactが何千ものpatch作業にならないようにします。CFITSIOのassessmentでは、AFLTriageによって最初のcrash群が少数のroot causeに絞り込まれました。これを受けたadvisoryでは、宛先サイズのチェックミス、`realloc()`後の古いpointer、算術エラー、安全でないparser cleanup pathなど、異なるfailureが示されています。<sup>[[21]](#references)[[22]](#references)</sup>

1. 各clusterの代表的な入力を最小化し、AddressSanitizerを使って再現する。
2. 失敗したaccess、source location、allocation/freeの履歴、不変条件が崩れたparser stateを正確に記録する。
3. 範囲を絞ったcandidate patchを1つ適用し、同じcoverageおよびsanitizer instrumentationで再ビルドする。
4. 元のreproducerと**cluster内のすべての入力**を再実行する。エラーパスでmemory-safetyの修正がownershipを壊す可能性もあるため、leak detectionも有効にする。
5. 実ファイルを使ったfunctional testを実行し、蓄積したqueueから再開する（または、binaryの変更後にengineが新しいoutput directoryを必要とする場合は、そのqueueを再インポートする）。
6. この手順を繰り返す。最初の浅いcrashを取り除くことで、既存のseedがより深いparser stateまで進めることがよくあります。

crashing input、sanitizer report、harness、関連するsourceを与えれば、LLMは手順2を迅速化し、手順3の案を作成できますが、そのpatchは信頼できるものとして扱ってはいけません。修正を受け入れるかどうかを決めるのは、sanitizerによる再実行とregression gateであり、modelの説明ではありません。<sup>[[22]](#references)</sup>

## Edge Coverageで異なるPathが区別できない場合の、より豊富なFeedback

通常のedge coverageでは、同じhelperを異なるcaller経由で実行した場合や、関数内で異なるbranchの組み合わせを通った場合でも、2つの実行を区別できません。共有decoder、protocol dispatcher、interpreter helperなどでは、edgeに到達するまでの**経路**によって、live stateが異なるため重要です。一方、すべてのcalling contextを単純に追跡すると危険です。coverage mapとqueueが急増する可能性があります。そのため、context-sensitive fuzzingの研究では、call graph全体をcontext-sensitiveに扱うのではなく、有望なcontextだけを絞り込むことが推奨されています。<sup>[[14]](#references)</sup>

最近のAFL++のbuildでは、通常のedge coverageに加えて、**関数ごとのBall-Larus path coverage**を利用できます。これは関数内の各非巡回pathにfeatureを割り当てます。loopのback-edgeは取り除かれるため、このfeedbackで区別できるのはbranchの組み合わせであり、**loopの反復回数ではありません**。まずは緩いlevel `1`から始め、path数が指数関数的に増える可能性があるため、より厳しいmodeは疑わしいparserやstate machineのコードに限定して適用します。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

多くのセキュリティ関連箇所から呼び出されるヘルパーでは、LTO モードにより各関数のパスと直近の呼び出し元を組み合わせることができます:<sup>[[13]](#references)</sup>

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

- 通常の edge-coverage インスタンスも並行して実行してください。追加の queue/map コストによって executions per second が損なわれない場合に限り、より豊富なフィードバックが有効です。
- 大規模なテンプレート主体のライブラリや汎用ユーティリティコードが map の大部分を占める場合は、`AFL_LLVM_ALLOWLIST` を使って path/caller instrumentation の対象を絞り込んでください。
- acyclic path が過剰な関数は AFL++ でスキップされる場合があります。コンパイル時の警告は、対象に allowlisting を適用するか、より緩い level を使う必要があることを示しています。
- Caller + path coverage が対応する caller depth は 1 つだけです。より深い context stack と組み合わせないでください。
- Path ID は LLVM のメジャーバージョン間で変わることがあります。キャンペーン中は toolchain を固定し、PATH ベースの corpus を、build 間で feature ID が安定しているかのように同期しないでください。
- このフィードバックは `CMPLOG` を補完します。comparison tracing は **guard を通過する値**を特定するのに対し、path/caller feedback は**どの経路と分岐の組み合わせでそこに到達したか**を保持します。

## Stateful Fuzzing: シーケンスを seed にする

**protocol**、**authenticated workflow**、**multi-stage parser** では、興味深い単位は単一の blob ではなく、**message sequence** であることがよくあります。transcript 全体を 1 つのファイルに連結して盲目的に mutation する方法は、たいてい効率がよくありません。fuzzer は、脆弱な状態に到達するのが後続の message だけであっても、すべてのステップを均等に mutation するためです。<sup>[[4]](#references)</sup>

より効果的な方法は、**sequence 自体を seed として扱い**、追加のフィードバックとして**観測可能な状態**（response code、protocol state、parser phase、返された object type）を使うことです。<sup>[[4]](#references)</sup>

- **有効な prefix message** は安定させ、**状態遷移を引き起こす** message の mutation に集中してください。
- 次のステップが依存する場合は、識別子やサーバー生成値を以前の response からキャッシュしてください。
- シリアライズされた transcript 全体を不透明な blob として mutation するより、message ごとの mutation/splicing を優先してください。
- protocol が意味のある response code を返す場合は、それを**低コストな状態 oracle**として使い、より深く進行する sequence を優先してください。

これが、認証が必要な bug、隠れた状態遷移、または「handshake 後のみ」の parser bug が、従来の file-style fuzzing では見逃されやすい理由です。fuzzer は構造だけでなく、**順序、状態、依存関係**も維持する必要があります。<sup>[[4]](#references)</sup>

### Android Binder: 複数クライアントの driver fuzzing

edge coverage が高くても、coverage では**object の所有権、reference count、保留中の message、cleanup の順序、thread の interleaving**を把握できないため、IPC driver の bug を見逃すことがあります。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) のページでは driver の object model を解説しています。この例では fuzzer harness に焦点を当てます。Android Binder は有用なモデルです。複数の process に必要な順序で同じ kernel object を操作させられなければ、allocation path と free path の両方に到達するだけでは不十分です。<sup>[[15]](#references)</sup>

#### 個々の `ioctl` buffer ではなく protocol をモデル化する

test case は、**client identity + operation + structured argument**からなる順序付き grammar として表現します。Binder LKL fuzzer は protobuf と `libprotobuf-mutator` を使い、persistent な context-manager client 1 つと通常の client 2 つを用意します。semantic harness は、盲目的な byte mutation で壊れてしまう関係性を維持します。<sup>[[15]](#references)</sup>

- 先行する operation から返された値をキャッシュします。たとえば、`BC_FREE_BUFFER` では、以前の `ioctl` が返した transaction-buffer pointer を再利用する必要があります。
- 有効なデフォルトの reply を生成し、同期 transaction を完了できるようにして、後続の operation に到達できる状態を保ちます。
- self-transaction や、同じ target に対する複数の保留中 transaction など、不可能な状態遷移を拒否します。
- singleton の bootstrap state は、入力ごとの reset の対象外にします。Binder では boot ごとに `BINDER_SET_CONTEXT_MGR` の登録は 1 回しかできないため、その client を繰り返し破棄して作り直すと、後続の入力が無効になります。

有用な lifetime-race のテンプレートでは、ある client に object を転送させ、thread または process の cleanup を開始し、受信側の client に transaction buffer を同時に解放させます。CVE-2020-0423 の例では、`BINDER_TYPE_WEAK_BINDER` の転送後に `BINDER_THREAD_EXIT` と `BC_FREE_BUFFER` が競合すると、終了中の thread の cleanup path がまだ使用している embedded `binder_work` が解放される可能性がありました。<sup>[[15]](#references)</sup>

#### userspace kernel で制御された interleaving を再現する

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) は実際の kernel code を userspace harness に link し、`lkl_syscall` を通じて syscall interface を公開します。これにより、protobuf state、coverage、KASAN を 1 つの process 内で簡単に連携できます。ただし LKL は通常、別の kernel thread に割り込まれずに syscall を実行します。race campaign では、選択した lock/unlock と lifetime の境界付近に `schedule()` point を挿入し、各 yield で次の client を harness にランダムに選ばせてください。各 point は scheduling の探索空間を増大させるため、対象を絞ってください。研究者が説明した randomized scheduler は、upstream Binder fuzzer には含まれていません。<sup>[[15]](#references)</sup>

#### シリアライズされた回帰 seed を build して再実行する

upstream harness は互換性のある `libprotobuf-mutator` を固定し、`LKL_FUZZING=1` で LKL fuzzing instrumentation と KASAN を有効にし、Binder 用に `MMU=1` で `CONFIG_MMU` を有効にします。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

意図的に脆弱なリビジョンをチェックアウトするか、upstreamで文書化されたロールバックパッチを適用すれば、シリアライズされたシードを使って、場当たり的なC製PoCで状態遷移を再構築することなく、複数クライアント間の状態遷移全体を再現できます。<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

生成された use-after-free の KASAN を、seed が脆弱なライフタイム経路に到達したことの確認として扱います。これは、カーネルコード実行や権限昇格に必要な後続のプリミティブを実証するものでは**ありません**。<sup>[[16]](#references)</sup>

## 単一マシンで多様性を生み出す方法（Jackalope 方式）

**生成による新規性**と**coverage の再利用**を組み合わせる実用的な方法は、永続サーバーに対して短命の worker を再起動することです。各 worker は空の corpus から開始し、`T` 秒後に同期し、統合された corpus でさらに `T` 秒間実行して、再度同期した後に終了します。これにより、蓄積した coverage を活用しながら、**世代ごとに新しい構造**を生成できます。<sup>[[1]](#references)[[2]](#references)</sup>

**サーバー:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequential workers（ループの例）：**

<details>
<summary>Jackalope ワーカーの再起動ループ</summary>

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
- `-server_update_interval T` は**遅延同期**（最初は novelty を優先し、その後 reuse）を近似します。
- grammar fuzzing mode では、デフォルトで**初期 server sync はスキップされます**（`-skip_initial_server_sync` は不要）。
- 最適な `T` は**target に依存します**。worker が「簡単な」coverage の大半を発見した後に切り替えるとうまくいく傾向があります。

## ハーネス化が難しい Target 向けの Snapshot Fuzzing

テストしたい code に到達するまでに**大きなセットアップコスト**（VM の起動、ログインの完了、packet の受信、container の解析、service の初期化など）がかかる場合、**snapshot fuzzing**が有用な代替手段になります。準備が整った process または VM の状態を取得し、各 testcase を target の入力経路に注入して、crash/timeout まで実行した後、snapshot を復元します。これにより初期化や protocol prefix の繰り返しを避けられ、**network service**、**firmware**、**認証後の attack surface**、**binary-only target**に役立ちます。<sup>[[9]](#references)[[10]](#references)</sup>

1. 興味のある状態が準備できるまで target を実行します。
2. その時点の**memory + registers**を snapshot に保存します。
3. 各 testcase について、mutate した入力を関連する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. snapshot を復元します。VM target では、対応している場合は**dirty page**のみを復元し、繰り返します。

snapshot は、`recv`/`read` の後や packet のデシリアライズ時など、最初にコストのかかる parse/dispatch が行われる箇所のできるだけ近くに配置し、target が使用する入力 buffer を記録します。これは、処理を繰り返さずに済むよう snapshot を入力処理の奥へ移動する、適応的配置の原則に沿っています。<sup>[[11]](#references)</sup>

### Protocol state 向けの Incremental snapshot

固定 snapshot はセットアップコストを避けられますが、複数の有効な message を必要とする遷移を、それだけで探索できるわけではありません。LibAFL-Qemu harness は protocol-state field への書き込みを監視し、state が変化したときに新しい snapshot を保存できます。[libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) は `tcpcb.t_state` を監視し、state と response flag を hash 化して snapshot の重複を排除し、親 snapshot との差分 dirty page を保存します。次の構造化 message を mutate する前に、選択した snapshot を親からたどって復元します。testcase は `SnapshotId` と生成した入力 byte（`gen_bytes`）を保持し、snapshot manager は replay に必要な親子関係を追跡します。<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu の user-mode `SnapshotModule` は mapping と target memory を保存しますが、CPU register は保存しません。必要に応じて別途保持してください。説明されている manager が扱えるのは root snapshot tree 1 つで、worker 間で snapshot ID を共有できません。また、その multi-snapshot mode では QASAN shadow state を直接再利用できません。offline triage では、別の instrumented process で入力 chain を再構築してください。`AsanHostModule` と `DrCovModule` を使う場合、`fuzzer.evaluate_input` は必要な `pre_exec`/`post_exec` callback を実行しますが、`qemu.run` だけでは実行されません。<sup>[[27]](#references)[[28]](#references)</sup>

### 論理 ring buffer の overread を検出する

buffer の*有効データ数*を超えた read が host allocation の範囲内に収まると、通常の ASAN では検出されないことがあります。[libslirp の urgent-data の例](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes)では、unsigned byte count の underflow も発生します。source が利用できる場合は、signed/unsigned integer-overflow instrumentation でその副作用を検出できます。報告を抑制する前に、意図的な TCP sequence-number の wrap と区別してください。より強力な oracle として提案されているのは、custom ring allocation を poison し、内部 allocator の進行に合わせて有効範囲のみを unpoison し、解放された範囲を再度 poison する方法です。LibAFL-Qemu は、source instrumentation が実用的でない target 向けに ASAN poisoning API を提供しています。<sup>[[27]](#references)</sup>

## MAccConc による Linux Kernel Race の探索

[MAccConc](https://github.com/googleprojectzero/MAccConc) は、タイミングに左右される Linux kernel の race を、再現可能な memory-access schedule に変換します。2-context の **A-B-A** 実行を自動で列挙することも、terminal UI/GUI で analyst が順序制約を指定することもできます。これは完全な concurrency fuzzer ではなく、実験的な研究ツールです。現在は LLVM 23+ と project の patch 適用済み kernel が必要で、command-line tool がサポートする test thread は 2 つです。また、提案されている userspace fuzzing layer は未実装です。<sup>[[17]](#references)[[18]](#references)</sup>

### Context 間の通信ポイントを収集する

KASAN outline callback と、patch 適用済み KCOV memory-record support を有効にして instrumented kernel を build します。project の README では、call stack を利用可能な状態に保つため、sibling-call optimization を無効にすることも推奨しています。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) は、instrumented access を helper call に変換します。MAccConc の kernel patch は `asan-opt-same-temp` を無効にして連続する access がマージされないようにします。global variable の race を検出する必要がある場合は、`asan-opt-globals` 最適化も無効にします。KCOV は生成された record を userspace に渡します。異なる実行コンテキストからの access を比較し、byte range が重複し、少なくとも一方が write であるペアを保持します。lifetime の遷移も候補に含めるため、`kfree()` は write としてモデル化します。<sup>[[17]](#references)</sup>

initiating task の外で行われる packet processing や RCU callback などの処理では、subsystem が KCOV remote-coverage handle を伝播する必要があります。upstream の remote KCOV は opt-in であり、任意の background work で自動的に利用できるわけではないため、伝播が欠けると実際の相互作用が検出されない可能性があります。<sup>[[17]](#references)[[19]](#references)</sup>

### 毎回同じ動的 access を特定する

割り当てごとに変わる可能性のある具体的な heap address や、`memcpy()` や `spin_lock()` などの helper 内では曖昧になる instruction address だけを使って replay しないでください。MAccConc は **count-augmented stack trace** を使用します。各 frame は callee と、その caller 内での呼び出し回数を識別し、最後の要素は memory-access instruction を識別します。SanitizerCoverage の function-entry/exit record を使い、userspace がこの動的識別子を再構成します。これは address の変化や無関係な control-flow のノイズがあっても安定しています。<sup>[[17]](#references)</sup>

### 候補ペアを強制スケジュールに変換する

パッチ適用済みの `KCOV_SET_DI` ioctl は、count-augmented access identifier を shared-flag action に関連付けます。<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 選択した access の直前に flag *N* を設定します。 |
| `DI_STACK_WAIT` | 選択した access の直前に、flag *N* が設定されるか、設定済みの上限時間が経過するまで spin します。 |
| `DI_STACK_WAKE_POST` | 選択した access の直後に flag *N* を設定します。 |

部分的な **A-happens-before-B** 制約では、A に `DI_STACK_WAKE_POST`、B に `DI_STACK_WAIT` を同じ flag で設定します。完全に指定された二つのコンテキストのスケジュールでは、B をブロック状態で開始し、A が最初の切り替え地点で B を起こして待機するようにします。次の切り替え地点では、B が逆の操作を行います。後者は決定論的な context switching のように動作し、自動 A-B-A explorer が使用する方式です。<sup>[[17]](#references)</sup>

最小限の campaign では、4 つの hook（`test_setup`、2 つの thread function、`test_end`）を含む test case を shared library としてコンパイルし、制約のない trace を収集してから、A-B-A 候補を列挙するか、疑わしい access の周辺に手動で制約を追加します。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

タイムアウトと成功した順序変更は別々に解釈してください。ロックや初期化／公開の依存関係によって、2つ目のコンテキストが注入ポイントに到達できず、要求した順序が実現不可能な場合があります。また、KASANの検出できないケースにも注意してください。直接のスタックアクセスは、範囲外アクセスの可能性がない限り通常フックされず、デフォルトの最適化ではグローバル変数が省略され、現在のコンパイラはASANとTSANのフックを同時に生成できません。さらに、このプロトタイプではゲストがパニックを起こすとKCOVバッファが失われるため、独立したクラッシュコンソール／オラクルを用意してください。<sup>[[17]](#references)</sup>

今後の並行性ガイド型ファジングでは、入力またはシステムコールごとにメモリアクセスの概要を記録し、コンテキスト間の通信ポイントを形成する操作を組み合わせて、その組み合わせだけを探索します。VMスナップショットを使えば、グローバル状態とアドレスを安定させられます。スナップショットを使わない場合は、割り当て地点のメタデータを使って実行間でオブジェクトを抽象化できます。これは提案されている拡張であり、現在のMAccConcユーザースペースツールの機能ではありません。<sup>[[17]](#references)</sup>

## Harnessのイントロスペクション: 浅いFuzzerを早期に見つける

キャンペーンが停滞したとき、問題はmutatorではなく、**Harness**にあることがよくあります。**到達可能性／カバレッジのイントロスペクション**を使い、ファズターゲットから静的には到達可能でも、動的にはほとんど、あるいはまったくカバーされない関数を見つけてください。これらの関数は通常、次の3つの問題のいずれかを示しています。<sup>[[12]](#references)</sup>

- Harnessがターゲットに入るタイミングが早すぎる、または遅すぎる。
- シードコーパスに機能群全体が欠けている。
- 対象には、何でも処理する巨大なHarnessを1つ用意するのではなく、**2つ目のHarness**が本当に必要である。

OSS-Fuzz／ClusterFuzz形式のワークフローを使っている場合、Fuzz Introspectorは静的な到達可能性と実行時カバレッジを比較し、時間を区切った実行や公開コーパスからレポートを生成できます。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

レポートを参考に、未テストのパーサーパス向けに新しいハーネスを追加するか、特定の機能のコーパスを拡充するか、単一の巨大なハーネスをより小さなエントリポイントに分割するかを判断します。

## グラフ優先のファズターゲット選定とミューテーションのトリアージ

すでに**静的解析の検出結果**、**ミューテーションテストの生存変異**、**カバレッジレポート**がある場合、それらを独立したリストとしてトリアージしないでください。まず**コールグラフ**を作成し、ノードに**循環的複雑度**、**エントリポイント／信頼されない入力からの到達可能性**、外部の検出結果を注釈として付けてから、グラフに関する問いを立てます。<sup>[[5]](#references)[[6]](#references)</sup>

- 複雑度の高い関数のうち、信頼されない入力から到達可能なのはどれか？
- パーサー／ハンドラーからセキュリティ上重要なコードへのパス上にある生存変異はどれか？
- 異常に大きな**影響範囲**を持つ、アーキテクチャ上の要所となる関数はどれか？

この方法では、単に「カバレッジが最も低い」関数を選ぶよりも、優れたファズターゲットが見つかることがよくあります。**複雑度が高く**、**外部から到達可能であることが確認されている**パーサー／デコーダーは、カバレッジが低くても攻撃者が制御できるパスがない孤立した内部ヘルパーより、ハーネスの有力候補です。

### 実践的なトリアージのワークフロー

1. コードベースから**コードグラフ**を作成し、関数ごとの複雑度／分岐のメトリクスを抽出します。
2. 攻撃者が制御する入力を受け付ける**エントリポイント**を列挙します。例：リクエストハンドラー、デコーダー、インポーター、プロトコルパーサー、CLI／ファイルリーダー。
3. エントリポイントから候補関数へのパスクエリを実行し、到達可能な攻撃対象領域と、到達不能または内部のみで使用されるコードを区別します。
4. 次の条件が重なるノードを優先します。
   - 高い**循環的複雑度**
   - 信頼されない入力からの**到達可能性が確認されている**
   - 大きな**影響範囲**、または下流の依存先が多数ある
   - **SARIF**の検出結果、監査メモ、生存変異などの裏付けとなる証拠がある
5. 評価の高いノードから、対象を絞ったハーネスを作成します。特に、hex/Base64/IP/メッセージデコーダーなどの**パーサー／codec**を優先します。

### 生存変異：等価か、対処可能か

ミューテーションテストでは、生存変異のリストにノイズが多く含まれることがよくあります。すべての生存変異をセキュリティ上の問題として扱う前に、グラフを使って次の点を確認します。

- 変異された関数は、攻撃者が制御するエントリポイントから到達可能か？
- すべての呼び出しパスは、変異されたチェックよりも強い不変条件によって制約されているか？
- そのノードは、デッドコード、書式設定のみのロジック、または影響の大きい算術／パーサーパスのいずれに位置するか？

到達不能なままの生存変異や、構造的な制約を受けている生存変異は、多くの場合**等価変異**です。**到達可能**なままで、**境界条件**、**オーバーフロー／キャリーのパス**、または**セキュリティ上重要な算術処理／パース処理**に関わる生存変異は、次の項目に昇格させるべきです。

- 新しいファズハーネス
- 直接的なプロパティ／不変条件テスト
- 対象を絞ったエッジケースのテストベクター

### 外部の検出結果をグラフに対応付ける

SASTパイプラインから**SARIF**をエクスポートする場合、**ファイル名＋行範囲**で検出結果をグラフのノードに対応付け、グラフを使って影響範囲を広げて確認します。<sup>[[6]](#references)</sup>

- 検出対象の関数の**影響範囲**を算出する
- 検出結果がエントリポイントからのいずれかのパス上にあるか確認する
- 近接する検出結果を、同じ要所に集約されるものごとにまとめる

この方法は、特定の関数にファズの時間を割くべきか判断する際に役立ちます。**到達可能**で、**複雑度が高く**、すでに**SASTの検出結果がある**ノードは、攻撃者からのパスがない複雑なだけのノードより、有力なターゲットとなることがよくあります。

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

重要な方法論は、**複雑さ x 露出度 x 影響度**の交差点です。グラフを使って、期待されるセキュリティ価値が最も高い fuzz 対象を選び、変異後も残った入力をもとに、ハーネスで負荷をかけるべき境界や不変条件を判断します。<sup>[[5]](#references)</sup>

## 暗号鍵エンコーディングの差分 fuzzing

有効なシリアライズ済み鍵または標準テストベクトルから始めます。import と操作の処理経路に到達できるよう、必要な長さや構造を保ちながらエンコードされたフィールドを変異させ、同じバイト列を独立した実装に入力します。受け入れの可否とエラーを比較します。ランダム化される署名や暗号文には、バイト単位の比較ではなく、正しさを判定するオラクルが必要です。署名を検証するか、カプセル化／デカプセル化の往復で共有秘密を比較します。テストベクトルは既知のケースに対する準拠を確認し、差分変異はその範囲を超えた不正なエンコーディングを調べます。<sup>[[23]](#references)[[26]](#references)</sup>

これらの鍵形式では、形式ごとのオラクルを使用します。<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** 鍵をパース可能な状態に保ちながら、パックされた `s1` または `s2` の係数を `[-η, η]` の範囲外に変更します。import または署名が拒否されるか、生成された署名が検証に通るかを確認します。受け入れの可否に差があるだけでは、規格違反とは限りません。FIPS 204 は追加の秘密鍵チェックを義務付けていないためです。[conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)を参照してください。
- **ML-KEM key pairs:** 必須のカプセル化鍵チェックおよびデカプセル化入力チェックと、import した鍵ペアに対する任意のペアワイズ整合性チェック（PCT）を分けて確認します。公開鍵でカプセル化し、秘密鍵でデカプセル化して、共有秘密を比較します。個々の鍵が入力チェックを通過しても、不一致があれば暗号化通信が破損する可能性があります。API が操作内で入力を検証するのか、別の呼び出しで検証するのか確認します。libcrux は `validate_public_key(pk)` と `validate_private_key(sk, ct)` を提供しますが、これらは PCT の代わりにはなりません。
- **XMSS/XMSSMT raw keys:** メモリ上の鍵を使った操作だけでなく、パラメーターセットごとにシリアライズされた**署名鍵と検証鍵**の往復をテストします。XMSS と XMSSMT はそれぞれ独立した4バイトの OID 名前空間を持つため、XMSS を先に試す OID のみのパーサーは、衝突する XMSSMT 鍵を誤分類してimportを拒否する可能性があります。報告された RustCrypto のパーサーの問題は、署名の偽造ではなく、相互運用性／可用性の障害を示すものです。

## gosentryによるGo Fuzzing: 強化されたエンジン、型付き入力、差分チェック

Go のターゲットにネイティブな `testing.F` ハーネスがある場合、実用的なアップグレード方法の一つは、[gosentry](https://github.com/trailofbits/gosentry)を使って同じハーネスを実行することです。これは `go test -fuzz` を維持しつつ、バックエンドを**LibAFL**に切り替える Go ツールチェーンのフォークです。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

これは、ネイティブの Go fuzzer が**難しい比較**、**型付き入力**、または**パーサー中心の形式**で停滞した場合に役立ちます。手法は同じです。

- シードには引き続き `f.Add(...)`、コールバックには `f.Fuzz(...)` を使用します。
- 同じ harness を再利用し、標準の toolchain ではなく gosentry の `go` バイナリで実行します。
- 結果の campaign は通常の coverage-guided run として扱いますが、LibAFL のスケジューリング／mutation と、より充実した周辺 detector を活用します。

### サイレントな失敗を fuzz の検出結果に変える

Go の assessment でよくある問題は、危険な動作がデフォルトでは**クラッシュしない**ことです。gosentry を使うと、「問題はあるがサイレント」な状態をいくつか検出結果に昇格できます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` を指定すると、選択した logging/error の処理をクラッシュのように動作させられます（通常はログを出して続行するだけの `log.Fatal` 系コードパスに有用です）。
- `--catch-races=true` を指定すると、新たに見つかった queue entry を Go race detector で再実行します。
- `--catch-leaks=true` を指定すると、新しい queue entry を `goleak` で再実行し、goroutine leak があれば停止します。
- LibAFL の hang 処理により、**無限ループ／非常に遅い入力**をタイムアウトとして消失させず、fuzz の検出結果として保持できます。
- 算術オーバーフローのチェックはデフォルトで組み込まれており、go-panikint 形式の instrumentation による切り詰めチェックも任意で有効にできます。

これは、セキュリティ上の影響がメモリ破損ではなく、**panic を伴わないパーサーの失敗**、**並行性のバグ**、または **DoS のみを引き起こす hang** である対象に特に有効です。

### 型付き Go API 向けの構造体対応 fuzzing

ネイティブの Go fuzzing は、主に `[]byte`、`string`、数値などのスカラー値を想定しています。テスト対象のコードが型付きオブジェクトを処理する場合、gosentry はバイト列を内部で mutation しながら、構造体、スライス、配列、ポインターなどの**複合値**を直接 fuzz できます。<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing専用の偽のwire formatを構築すると、harness内だけで使うパーサーコードの背後にlogic bugが隠れてしまいます。差分テストやgrammar-based fuzzingのcampaignでは、harnessの入力を単一の`[]byte`または`string`にし、代わりにcallback内でパースしてください。

### パーサーやプロトコル入力向けのgrammar-based fuzzing

パーサー、フォーマット、入力言語には、gosentryでLibAFL上の**Nautilus grammar fuzzing**を実行できます。grammarはproduction ruleのJSON配列で、通常、harnessは単一の`[]byte`または`string`引数を受け取るようにします。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- byte-level mutationsの大半が初期の構文チェックで失敗する場合は、grammar modeを使います。
- grammarは、言語やプロトコルの仕様全体ではなく、**セキュリティに関係するサブセット**に絞ります。
- terminal/nonterminalには大きな境界値を使い、整数、長さ、ステートマシンの境界をストレステストします。
- grammar modeでは入力の文法的な妥当性が保たれますが、ターゲットが受け取るのは引き続き**bytes/strings**です。そのため、パースとセマンティックチェックはハーネス化したコード内で行われます。

### Differential fuzzing: クラッシュだけでなく実装を比較する

Goエコシステムで有効なパターンは、**grammar-based differential fuzzing**です。妥当な構造化入力を生成し、2つのパーサー、クライアント、または状態遷移エンジンに渡します。<sup>[[7]](#references)[[8]](#references)</sup>

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
- 入力の受理・拒否結果が一致しない
- パースツリーまたはデコードされたオブジェクトが異なる
- 状態遷移、nonce、残高、state rootが異なる

これは、単純なクラッシュファジングでは見つけにくい**コンセンサスの不一致**、**パーサーの曖昧さ**、**仕様と実装の乖離**を見つける実践的な方法です。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### カバレッジレポートの生成にキャンペーンのコーパスを再利用する

キャンペーン後に保存済みのキューコーパスを再生すれば、別途コーパスを手動でエクスポートせずにGoのカバレッジレポートを生成できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

同じ package から、同じ `-fuzz` target を指定してコマンドを実行し、gosentry が正しいキャッシュ済み campaign state を解決できるようにします。

## References

- [1] [変異文法ファジング](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ ファジングの詳細](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [5年後のAFLNet：カバレッジガイド型プロトコルファジングについて](https://arxiv.org/abs/2412.20324)
- [5] [Trailmarkはコードをグラフに変換する](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Goのファジングにはツールキットの半分が欠けていた。それを修正するため、ツールチェーンをforkした。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：スナップショットを用いたステートフルネットワークプロトコル向け高速Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [文法がなくても問題なし：システムコール記述なしでLinuxカーネルをファジングするために](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：適応型・変更可能なスナップショットによる効率的なファジング](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation：パスと呼び出し元のカバレッジ](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [予測型コンテキスト依存ファジング](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - ビルドと回帰シードのドキュメント](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：制御されたメモリアクセスのインターリーブによるLinuxカーネルの競合状態の調査](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：ファジング向けコードカバレッジ](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO拡張ファイル名構文](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensecアドバイザリ：CFITSIO 2025年第4四半期](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO拡張ファイル名構文のファジング：16件のメモリ安全性脆弱性とCodex支援によるトリアージ](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [暗号技術の差分ファジング](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203：モジュール格子ベースの鍵カプセル化メカニズム標準](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID解析バグ - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [耐量子暗号の実装状況](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [スナップショットを活用してCVE-2026-9539にたどり着く](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
