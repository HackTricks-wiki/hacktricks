# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** では、入力を **grammar-valid** な状態に保ちながら変異させます。coverage-guided モードでは、**new coverage** を発生させたサンプルのみが corpus seed として保存されます。**language targets**（parser、interpreter、engine）では、ある構造体の出力が別の構造体の入力になるような **semantic/dataflow chain** を必要とするバグを見逃す可能性があります。<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer は `document()` と `generate-id()`（または類似の primitive）を個別に実行する seed を見つけますが、**chained dataflow** を保持しないため、「bug に近い」サンプルは coverage を追加しないものとして破棄されます。依存するステップが 3 つ以上ある場合、ランダムな再結合は高コストになり、coverage feedback では探索を誘導できません。<sup>[[1]](#references)</sup>

**Implication:** 依存関係の多い grammar では、**mutational phase** と **generative phase** を **hybridize** するか、coverage だけでなく **function chaining** パターンを優先するよう generation に bias をかけることを検討してください。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation は **greedy** です。new coverage を持つサンプルはすぐに保存され、多くの場合、大部分の変更されていない領域も保持されます。時間の経過とともに、corpus は構造的多様性の低い **near-duplicate** で構成されるようになります。過度な minimization は有用な context を削除する可能性があるため、実用的な妥協策は、**minimum token threshold** に達した時点で停止する **grammar-aware minimization** です（noise を減らしつつ、mutation-friendly であり続けるのに十分な周辺構造を維持します）。<sup>[[1]](#references)</sup>

mutational fuzzing における実用的な corpus のルールは、多数の near-duplicate よりも、coverage を最大化する構造的に異なる少数の seed を **prefer** することです。実際には、通常は次のようになります。<sup>[[1]](#references)[[3]](#references)</sup>

- **real-world samples**（public corpus、crawling、captured traffic、target ecosystem から取得した file set）から開始する。
- すべての valid sample を保持するのではなく、**coverage-based corpus minimization** で絞り込む。
- mutation が意味のある field に適用されるよう、seed は十分に小さく保つ。これにより、無関係な byte に大半の cycle を費やすことを避ける。
- 大規模な harness/instrumentation の変更後は corpus minimization を再実行する。reachability が変化すると、「最適な」corpus も変わるためである。

## Comparison-Aware Mutation For Magic Values

fuzzer が plateau に達する一般的な理由は syntax ではなく、magic byte、length check、enum string、checksum、または `memcmp`、switch table、連続した comparison によって保護された parser dispatch value などの **hard comparison** です。Pure random mutation では、これらの値を byte 単位で推測しようとして cycle を浪費します。

このような target には **comparison tracing**（例えば AFL++ の `CMPLOG` / Redqueen-style workflow）を使用し、fuzzer が failed comparison の operand を観測できるようにします。これにより、それらを満たす値に向けて mutation を bias できます。<sup>[[3]](#references)</sup>
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

- これは、target が **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** の背後に深いロジックを隠している場合に特に有用です。
- 実際のサンプル、protocol specs、または debug logs から抽出した **dictionaries** と組み合わせてください。grammar tokens、chunk names、verbs、delimiters を含む小規模な dictionary は、大規模な汎用 wordlist よりも価値があることがよくあります。
- target が多数の sequential checks を実行する場合は、最初に最も早い「magic」比較を解決し、その後、得られた corpus を再度 minimize してください。これにより、後続ステージはすでに有効な prefixes から開始できます。

## Edge Coverage で異なる Path が区別できない場合の、より豊富な Feedback

通常の edge coverage では、異なる caller を経由して同じ helper を通過する executions や、function 内で異なる branch combinations を選択する executions を区別できません。これは、**route** から edge までの経路が live state を決定する、shared decoders、protocol dispatchers、interpreter helpers で重要になります。すべての calling context を単純に追跡するのも危険です。coverage map と queue が爆発的に増大する可能性があるためです。そのため、context-sensitive fuzzing の研究では、call graph 全体を context-sensitive として扱うのではなく、有望な contexts のみを段階的に詳細化することが推奨されています。<sup>[[14]](#references)</sup>

最近の AFL++ builds では、通常の edge coverage に加えて **Ball-Larus per-function path coverage** が提供されています。これは function を通る各 acyclic path に feature を割り当てます。loop back-edges は削除されるため、この feedback で区別できるのは branch combinations であり、**loop iteration counts ではありません**。まずは緩やかな level `1` から開始し、path の数が指数関数的に増加する可能性があるため、より厳格な modes は疑わしい parser/state-machine code に限定してください。<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
多くの security-relevant な箇所から呼び出される helper では、LTO mode により、各関数パスをその直接の call site と組み合わせられます:<sup>[[13]](#references)</sup>
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

- 通常のedge-coverageインスタンスを並行して実行してください。追加のqueue/mapコストによって1秒あたりの実行回数が大幅に低下しない場合にのみ、richer feedbackは有用です。
- 大規模なtemplate-heavy libraryや汎用utility codeがmapの大部分を占める場合は、`AFL_LLVM_ALLOWLIST`を使用してpath/caller instrumentationを制限してください。
- 非循環pathが過剰なfunctionはAFL++でスキップできます。コンパイル中のwarningは、targetにallowlistingまたはより緩いlevelが必要であることを示します。
- Caller + path coverageがサポートするcaller depthは1つだけです。これをより深いcontext stackと組み合わせないでください。
- Path IDはLLVMのmajor version間で変わる可能性があります。1つのcampaignではtoolchainを固定し、PATHベースのcorpusを、build間でfeature IDが安定しているかのように同期しないでください。
- このfeedbackは`CMPLOG`を補完します。comparison tracingは**guardを通過する値**を解決する一方、path/caller feedbackは**どのrouteとbranchの組み合わせがそこへ到達したか**を保持します。

## Stateful Fuzzing: SequenceはSeed

**protocol**、**authenticated workflow**、**multi-stage parser**では、興味深い単位は単一のblobではなく、**message sequence**であることがよくあります。transcript全体を1つのfileに連結して盲目的にmutateする方法は、通常非効率的です。fuzzerが各stepを同じようにmutateするため、fragileなstateに到達するのが後続のmessageだけであっても区別しないからです。<sup>[[4]](#references)</sup>

より効果的なpatternは、**sequence自体をseedとして扱い**、observable state（response code、protocol state、parser phase、返されたobject type）を追加のfeedbackとして使用することです。<sup>[[4]](#references)</sup>

- **valid prefix message**は安定させ、**transition-driving** messageにmutationsを集中させます。
- 次のstepがそれらに依存する場合は、前のresponseからidentifierとserver-generated valueをcacheします。
- serialized transcript全体をopaque blobとしてmutateするより、message単位のmutation/splicingを優先します。
- protocolが意味のあるresponse codeを公開している場合は、それらを**安価なstate oracle**として使用し、より深く進行するsequenceを優先します。

これは、authenticated bug、hidden transition、または「handshake後にのみ発生する」parser bugがvanillaのfile-style fuzzingで見逃されやすい理由と同じです。fuzzerはstructureだけでなく、**order、state、dependency**を保持する必要があります。<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty**と**coverage reuse**をhybridizeする実用的な方法は、persistent serverに対して短命のworkerをrestartすることです。各workerはempty corpusから開始し、`T`秒後にsyncし、統合されたcorpusでさらに`T`秒実行して再度syncした後、exitします。これにより、蓄積されたcoverageを活用しながら、**各generationでfreshなstructure**を得られます。<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (example loop):**

<details>
<summary>Jackalope worker restart loop</summary>
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

- `-in empty` は、各 generation で **fresh corpus** を強制します。
- `-server_update_interval T` は **delayed sync** を近似します（最初は novelty、その後に reuse）。
- grammar fuzzing mode では、**initial server sync** はデフォルトで skip されます（`-skip_initial_server_sync` は不要です）。
- 最適な `T` は **target-dependent** です。worker が “easy” な coverage の大部分を発見した後に切り替えると、通常は最も効果的です。

## Snapshot Fuzzing For Hard-To-Harness Targets

テスト対象の code が **大きな setup cost**（VM の boot、login の完了、packet の受信、container の parse、service の初期化）の後でしか到達可能にならない場合、便利な代替手段が **snapshot fuzzing** です。ready 状態の process または VM state を capture し、各 test case を target の input path に inject して crash/timeout まで実行し、その後 snapshot を restore します。これにより initialization や protocol prefix の繰り返しを避けられ、**network services**、**firmware**、**post-auth attack surfaces**、**binary-only targets** に有用です。<sup>[[9]](#references)[[10]](#references)</sup>

1. 目的の state が ready になるまで target を実行します。
2. その時点で **memory + registers** の snapshot を取得します。
3. 各 test case について、mutated input を関連する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. snapshot を restore します。VM targets では、サポートされている場合は **dirty pages** のみを restore し、その後繰り返します。

snapshot は、最初の高コストな parse/dispatch step に可能な限り近い位置、たとえば `recv`/`read` の後、または packet-deserialization point に配置し、target が使用する input buffer を記録します。これは、作業の繰り返しを避けるために snapshot を input processing のさらに深い位置へ移動する adaptive-placement principle に従ったものです。<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

campaign が停滞した場合、問題は mutator ではなく **harness** にあることがよくあります。**reachability/coverage introspection** を使用して、fuzz target から static には reach 可能ですが、dynamic にはほとんど、またはまったく coverage されていない functions を見つけます。通常、これらの functions は次の 3 つの問題のいずれかを示します。<sup>[[12]](#references)</sup>

- harness が target に入るのが早すぎる、または遅すぎる。
- seed corpus に feature family 全体が欠けている。
- target には、1 つの oversized な “do everything” harness ではなく、**second harness** が本当に必要である。

OSS-Fuzz / ClusterFuzz-style workflows を使用している場合、Fuzz Introspector は static reachability と runtime coverage を比較し、timed run または public corpus から reports を生成できます。<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
このレポートを使用して、未テストの parser path 用に新しい harness を追加するか、特定の feature 用に corpus を拡張するか、monolithic harness をより小さな entry point に分割するかを判断します。

## Graph-First Fuzz Target Selection And Mutation Triage

すでに **static-analysis findings**、**mutation-testing survivors**、**coverage reports** がある場合、それらを独立したリストとして triage しないでください。まず **call graph** を構築し、各 node に **cyclomatic complexity**、**entrypoint/untrusted-input reachability**、外部 findings を注釈として付与し、そのうえで graph に関する問いを検討します。<sup>[[5]](#references)[[6]](#references)</sup>

- untrusted input から到達可能な高 complexity の function はどれか？
- parser/handler から security-critical code へ至る path 上に、どの mutation survivor が存在するか？
- 異常に大きな **blast radius** を持つ、architectural choke point となる function はどれか？

通常、これは「coverage が最も低いもの」だけを基準にするより、優れた fuzz target を明らかにします。**high complexity** で **external reachability** が確認された parser/decoder は、coverage が低くても attacker-controlled path を持たない孤立した internal helper より、強力な harness 候補です。

### Practical triage workflow

1. codebase から **code graph** を構築し、function ごとの complexity/branch metrics を抽出します。
2. attacker-controlled input を受け入れる **entrypoint** を列挙します：request handler、decoder、importer、protocol parser、CLI/file reader。
3. それらの entrypoint から候補 function への **path query** を実行し、到達可能な attack surface と dead/internal-only code を分離します。
4. 以下を組み合わせて満たす node を優先します：
- 高い **cyclomatic complexity**
- **untrusted input からの reachability** が確認されている
- 大きな **blast radius** または多数の downstream dependent
- **SARIF** findings、audit notes、mutation survivor などの裏付けとなる証拠
5. 特に hex/Base64/IP/message decoder などの **parser/codec** を対象として、スコアの高い node 用の focused harness を先に作成します。

### Mutation survivors: equivalent vs actionable

Mutation testing では、しばしば大量の survivor list が生成されます。すべての survivor を security gap とみなす前に、graph を使用して以下を確認します：

- mutated function は attacker-controlled entrypoint から到達可能か？
- すべての call path は、mutated check より強い invariant によって制約されているか？
- その node は dead code、formatting-only logic、または影響の大きい arithmetic/parser path に位置しているか？

到達不能なまま、または構造的に制約されている survivor は、**equivalent mutant** であることが多いです。一方、**reachable** のままで、**boundary condition**、**overflow/carry path**、または **security-critical arithmetic/parsing** に関与する survivor は、以下に昇格させるべきです：

- 新しい fuzz harness
- 直接的な property/invariant test
- 対象を絞った edge-case vector

### Correlate external findings onto the graph

SAST pipeline が **SARIF** を export する場合、**file + line range** によって findings を graph node に投影し、graph を使用して影響範囲を拡張します。<sup>[[6]](#references)</sup>

- flag された function の **blast radius** を計算する
- finding が entrypoint からのいずれかの path 上にあるか確認する
- 同じ choke point に集約される近接した findings を cluster 化する

これは、特定の function に fuzzing の時間を費やすか判断する際に有用です。**reachable** で、**complex** かつすでに **SAST hits** がある node は、complex であっても attacker path を持たない node より、より適切な target であることが多いです。

Trailmark を使用した example workflow。<sup>[[6]](#references)</sup>
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
重要な methodology は、**complexity x exposure x impact** の交差部分です。graph を使って、期待される security value が最も高い fuzz target を選び、その後 mutation survivors を使って、harness が stress すべき boundaries と invariants を決定します。<sup>[[5]](#references)</sup>

## gosentry による Go Fuzzing: より強力な Engine、Typed Inputs、そして Differential Checks

Go target にすでに native な `testing.F` harness がある場合、実用的な upgrade path は、[gosentry](https://github.com/trailofbits/gosentry) を使って同じ harness を実行することです。gosentry は fork された Go toolchain であり、`go test -fuzz` を維持しながら backend を **LibAFL** に置き換えます。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
これは、native Go fuzzer が **hard comparisons**、**typed inputs**、または **parser-heavy formats** で停止した場合に有用です。方法論は同じです。

- seed には引き続き `f.Add(...)`、callback には `f.Fuzz(...)` を使用します。
- 同じ harness を再利用しますが、stock toolchain ではなく gosentry の `go` binary で実行します。
- 生成された campaign は通常の coverage-guided run として扱いますが、LibAFL の scheduling/mutation と、周辺のより優れた detectors を利用できます。

### silent failures を fuzz findings に変換する

Go の assessment では、危険な挙動がデフォルトで **crash** しないことがよくあります。gosentry では、「bad but silent」な状態を複数の種類の findings に昇格できます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` を使用すると、指定した logging/error paths を crash のように動作させられます（通常は log のみ出力して処理を続行する `log.Fatal` 型の code paths に有用）。
- `--catch-races=true` を使用すると、新たに発見された queue entries を Go race detector で再実行できます。
- `--catch-leaks=true` を使用すると、新しい queue entries を `goleak` で再実行し、goroutine leaks の発生時に停止できます。
- LibAFL の hang handling により、**infinite loops / very slow inputs** を timeout として消失させず、fuzz findings として保持できます。
- デフォルトで組み込みの arithmetic overflow checks が有効です。また、go-panikint-style instrumentation による truncation checks もオプションで利用できます。

これは、security impact が memory corruption ではなく、**panicless parser failure**、**concurrency bug**、または **DoS-only hang** である target に特に有用です。

### typed Go APIs の struct-aware fuzzing

Native Go fuzzing は主に `[]byte`、`string`、数値などの scalars を想定しています。テスト対象の code が typed objects を受け取る場合、gosentry は bytes を内部で mutation しながら、structs、slices、arrays、pointers などの **composite values** を直接 fuzzing できます。<sup>[[7]](#references)[[8]](#references)</sup>
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
fake wire format を構築すると、harness 専用の parsing code によって logic bugs が隠れてしまうため、fuzzing の目的だけでこれを使用することは避けてください。Differential または grammar-based campaign では、harness input を単一の `[]byte` または `string` として保持し、代わりに callback 内で parse してください。

### parser と protocol input の Grammar-based fuzzing

parser、format、input language に対して、gosentry は LibAFL 上で **Nautilus grammar fuzzing** を実行できます。grammar は production rule の JSON array であり、harness は通常、単一の `[]byte` または `string` 引数を受け取る必要があります。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- byte-level mutations が初期の syntax checks でほとんど失敗する場合は、grammar mode を使用する。
- full specification をモデル化するのではなく、grammar を言語や protocol の **security-relevant subset** に絞る。
- terminals/nonterminals では大きな境界値を使用して、integer、length、state-machine のエッジを検証する。
- grammar mode により入力は grammar-valid に保たれるが、target が受け取るのは依然として **bytes/strings** であるため、parsing と semantic checks は harnessed code 内で引き続き実行される。

### Differential fuzzing: クラッシュだけでなく実装を比較する

Go ecosystems で有効なパターンは、**grammar-based differential fuzzing** である。これは、valid な構造化入力を生成し、2 つの parsers、clients、または state-transition engines に入力する手法である。<sup>[[7]](#references)[[8]](#references)</sup>
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
以下を findings として扱います。

- 一方の実装は panic するが、もう一方は正常に reject する
- 受理される入力と reject される入力の不一致
- 異なる parse tree または decoded object
- state transition、nonce、balance、または state root の相違

これは、純粋な crash fuzzing では見逃しやすい **consensus mismatches**、**parser ambiguity**、**spec-vs-implementation drift** を見つける実践的な方法です。

### coverage reporting に campaign corpus を再利用する

campaign 後、保存した queue corpus を replay して、別の corpus を手動で export することなく Go coverage report を生成できます。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
同じ package から、かつ同じ `-fuzz` target を指定してコマンドを実行し、gosentry が正しい cached campaign state を解決できるようにします。



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark が code を graphs に変換](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing には toolkit の半分が欠けていた。toolchain を fork して修正した。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots を使用した Stateful Network Protocols 向けの Fast Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar がなくても問題なし: System-Call Descriptions なしで Linux Kernel を Fuzzing するために](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive and Mutable Snapshots による Efficient Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path and caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
