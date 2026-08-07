# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: カバレッジ vs. セマンティクス

**mutational grammar fuzzing** では、入力を **grammar-valid** に保ったまま mutation します。coverage-guided mode では、**new coverage** を trigger したサンプルだけが corpus seed として保存されます。**language targets**（parsers、interpreters、engines）では、ある construct の output が別の construct の input になるような **semantic/dataflow chains** を必要とする bug を見逃す可能性があります。

**Failure mode:** fuzzer は `document()` と `generate-id()`（または類似の primitives）を個別に exercise する seeds を見つけますが、**chained dataflow** を **preserve** しないため、「bug により近い」サンプルが coverage を追加しないという理由で drop されます。**3+ dependent steps** では、random recombination のコストが高くなり、coverage feedback も search を guide できません。

**Implication:** dependency-heavy grammars では、**mutational** phase と **generative** phase の hybridization、または（coverage だけでなく）**function chaining** patterns に generation を bias することを検討してください。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation は **greedy** です。new-coverage sample は即座に保存され、多くの場合、大きな unchanged regions も保持されます。時間の経過とともに、corpus は structural diversity の低い **near-duplicates** になります。Aggressive minimization によって有用な context が削除される可能性があるため、実用的な compromise は、**minimum token threshold** に達した後に停止する **grammar-aware minimization** です（noise を減らしつつ、mutation-friendly であり続けるのに十分な surrounding structure を維持します）。<sup>[[1]](#references)</sup>

mutational fuzzing における実用的な corpus rule は、大量の near-duplicates よりも、coverage を最大化する structurally different な少数の seeds を **prefer** することです。実際には、通常は次のことを意味します。<sup>[[1]](#references)</sup>

- **real-world samples**（public corpora、crawling、captured traffic、target ecosystem の file sets）から開始する。
- すべての valid sample を保持するのではなく、**coverage-based corpus minimization** で distill する。
- mutations が meaningful fields に適用されるよう、seeds を十分に **small** に保つ。これにより、大半の cycles を irrelevant bytes に費やすことを防ぐ。
- major harness/instrumentation changes の後に corpus minimization を再実行する。reachability が変化すると、「best」な corpus も変わるため。

## Comparison-Aware Mutation For Magic Values

fuzzer が plateau する一般的な理由は syntax ではなく、magic bytes、length checks、enum strings、checksums、または `memcmp`、switch tables、cascaded comparisons によって guard された parser dispatch values などの **hard comparisons** です。Pure random mutation では、これらの values を byte-by-byte で推測しようとして cycles を浪費します。

これらの targets では、**comparison tracing**（たとえば AFL++ `CMPLOG` / Redqueen-style workflows）を使用します。これにより、fuzzer は failed comparisons の operands を observe し、それらを満たす values に向けて mutations を bias できます。<sup>[[3]](#references)</sup>
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
**実践的なメモ:**

- これは、対象が**file signatures**、**protocol verbs**、**type tags**、または**version-dependent feature bits**によって深いロジックへのアクセスを制御している場合に特に有用です。
- 実際のサンプル、protocol specs、またはdebug logsから抽出した**dictionaries**と組み合わせます。grammar tokens、chunk names、verbs、delimitersを含む小規模なdictionaryは、巨大な汎用wordlistより価値があることがよくあります。
- 対象が多数のsequential checksを実行する場合は、最初に最も早い“magic” comparisonsを解決し、その後に生成されたcorpusを再度minimizeします。これにより、後続ステージはすでに有効なprefixから開始できます。

## Stateful Fuzzing: Sequences Are Seeds

**protocols**、**authenticated workflows**、**multi-stage parsers**では、興味深い単位は単一のblobではなく、**message sequence**であることがよくあります。transcript全体を1つのfileに連結して盲目的にmutateする方法は、通常非効率です。fuzzerが各stepを均等にmutateしてしまう一方で、脆弱なstateに到達するのは後続のmessageだけである場合があるためです。

より効果的なpatternは、**sequence自体をseed**として扱い、**observable state**（response codes、protocol states、parser phases、返されるobject types）を追加のfeedbackとして使用することです:<sup>[[4]](#references)</sup>

- **valid prefix messages**は安定したままにし、**transition-driving** messageにmutationを集中させます。
- 次のstepがそれらに依存する場合は、以前のresponseからidentifierとserver-generated valuesをcacheします。
- opaque blobとしてserialized transcript全体をmutateするより、message単位のmutation/splicingを優先します。
- protocolが意味のあるresponse codesを公開している場合は、それらを**cheap state oracle**として使用し、より深く進行するsequenceを優先します。

これが、authenticated bugs、hidden transitions、または“only-after-handshake” parser bugsがvanilla file-style fuzzingでは見逃されやすい理由と同じです。fuzzerは単にstructureだけでなく、**order、state、dependencies**も保持しなければなりません。

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty**と**coverage reuse**をhybridizeする実用的な方法は、persistent serverに対して短時間だけ動作するworkerを**restart**することです。各workerはempty corpusから開始し、`T`秒後にsyncし、統合されたcorpusでさらに`T`秒実行し、再度syncしてから終了します。これにより、蓄積されたcoverageを活用しながら、各generationで**fresh structures**を生成できます。<sup>[[2]](#references)</sup>

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
- `-server_update_interval T` は **delayed sync**（最初に novelty を優先し、後から reuse）を近似します。
- grammar fuzzing mode では、デフォルトで **initial server sync** がスキップされます（`-skip_initial_server_sync` は不要です）。
- 最適な `T` は **target-dependent** です。worker が大部分の「easy」な coverage を見つけた後に切り替えると、うまくいく傾向があります。

## Hard-To-Harness Targets 向けの Snapshot Fuzzing

テストしたい code が **大きな setup cost**（VM の起動、login の完了、packet の受信、container の parsing、service の初期化）の後でしか到達可能にならない場合、有用な代替手段が **snapshot fuzzing** です。

1. interesting state の準備が整うまで target を実行します。
2. その時点の **memory + registers** を snapshot します。
3. 各 test case で、mutated input を関連する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. **dirty pages** のみを restore して繰り返します。

これにより、各 iteration で full setup cost を支払う必要がなくなります。特に **network services**、**firmware**、**post-auth attack surfaces**、および classic in-process harness への refactor が困難な **binary-only targets** に有用です。

実用的な方法は、`recv`/`read`/packet-deserialization point の直後で直ちに break し、input buffer の address を確認してその場所で snapshot を作成し、その後各 iteration でその buffer を直接 mutate することです。これにより、毎回 handshake 全体を再構築せずに、deep parsing logic を fuzz できます。

## Harness Introspection: Shallow Fuzzers を早期に発見する

campaign が停滞した場合、問題は mutator ではなく **harness** にあることが多くあります。**reachability/coverage introspection** を使用して、fuzz target から static には reachable だが、dynamic にはほとんど、またはまったく covered されていない functions を見つけます。これらの functions は通常、次の 3 つの問題のいずれかを示します。

- harness が target に入るタイミングが遅すぎる、または早すぎる。
- seed corpus に feature family 全体が欠けている。
- target には、1 つの巨大な「do everything」harness ではなく、**second harness** が本当に必要である。

OSS-Fuzz / ClusterFuzz-style workflows を使用している場合、この triage には Fuzz Introspector が役立ちます。
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
レポートを使用して、未テストのparser path向けに新しいharnessを追加するか、特定のfeatureのcorpusを拡張するか、monolithicなharnessをより小さなentry pointに分割するかを判断します。

## Graph-FirstによるFuzz Target SelectionとMutation Triage

すでに**static-analysis findings**、**mutation-testing survivors**、**coverage reports**がある場合、それらを独立したリストとしてtriageしないでください。まず**call graph**を構築し、ノードに**cyclomatic complexity**、**entrypoint/untrusted-input reachability**、外部のfindingを付与してから、グラフに関する問いを立てます:<sup>[[5]](#references)[[6]](#references)</sup>

- **untrusted input**から到達可能な高complexityのfunctionはどれか？
- parser/handlerからsecurity-critical codeへのpath上にあるmutation survivorはどれか？
- 異常に大きな**blast radius**を持つ、architectural choke pointとなるfunctionはどれか？

これは通常、「coverageが最低」という基準だけの場合よりも、優れたfuzz targetを見つけ出します。**high complexity**で、**external reachability**が確認されたparser/decoderは、coverageが低いだけでattacker-controlled pathを持たない孤立したinternal helperよりも、harnessの有力な候補です。

### Practical triage workflow

1. codebaseから**code graph**を構築し、functionごとのcomplexity/branch metricsを抽出します。
2. attacker-controlled inputを受け付ける**entrypoint**を列挙します: request handler、decoder、importer、protocol parser、CLI/file readerなど。
3. それらのentrypointからcandidate functionへの**path query**を実行し、到達可能なattack surfaceとdead/internal-only codeを分離します。
4. 以下の条件を組み合わせて満たすノードを優先します:
- high **cyclomatic complexity**
- **untrusted inputからのreachability**が確認されている
- 高い**blast radius**または多数のdownstream dependent
- **SARIF** finding、audit note、mutation survivorなどの裏付けとなる証拠
5. スコアの高いノードから、特にhex/Base64/IP/message decoderなどの**parser/codec**向けに、focused harnessを作成します。

### Mutation survivors: equivalent vs actionable

Mutation testingでは、しばしば大量のsurvivor listが生成されます。すべてのsurvivorをsecurity gapとして扱う前に、グラフを使用して以下を確認します:

- mutated functionはattacker-controlled entrypointから到達可能か？
- すべてのcall pathは、mutated checkよりも強いinvariantによって制約されているか？
- そのノードはdead code、formatting-only logic、またはimpactの大きいarithmetic/parser path上にあるか？

到達不能なまま、または構造的に制約されたままのsurvivorは、**equivalent mutant**であることが多くあります。**reachable**なままで、**boundary conditions**、**overflow/carry path**、または**security-critical arithmetic/parsing**に関係するsurvivorは、以下へ昇格させるべきです:

- 新しいfuzz harness
- 直接的なproperty/invariant test
- 対象を絞ったedge-case vector

### Correlate external findings onto the graph

SAST pipelineが**SARIF**をexportする場合、**file + line range**によってfindingをgraph nodeに投影し、グラフを使用して影響範囲を拡張します:

- flagged functionの**blast radius**を計算する
- findingがentrypointからのいずれかのpath上にあるか確認する
- 同じchoke pointに集約される近接したfindingをcluster化する

これは、特定のfunctionにfuzzingの時間を費やすべきか判断するときに有用です。**reachable**で、**complex**であり、すでに**SAST hit**があるノードは、attacker pathのない単にcomplexなノードよりも、優れたtargetであることが多くあります。

Trailmarkを使用したExample workflow:<sup>[[6]](#references)</sup>
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
重要な methodology は、**complexity x exposure x impact** の交差部分です。graph を使用して、期待される security value が最も高い fuzz target を選び、その後 mutation survivor を使用して、harness が stress すべき境界と invariant を決定します。

## gosentry による Go Fuzzing: より強力なエンジン、型付き入力、差分チェック

Go target にすでに native な `testing.F` harness がある場合、実用的な upgrade path は、[gosentry](https://github.com/trailofbits/gosentry) を使用して同じ harness を実行することです。gosentry は fork された Go toolchain で、`go test -fuzz` を維持しながら backend を **LibAFL** に置き換えます。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
これは、native Go fuzzer が **hard comparisons**、**typed inputs**、または **parser-heavy formats** で停止してしまう場合に有用です。methodology は同じです。

- seeds には引き続き `f.Add(...)` を使用し、callback には `f.Fuzz(...)` を使用します。
- 同じ harness を再利用しますが、stock toolchain ではなく gosentry の `go` binary で実行します。
- 生成された campaign は通常の coverage-guided run として扱いますが、LibAFL の scheduling/mutation と、より優れた周辺 detector が利用されます。

### silent failures を fuzz findings に変える

Go の assessment で繰り返し発生する問題は、危険な挙動がデフォルトでは crash しないことです。gosentry では、複数の種類の「bad but silent」な状態を findings に変換できます。

- `--panic-on=pkg.Func,...` を使用すると、選択した logging/error path を crash として扱えます（通常は log だけ出力して処理を継続する `log.Fatal` 形式の code path に有用です）。
- `--catch-races=true` を使用すると、新たに発見された queue entry を Go race detector で再実行できます。
- `--catch-leaks=true` を使用すると、新しい queue entry を `goleak` で再実行し、goroutine leak が発生した時点で停止できます。
- LibAFL の hang handling により、**infinite loops / very slow inputs** を timeout として消失させず、fuzz findings として保持できます。
- デフォルトで組み込みの arithmetic overflow checks が有効になり、さらに go-panikint-style instrumentation による truncation checks も任意で有効化できます。

これは、security impact が memory corruption ではなく、**panicless parser failure**、**concurrency bug**、または **DoS-only hang** である target に特に有用です。

### typed Go API 向けの Struct-aware fuzzing

Native Go fuzzing は主に `[]byte`、`string`、数値などの scalar を想定しています。test 対象の code が typed object を受け取る場合、gosentry では、内部で bytes を mutation しながら、composite value（struct、slice、array、pointer）を直接 fuzzing できます。
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
fuzzing専用の偽の wire format を構築すると、harness 内だけで使用するパーサーコードによってロジックバグが隠れてしまいます。differential または grammar-based campaign では、harness の入力を単一の `[]byte` または `string` とし、代わりに callback 内でパースしてください。

### parser と protocol input の grammar-based fuzzing

parser、format、input language では、gosentry は LibAFL 上で **Nautilus grammar fuzzing** を実行できます。grammar は production rule の JSON array であり、harness は通常、単一の `[]byte` または `string` 引数を受け取るようにします。
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- byte-level mutations が主に初期の syntax checks で失敗する場合は、grammar mode を使用する。
- 全 specification をモデル化するのではなく、language/protocol の **security-relevant subset** に grammar の対象を絞る。
- terminals/nonterminals では大きな boundary values を使用し、integer、length、state-machine のエッジに負荷をかける。
- grammar mode は inputs を grammar-valid に保つが、target が受け取るのは依然として **bytes/strings** であるため、parsing と semantic checks は harnessed code 内に残る。

### Differential fuzzing: crash だけでなく implementations を比較する

Go ecosystems における強力なパターンは、**grammar-based differential fuzzing** である。valid な structured inputs を生成し、それらを2つの parsers、clients、または state-transition engines に入力する。
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

- 一方の実装が panic する一方で、もう一方が正常に拒否する
- 受理・拒否される入力が一致しない
- parse tree または decoded object が異なる
- state transition、nonce、balance、state root が異なる

これは、純粋な crash fuzzing では見落としがちな **コンセンサスの不一致**、**parser の曖昧性**、**仕様と実装の乖離** を見つける実践的な方法です。

### coverage reporting に campaign corpus を再利用する

campaign 後、別の corpus を手動でエクスポートせず、保存された queue corpus を replay して Go coverage report を生成します。
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
同じ package から、同じ `-fuzz` target を指定して command を実行してください。これにより、gosentry が正しい cached campaign state を解決できます。

## 参考資料

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
