# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** では、入力を **grammar-valid** な状態に保ちながら mutation します。coverage-guided mode では、**new coverage** を trigger した sample だけが corpus seed として保存されます。**language targets**（parsers、interpreters、engines）では、ある construct の output が別の construct の input になるような **semantic/dataflow chains** を必要とする bug を、これによって見逃す可能性があります。<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer は `document()` と `generate-id()`（または類似の primitives）を個別に exercise する seeds を見つけますが、**chained dataflow** を保持しないため、“closer-to-bug” な sample は coverage を追加しないものとして drop されます。依存する step が **3+** ある場合、random recombination は高コストになり、coverage feedback も search を guide できません。<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars では、**mutational** phase と **generative** phase を **hybridizing** するか、単なる coverage ではなく **function chaining** patterns に generation を bias することを検討してください。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation は **greedy** です。new-coverage sample はすぐに保存され、多くの場合、大きな unchanged regions も保持されます。時間の経過とともに、corpora は structural diversity の低い **near-duplicates** になります。Aggressive minimization は有用な context を削除する可能性があるため、実用的な compromise は、**minimum token threshold** に達した時点で停止する **grammar-aware minimization** です（noise を減らしつつ、mutation-friendly であり続けるのに十分な surrounding structure を維持します）。<sup>[[1]](#references)</sup>

mutational fuzzing における実用的な corpus rule は、大量の near-duplicates よりも、coverage を最大化する **structurally different な少数の seeds** を優先することです。実際には、通常は次のようになります。<sup>[[1]](#references)[[3]](#references)</sup>

- **real-world samples**（public corpora、crawling、captured traffic、target ecosystem の file sets）から開始する。
- すべての valid sample を保持するのではなく、**coverage-based corpus minimization** で distill する。
- mutations が irrelevant bytes に大半の cycles を費やすのではなく、meaningful fields に着地するよう、seeds を **十分に小さく** 保つ。
- 大幅な harness/instrumentation の変更後には corpus minimization を再実行する。reachability が変化すると、「best」な corpus も変わるためです。

## Comparison-Aware Mutation For Magic Values

fuzzers が plateau する一般的な理由は syntax ではなく、**hard comparisons** です。具体的には、magic bytes、length checks、enum strings、checksums、または `memcmp`、switch tables、cascaded comparisons によって guard された parser dispatch values などです。Pure random mutation では、これらの values を byte-by-byte で推測しようとして cycles を無駄にします。

これらの targets には **comparison tracing**（例えば AFL++ の `CMPLOG` / Redqueen-style workflows）を使用し、fuzzer が failed comparisons の operands を observe できるようにします。これにより、fuzzer はそれらを満たす values に向けて mutations を bias できます。<sup>[[3]](#references)</sup>
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
**実践的な注意点：**

- これは、対象が **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** によって深いロジックへのアクセスを制御している場合に、特に有効です。
- 実際のサンプル、protocol specs、または debug logs から抽出した **dictionaries** と組み合わせてください。grammar tokens、chunk names、verbs、delimiters を含む小規模な dictionary のほうが、巨大で汎用的な wordlist より価値があることがよくあります。
- 対象が多数の sequential checks を実行する場合は、最初の “magic” comparisons を先に解決し、その後、得られた corpus を再度 minimize してください。これにより、後続ステージがすでに有効な prefixes から開始できます。

## Stateful Fuzzing: Sequences Are Seeds

**protocols**、**authenticated workflows**、**multi-stage parsers** では、興味深い単位は単一の blob ではなく、**message sequence** であることがよくあります。transcript 全体を1つの file に連結して盲目的に mutate する方法は、通常は非効率です。fragile state に到達するのが後続の message だけであっても、fuzzer はすべてのステップを均等に mutate してしまうためです。<sup>[[4]](#references)</sup>

より効果的な方法は、**sequence 自体を seed として扱い**、**observable state**（response codes、protocol states、parser phases、返される object types）を追加の feedback として使用することです。<sup>[[4]](#references)</sup>

- **valid prefix messages** は安定させ、mutations は **transition-driving** message に集中させます。
- 次のステップが prior responses に依存する場合は、identifiers と server-generated values を cache します。
- serialized transcript 全体を opaque blob として mutate するよりも、message ごとの mutation/splicing を優先します。
- protocol が意味のある response codes を公開している場合は、それらを **cheap state oracle** として使用し、より深く進行する sequences を優先します。

これは、authenticated bugs、hidden transitions、または “only-after-handshake” parser bugs が vanilla file-style fuzzing で見落とされやすい理由と同じです。fuzzer は単に structure だけでなく、**order、state、dependencies** も維持しなければなりません。<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** と **coverage reuse** を hybridize する実践的な方法は、persistent server に対して短命な workers を **restart** することです。各 worker は empty corpus から開始し、`T` 秒後に sync し、combined corpus に対してさらに `T` 秒実行し、再度 sync してから終了します。これにより、蓄積された coverage を活用しながら、**各 generation で fresh structures** を得られます。<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` は各 generation で **fresh corpus** を強制します。
- `-server_update_interval T` は **delayed sync**（novelty を先に、reuse を後に）を近似します。
- grammar fuzzing mode では、**initial server sync** はデフォルトでスキップされます（`-skip_initial_server_sync` は不要です）。
- 最適な `T` は **target-dependent** です。worker が「easy」な coverage の大部分を見つけた後に切り替える方法が、通常は最も効果的です。

## Snapshot Fuzzing For Hard-To-Harness Targets

テスト対象の code が **large setup cost**（VM の boot、login の完了、packet の受信、container の parsing、service の initialization）の後でしか到達可能にならない場合、便利な代替手段が **snapshot fuzzing** です。ready 状態の process または VM state を capture し、各 test case を target の input path に inject して crash/timeout まで execute した後、snapshot を restore します。これにより initialization や protocol prefixes の繰り返しを避けられ、**network services**、**firmware**、**post-auth attack surfaces**、**binary-only targets** に有用です。<sup>[[9]](#references)[[10]](#references)</sup>

1. interesting state の準備が完了するまで target を実行します。
2. その時点で **memory + registers** を snapshot します。
3. 各 test case について、mutated input を関連する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. snapshot を restore します。VM targets では、サポートされている場合は **dirty pages** のみを restore してから繰り返します。

snapshot は、最初の高コストな parse/dispatch step の可能な限り近くに配置します。たとえば `recv`/`read` の後、または packet-deserialization point の後です。また、target が使用する input buffer を記録します。これは、input processing のより深い位置へ snapshot を移動して処理の繰り返しを避ける、adaptive-placement principle に従うものです。<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

campaign が停滞した場合、問題は mutator ではなく **harness** にあることがよくあります。**reachability/coverage introspection** を使用して、fuzz target から statically reachable でありながら、dynamically covered されることがほとんどない、またはまったくない functions を見つけます。通常、これらの functions は次の3つの問題のいずれかを示します。<sup>[[12]](#references)</sup>

- harness が target に入るタイミングが遅すぎる、または早すぎる。
- seed corpus に feature family 全体が欠けている。
- target には、巨大な「do everything」harness 1つではなく、**second harness** が本当に必要である。

OSS-Fuzz / ClusterFuzz-style workflows を使用している場合、Fuzz Introspector は static reachability と runtime coverage を比較し、timed run または public corpus から reports を生成できます。<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
レポートを使用して、未テストの parser path 用に新しい harness を追加するか、特定の feature の corpus を拡張するか、monolithic harness をより小さな entry point に分割するかを判断します。

## Graph-First Fuzz Target Selection And Mutation Triage

すでに **static-analysis findings**、**mutation-testing survivors**、**coverage reports** がある場合、それらを独立したリストとして triage しないでください。まず **call graph** を構築し、ノードに **cyclomatic complexity**、**entrypoint/untrusted-input reachability**、外部の findings を付加してから、graph に関する問いを検討します。<sup>[[5]](#references)[[6]](#references)</sup>

- どの高 complexity 関数が untrusted input から到達可能か？
- どの mutation survivor が parser/handler から security-critical code への path 上にあるか？
- どの関数が、異常に大きな **blast radius** を持つ architectural choke point か？

通常、これは「lowest coverage」だけを見るよりも優れた fuzz target を明らかにします。**high complexity** で **external reachability** が確認された parser/decoder は、coverage が低くても attacker-controlled path が存在しない孤立した internal helper より、強力な harness 候補です。

### Practical triage workflow

1. codebase から **code graph** を構築し、関数ごとの complexity/branch metrics を抽出します。
2. attacker-controlled input を受け付ける **entrypoint**（request handler、decoder、importer、protocol parser、CLI/file reader）を列挙します。
3. それらの entrypoint から候補関数への **path query** を実行し、到達可能な attack surface と dead/internal-only code を分離します。
4. 以下の条件を組み合わせて満たすノードを優先します。
- 高い **cyclomatic complexity**
- **untrusted input からの reachability** が確認されている
- 大きな **blast radius** または多数の downstream dependents
- **SARIF** findings、audit notes、mutation survivors などの裏付け情報
5. 特に hex/Base64/IP/message decoder などの **parser/codec** を中心に、スコアの高いノードから focused harness を作成します。

### Mutation survivors: equivalent vs actionable

Mutation testing では、ノイズの多い survivor list が生成されることがよくあります。すべての survivor を security gap とみなす前に、graph を使って以下を確認します。

- mutated function は attacker-controlled entrypoint から到達可能か？
- すべての call path が、mutated check より強い invariant によって制約されているか？
- そのノードは dead code、formatting-only logic、または影響の大きい arithmetic/parser path のいずれに存在するか？

到達不能なまま、または構造的に制約された survivor は、多くの場合 **equivalent mutant** です。一方、**reachable** のままで **boundary conditions**、**overflow/carry paths**、または **security-critical arithmetic/parsing** に関わる survivor は、以下に昇格させるべきです。

- 新しい fuzz harness
- 直接的な property/invariant test
- 対象を絞った edge-case vector

### Correlate external findings onto the graph

SAST pipeline が **SARIF** を出力する場合、**file + line range** に基づいて findings を graph node に投影し、graph を使って影響範囲を拡張します。<sup>[[6]](#references)</sup>

- flagged function の **blast radius** を計算する
- finding が entrypoint からのいずれかの path 上にあるか確認する
- 同じ choke point に集約される近接した findings を cluster 化する

これは、特定の関数に fuzzing の時間を割くかどうかを判断する際に有用です。**reachable** で **complex**、かつすでに **SAST hits** があるノードは、complex であるだけで attacker path が存在しないノードより、優れた target であることがよくあります。

Trailmark を使用した workflow の例です。<sup>[[6]](#references)</sup>
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
重要な methodology は、**complexity x exposure x impact** の交差点です。グラフを使って、期待される security value が最も高い fuzz target を選び、その後 mutation survivors を使って、harness が stress すべき境界と invariant を判断します。<sup>[[5]](#references)</sup>

## gosentry による Go Fuzzing: より強力な Engine、Typed Inputs、そして Differential Checks

Go target にすでに native な `testing.F` harness がある場合、実用的な upgrade path は、[gosentry](https://github.com/trailofbits/gosentry) を使って同じ harness を実行することです。gosentry は fork された Go toolchain で、`go test -fuzz` を維持しながら backend を **LibAFL** に置き換えます。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
これは、native Go fuzzer が **hard comparisons**、**typed inputs**、または **parser-heavy formats** で停滞する場合に有用です。方法論は同じです。

- seed には引き続き `f.Add(...)` を使用し、callback には `f.Fuzz(...)` を使用します。
- 同じ harness を再利用しますが、stock toolchain の代わりに gosentry の `go` binary で実行します。
- 結果として得られる campaign は通常の coverage-guided run として扱います。ただし、LibAFL の scheduling/mutation と、周辺の detector の改善が加わります。

### silent failures を fuzz findings に変える

Go の assessment で繰り返し発生する問題は、危険な挙動がデフォルトでは crash しないことです。gosentry では、「bad but silent」な状態を複数のクラスで findings に昇格できます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` により、指定した logging/error path を crash と同様に動作させます（それ以外の場合は log を出力して処理を続行する `log.Fatal` 型の code path に有用です）。
- `--catch-races=true` により、新たに発見された queue entry を Go race detector で再実行します。
- `--catch-leaks=true` により、新しい queue entry を `goleak` で再実行し、goroutine leak が発生した時点で停止します。
- LibAFL の hang handling により、**infinite loops / very slow inputs** を timeout として消失させず、fuzz findings として保持します。
- デフォルトで組み込まれている arithmetic overflow checks に加え、go-panikint-style instrumentation による任意の truncation checks も利用できます。

これは、security impact が memory corruption ではなく、**panicless parser failure**、**concurrency bug**、または **DoS-only hang** である target に特に有効です。

### typed Go API 向けの struct-aware fuzzing

Native Go fuzzing は主に `[]byte`、`string`、数値などの scalar を想定しています。test 対象の code が typed object を受け取る場合、gosentry では bytes を基盤として mutation しながら、struct、slice、array、pointer などの **composite values** を直接 fuzz できます。<sup>[[7]](#references)[[8]](#references)</sup>
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
これは、fuzzing専用の fake wire format を構築する際に使用してください。そうしないと、harness 専用の parsing code によって logic bug が隠れてしまいます。differential または grammar-based の campaign では、harness の input を単一の `[]byte` または `string` とし、代わりに callback 内で parse してください。

### parser と protocol input の grammar-based fuzzing

parser、format、input language に対して、gosentry は LibAFL 上で **Nautilus grammar fuzzing** を実行できます。grammar は production rule の JSON array であり、harness は通常、単一の `[]byte` または `string` 引数を受け取るようにします。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- byte-level mutations が early syntax checks でほとんど停止する場合は、grammar mode を使用します。
- full specification をモデル化するのではなく、language/protocol の **security-relevant subset** に grammar を絞ります。
- terminals/nonterminals では大きな boundary values を使用して、integer、length、state-machine の境界を stress します。
- grammar mode は inputs を grammar-valid に保ちますが、target が受け取るのは依然として **bytes/strings** であるため、parsing と semantic checks は harness された code 内に残ります。

### Differential fuzzing: crashes だけでなく implementations を比較する

Go ecosystems で有効なパターンは、**grammar-based differential fuzzing** です。valid な structured inputs を生成し、それらを2つの parsers、clients、または state-transition engines に渡します。<sup>[[7]](#references)[[8]](#references)</sup>
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
これらを findings として扱います：

- 一方の実装は panic する一方で、もう一方は正常に reject する
- accepted/rejected input の不一致
- 異なる parse tree または decoded object
- state transition、nonce、balance、state root の相違

これは、純粋な crash fuzzing では見落とされがちな **consensus mismatch**、**parser ambiguity**、**spec-vs-implementation drift** を発見する実践的な方法です。

### coverage reporting に campaign corpus を再利用する

campaign の後、保存された queue corpus を replay して、別の corpus を手動で export することなく Go coverage report を生成できます。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
同じ **package** から、かつ同じ `-fuzz` target を指定してコマンドを実行し、gosentry が正しい cached campaign state を解決できるようにします。

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: Coverage-Guided Protocol Fuzzing の5年後](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark は code を graphs に変換する](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing には toolkit の半分が欠けていた。toolchain を fork して修正した。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots を使用した Stateful Network Protocols 向け高速 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar がなくても問題なし：System-Call Descriptions なしで Linux Kernel を Fuzzing するために](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive and Mutable Snapshots による効率的な Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
