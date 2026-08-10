# Fuzzing Methodology

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** では、入力を **grammar-valid** な状態に保ちながら mutation します。coverage-guided mode では、**new coverage** を trigger したサンプルのみが corpus seed として保存されます。**language targets**（parser、interpreter、engine）では、ある construct の output が別の construct の input になるような **semantic/dataflow chains** を必要とする bug を見逃す可能性があります。<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer は `document()` と `generate-id()`（または類似の primitive）を個別に exercise する seed を見つけますが、**chained dataflow** を保持しないため、「bug に近い」サンプルは coverage を追加しないという理由で破棄されます。**3+ dependent steps** では、random recombination は高コストになり、coverage feedback も search を guide できません。<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammar では、**mutational** phase と **generative** phase を **hybridize** するか、coverage だけでなく **function chaining** pattern を優先して generation することを検討してください。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation は **greedy** です。new coverage を持つサンプルは即座に保存され、多くの場合、大きく変更されていない領域も保持されます。時間の経過とともに、corpus は structural diversity の低い **near-duplicates** になります。Aggressive minimization によって有用な context が削除される可能性があるため、実用的な妥協案は、**minimum token threshold** に達した後に停止する **grammar-aware minimization** です（noise を減らしつつ、mutation-friendly であり続けるのに十分な周辺 structure を維持します）。<sup>[[1]](#references)</sup>

mutational fuzzing における実用的な corpus rule は、大量の near-duplicates よりも、coverage を最大化する、structurally different な少数の seed を **prefer** することです。実際には、通常は次のようになります。<sup>[[1]](#references)[[3]](#references)</sup>

- **real-world samples**（public corpus、crawling、captured traffic、target ecosystem の file set）から開始する。
- すべての valid sample を保持するのではなく、**coverage-based corpus minimization** によって distill する。
- mutation が irrelevant bytes に大半の cycle を費やすのではなく、meaningful fields に適用されるよう、seed を十分に小さく保つ。
- harness や instrumentation に大きな変更を加えた後は corpus minimization を再実行する。reachability が変わると、「最適な」corpus も変わるためです。

## Comparison-Aware Mutation For Magic Values

fuzzer が plateau する一般的な理由は syntax ではなく、magic bytes、length checks、enum strings、checksums、または `memcmp`、switch tables、cascaded comparisons によって guard された parser dispatch values などの **hard comparisons** です。Pure random mutation では、これらの values を byte-by-byte で推測しようとして cycle を浪費します。

これらの target には **comparison tracing**（例：AFL++ の `CMPLOG` / Redqueen-style workflow）を使用し、failed comparisons の operands を fuzzer が観測できるようにします。これにより、fuzzer はそれらを satisfy する values に向けて mutation を bias できます。<sup>[[3]](#references)</sup>
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

- これは、target が **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** の背後に深い logic を隠している場合に特に有用です。
- 実際のサンプル、protocol specs、または debug logs から抽出した **dictionaries** と組み合わせてください。grammar tokens、chunk names、verbs、delimiters を含む小規模な dictionary は、巨大で汎用的な wordlist よりも価値があることがよくあります。
- target が多くの sequential checks を実行する場合は、最初に最も早い “magic” comparisons を解決し、その後、得られた corpus を再度 minimize してください。これにより、後続 stages はすでに有効な prefixes から開始できます。

## Stateful Fuzzing: シーケンスは Seed

**protocols**、**authenticated workflows**、**multi-stage parsers** では、興味深い unit は単一の blob ではなく、**message sequence** であることがよくあります。transcript 全体を 1 つの file に連結して盲目的に mutate する方法は、通常非効率です。fuzzer がすべての step を同じように mutate してしまう一方で、fragile state に到達するのは後半の message だけである場合があるためです。<sup>[[4]](#references)</sup>

より効果的な pattern は、**sequence 自体を seed** として扱い、observable state（response codes、protocol states、parser phases、returned object types）を追加の feedback として使用することです。<sup>[[4]](#references)</sup>

- **valid prefix messages** は安定させ、**transition-driving** message に mutations を集中させます。
- 次の step が prior responses に依存する場合は、identifiers と server-generated values を cache します。
- opaque blob として serialized transcript 全体を mutate するより、message 単位の mutation/splicing を優先します。
- protocol が意味のある response codes を公開している場合は、それらを **cheap state oracle** として使用し、より深く進行する sequences を優先します。

これは、authenticated bugs、hidden transitions、または “only-after-handshake” parser bugs が vanilla file-style fuzzing で見落とされやすい理由と同じです。fuzzer は structure だけでなく、**order、state、dependencies** も維持しなければなりません。<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** と **coverage reuse** を hybridize する実践的な方法は、persistent server に対して短命な workers を **restart** することです。各 worker は空の corpus から開始し、`T` 秒後に sync し、統合された corpus に対してさらに `T` 秒実行し、再度 sync してから終了します。これにより、蓄積された coverage を活用しながら、**各 generation で fresh structures** を得られます。<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` は各 generation で **fresh corpus** を強制します。
- `-server_update_interval T` は **delayed sync**（最初は novelty、後から reuse）を近似します。
- grammar fuzzing mode では、**initial server sync はデフォルトでスキップ**されます（`-skip_initial_server_sync` は不要です）。
- 最適な `T` は **target-dependent** です。worker が「easy」な coverage の大部分を発見した後に切り替えると、通常は最も効果的です。

## Snapshot Fuzzing For Hard-To-Harness Targets

テスト対象の code が **大きな setup cost**（VM の boot、login の完了、packet の受信、container の parsing、service の initialization）の後でしか到達可能にならない場合、便利な代替手段が **snapshot fuzzing** です。ready 状態の process または VM state を取得し、各 test case を target の input path に注入し、crash/timeout まで実行してから snapshot を restore します。これにより initialization や protocol prefixes の反復を避けられ、**network services**、**firmware**、**post-auth attack surfaces**、**binary-only targets** に有用です。<sup>[[9]](#references)[[10]](#references)</sup>

1. 対象を、interesting state の準備が完了するまで実行します。
2. その時点で **memory + registers** の snapshot を取得します。
3. 各 test case について、mutated input を関連する guest/process buffer に直接書き込みます。
4. crash/timeout/reset まで実行します。
5. snapshot を restore します。VM targets では、サポートされている場合は **dirty pages** のみを restore してから繰り返します。

snapshot は、最初の高コストな parse/dispatch step に可能な限り近い位置、たとえば `recv`/`read` の後や packet-deserialization point に配置し、target が使用する input buffer を記録します。これは、作業の反復を避けるために snapshot を input processing のさらに深い位置へ移動する adaptive-placement principle に従います。<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

campaign が停滞した場合、問題は mutator ではなく **harness** であることがよくあります。**reachability/coverage introspection** を使用して、fuzz target から static には到達可能であるものの、dynamic にはほとんど、またはまったく coverage されていない functions を見つけます。これらの functions は通常、次の 3 つの問題のいずれかを示します。<sup>[[12]](#references)</sup>

- harness が target に入るのが遅すぎる、または早すぎる。
- seed corpus に feature family 全体が欠けている。
- target には、1 つの oversized な「do everything」harness ではなく、**second harness** が本当に必要である。

OSS-Fuzz / ClusterFuzz-style workflows を使用している場合、Fuzz Introspector は static reachability と runtime coverage を比較し、timed run または public corpus から reports を生成できます。<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
レポートを使用して、未テストの parser path 用に新しい harness を追加するか、特定の feature の corpus を拡張するか、monolithic harness をより小さな entry point に分割するかを判断します。

## Graph-First Fuzz Target Selection And Mutation Triage

すでに **static-analysis findings**、**mutation-testing survivors**、**coverage reports** がある場合、それらを独立したリストとして triage しないでください。まず **call graph** を構築し、ノードに **cyclomatic complexity**、**entrypoint/untrusted-input reachability**、外部の findings を注釈として付与してから、graph に関する問いを立てます。<sup>[[5]](#references)[[6]](#references)</sup>

- **untrusted input** から到達可能な high-complexity function はどれか？
- parser/handler から security-critical code への path 上に、どの mutation survivor が存在するか？
- 異常に大きな **blast radius** を持つ architectural choke point はどの function か？

これは通常、単に「lowest coverage」だけを見るよりも、優れた fuzz target を見つけるのに役立ちます。**high complexity** で **external reachability** が確認された parser/decoder は、coverage が低くても attacker-controlled path がない孤立した internal helper より、強力な harness 候補です。

### Practical triage workflow

1. codebase から **code graph** を構築し、function ごとの complexity/branch metrics を抽出します。
2. attacker-controlled input を受け付ける **entrypoint** を列挙します：request handler、decoder、importer、protocol parser、CLI/file reader。
3. それらの entrypoint から candidate function への **path query** を実行し、到達可能な attack surface と dead/internal-only code を分離します。
4. 以下の条件を組み合わせて満たす node を優先します：
- high **cyclomatic complexity**
- **untrusted input からの reachability** が確認されている
- high **blast radius** または多数の downstream dependent
- **SARIF** findings、audit note、mutation survivor などの裏付けとなる evidence
5. 特に hex/Base64/IP/message decoder などの **parser/codec** を中心に、スコアの高い node 用の focused harness を先に作成します。

### Mutation survivors: equivalent vs actionable

Mutation testing では、しばしば大量の noisy な survivor list が生成されます。すべての survivor を security gap とみなす前に、graph を使用して以下を確認します：

- mutated function は attacker-controlled entrypoint から到達可能か？
- すべての call path は、mutated check より強い invariant によって制約されているか？
- node は dead code、formatting-only logic、または high-impact arithmetic/parser path のいずれに存在するか？

到達不能または構造的に制約されている survivor は、多くの場合 **equivalent mutant** です。一方、**reachable** のままで、**boundary condition**、**overflow/carry path**、または **security-critical arithmetic/parsing** に影響する survivor は、以下へ昇格させるべきです：

- new fuzz harness
- direct property/invariant test
- targeted edge-case vector

### Correlate external findings onto the graph

SAST pipeline が **SARIF** を export する場合、**file + line range** によって findings を graph node に project し、graph を使用して impact を拡張します。<sup>[[6]](#references)</sup>

- flagged function の **blast radius** を計算する
- finding が entrypoint からのいずれかの path 上にあるか確認する
- 同じ choke point に集約される nearby findings を cluster 化する

これは、特定の function に fuzzing の時間を費やすか判断する際に有用です：**reachable** で、**complex** かつすでに **SAST hits** がある node は、complex であっても attacker path がない node より、通常は優れた target です。

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
重要な methodology は、**complexity x exposure x impact** の交差部分です。グラフを使って、期待される security value が最も高い fuzz target を選び、その後、mutation survivor を使って、harness が stress すべき boundary と invariant を判断します。<sup>[[5]](#references)</sup>

## gosentry による Go Fuzzing: より強力な Engine、Typed Input、そして Differential Check

Go target にすでにネイティブな `testing.F` harness がある場合、実用的な upgrade path は、[gosentry](https://github.com/trailofbits/gosentry) を使って同じ harness を実行することです。gosentry は fork された Go toolchain で、`go test -fuzz` を維持しながら、backend を **LibAFL** に置き換えます。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
これは、native Go fuzzer が **hard comparisons**、**typed inputs**、または **parser-heavy formats** で停止した場合に役立ちます。方法論は同じです。

- seeds には引き続き `f.Add(...)` を使用し、callback には `f.Fuzz(...)` を使用します。
- 同じ harness を再利用しますが、stock toolchain ではなく gosentry の `go` binary で実行します。
- 結果として得られる campaign は通常の coverage-guided run として扱います。ただし、LibAFL の scheduling/mutation と、より優れた周辺 detector が使用されます。

### サイレントな失敗を fuzz findings に変える

Go の assessment で繰り返し発生する問題は、危険な挙動がデフォルトでは crash しないことです。gosentry では、複数の「bad but silent」な状態を findings に昇格できます。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` を使用すると、指定した logging/error path を crash として扱えます（通常は log のみ出力して処理を継続する `log.Fatal` 型の code path に有用です）。
- `--catch-races=true` を使用すると、新たに発見した queue entry を Go race detector で再実行できます。
- `--catch-leaks=true` を使用すると、新しい queue entry を `goleak` で再実行し、goroutine leak の発生時に停止できます。
- LibAFL の hang handling により、**infinite loop / very slow input** を timeout として消失させず、fuzz findings として保持できます。
- デフォルトで組み込まれている arithmetic overflow check に加え、go-panikint-style instrumentation による truncation check も任意で有効化できます。

これは、security impact が memory corruption ではなく、**panicless parser failure**、**concurrency bug**、または **DoS-only hang** である target に特に有用です。

### typed Go API の struct-aware fuzzing

Native Go fuzzing は主に `[]byte`、`string`、数値などの scalar を想定しています。テスト対象の code が typed object を受け取る場合、gosentry は bytes を内部で mutation しながら、struct、slice、array、pointer などの **composite value** を直接 fuzz できます。<sup>[[7]](#references)[[8]](#references)</sup>
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
これは、fuzzing 専用の fake wire format を構築する場合に使用すると、harness 専用のパースコードによって logic bug が隠れてしまいます。差分 fuzzing や grammar-based campaign では、harness の入力を単一の `[]byte` または `string` として保持し、代わりに callback 内でパースしてください。

### parser と protocol input 向けの grammar-based fuzzing

parser、format、input language では、gosentry は LibAFL 上で **Nautilus grammar fuzzing** を実行できます。grammar は production rule の JSON 配列であり、harness は通常、単一の `[]byte` または `string` 引数を受け取るようにします。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- byte-level mutations が初期の syntax checks でほとんど失敗する場合は、grammar mode を使用する。
- 言語や protocol の完全な仕様をモデル化するのではなく、**security-relevant subset** に grammar の範囲を絞る。
- terminals/nonterminals で大きな境界値を使用し、integer、length、state-machine のエッジに負荷をかける。
- grammar mode では入力が grammar-valid に保たれるが、target が受け取るのは依然として **bytes/strings** であるため、parsing と semantic checks は harness 化された code 内に残る。

### Differential fuzzing: crash だけでなく実装を比較する

Go ecosystem で有効な pattern は **grammar-based differential fuzzing** である。valid な structured inputs を生成し、それらを2つの parser、client、または state-transition engine に渡す。<sup>[[7]](#references)[[8]](#references)</sup>
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
以下を findings として扱います：

- 一方の実装は panic するが、もう一方は正常に reject する
- accepted/rejected input の不一致
- parse tree または decoded object の相違
- state transition、nonce、balance、state root の相違

これは、純粋な crash fuzzing では見落とされがちな **consensus mismatches**、**parser ambiguity**、**spec-vs-implementation drift** を発見する実用的な方法です。

### coverage reporting のために campaign corpus を再利用する

campaign の後、保存された queue corpus を replay することで、別の corpus を手動で export せずに Go coverage report を生成できます。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
同じ package から、同じ `-fuzz` target を指定してコマンドを実行し、gosentry が正しいキャッシュ済み campaign state を解決できるようにします。

## References

- [1] [変異文法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing の詳細](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: カバレッジ誘導型プロトコル fuzzing について](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark がコードをグラフに変換](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing には toolkit の半分が欠けていた。私たちはそれを修正するために toolchain を fork した。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: スナップショットを使用した stateful network protocols 向け高速 greybox fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar がなくても問題なし: system-call descriptions なしで Linux kernel を fuzzing するために](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: adaptive かつ mutable な snapshots による効率的な fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
