# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutation Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**では、入力は **grammar-valid** を保ったまま変異されます。coverage-guided モードでは、**new coverage** を引き起こしたサンプルだけが corpus seeds として保存されます。**language targets**（parsers、interpreters、engines）では、これは、ある構文要素の出力が別の構文要素の入力になるような **semantic/dataflow chains** を必要とするバグを見逃すことがあります。

**Failure mode:** fuzzer は個別に `document()` と `generate-id()`（または同様のプリミティブ）を実行する seeds を見つけますが、**連結された dataflow を保持しない**ため、bug により近いサンプルは coverage を増やさないので捨てられます。**3+ dependent steps** があると、ランダムな再結合は高コストになり、coverage feedback は探索を導きません。

**Implication:** dependency-heavy な grammars では、**mutational** と **generative** フェーズを **hybridize** するか、coverage だけでなく **function chaining** パターンに生成を寄せることを検討してください。

## Corpus Diversity Pitfalls

Coverage-guided mutation は **greedy** です。新しい coverage を持つサンプルは即座に保存され、しばしば大きく未変更の領域が残ります。時間が経つと corpus は **near-duplicates** だらけになり、構造的多様性が低くなります。強い minimization は有用な文脈を削ってしまうため、実用的な妥協案は、**最小 token threshold** で **停止する grammar-aware minimization** です（ノイズを減らしつつ、mutation-friendly のまま十分な周辺構造を残す）。

mutational fuzzing における実践的な corpus ルールは、**near-duplicates の大きな山よりも、coverage を最大化する構造的に異なる少数の seeds を優先する**ことです。実際には、これは通常次を意味します。

- **real-world samples**（public corpora、crawling、captured traffic、target ecosystem の file sets）から始める。
- すべての valid sample を保持するのではなく、**coverage-based corpus minimization** で絞り込む。
- mutation が意味のある fields に当たるように、seeds を **十分小さく** 保つ。無関係な bytes に大半の cycle を費やさないようにする。
- 到達可能性が変わると “best” corpus も変わるため、主要な harness/instrumentation の変更後には corpus minimization を再実行する。

## Comparison-Aware Mutation For Magic Values

fuzzer が停滞する一般的な理由は syntax ではなく、**hard comparisons** です。magic bytes、length checks、enum strings、checksums、あるいは `memcmp`、switch tables、連鎖した comparisons によって守られた parser dispatch values です。純粋なランダム変異は、これらの値を byte-by-byte で当てようとして cycle を浪費します。

この種の target では、**comparison tracing**（たとえば AFL++ `CMPLOG` / Redqueen-style workflows）を使い、fuzzer が失敗した comparisons の operands を観測して、それらを満たす値へ mutation を寄せられるようにしてください。
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
**実践メモ:**

- これは、対象が **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** の背後に深いロジックを隠している場合に特に有効です。
- 実サンプル、protocol specs、または debug logs から抽出した **dictionaries** と組み合わせます。grammar tokens、chunk names、verbs、delimiter を含む小さな dictionary は、巨大な汎用 wordlist よりも価値が高いことがよくあります。
- 対象が多段の sequential checks を行う場合は、まず最初の “magic” 比較を解き、その後に結果の corpus をもう一度最小化して、後段がすでに valid な prefix から始まるようにします。

## Stateful Fuzzing: Sequences Are Seeds

**protocols**、**authenticated workflows**、**multi-stage parsers** では、興味深い単位は単一の blob ではなく **message sequence** であることが多いです。全 transcript を 1 つの file に連結して無差別に mutation するのは、通常は非効率です。fuzzer は各 step を等しく mutate しますが、fragile state に到達するのは後半の message だけだからです。

より効果的なやり方は、**sequence 自体を seed として扱い**、**observable state**（response codes、protocol states、parser phases、returned object types）を追加の feedback として使うことです:

- **valid prefix messages** は安定させ、mutation は **transition-driving** な message に集中させます。
- 次の step がそれに依存する場合は、前の response から identifier や server-generated values をキャッシュします。
- 不透明な blob として serialized transcript 全体を mutate するより、message ごとの mutation/splicing を優先します。
- protocol が意味のある response codes を公開しているなら、それを **cheap state oracle** として使い、より深く進む sequence を優先します。

これが、authenticated bugs、hidden transitions、または “only-after-handshake” の parser bugs が、素朴な file-style fuzzing では見落とされやすい理由です。fuzzer は構造だけでなく、**order, state, and dependencies** も維持しなければなりません。

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** と **coverage reuse** をハイブリッド化する実用的な方法は、永続的な server に対して **短命の workers を再起動** することです。各 worker は空の corpus から始め、`T` 秒後に sync し、結合した corpus でさらに `T` 秒実行し、再び sync してから終了します。これにより、蓄積された coverage を活用しつつ、各 generation ごとに **fresh structures** を得られます。

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

- `-in empty` は、各生成ごとに **fresh corpus** を強制する。
- `-server_update_interval T` は、**遅延 sync**（新規性を先に、再利用を後で）を近似する。
- grammar fuzzing モードでは、**initial server sync はデフォルトでスキップされる**（`-skip_initial_server_sync` は不要）。
- 最適な `T` は **target-dependent** であり、worker が “easy” coverage の大半を見つけた後に切り替えるのが最も効果的なことが多い。

## Snapshot Fuzzing For Hard-To-Harness Targets

テストしたい code が、**大きな setup cost**（VM の起動、login の完了、packet の受信、container の parsing、service の初期化）の後でしか到達可能にならない場合、便利な代替手段が **snapshot fuzzing** です:

1. target を、興味のある state が ready になるまで実行する。
2. その時点で **memory + registers** を snapshot する。
3. 各 test case ごとに、mutated input を関連する guest/process buffer に直接書き込む。
4. crash/timeout/reset まで execute する。
5. **dirty pages** だけを restore して repeat する。

これにより、毎回フルの setup cost を払わずに済み、特に **network services**、**firmware**、**post-auth attack surfaces**、および classic な in-process harness に refactor するのが面倒な **binary-only targets** に非常に有効です。

実用的な trick は、`recv`/`read`/packet-deserialization の直後で即座に break し、input buffer address を記録し、その後は各 iteration でその buffer を直接 mutate することです。これにより、毎回 handshake 全体を再構築することなく、深い parsing logic を fuzz できます。

## Harness Introspection: Find Shallow Fuzzers Early

campaign が stall したとき、問題は mutator ではなく **harness** にあることが多いです。**reachability/coverage introspection** を使って、fuzz target から静的には到達可能だが、動的にはほとんど、またはまったく covered されない function を見つけます。そうした function は通常、次の 3 つの問題のどれかを示しています:

- harness が target に入るのが遅すぎるか、早すぎる。
- seed corpus に feature family が丸ごと欠けている。
- target には、1 つの巨大な「全部やる」harness ではなく、**second harness** が本当に必要。

OSS-Fuzz / ClusterFuzz-style workflows を使っているなら、Fuzz Introspector はこの triage に役立ちます:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
レポートを使って、未テストの parser パスに新しい harness を追加するか、特定の機能向けに corpus を拡張するか、あるいはモノリシックな harness を小さな entry point に分割するかを判断する。

## Graph-First Fuzz Target Selection And Mutation Triage

すでに **static-analysis findings**、**mutation-testing survivors**、および **coverage reports** があるなら、それらを独立したリストとして triage しない。まず **call graph** を構築し、ノードに **cyclomatic complexity**、**entrypoint/untrusted-input reachability**、および外部の findings を注釈してから、graph に対して問いを立てる。

- どの高複雑度関数が untrusted input から到達可能か？
- どの mutation survivors が parser/handler から security-critical code へ至る path 上にあるか？
- どの関数が、異常に高い **blast radius** を持つ architectural choke point か？

これは通常、「lowest coverage」だけよりも良い fuzz target を見つける。**high complexity** を持ち、かつ外部からの到達性が確認できている parser/decoder は、coverage は低いが attacker-controlled path を持たない孤立した internal helper よりも、より強い harness 候補である。

### Practical triage workflow

1. codebase から **code graph** を作成し、関数ごとの complexity/branch metrics を抽出する。
2. attacker-controlled input を受け付ける **entrypoints** を列挙する: request handlers, decoders, importers, protocol parsers, CLI/file readers。
3. それらの entrypoints から candidate functions への **path queries** を実行し、到達可能な attack surface と dead/internal-only code を分離する。
4. 以下を組み合わせたノードを優先する:
- high **cyclomatic complexity**
- untrusted input からの confirmed **reachability**
- high **blast radius** または多くの downstream dependents
- **SARIF** findings, audit notes, mutation survivors などの補強証拠
5. 最もスコアの高いノードに対して focused harness を最初に書く。特に hex/Base64/IP/message decoders のような **parsers/codecs** を優先する。

### Mutation survivors: equivalent vs actionable

Mutation testing はしばしば noisy な survivor list を生成する。すべての survivor を security gap と見なす前に、graph を使って次を確認する。

- mutated function は attacker-controlled entrypoint から到達可能か？
- すべての call path は、mutated check より強い invariant によって制約されているか？
- そのノードは dead code、formatting-only logic、または高インパクトな arithmetic/parser path にあるか？

到達不能または構造的に制約されたままの survivors は、しばしば **equivalent mutants** である。**reachable** であり、かつ **boundary conditions**、**overflow/carry paths**、または **security-critical arithmetic/parsing** に触れる survivors は、次へ昇格させるべきである。

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

SAST pipeline が **SARIF** を出力する場合、**file + line range** によって findings を graph nodes に投影し、graph を使って影響範囲を広げる。

- flagged function の **blast radius** を計算する
- その finding が entrypoint からの any path 上にあるか確認する
- 近接する findings をまとめて、同じ choke point に収束するか cluster する

これは、特定の関数に fuzzing 時間を使うべきか決めるときに有用である。**reachable** で、**complex** で、すでに **SAST hits** があるノードは、単に複雑なだけで attacker path のないノードより、しばしばより良い target である。

Example workflow with Trailmark:
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
重要な方法論は交差点です: **complexity x exposure x impact**。グラフを使って、期待される security value が最も高い fuzz 対象を選び、その後 mutation survivors を使って、ハーネスがどの境界と不変条件を強くストレスすべきかを判断します。

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Go のターゲットにすでに native の `testing.F` harness がある場合、実用的な更新方法は、その同じ harness を [gosentry](https://github.com/trailofbits/gosentry) で実行することです。これは fork された Go toolchain で、`go test -fuzz` を維持しつつ backend を **LibAFL** に置き換えます。
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
ネイティブの Go fuzzer が **hard comparisons**、**typed inputs**、または **parser-heavy formats** で停止する場合に便利です。方法論は同じです:

- シードには `f.Add(...)` を使い続け、コールバックには `f.Fuzz(...)` を使う。
- 同じハーネスを再利用するが、標準の toolchain ではなく gosentry の `go` binary で実行する。
- 結果の campaign は通常の coverage-guided run として扱うが、LibAFL の scheduling/mutation と、より優れた周辺の detector を使う。

### 無音の失敗を fuzz finding に変える

Go の assessment で繰り返し起こる問題は、危険な動作がデフォルトではしばしば **crash** しないことです。gosentry を使うと、いくつかの “bad but silent” な状態を finding に昇格できます:

- `--panic-on=pkg.Func,...` で、選択した logging/error path を crash のように振る舞わせる（通常は log して継続するだけの `log.Fatal` スタイルの code path に有用）。
- `--catch-races=true` で、新しく見つかった queue entry を Go race detector で再実行する。
- `--catch-leaks=true` で、新しい queue entry を `goleak` で再実行し、goroutine leak で停止する。
- LibAFL の hang handling により、**infinite loops / very slow inputs** を timeout として消すのではなく fuzz finding として保持する。
- デフォルトの arithmetic overflow チェックに加え、go-panikint-style instrumentation を通じた optional truncation checks。

これは特に、security impact が memory corruption ではなく **panicless parser failure**、**concurrency bug**、または **DoS-only hang** である target に対して非常に有用です。

### typed Go API 向けの struct-aware fuzzing

ネイティブの Go fuzzing は主に `[]byte`、`string`、数値のような scalar を想定しています。テスト対象の code が typed object を受け取る場合、gosentry は内部では byte を mutating しつつ、**composite values**（struct、slice、array、pointer）を直接 fuzz できます。
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
偽の wire format を fuzzing 専用に作るのは、harness 専用の parsing code の背後に logic bug を隠してしまう。differential や grammar-based のキャンペーンでは、harness input は単一の `[]byte` または `string` のままにして、代わりに callback の中で parse する。

### parser と protocol input のための Grammar-based fuzzing

parser、format、input language については、gosentry は LibAFL の上で **Nautilus grammar fuzzing** を実行できる。grammar は production rule の JSON array で、harness は通常、単一の `[]byte` または `string` の引数を取るべきである。
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- バイトレベルの変異が初期の構文チェックでほとんど死ぬ場合は、grammar mode を使う。
- full specification をモデル化するのではなく、言語/protocol の **security-relevant subset** に grammar を絞る。
- integer、length、state-machine の境界をあぶり出すため、terminals/nonterminals には大きな境界値を使う。
- Grammar mode は inputs を grammar-valid に保つが、target は依然として **bytes/strings** を受け取るため、parsing と semantic checks は harnessed code の中に残る。

### Differential fuzzing: compare implementations, not just crashes

Go ecosystem での強力な pattern は **grammar-based differential fuzzing** です: valid な structured inputs を生成し、2つの parsers、clients、または state-transition engines に投入する。
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
以下を findings として扱ってください:

- 一方の実装は panic するが、もう一方は適切に reject する
- accepted/rejected input の不一致
- 異なる parse tree または decoded objects
- state transitions, nonce, balances, または state roots の不一致

これは、pure crash fuzzing では見落としがちな **consensus mismatches**、**parser ambiguity**、および **spec-vs-implementation drift** を見つける実践的な方法です。

### coverage reporting のために campaign corpus を再利用する

campaign の後、保存された queue corpus を replay して、別途 corpus を手動で export せずに Go coverage report を生成します:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
同じ package から、同じ `-fuzz` target で command を実行してください。そうすることで gosentry が正しい cached campaign state を解決できます。

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
