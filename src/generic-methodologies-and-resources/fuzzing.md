# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** では、入力は **grammar-valid** を保ったまま変異されます。coverage-guided モードでは、**新しい coverage** を引き起こしたサンプルだけが corpus seeds として保存されます。**language targets**（parsers、interpreters、engines）では、これはある構文要素の出力が別の構文要素の入力になるような **semantic/dataflow chains** を必要とするバグを見逃すことがあります。

**Failure mode:** fuzzer は個別には `document()` と `generate-id()`（または同様の primitive）を実行する seeds を見つけますが、**連結された dataflow を維持しません**。そのため、bug により近いサンプルでも、coverage を増やさないので捨てられてしまいます。**3+ の依存ステップ** があると、ランダムな再結合は高コストになり、coverage feedback は探索を導けません。

**Implication:** dependency-heavy な grammars では、**mutational と generative の phases を hybridize** するか、coverage だけでなく **function chaining** パターンに寄せて生成することを検討してください。

## Corpus Diversity Pitfalls

Coverage-guided mutation は **greedy** です。新しい coverage を持つサンプルは即座に保存され、しばしば大きな未変更領域を保持します。時間が経つと corpus は、構造的多様性の低い **near-duplicates** だらけになります。過度な minimization は有用な文脈を削ってしまうため、実用上の妥協点は、**最小 token threshold に達したら止める** **grammar-aware minimization** です（mutation-friendly な周辺構造を十分残しつつ、ノイズを減らす）。

mutational fuzzing における実用的な corpus ルールは、**near-duplicates の大量保有よりも、coverage を最大化する構造的に異なる少数の seeds を優先する**ことです。実際には、これは通常次を意味します。

- **real-world samples**（public corpora、crawling、captured traffic、target ecosystem 由来の file sets）から始める。
- すべての valid sample を残すのではなく、**coverage-based corpus minimization** で絞り込む。
- mutation が無関係な bytes ではなく意味のある fields に当たるよう、seeds を **十分小さく** 保つ。
- reachability が変わると「最適な」corpus も変わるため、主要な harness/instrumentation 変更後には corpus minimization を再実行する。

## Comparison-Aware Mutation For Magic Values

fuzzer が頭打ちになる一般的な理由は syntax ではなく、**hard comparisons** です。magic bytes、length checks、enum strings、checksums、あるいは `memcmp`、switch tables、連鎖した comparisons によって保護された parser dispatch values です。純粋な random mutation は、これらの値を byte-by-byte で当てようとして cycle を浪費します。

これらの targets では、**comparison tracing**（たとえば AFL++ `CMPLOG` / Redqueen-style workflows）を使い、fuzzer が失敗した comparisons の operands を観測して、それらを満たす values へ mutation を寄せられるようにしてください。
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
- 実サンプル、protocol specs、または debug logs から抽出した **dictionaries** と組み合わせます。grammar tokens、chunk names、verbs、delimiter を含む小さな dictionary のほうが、巨大な汎用 wordlist より価値が高いことがよくあります。
- 対象が多段の sequential checks を行う場合は、まず最初の “magic” comparison を解き、次に生成された corpus をもう一度最小化して、後段がすでに有効な prefix から始まるようにします。

## Stateful Fuzzing: Sequences Are Seeds

**protocols**、**authenticated workflows**、そして **multi-stage parsers** では、面白い単位は単一の blob ではなく **message sequence** であることがよくあります。トランスクリプト全体を 1 つの file に連結して盲目的に mutation するのは、たいてい非効率です。fuzzer は各 step を同じ重みで mutation してしまいますが、fragile な state に到達するのは後半の message だけだからです。

より効果的な方法は、**sequence そのものを seed** として扱い、**observable state**（response codes、protocol states、parser phases、returned object types）を追加の feedback として使うことです:

- **valid prefix messages** は安定させ、mutation は **transition-driving** な message に集中させます。
- 次の step が前の response に依存する場合は、identifier や server-generated values を保持してキャッシュします。
- opaque な blob として transcript 全体を mutation するより、message ごとの mutation/splicing を優先します。
- protocol が意味のある response codes を公開しているなら、より深い状態へ進んだ sequence を優先するための **cheap state oracle** として使います。

これが、authenticated bugs、hidden transitions、あるいは “only-after-handshake” の parser bug が、通常の file-style fuzzing では見逃されやすい理由です。fuzzer は構造だけでなく、**順序、state、dependency** を維持しなければなりません。

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** と **coverage reuse** を組み合わせる実用的な方法は、persistent server に対して **short-lived workers** を再起動し続けることです。各 worker は空の corpus から開始し、`T` 秒後に sync し、結合された corpus でさらに `T` 秒実行し、再び sync してから終了します。これにより、**fresh structures each generation** を得つつ、蓄積された coverage も活用できます。

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

- `-in empty` は、各生成ごとに **fresh corpus** を強制します。
- `-server_update_interval T` は **delayed sync** を近似します（novelty を先に、reuse を後で）。
- grammar fuzzing モードでは、**initial server sync はデフォルトでスキップ**されます（`-skip_initial_server_sync` は不要）。
- 最適な `T` は **target-dependent** です。worker が大半の “easy” coverage を見つけた後に切り替えるのが最も効果的な傾向があります。

## Snapshot Fuzzing For Hard-To-Harness Targets

テストしたい code が、**大きな setup cost** の後でしか到達不能な場合（VM の起動、login の完了、packet の受信、container の parsing、service の initialization など）、有用な代替手段が **snapshot fuzzing** です:

1. target を、興味深い state が準備できるところまで実行する。
2. その時点で **memory + registers** を snapshot する。
3. 各 test case ごとに、mutated input を relevant な guest/process buffer に直接書き込む。
4. crash/timeout/reset まで実行する。
5. **dirty pages** のみを restore して繰り返す。

これにより、毎回フルの setup cost を支払わずに済み、特に **network services**、**firmware**、**post-auth attack surfaces**、そして classic な in-process harness にリファクタリングするのが厄介な **binary-only targets** に有効です。

実用的なコツは、`recv`/`read`/packet-deserialization の地点で即座に break し、input buffer の address を記録して、その buffer を各反復で直接 mutate することです。これにより、毎回 handshake 全体を再構築せずに、deep な parsing logic を fuzz できます。

## Harness Introspection: Find Shallow Fuzzers Early

campaign が停滞したとき、問題は mutator ではなく **harness** にあることがよくあります。**reachability/coverage introspection** を使って、fuzz target から静的には到達可能だが、動的にはほとんど、あるいはまったく covered されない functions を見つけます。そうした functions は通常、次の 3 つの問題のいずれかを示します:

- harness が target に入るのが早すぎる、または遅すぎる。
- seed corpus に feature family が丸ごと不足している。
- target には、1 つの巨大な “do everything” harness ではなく、**second harness** が本当に必要。

OSS-Fuzz / ClusterFuzz 系の workflows を使っているなら、Fuzz Introspector はこの triage に役立ちます:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
レポートを使って、未テストのパーサーパス用に新しい harness を追加するか、特定の機能向けに corpus を拡張するか、あるいは単一の monolithic harness をより小さな entry point に分割するかを判断します。

## Graph-First Fuzz Target Selection And Mutation Triage

すでに **static-analysis findings**、**mutation-testing survivors**、および **coverage reports** があるなら、それらを独立したリストとして triage しないでください。まず **call graph** を構築し、ノードに **cyclomatic complexity**、**entrypoint/untrusted-input reachability**、および外部の findings を注釈付けしてから、graph に対して質問します:

- どの高複雑度関数が untrusted input から到達可能か?
- どの mutation survivors が parser/handler から security-critical code への path 上にあるか?
- どの関数が、異常に高い **blast radius** を持つ architectural choke point か?

これは通常、「lowest coverage」だけを見るよりも良い fuzz target を見つけます。**高い complexity** と確認済みの **external reachability** を持つ parser/decoder は、coverage が低いだけで attacker-controlled path を持たない isolated な internal helper よりも、より強い harness 候補です。

### Practical triage workflow

1. codebase から **code graph** を構築し、関数ごとの complexity/branch metrics を抽出します。
2. attacker-controlled input を受け取る **entrypoints** を列挙します: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. それらの entrypoints から candidate functions への **path queries** を実行し、到達可能な attack surface と dead/internal-only code を分離します。
4. 以下を組み合わせたノードを優先します:
- 高い **cyclomatic complexity**
- untrusted input からの到達可能性が確認済み
- 高い **blast radius** または多数の downstream dependents
- **SARIF** findings, audit notes, mutation survivors などの補強証拠
5. まず最もスコアの高いノードに対して focused harness を書きます。特に hex/Base64/IP/message decoders のような **parsers/codecs** を優先します。

### Mutation survivors: equivalent vs actionable

Mutation testing はしばしばノイジーな survivor list を生成します。すべての survivor を security gap とみなす前に、graph を使って次を確認します:

- 変異させた関数は attacker-controlled entrypoint から到達可能か?
- すべての call path は、変異したチェックより強い invariant によって制約されているか?
- そのノードは dead code、formatting-only logic、または高影響の arithmetic/parser path にあるか?

到達不能のままか、構造的に強く制約された survivors は、しばしば **equivalent mutants** です。到達可能で、**boundary conditions**、**overflow/carry paths**、または **security-critical arithmetic/parsing** に触れる survivors は、次の対象へ昇格させるべきです:

- 新しい fuzz harness
- 直接の property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

SAST pipeline が **SARIF** を出力するなら、**file + line range** によって findings を graph node に投影し、graph を使って影響範囲を拡大します:

- フラグが付いた関数の **blast radius** を計算する
- その finding が entrypoint からの path 上にあるか確認する
- 近接する findings をクラスタ化し、同じ choke point に収束するかを見る

これは、特定の関数に fuzzing 時間を使うべきか判断するときに役立ちます。**reachable** で **complex** かつすでに **SAST hits** があるノードは、単に複雑なだけで attacker path のないノードより、しばしば良い target です。

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
重要な方法論は交差点です: **complexity x exposure x impact**。グラフを使って期待される security value が最も高い fuzz target を選び、その後 mutation survivors を使って、どの境界と invariants を harness で強く試すべきかを判断します。

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
