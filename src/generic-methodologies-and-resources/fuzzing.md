# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## 変異的 Grammar Fuzzing: Coverage vs. Semantics

**変異的 grammar fuzzing** では、入力は **grammar-valid** を保ったまま変異される。coverage-guided モードでは、**新しい coverage** を引き起こしたサンプルだけが corpus seeds として保存される。**language targets**（parsers, interpreters, engines）では、これは、1つの構文要素の出力が別の構文要素の入力になるような **semantic/dataflow chains** を必要とするバグを見逃すことがある。

**Failure mode:** fuzzer は個別に `document()` と `generate-id()`（または同様の primitive）を実行する seeds を見つけるが、**連結された dataflow を保持しない**ため、bug により近い sample は coverage を増やさないので捨てられる。**3+ dependent steps** では、ランダムな再結合は高コストになり、coverage feedback は探索を導かない。

**Implication:** dependency-heavy な grammar では、**mutational と generative の phase を hybridize** するか、生成を **function chaining** パターンへ寄せることを検討する（coverage だけに頼らない）。

## Corpus Diversity の落とし穴

Coverage-guided mutation は **greedy** である: 新しい coverage の sample は即座に保存され、しばしば大きく未変更の領域を保持する。時間がたつと corpus は、構造的多様性の低い **near-duplicates** だらけになる。過度な minimization は有用な文脈を削除してしまうため、実用的な妥協策は、**最小 token threshold** に達したら止める **grammar-aware minimization** である（mutation しやすいだけの周辺構造を十分残しつつ、ノイズを減らす）。

mutational fuzzing における実用的な corpus ルールは、**near-duplicates を大量に持つより、coverage を最大化する構造的に異なる少数の seeds を優先する** ことである。実際には、これは通常次を意味する:

- **real-world samples** から始める（public corpora, crawling, captured traffic, target ecosystem の file sets）。
- すべての valid sample を保持するのではなく、**coverage-based corpus minimization** で絞り込む。
- seeds は **十分小さく** 保ち、mutation が無関係な byte ではなく意味のある field に当たるようにする。
- 大きな harness/instrumentation の変更後は corpus minimization を再実行する。reachability が変わると “best” corpus も変わるからである。

## Magic Values のための Comparison-Aware Mutation

fuzzer が plateau する一般的な理由は syntax ではなく、**hard comparisons** である: magic bytes, length checks, enum strings, checksums, または `memcmp`, switch tables, 連鎖した comparisons で保護された parser dispatch values。純粋な random mutation では、これらの値を byte-by-byte で推測しようとして cycle を浪費する。

この種の target では、**comparison tracing**（たとえば AFL++ `CMPLOG` / Redqueen-style workflows）を使い、fuzzer が失敗した comparison の operands を観測して、それらを満たす値へ mutation を寄せられるようにする。
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

- これは、対象が **file signatures**、**protocol verbs**、**type tags**、または **version-dependent feature bits** の背後に深いロジックを隠している場合に特に有用です。
- 実サンプル、protocol specs、または debug logs から抽出した **dictionaries** と組み合わせます。grammar tokens、chunk names、verbs、区切り文字を含む小さな dictionary の方が、巨大な汎用 wordlist よりも役立つことが多いです。
- 対象が多段の sequential checks を行う場合は、まず最初の “magic” comparisons を解き、その後で生成された corpus をもう一度最小化し、後段がすでに valid な prefixes から始まるようにします。

## Stateful Fuzzing: Sequences Are Seeds

**protocols**、**authenticated workflows**、および **multi-stage parsers** では、重要な単位は単一の blob ではなく **message sequence** であることが多いです。トランスクリプト全体を 1 つのファイルに連結して無差別に変異させるのは、たいてい非効率です。なぜなら、fuzzer は各ステップを同じように変異させますが、脆弱な state に到達するのは後半の message だけだからです。

より効果的なパターンは、**sequence 自体を seed として扱い**、**observable state**（response codes、protocol states、parser phases、返された object types）を追加のフィードバックとして使うことです:

- **valid prefix messages** を安定させたままにし、**transition-driving** な message に変異を集中させます。
- 次の step が前の response に依存する場合は、そこから identifier や server-generated values をキャッシュします。
- 透過的な blob として entire serialized transcript を変異させるより、message ごとの mutation/splicing を優先します。
- protocol が意味のある response codes を返すなら、それを **cheap state oracle** として使い、より深く進む sequence を優先します。

これが、authenticated bugs、hidden transitions、または “only-after-handshake” の parser bugs が、通常の file-style fuzzing で見落とされやすい理由です。fuzzer は構造だけでなく、**order, state, and dependencies** を保持しなければならないからです。

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** と **coverage reuse** をハイブリッド化する実践的な方法は、persistent server に対して **短命な workers を再起動** することです。各 worker は空の corpus から開始し、`T` 秒後に sync し、結合された corpus 上でさらに `T` 秒動作し、再度 sync してから終了します。これにより、**各 generation ごとに新しい structures** を得ながら、蓄積された coverage も活用できます。

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

**注:**

- `-in empty` は生成ごとに **新しいコーパス** を強制する。
- `-server_update_interval T` は **遅延同期** を近似する（新規性を先、再利用を後）。
- grammar fuzzing モードでは、**初期の server sync はデフォルトでスキップ** される（`-skip_initial_server_sync` は不要）。
- 最適な `T` は **対象依存** であり、worker が大半の「簡単な」coverage を見つけた後に切り替えるのが最も効果的なことが多い。

## Snapshot Fuzzing For Hard-To-Harness Targets

テストしたい code が **大きなセットアップコスト**（VM の起動、login の完了、packet の受信、container の parsing、service の初期化）の後にしか到達可能にならない場合、便利な代替手段が **snapshot fuzzing** である:

1. 興味のある state が準備できるまで target を実行する。
2. その時点で **memory + registers** を snapshot する。
3. 各 test case ごとに、mutated input を relevant な guest/process buffer に直接書き込む。
4. crash/timeout/reset まで実行する。
5. **dirty pages** のみを restore して繰り返す。

これにより、毎回の iteration で完全なセットアップコストを払わずに済み、特に **network services**、**firmware**、**post-auth attack surfaces**、および classic な in-process harness にリファクタするのが厄介な **binary-only targets** に有用である。

実用的な手法としては、`recv`/`read`/packet-deserialization の直後で即座に break し、input buffer の address を記録し、そこで snapshot を取る。そして各 iteration でその buffer を直接 mutate する。これにより、毎回 handshake 全体を再構築せずに深い parsing logic を fuzzing できる。

## Harness Introspection: Find Shallow Fuzzers Early

campaign が停滞したとき、問題は mutator ではなく **harness** にあることが多い。**reachability/coverage introspection** を使って、fuzz target から静的には到達可能だが、動的にはほとんど、またはまったく coverage されない functions を見つける。そうした functions は通常、次の3つの問題のいずれかを示している:

- harness が target に入るのが遅すぎるか早すぎる。
- seed corpus に feature family が丸ごと欠けている。
- target には、1つの過大な「何でもやる」harness ではなく、**second harness** が本当に必要である。

OSS-Fuzz / ClusterFuzz-style の workflow を使っているなら、Fuzz Introspector はこの切り分けに役立つ:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
レポートを使って、未テストのパーサーパスに新しい harness を追加するか、特定の機能向けにコーパスを拡張するか、または単一の harness をより小さなエントリポイントに分割するかを判断してください。

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
