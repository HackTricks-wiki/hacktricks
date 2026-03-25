# Fuzzing 方法論

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**では、入力は**grammar-valid**のまま変異されます。coverage-guided モードでは、**new coverage** を引き起こすサンプルのみが corpus seeds として保存されます。特に **language targets**（parsers, interpreters, engines）では、ある構成要素の出力が別の入力になるような **semantic/dataflow chains** を必要とするバグを見逃す可能性があります。

**Failure mode:** the fuzzer finds seeds that individually exercise `document()` and `generate-id()` (or similar primitives), but **does not preserve the chained dataflow**, so the “closer-to-bug” sample is dropped because it doesn’t add coverage. With **3+ dependent steps**, random recombination becomes expensive and coverage feedback does not guide search.

**Implication:** 依存度の高い grammars では、**hybridizing mutational and generative phases** を検討するか、生成を **function chaining** パターンに偏らせる（単なる coverage に依存しない）ことを検討してください。

## Corpus Diversity Pitfalls

Coverage-guided mutation は **greedy** です：**new-coverage** サンプルが即座に保存され、大きな未変更領域が残ることが多いです。時間とともに corpora は構造的多様性の低い **near-duplicates** になってしまいます。攻撃的な minimization は有用なコンテキストを削除することがあるため、実用的な妥協策としては **grammar-aware minimization** を行い、**stops after a minimum token threshold**（ノイズを減らしつつ変異しやすい十分な周辺構造を保持する）ことが挙げられます。

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** を **coverage reuse** とハイブリッド化する実用的な方法は、persistent server に対して **restart short-lived workers** することです。各 worker は空の corpus から開始し、`T` 秒後に sync して、結合された corpus でさらに `T` 秒実行し、再度 sync してから終了します。これにより蓄積された coverage を活用しつつ、各世代で **fresh structures each generation** を得られます。

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**順次 workers (example loop):**

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

**注意:**

- `-in empty` は各生成ごとに**新しいコーパス**を強制します。
- `-server_update_interval T` は**遅延同期**を近似します（新規性優先、後で再利用）。
- In grammar fuzzing mode、**初期のサーバー同期はデフォルトでスキップされます**（`-skip_initial_server_sync` は不要）。
- 最適な `T` は**ターゲット依存**です；worker がほとんどの “easy” カバレッジを見つけた後で切り替えると最良になる傾向があります。

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
