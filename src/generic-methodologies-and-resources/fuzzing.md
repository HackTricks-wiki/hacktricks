# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

在 **mutational grammar fuzzing** 中，inputs 会被变异，但保持 **grammar-valid**。在 coverage-guided 模式下，只有触发 **new coverage** 的样本会被保存为 corpus seeds。对于 **language targets**（parsers、interpreters、engines），这可能会遗漏那些需要 **semantic/dataflow chains** 的漏洞——即一个构造的输出成为另一个构造的输入。

**Failure mode：**fuzzer 可能找到分别能触发 `document()` 和 `generate-id()`（或类似原语）的 seeds，但**没有保留链式数据流**，因此更“接近 bug” 的样本会被丢弃，因为它没有增加 coverage。当存在 **3+ dependent steps** 时，随机重组合代价高昂，coverage 反馈无法有效引导搜索。

**Implication：**对于依赖性强的 grammar，考虑 **hybridizing mutational and generative phases**，或在生成时偏向 **function chaining** 模式（而不仅仅追求 coverage）。

## Corpus Diversity Pitfalls

Coverage-guided mutation 是 **greedy**：一旦出现 new-coverage 的样本就会被立即保存，通常保留大量未改变的区域。随着时间推移，corpora 会变成 **near-duplicates**，结构多样性很低。激进的最小化可能移除有用的上下文，所以一个实用的折衷是采用 **grammar-aware minimization**，并**在达到最小 token 阈值后停止**（减少噪声，同时保留足够的周边结构以便继续方便地进行 mutation）。

## Single-Machine Diversity Trick (Jackalope-Style)

一种将 **generative novelty** 与 **coverage reuse** 混合的实用方法是对持久 server **restart short-lived workers**。每个 worker 从空的 corpus 开始，运行 `T` 秒后同步（sync），在合并后的 corpus 上再运行另一个 `T` 秒，再次同步，然后退出。这会在每一代产生 **fresh structures each generation**，同时仍能利用已累积的 coverage。

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**顺序 workers（示例 loop）：**

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

- `-in empty` 强制在每次生成时使用 **全新语料库**。
- `-server_update_interval T` 近似 **延迟同步**（先新颖，后重用）。
- 在 grammar fuzzing mode 中，**默认会跳过 initial server sync**（无需 `-skip_initial_server_sync`）。
- 最佳的 `T` 是 **取决于目标**；在 worker 找到大部分 “easy” coverage 之后切换通常效果最佳。

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
