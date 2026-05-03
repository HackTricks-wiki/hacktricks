# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

在 **mutational grammar fuzzing** 中，输入会在保持 **grammar-valid** 的同时被变异。在 coverage-guided 模式下，只有触发 **new coverage** 的样本才会被保存为 corpus seeds。对于 **language targets**（parsers、interpreters、engines），这可能会错过那些需要 **semantic/dataflow chains** 的 bug，也就是一个构造的输出会成为另一个构造的输入。

**Failure mode：** fuzzer 找到了分别能单独触发 `document()` 和 `generate-id()`（或类似原语）的 seeds，但 **没有保留链式 dataflow**，所以“更接近 bug”的样本因为没有增加 coverage 而被丢弃。对于 **3+ dependent steps**，随机重组会变得很昂贵，而且 coverage feedback 无法引导搜索。

**Implication：** 对于依赖性很强的 grammars，考虑将 **mutational** 和 **generative** 阶段混合，或者把生成过程偏向 **function chaining** 模式（而不只是 coverage）。

## Corpus Diversity Pitfalls

Coverage-guided mutation 是 **greedy** 的：一个 new-coverage 样本会立刻被保存，通常会保留大量未改动区域。随着时间推移，corpora 会变成低结构多样性的 **near-duplicates**。激进的最小化可能会移除有用上下文，所以一个实用的折中是 **grammar-aware minimization**：在达到 **minimum token threshold** 后停止（减少噪声，同时保留足够的周边结构以保持易变异）。

一个适用于 mutational fuzzing 的实用 corpus 规则是：**优先选择少量结构不同、且能最大化 coverage 的 seeds，而不是一大堆 near-duplicates**。在实践中，这通常意味着：

- 从 **real-world samples** 开始（public corpora、爬取内容、捕获的流量、来自目标生态的文件集合）。
- 用 **coverage-based corpus minimization** 提炼它们，而不是保留每个有效样本。
- 保持 seeds 足够 **small**，这样变异更容易落在有意义的字段上，而不是把大部分循环浪费在无关字节上。
- 在重大 harness/instrumentation 改动后重新运行 corpus minimization，因为 reachability 变化时，“最佳” corpus 也会变化。

## Comparison-Aware Mutation For Magic Values

fuzzer 停滞的一个常见原因不是语法，而是 **hard comparisons**：magic bytes、长度检查、枚举字符串、校验和，或者由 `memcmp`、switch tables、或级联比较保护的 parser dispatch values。纯随机变异会把大量周期浪费在逐字节猜这些值上。

对于这类目标，使用 **comparison tracing**（例如 AFL++ `CMPLOG` / Redqueen-style workflows），这样 fuzzer 就能观察失败比较中的操作数，并把变异偏向能够满足这些比较的值。
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
**实践笔记：**

- 当目标把深层逻辑隐藏在 **file signatures**、**protocol verbs**、**type tags** 或 **version-dependent feature bits** 后面时，这尤其有用。
- 将它与从真实样本、protocol 规范或 debug logs 中提取的 **dictionaries** 配对使用。一个包含 grammar tokens、chunk names、verbs 和 delimiters 的小型字典，通常比一个巨大的通用 wordlist 更有价值。
- 如果目标执行许多顺序检查，先解决最早的“magic”比较，然后再次最小化得到的 corpus，这样后续阶段就会从已经有效的前缀开始。

## Stateful Fuzzing：Sequences Are Seeds

对于 **protocols**、**authenticated workflows** 和 **multi-stage parsers**，有趣的单位往往不是单个 blob，而是一个 **message sequence**。把整个 transcript 拼接成一个文件并盲目变异通常效率很低，因为 fuzzer 会平均变异每一步，即使只有后面的 message 才会到达脆弱状态。

更有效的模式是把 **sequence 本身当作 seed**，并把 **可观察状态**（response codes、protocol states、parser phases、返回的 object types）作为额外反馈：

- 保持 **valid prefix messages** 稳定，把变异重点放在驱动状态转换的 **transition-driving** message 上。
- 当下一步依赖前一步响应时，缓存前序响应中的标识符和 server-generated values。
- 优先对单条 message 做 mutation/splicing，而不是把整个序列化 transcript 作为一个不可见的 blob 来变异。
- 如果 protocol 暴露了有意义的 response codes，把它们当作一种 **cheap state oracle**，优先选择能更深入推进的 sequences。

这也是为什么 authenticated bugs、隐藏的 transitions，或“仅在 handshake 之后”才出现的 parser bugs，常常会被普通的 file-style fuzzing 漏掉：fuzzer 必须保留 **顺序、状态和依赖关系**，而不只是结构。

## Single-Machine Diversity Trick (Jackalope-Style)

一种将 **generative novelty** 与 **coverage reuse** 混合的实用方法，是对一个持久 server **重启短生命周期的 worker**。每个 worker 都从空 corpus 开始，运行 `T` 秒后同步，接着在合并后的 corpus 上再运行 `T` 秒，再同步一次，然后退出。这样既能在每一代产生 **fresh structures**，又能利用已累计的 coverage。

**Server：**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**顺序 worker（示例循环）：**

<details>
<summary>Jackalope worker 重启循环</summary>
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

- `-in empty` 强制每次生成都使用一个**全新的 corpus**。
- `-server_update_interval T` 近似实现**延迟同步**（先新颖性，后复用）。
- 在 grammar fuzzing 模式下，默认会跳过初始 server sync（无需 `-skip_initial_server_sync`）。
- 最优的 `T` 是**取决于目标**的；在 worker 已经找到大部分“容易”的 coverage 之后再切换，通常效果最好。

## Snapshot Fuzzing For Hard-To-Harness Targets

当你要测试的代码只有在**付出较大的初始化成本**之后才可达时（启动 VM、完成登录、接收一个 packet、解析一个 container、初始化一个 service），一个有用的替代方案是 **snapshot fuzzing**：

1. 运行目标，直到有趣的状态准备好。
2. 在该时刻 snapshot **memory + registers**。
3. 对于每个测试用例，直接把变异后的输入写入相关的 guest/process buffer。
4. 执行直到 crash/timeout/reset。
5. 只恢复**dirty pages**，然后重复。

这避免了每次迭代都支付完整的初始化成本，尤其适用于**network services**、**firmware**、**post-auth attack surfaces**，以及那些很难重构成经典 in-process harness 的**binary-only targets**。

一个实用技巧是在 `recv`/`read`/packet-deserialization 点立刻中断，记录输入 buffer 地址，在那里 snapshot，然后在每次迭代中直接变异该 buffer。这样你就能 fuzz 深层解析逻辑，而不必每次都重建整个 handshake。

## Harness Introspection: Find Shallow Fuzzers Early

当一次 campaign 停滞时，问题往往不在 mutator，而在 **harness**。使用 **reachability/coverage introspection** 找出那些在静态上可从 fuzz target 到达，但在动态上很少或从未被覆盖的函数。这些函数通常表明以下三类问题之一：

- harness 进入 target 太晚或太早。
- seed corpus 缺少某个完整的功能家族。
- 目标实际上需要一个**second harness**，而不是一个过大的“do everything” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 对于这类分流很有用：
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## Graph-First Fuzz Target Selection And Mutation Triage

If you already have **static-analysis findings**, **mutation-testing survivors**, and **coverage reports**, don't triage them as independent lists. Build a **call graph** first, annotate nodes with **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, and any external findings, then ask graph questions:

- Which high-complexity functions are reachable from untrusted input?
- Which mutation survivors sit on paths from parsers/handlers to security-critical code?
- Which functions are architectural choke points with unusually high **blast radius**?

This usually surfaces better fuzz targets than "lowest coverage" alone. A parser/decoder with **high complexity** and confirmed **external reachability** is a stronger harness candidate than an isolated internal helper with weak coverage but no attacker-controlled path.

### Practical triage workflow

1. Build a **code graph** from the codebase and extract per-function complexity/branch metrics.
2. Enumerate **entrypoints** that accept attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Run **path queries** from those entrypoints to candidate functions to separate reachable attack surface from dead/internal-only code.
4. Prioritize nodes that combine:
- high **cyclomatic complexity**
- confirmed **reachability from untrusted input**
- high **blast radius** or many downstream dependents
- corroborating evidence such as **SARIF** findings, audit notes, or mutation survivors
5. Write focused harnesses for the best-scoring nodes first, especially **parsers/codecs** such as hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing often produces a noisy survivor list. Before treating every survivor as a security gap, use the graph to ask:

- Is the mutated function reachable from an attacker-controlled entrypoint?
- Are all call paths constrained by stronger invariants than the mutated check?
- Does the node sit in dead code, formatting-only logic, or in a high-impact arithmetic/parser path?

Survivors that remain unreachable or structurally constrained are often **equivalent mutants**. Survivors that stay **reachable** and touch **boundary conditions**, **overflow/carry paths**, or **security-critical arithmetic/parsing** should be promoted into:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

If your SAST pipeline exports **SARIF**, project findings onto graph nodes by **file + line range** and use the graph to expand the impact:

- compute the **blast radius** of the flagged function
- check whether the finding is on any path from an entrypoint
- cluster nearby findings that collapse into the same choke point

This is useful when deciding whether to spend fuzzing time on a specific function: a node that is **reachable**, **complex**, and already has **SAST hits** is often a better target than a merely complex node with no attacker path.

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
重要的方法论是交集：**complexity x exposure x impact**。使用图来挑选具有最高预期安全价值的 fuzz targets，然后使用 mutation survivors 来决定你的 harness 必须重点施压哪些边界和不变量。

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
