# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## 突变式 Grammar Fuzzing: Coverage vs. Semantics

在 **mutational grammar fuzzing** 中，输入会在保持 **grammar-valid** 的同时被突变。 在 coverage-guided 模式下，只有触发 **new coverage** 的样本才会被保存为 corpus seeds。 对于 **language targets**（parsers、interpreters、engines），这可能会漏掉需要 **semantic/dataflow chains** 的 bug，也就是一个构造的输出会变成另一个构造的输入。

**Failure mode:** fuzzer 找到了分别能触发 `document()` 和 `generate-id()`（或类似原语）的 seeds，但 **没有保留链式 dataflow**，所以更接近 bug 的样本会因为没有增加 coverage 而被丢弃。 当存在 **3+ 个依赖步骤** 时，随机重组会变得很昂贵，而 coverage feedback 也无法引导搜索。

**Implication:** 对于依赖性很强的 grammars，可以考虑将 **mutational** 和 **generative** 阶段 **hybridizing**，或者让生成过程偏向 **function chaining** 模式（而不只是 coverage）。

## Corpus 多样性陷阱

Coverage-guided mutation 是 **greedy** 的：一个 new-coverage 样本会被立即保存，通常还保留了大量未变的区域。 随着时间推移，corpora 会变成 **near-duplicates**，结构多样性很低。 激进的 minimization 可能会移除有用上下文，因此一个实用的折中是 **grammar-aware minimization**，并且 **在达到最小 token 阈值后停止**（减少噪声，同时保留足够的上下文结构，以便仍然适合 mutation）。

对于 mutational fuzzing，一个实用的 corpus 规则是：**优先选择少量结构上不同、且能最大化 coverage 的 seeds**，而不是一大堆 near-duplicates。 实践中，这通常意味着：

- 从 **real-world samples** 开始（public corpora、爬虫抓取、捕获的流量、来自目标生态系统的文件集合）。
- 使用 **coverage-based corpus minimization** 对它们进行提炼，而不是保留每个有效样本。
- 保持 seeds **足够小**，这样 mutations 会落到有意义的字段上，而不是把大部分 cycle 花在无关字节上。
- 在 major harness/instrumentation 变更后重新运行 corpus minimization，因为当 reachability 改变时，“最佳” corpus 也会改变。

## 用于 Magic Values 的 Comparison-Aware Mutation

fuzzer 卡住的一个常见原因不是语法，而是 **hard comparisons**：magic bytes、长度检查、enum strings、checksums，或由 `memcmp`、switch tables、或者级联 comparisons 保护的 parser dispatch values。 纯随机 mutation 会浪费 cycle 去逐字节猜这些值。

对于这类 targets，使用 **comparison tracing**（例如 AFL++ `CMPLOG` / Redqueen-style workflows），这样 fuzzer 就能观察失败 comparisons 的操作数，并把 mutations 偏向于满足这些值。
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
**实践注意事项：**

- 当目标把深层逻辑隐藏在 **file signatures**、**protocol verbs**、**type tags** 或 **version-dependent feature bits** 后面时，这尤其有用。
- 将其与从真实样本、protocol 规范或 debug logs 中提取的 **dictionaries** 结合使用。一个包含 grammar tokens、chunk names、verbs 和 delimiters 的小字典，通常比一个庞大的通用 wordlist 更有价值。
- 如果目标执行许多顺序检查，先解决最早的 “magic” 比较，然后再对结果 corpus 进行最小化，这样后续阶段就会从已经有效的前缀开始。

## Stateful Fuzzing：Sequences Are Seeds

对于 **protocols**、**authenticated workflows** 和 **multi-stage parsers**，有趣的单位往往不是单个 blob，而是一个 **message sequence**。把整个 transcript 拼成一个文件并盲目变异通常效率很低，因为 fuzzer 会平均变异每一步，即使只有后面的 message 才会到达脆弱状态。

更有效的模式是把 **sequence 本身当作 seed**，并把 **observable state**（response codes、protocol states、parser phases、returned object types）作为额外反馈：

- 保持 **valid prefix messages** 稳定，把变异重点放在 **transition-driving** 的 message 上。
- 当下一步依赖前一步响应时，从之前的 responses 中缓存 identifiers 和 server-generated values。
- 优先对单条 message 进行 mutation/splicing，而不是把整个序列化 transcript 当作一个不透明 blob 来变异。
- 如果 protocol 暴露了有意义的 response codes，就把它们当作一个 **cheap state oracle**，优先处理那些能推进到更深层的 sequences。

这也是为什么 authenticated bugs、hidden transitions，或者 “only-after-handshake” 的 parser bugs 经常会被普通的 file-style fuzzing 漏掉：fuzzer 必须保留 **顺序、状态和依赖关系**，而不只是结构。

## Single-Machine Diversity Trick (Jackalope-Style)

一种将 **generative novelty** 与 **coverage reuse** 混合起来的实用方法，是针对一个持久化 server **重启短生命周期 workers**。每个 worker 都从空 corpus 开始，经过 `T` 秒后同步，再在合并后的 corpus 上运行另一个 `T` 秒，再次同步，然后退出。这样既能在每一代产生 **fresh structures**，又能继续利用累积的 coverage。

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
- `-server_update_interval T` 近似实现**延迟 sync**（先新颖，后复用）。
- 在 grammar fuzzing 模式下，**默认会跳过初始 server sync**（不需要 `-skip_initial_server_sync`）。
- 最优的 `T` **取决于 target**；通常在 worker 已经找到大多数“简单” coverage 之后再切换效果最好。

## Snapshot Fuzzing For Hard-To-Harness Targets

当你想测试的 code 只有在**大量初始化成本**之后才可达时（启动 VM、完成登录、接收 packet、解析 container、初始化 service），一个有用的替代方案是 **snapshot fuzzing**：

1. 运行 target，直到进入有趣的状态。
2. 在该时刻 snapshot **memory + registers**。
3. 对每个 test case，直接把变异后的 input 写入相关的 guest/process buffer。
4. 执行直到 crash/timeout/reset。
5. 只恢复 **dirty pages**，然后重复。

这避免了每次迭代都支付完整的初始化成本，尤其适合 **network services**、**firmware**、**post-auth attack surfaces**，以及那些很难重构成传统进程内 harness 的 **binary-only targets**。

一个实用技巧是在 `recv`/`read`/packet-deserialization 点之后立即 break，记录 input buffer 地址，在那里 snapshot，然后在每次迭代中直接变异那个 buffer。这样你就可以 fuzz 深层解析逻辑，而不必每次都重建整个 handshake。

## Harness Introspection: Find Shallow Fuzzers Early

当一次 campaign 停滞时，问题通常不是 mutator，而是 **harness**。使用 **reachability/coverage introspection** 来找出那些在静态上可从 fuzz target 到达、但在动态上很少或从未被覆盖的函数。这些函数通常说明下面三种问题之一：

- harness 进入 target 的时间太晚或太早。
- seed corpus 缺少整个 feature family。
- target 其实需要一个**第二个 harness**，而不是一个过大的“什么都做” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 对这类排查很有用：
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
