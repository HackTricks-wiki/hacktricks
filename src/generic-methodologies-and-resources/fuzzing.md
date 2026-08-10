# Fuzzing 方法论

## Mutational Grammar Fuzzing：Coverage 与语义

在 **mutational grammar fuzzing** 中，输入会在保持 **grammar-valid** 的同时进行变异。在 coverage-guided 模式下，只有触发了 **new coverage** 的样本才会被保存为 corpus seed。对于 **language targets**（parsers、interpreters、engines），这种方式可能遗漏需要 **semantic/dataflow chains** 的 bugs，即某个 construct 的输出成为另一个 construct 的输入。<sup>[[1]](#references)</sup>

**Failure mode：** fuzzer 找到的 seeds 会分别执行 `document()` 和 `generate-id()`（或类似 primitives），但**不会保留 chained dataflow**，因此更接近 bug 的样本由于没有增加 coverage 而被丢弃。当存在 **3+ dependent steps** 时，随机重组的成本会变高，而 coverage feedback 无法引导搜索。<sup>[[1]](#references)</sup>

**Implication：** 对于依赖关系密集的 grammars，可以考虑将 mutational 和 generative phases **hybridize**，或让 generation 偏向 **function chaining** patterns，而不只是依赖 coverage。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation 具有**贪婪性**：new-coverage sample 会立即被保存，并且通常会保留大段未变化的区域。随着时间推移，corpora 会变成结构多样性较低的**近似重复样本**。过于激进的 minimization 可能移除有用的 context，因此一种实用的折中方案是采用 **grammar-aware minimization**，在达到 minimum token threshold 后停止（减少噪声，同时保留足够的周边结构，使其仍然便于 mutation）。<sup>[[1]](#references)</sup>

mutational fuzzing 的一条实用 corpus 规则是：相比保存大量近似重复样本，**优先选择一小组结构不同且能最大化 coverage 的 seeds**。在实践中，这通常意味着以下几点。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实世界样本**开始（public corpora、crawling、captured traffic、来自 target ecosystem 的 file sets）。
- 使用 **coverage-based corpus minimization** 对其进行提炼，而不是保留每个 valid sample。
- 让 seeds **足够小**，使 mutations 落在有意义的 fields 上，而不是将大多数 cycles 浪费在无关的 bytes 上。
- 在 harness/instrumentation 发生重大变化后重新运行 corpus minimization，因为 reachability 发生变化时，“最佳” corpus 也会改变。

## Comparison-Aware Mutation For Magic Values

fuzzers 陷入瓶颈的一个常见原因不是 syntax，而是**严格比较**：magic bytes、length checks、enum strings、checksums，或由 `memcmp`、switch tables 或级联 comparisons 保护的 parser dispatch values。纯随机 mutation 会浪费大量 cycles，逐字节地尝试猜测这些 values。

对于这类 targets，应使用 **comparison tracing**（例如 AFL++ `CMPLOG` / Redqueen-style workflows），使 fuzzer 能够观察失败 comparisons 中的 operands，并将 mutations 偏向于能够满足这些 comparisons 的 values。<sup>[[3]](#references)</sup>
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

- 当目标将深层逻辑置于 **file signatures**、**protocol verbs**、**type tags** 或 **version-dependent feature bits** 之后时，这种方法尤其有用。
- 将其与从真实样本、protocol specs 或 debug logs 中提取的 **dictionaries** 配合使用。包含 grammar tokens、chunk names、verbs 和 delimiters 的小型 dictionary，通常比庞大的通用 wordlist 更有价值。
- 如果目标会执行许多连续检查，先解决最早的 “magic” comparisons，然后再次最小化得到的 corpus，使后续阶段从已经有效的 prefixes 开始。

## 有状态 Fuzzing：Sequences 就是 Seeds

对于 **protocols**、**authenticated workflows** 和 **multi-stage parsers**，有趣的单位通常不是单个 blob，而是一个 **message sequence**。将整个 transcript 拼接到一个文件中并盲目进行 mutation 通常效率较低，因为 fuzzer 会对每一步进行同等 mutation，即使只有后续 message 才能到达脆弱状态。<sup>[[4]](#references)</sup>

更有效的方式是将 **sequence 本身作为 seed**，并将 **observable state**（response codes、protocol states、parser phases、returned object types）作为额外的 feedback。<sup>[[4]](#references)</sup>

- 保持 **valid prefix messages** 稳定，将 mutation 集中在驱动 **transition** 的 message 上。
- 当下一步依赖前面 responses 中的 identifiers 和 server-generated values 时，将它们缓存起来。
- 优先使用 per-message mutation/splicing，而不是将整个 serialized transcript 作为不透明的 blob 进行 mutation。
- 如果 protocol 暴露了有意义的 response codes，则将其作为廉价的 **state oracle**，优先处理能够进一步推进的 sequences。

这也是 authenticated bugs、hidden transitions 或 “only-after-handshake” parser bugs 经常被 vanilla file-style fuzzing 遗漏的原因：fuzzer 必须保留 **order、state 和 dependencies**，而不仅仅是 structure。<sup>[[4]](#references)</sup>

## 单机多样性技巧（Jackalope-Style）

将 **generative novelty** 与 **coverage reuse** 结合的一种实用方式，是针对持久运行的 server **restart short-lived workers**。每个 worker 从空 corpus 开始，在运行 `T` 秒后进行 sync，使用合并后的 corpus 再运行 `T` 秒，再次 sync，然后退出。这样可以在每一代生成 **fresh structures**，同时继续利用累积的 coverage。<sup>[[1]](#references)[[2]](#references)</sup>

**Server：**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (example loop):**

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

- `-in empty` 会在每次生成时强制使用 **fresh corpus**。
- `-server_update_interval T` 可近似模拟 **delayed sync**（先关注 novelty，之后再复用）。
- 在 grammar fuzzing mode 中，默认会跳过 **initial server sync**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` 取决于 **target**；通常在 worker 找到大部分“easy” coverage 后再切换效果最好。

## Snapshot Fuzzing：适用于难以构建 Harness 的 Target

当你要测试的代码只有在付出较大的 setup cost 后才变得可达（启动 VM、完成 login、接收 packet、解析 container、初始化 service），一种有用的替代方案是 **snapshot fuzzing**：捕获已就绪的 process 或 VM 状态，将每个 test case 注入 target 的 input path，执行直到 crash/timeout，然后恢复 snapshot。这样可以避免重复初始化或 protocol prefixes，适用于 **network services**、**firmware**、**post-auth attack surfaces** 和 **binary-only targets**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行 target，直到所需的 state 就绪。
2. 在此时对 **memory + registers** 执行 snapshot。
3. 对每个 test case，直接将 mutated input 写入相关的 guest/process buffer。
4. 执行直到 crash/timeout/reset。
5. 恢复 snapshot；对于 VM targets，在支持时只恢复 **dirty pages**，然后重复执行。

将 snapshot 放置在实际可行的、尽量靠近第一个 expensive parse/dispatch step 的位置，例如 `recv`/`read` 之后或 packet-deserialization point，并记录 target 使用的 input buffer。这遵循 adaptive-placement principle：将 snapshot 进一步移入 input processing，以避免重复执行工作。<sup>[[11]](#references)</sup>

## Harness Introspection：尽早发现 Shallow Fuzzers

当一次 campaign 停滞时，问题通常不在 mutator，而在 **harness**。使用 **reachability/coverage introspection**，查找从 fuzz target 在静态上可达、但在动态执行中很少或从未被覆盖的 functions。这些 functions 通常表明存在以下三种问题之一。<sup>[[12]](#references)</sup>

- Harness 进入 target 的时机过晚或过早。
- Seed corpus 缺少整个 feature family。
- Target 确实需要一个 **second harness**，而不是一个过于庞大的“do everything” harness。

如果你使用 OSS-Fuzz / ClusterFuzz-style workflows，Fuzz Introspector 可以比较 static reachability 与 runtime coverage，并根据 timed run 或 public corpus 生成 reports。<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
使用该报告来决定：是否为未经测试的 parser path 添加新的 harness、为特定 feature 扩展 corpus，或将单体式 harness 拆分为更小的 entry point。

## 以 Graph 为先的 Fuzz Target 选择与 Mutation Triage

如果你已经有 **static-analysis findings**、**mutation-testing survivors** 和 **coverage reports**，不要将它们作为相互独立的列表进行 triage。先构建 **call graph**，为节点标注 **cyclomatic complexity**、**entrypoint/untrusted-input reachability** 以及任何外部 findings，然后提出 graph 层面的问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可以从 untrusted input 到达？
- 哪些 mutation survivors 位于从 parsers/handlers 到 security-critical code 的路径上？
- 哪些函数是具有异常高 **blast radius** 的架构 choke point？

这通常比单独关注“最低 coverage”更容易发现优质的 fuzz target。一个具有 **high complexity** 且已确认 **external reachability** 的 parser/decoder，比一个 coverage 较弱但不存在 attacker-controlled path 的孤立内部 helper 更适合作为 harness 候选。

### 实用的 triage 工作流

1. 从代码库构建 **code graph**，并提取每个函数的 complexity/branch metrics。
2. 枚举接受 attacker-controlled input 的 **entrypoints**：request handlers、decoders、importers、protocol parsers、CLI/file readers。
3. 从这些 entrypoints 对候选函数执行 **path queries**，将可到达的 attack surface 与 dead/internal-only code 区分开。
4. 优先处理同时具备以下特征的节点：
- 高 **cyclomatic complexity**
- 已确认可从 untrusted input 到达
- 高 **blast radius** 或存在许多下游依赖
- 有 **SARIF** findings、audit notes 或 mutation survivors 等佐证
5. 首先为得分最高的节点编写 focused harness，尤其是 **parsers/codecs**，例如 hex/Base64/IP/message decoders。

### Mutation survivors：equivalent 与 actionable

Mutation testing 通常会产生嘈杂的 survivor 列表。在将每个 survivor 都视为 security gap 之前，使用 graph 提出以下问题：

- 被 mutation 的函数是否可以从 attacker-controlled entrypoint 到达？
- 所有 call paths 是否受到比被 mutation 的 check 更强的 invariants 约束？
- 该节点是否位于 dead code、仅负责 formatting 的逻辑，或高影响的 arithmetic/parser path 中？

仍然不可达或受结构约束的 survivors 通常是 **equivalent mutants**。仍然 **reachable** 且涉及 **boundary conditions**、**overflow/carry paths** 或 **security-critical arithmetic/parsing** 的 survivors，应提升为：

- 新的 fuzz harnesses
- 直接的 property/invariant tests
- 针对性的 edge-case vectors

### 将外部 findings 关联到 graph

如果你的 SAST pipeline 导出 **SARIF**，可按 **file + line range** 将 findings 投射到 graph nodes，并使用 graph 扩展其影响范围。<sup>[[6]](#references)</sup>

- 计算被标记函数的 **blast radius**
- 检查该 finding 是否位于从某个 entrypoint 出发的路径上
- 将附近、最终汇聚到同一 choke point 的 findings 聚类

当你需要决定是否在特定函数上投入 fuzzing 时间时，这很有用：一个同时 **reachable**、复杂且已有 **SAST hits** 的节点，通常比一个仅复杂但不存在 attacker path 的节点更适合作为 target。

使用 Trailmark 的示例工作流。<sup>[[6]](#references)</sup>
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
重要的方法论是三者的交集：**复杂度 x 暴露面 x 影响**。使用图表选择预期安全价值最高的 fuzz 目标，然后利用 mutation survivors 来确定 harness 必须重点施压的边界和不变量。<sup>[[5]](#references)</sup>

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入和 Differential Checks

如果 Go 目标已经具有原生的 `testing.F` harness，一个实际的升级路径是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个 fork 版 Go toolchain，保留 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
当原生 Go fuzzer 在**复杂比较**、**typed inputs**或**解析器密集型格式**上停滞时，这会非常有用。方法保持不变：

- 继续使用 `f.Add(...)` 添加 seeds，使用 `f.Fuzz(...)` 作为 callback。
- 复用相同的 harness，但使用 gosentry 的 `go` binary，而不是 stock toolchain 运行它。
- 将生成的 campaign 视为普通的 coverage-guided 运行，只是其使用了 LibAFL 的 scheduling/mutation，以及更完善的周边 detectors。

### 将静默失败转化为 fuzz findings

Go assessment 中一个反复出现的问题是，危险行为通常**默认不会**导致 crash。借助 gosentry，可以将多类“糟糕但静默”的状态提升为 findings。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` 让选定的 logging/error 路径表现得像 crash（适用于 `log.Fatal` 风格的 code paths；否则它们通常只记录日志并继续执行）。
- `--catch-races=true` 使用 Go race detector 重新执行新发现的 queue entries。
- `--catch-leaks=true` 使用 `goleak` 重新执行新的 queue entries，并在发现 goroutine leaks 时停止。
- LibAFL 的 hang handling 会将**无限循环 / 极慢输入**保留为 fuzz findings，而不是让它们作为 timeouts 消失。
- 默认启用内置 arithmetic overflow checks，并可通过 go-panikint 风格的 instrumentation 选择性启用 truncation checks。

对于安全影响表现为**无 panic 的 parser failure**、**concurrency bug**或**仅导致 DoS 的 hang**，而不是 memory corruption 的 targets，这一点尤其有价值。

### 面向 struct 的 typed Go API fuzzing

原生 Go fuzzing 主要期望 `[]byte`、`string` 和 numbers 等 scalars。如果被测试代码使用 typed objects，gosentry 可以直接对**复合值**（structs、slices、arrays、pointers）进行 fuzzing，同时继续在底层 mutating bytes。<sup>[[7]](#references)[[8]](#references)</sup>
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
在构建仅用于 fuzzing 的 fake wire format 时，使用它可能会将逻辑 bug 隐藏在仅供 harness 使用的解析代码之后。对于 differential 或 grammar-based campaigns，请将 harness 输入保持为单个 `[]byte` 或 `string`，并改为在 callback 内部进行解析。

### 面向解析器和协议输入的 Grammar-based fuzzing

对于解析器、格式和输入语言，gosentry 可以基于 LibAFL 运行 **Nautilus grammar fuzzing**。该 grammar 是一个 production rules 的 JSON 数组，harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
方法论笔记：

- 当 byte-level mutations 大多在早期 syntax checks 中失效时，使用 grammar mode。
- 将 grammar 聚焦于语言/协议的 **security-relevant subset**，而不是对完整 specification 建模。
- 在 terminals/nonterminals 中使用较大的边界值，以测试 integer、length 和 state-machine 的边界。
- grammar mode 会使输入保持 grammar-valid，但目标仍然接收 **bytes/strings**，因此 parsing 和 semantic checks 仍位于 harnessed code 内部。

### Differential fuzzing：比较 implementations，而不只是 crashes

对于 Go 生态系统，一个强大的模式是 **grammar-based differential fuzzing**：生成有效的结构化输入，并将其提供给两个 parsers、clients 或 state-transition engines。<sup>[[7]](#references)[[8]](#references)</sup>
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
将以下情况视为 findings：

- 一个实现发生 panic，而另一个实现能够正常拒绝
- 接受/拒绝的输入不匹配
- 不同的解析树或解码对象
- 不同的状态转换、nonce、余额或状态根

这是一种实用的方法，可用于发现**共识不匹配**、**解析器歧义**以及**规范与实现之间的偏差**，而这些问题通常很难通过纯 crash fuzzing 发现。

### 使用 campaign corpus 生成 coverage 报告

campaign 结束后，重新播放保存的 queue corpus，即可生成 Go coverage 报告，无需手动导出单独的 corpus。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
从**同一个 package**运行该命令，并使用相同的 `-fuzz` target，以便 gosentry 解析正确的 cached campaign state。

## References

- [1] [Mutational grammar fuzzing（变异语法 fuzzing）](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth（AFL++ 深入 fuzzing）](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing（AFLNet 五年后：关于 coverage-guided protocol fuzzing）](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs（Trailmark 将代码转换为图）](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.（Go fuzzing 缺少一半 toolkit。我们 fork 了 toolchain 来修复它。）](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: A Fast Greybox Fuzzer for Stateful Network Protocols using Snapshots（SNPSFuzzer：使用 snapshots 的快速 stateful network protocols greybox fuzzer）](https://arxiv.org/abs/2202.03643)
- [10] [No Grammar, No Problem: Towards Fuzzing the Linux Kernel without System-Call Descriptions（没有 grammar 也没问题：在没有 system-call descriptions 的情况下 fuzzing Linux kernel）](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efficient Fuzzing with Adaptive and Mutable Snapshots（Snappy：使用 adaptive and mutable snapshots 进行高效 fuzzing）](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
