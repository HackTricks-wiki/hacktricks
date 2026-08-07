# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## 变异语法 Fuzzing：覆盖率 vs. 语义

在 **变异语法 fuzzing** 中，输入会在保持 **语法有效** 的情况下进行变异。在 coverage-guided 模式下，只有触发了**新覆盖率**的样本才会被保存为 corpus seed。对于**语言目标**（parser、interpreter、engine），这可能会遗漏需要**语义/dataflow 链**的 bug，因为一个构造的输出会成为另一个构造的输入。

**失败模式：** fuzzer 找到分别执行 `document()` 和 `generate-id()`（或类似 primitive）的 seeds，但**不会保留链式 dataflow**，因此更接近 bug 的样本会因为没有增加覆盖率而被丢弃。当存在 **3+ 个依赖步骤**时，随机重组的成本会变高，而 coverage feedback 无法引导搜索。

**启示：**对于依赖关系复杂的 grammar，可以考虑**混合 mutational 和 generative 阶段**，或让生成过程偏向**function chaining** 模式，而不仅仅依赖 coverage。<sup>[[1]](#references)</sup>

## Corpus 多样性陷阱

Coverage-guided mutation 具有**贪心特性**：触发新 coverage 的样本会立即被保存，并且通常会保留大量未发生变化的区域。随着时间推移，corpus 会变成结构多样性较低的**近似重复样本**。激进的 minimization 可能会移除有用的上下文，因此一种实际可行的折中方案是使用**grammar-aware minimization**，并在达到最小 token 阈值后**停止**（减少噪声，同时保留足够的周边结构，使其仍然适合 mutation）。<sup>[[1]](#references)</sup>

对于 mutational fuzzing，一个实用的 corpus 规则是：相比大量近似重复样本，**优先选择一组结构不同且能够最大化 coverage 的少量 seeds**。实际操作中通常包括：<sup>[[1]](#references)</sup>

- 从**真实世界样本**开始（公开 corpus、爬取内容、捕获的流量、来自目标生态系统的文件集）。
- 使用**基于 coverage 的 corpus minimization**对其进行提炼，而不是保留每个有效样本。
- 保持 seeds **足够小**，使 mutation 命中有意义的字段，而不是将大部分 cycles 浪费在无关字节上。
- 在 harness/instrumentation 发生重大变化后重新运行 corpus minimization，因为 reachability 发生变化时，“最佳” corpus 也会改变。

## 面向 Magic Values 的 Comparison-Aware Mutation

fuzzer 陷入瓶颈的常见原因不是 syntax，而是**硬比较**：magic bytes、长度检查、enum 字符串、checksum，或由 `memcmp`、switch 表或级联比较保护的 parser dispatch 值。纯随机 mutation 会浪费 cycles，逐字节尝试猜测这些值。

对于这些目标，应使用 **comparison tracing**（例如 AFL++ 的 `CMPLOG` / Redqueen-style workflows），使 fuzzer 能够观察失败比较中的 operands，并让 mutation 偏向于满足这些比较的值。<sup>[[3]](#references)</sup>
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

- 当目标通过 **file signatures**、**protocol verbs**、**type tags** 或 **version-dependent feature bits** 控制深层逻辑时，这尤其有用。
- 将其与从真实样本、protocol specs 或 debug logs 中提取的 **dictionaries** 配合使用。包含 grammar tokens、chunk names、verbs 和 delimiters 的小型 dictionary，通常比庞大的通用 wordlist 更有价值。
- 如果目标会执行许多 sequential checks，先解决最早的 “magic” comparisons，然后再次 minimize 得到的 corpus，使后续阶段从已经有效的 prefixes 开始。

## Stateful Fuzzing: Sequences Are Seeds

对于 **protocols**、**authenticated workflows** 和 **multi-stage parsers**，有意义的单位通常不是单个 blob，而是一个 **message sequence**。将整个 transcript 拼接到一个文件中并盲目进行 mutation 通常效率很低，因为 fuzzer 会对每个步骤进行同等程度的 mutation，即使只有后续 message 才能到达脆弱状态。

一种更有效的模式是将 **sequence 本身作为 seed**，并将 **observable state**（response codes、protocol states、parser phases、返回的 object types）作为额外 feedback：<sup>[[4]](#references)</sup>

- 保持 **valid prefix messages** 稳定，将 mutations 集中到驱动 **transition** 的 message 上。
- 当下一步依赖先前 response 中的值时，缓存 identifiers 和 server-generated values。
- 优先进行 per-message mutation/splicing，而不是将整个 serialized transcript 作为不透明 blob 进行 mutation。
- 如果 protocol 提供有意义的 response codes，则将其作为一种 **cheap state oracle**，优先处理能够更深入推进的 sequences。

这也是 authenticated bugs、hidden transitions 或 “only-after-handshake” parser bugs 经常被 vanilla file-style fuzzing 遗漏的原因：fuzzer 必须保留 **order、state 和 dependencies**，而不仅仅是 structure。

## Single-Machine Diversity Trick (Jackalope-Style)

一种将 **generative novelty** 与 **coverage reuse** 混合的实用方法，是针对持久运行的 server **restart short-lived workers**。每个 worker 从空 corpus 开始，在运行 `T` 秒后进行 sync，使用合并后的 corpus 再运行 `T` 秒，再次 sync，然后退出。这样可以在每一代生成 **fresh structures**，同时继续利用累积的 coverage。<sup>[[2]](#references)</sup>

**Server：**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**顺序 workers（示例循环）：**

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
- `-server_update_interval T` 近似模拟 **delayed sync**（先发现 novelty，之后再复用）。
- 在 grammar fuzzing mode 中，默认会跳过 **initial server sync**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` 取决于 **target**；当 worker 找到大部分“容易获得”的 coverage 后再进行切换，通常效果最佳。

## Snapshot Fuzzing For Hard-To-Harness Targets

当你要测试的代码只有在付出较大 setup cost 后才会变得可达（启动 VM、完成 login、接收 packet、解析 container、初始化 service）时，一个实用的替代方案是 **Snapshot Fuzzing**：

1. 运行 target，直到感兴趣的 state 准备就绪。
2. 在该时刻对 **memory + registers** 创建 snapshot。
3. 对每个 test case，将 mutated input 直接写入相关的 guest/process buffer。
4. 执行，直到 crash/timeout/reset。
5. 仅恢复 **dirty pages**，然后重复。

这样可以避免每次迭代都付出完整的 setup cost，对于 **network services**、**firmware**、**post-auth attack surfaces** 以及难以重构为经典 in-process harness 的 **binary-only targets** 尤其有用。

一个实用技巧是在 `recv`/`read`/packet-deserialization 点之后立即中断，记录 input buffer 地址，然后在此处创建 snapshot，并在每次迭代中直接 mutation 该 buffer。这样无需每次重新构建完整的 handshake，就可以 fuzz 深层 parsing logic。

## Harness Introspection: Find Shallow Fuzzers Early

当一次 campaign 陷入停滞时，问题通常不在 mutator，而在 **harness**。使用 **reachability/coverage introspection**，找出从 fuzz target 静态可达、但动态 coverage 很少或从未覆盖的 functions。这些 functions 通常表明存在以下三种问题之一：

- harness 进入 target 的时机太晚或太早。
- seed corpus 缺少整个 feature family。
- target 实际上需要 **second harness**，而不是一个过度庞大的“do everything” harness。

如果你使用 OSS-Fuzz / ClusterFuzz-style workflows，Fuzz Introspector 对这种 triage 很有用：
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
使用该报告来决定：是否为尚未测试的 parser path 添加新的 harness、针对特定 feature 扩展 corpus，或将单体 harness 拆分为更小的 entry point。

## Graph-First Fuzz Target Selection And Mutation Triage

如果你已经有 **static-analysis findings**、**mutation-testing survivors** 和 **coverage reports**，不要将它们作为相互独立的列表进行 triage。先构建 **call graph**，为节点标注 **cyclomatic complexity**、**entrypoint/untrusted-input reachability** 以及任何外部 findings，然后从 graph 的角度提出问题：<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从 untrusted input 到达？
- 哪些 mutation survivors 位于从 parsers/handlers 到 security-critical code 的路径上？
- 哪些函数是具有异常高 **blast radius** 的架构 choke point？

相比单纯关注“最低 coverage”，这种方式通常能发现更好的 fuzz targets。一个具有 **high complexity** 且已确认 **external reachability** 的 parser/decoder，比一个 coverage 较弱但不存在 attacker-controlled path 的孤立内部 helper，更适合作为 harness 候选。

### Practical triage workflow

1. 从代码库构建 **code graph**，并提取每个函数的 complexity/branch metrics。
2. 枚举接受 attacker-controlled input 的 **entrypoints**：request handlers、decoders、importers、protocol parsers、CLI/file readers。
3. 从这些 entrypoints 对候选函数执行 **path queries**，将可达的 attack surface 与 dead/internal-only code 区分开。
4. 优先处理同时具备以下条件的节点：
- 高 **cyclomatic complexity**
- 已确认可从 untrusted input **reachability**
- 高 **blast radius** 或具有大量 downstream dependents
- 存在佐证，例如 **SARIF** findings、audit notes 或 mutation survivors
5. 首先为得分最高的节点编写 focused harnesses，尤其是 **parsers/codecs**，例如 hex/Base64/IP/message decoders。

### Mutation survivors: equivalent vs actionable

Mutation testing 通常会产生嘈杂的 survivor 列表。在将每个 survivor 都视为 security gap 之前，应借助 graph 提出以下问题：

- 被 mutation 的函数是否可从 attacker-controlled entrypoint 到达？
- 所有 call paths 是否受到比被 mutation 的 check 更强的 invariants 约束？
- 该节点是否位于 dead code、仅负责 formatting 的 logic，或高影响的 arithmetic/parser path 中？

仍然不可达或受结构性约束的 survivors 通常属于 **equivalent mutants**。仍然 **reachable** 且涉及 **boundary conditions**、**overflow/carry paths** 或 **security-critical arithmetic/parsing** 的 survivors，则应提升为：

- 新的 fuzz harnesses
- 直接的 property/invariant tests
- 针对性的 edge-case vectors

### Correlate external findings onto the graph

如果你的 SAST pipeline 导出 **SARIF**，则应通过 **file + line range** 将 findings 映射到 graph nodes，并利用 graph 扩展影响范围：

- 计算被标记函数的 **blast radius**
- 检查该 finding 是否位于从 entrypoint 出发的任意路径上
- 将附近、最终汇聚到同一 choke point 的 findings 聚类

当你决定是否将 fuzzing 时间投入某个特定函数时，这非常有用：一个同时具备 **reachable**、**complex** 且已有 **SAST hits** 的节点，通常比一个仅复杂但不存在 attacker path 的节点更值得作为目标。

使用 Trailmark 的示例 workflow：<sup>[[6]](#references)</sup>
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
重要的方法论是三者的交集：**complexity x exposure x impact**。使用图表选择预期安全价值最高的 fuzz 目标，然后利用 mutation survivors 判断 harness 必须重点施压的边界和不变量。

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入和差分检查

如果 Go 目标已经具备原生的 `testing.F` harness，一个实用的升级路径是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行相同的 harness。gosentry 是一个 fork 版 Go toolchain，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
当原生 Go fuzzer 在 **hard comparisons**、**typed inputs** 或 **parser-heavy formats** 上停滞时，这非常有用。方法保持不变：

- 继续使用 `f.Add(...)` 添加 seeds，并使用 `f.Fuzz(...)` 作为 callback。
- 复用相同的 harness，但使用 gosentry 的 `go` binary，而不是标准 toolchain 运行它。
- 将生成的 campaign 视为普通的 coverage-guided run，但其使用 LibAFL scheduling/mutation 以及更完善的周边 detectors。

### 将静默失败转化为 fuzz findings

Go assessment 中一个反复出现的问题是，危险行为通常**默认不会**触发 crash。借助 gosentry，你可以将几类“有问题但静默”的状态提升为 findings：

- 使用 `--panic-on=pkg.Func,...`，让选定的 logging/error paths 表现得像 crashes（适用于 `log.Fatal` 风格的 code paths，这些路径通常只会记录日志后继续执行）。
- 使用 `--catch-races=true`，通过 Go race detector 重新执行新发现的 queue entries。
- 使用 `--catch-leaks=true`，通过 `goleak` 重新执行新的 queue entries，并在发现 goroutine leaks 时停止。
- LibAFL hang handling 会将**无限循环 / 极慢输入**保留为 fuzz findings，而不是让它们作为 timeouts 消失。
- 默认启用内置 arithmetic overflow checks，并可通过 go-panikint 风格的 instrumentation 选择性启用 truncation checks。

对于这类 target，这一点尤其有价值：其 security impact 可能表现为**不会触发 panic 的 parser failure**、**concurrency bug** 或**仅导致 DoS 的 hang**，而不是 memory corruption。

### 面向 Struct 的 typed Go APIs fuzzing

原生 Go fuzzing 主要期望 `[]byte`、`string` 和数字等 scalars。如果被测试的 code 消费 typed objects，gosentry 可以直接对 **composite values**（structs、slices、arrays、pointers）进行 fuzzing，同时继续在底层 mutating bytes。
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
仅在用于 fuzzing 时构建 fake wire format，否则 harness-only parsing code 可能会掩盖逻辑 bug。对于 differential 或 grammar-based campaigns，应将 harness 输入保留为单个 `[]byte` 或 `string`，并在 callback 内部进行解析。

### 用于 parser 和 protocol input 的 grammar-based fuzzing

对于 parser、format 和 input language，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。该 grammar 是一个由 production rule 组成的 JSON array，harness 通常应接收单个 `[]byte` 或 `string` 参数。
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
方法论笔记：

- 当字节级变异大多在早期语法检查中失效时，使用 grammar mode。
- 将 grammar 聚焦于语言/协议的**与安全相关的子集**，而不是为完整规范建模。
- 在 terminals/nonterminals 中使用较大的边界值，以施压整数、长度和状态机边界。
- grammar mode 会使输入保持 grammar-valid，但目标仍然接收 **bytes/strings**，因此解析和语义检查仍会在被 harness 的代码中执行。

### Differential fuzzing：比较实现，而不仅仅是 crashes

对于 Go 生态系统，一个强大的模式是**基于 grammar 的 Differential fuzzing**：生成有效的结构化输入，并将其馈送给两个 parser、client 或状态转换引擎。
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

- 一个 implementation 发生 panic，而另一个则干净地拒绝
- accepted/rejected input 不匹配
- 不同的 parse trees 或 decoded objects
- divergent state transitions、nonces、balances 或 state roots

这是一种发现 **consensus mismatches**、**parser ambiguity** 和 **spec-vs-implementation drift** 的实用方法，而纯 crash fuzzing 往往会遗漏这些问题。

### 使用 campaign corpus 进行 coverage reporting

campaign 结束后，重新 replay 保存的 queue corpus，即可生成 Go coverage report，无需手动导出单独的 corpus：
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
从**同一个 package**运行该命令，并使用相同的 `-fuzz` target，以便 gosentry 解析正确的缓存 campaign 状态。

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing 深入解析](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 五年之后：关于 Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing 缺失了一半工具链。我们 fork 了工具链来修复它。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
