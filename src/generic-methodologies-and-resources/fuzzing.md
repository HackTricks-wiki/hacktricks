# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## 变异语法 Fuzzing：Coverage 与语义

在 **变异语法 Fuzzing** 中，输入会在保持 **语法有效** 的同时进行变异。在 coverage-guided 模式下，只有触发了 **新 coverage** 的样本才会被保存为 corpus seed。对于 **语言类目标**（parser、interpreter、engine），这种方式可能漏掉需要 **语义/数据流链** 的 bug，即一个构造的输出成为另一个构造的输入。<sup>[[1]](#references)</sup>

**失败模式：** fuzzer 找到的 seeds 分别单独触发了 `document()` 和 `generate-id()`（或类似 primitive），但**没有保留链式数据流**，因此更接近 bug 的样本因为没有增加 coverage 而被丢弃。当存在 **3 个以上的依赖步骤** 时，随机重组的成本会变高，而 coverage feedback 无法有效引导搜索。<sup>[[1]](#references)</sup>

**启示：** 对于依赖关系密集的语法，可以考虑**混合变异阶段与生成阶段**，或让生成过程偏向**函数链式调用**模式，而不仅仅依赖 coverage。<sup>[[1]](#references)</sup>

## Corpus 多样性陷阱

Coverage-guided mutation 具有**贪婪性**：触发新 coverage 的样本会立即被保存，并且通常保留大量未变化的区域。随着时间推移，corpus 会变成结构多样性较低的**近似重复样本**。过于激进的 minimization 可能移除有用的上下文，因此一种实用的折中方案是使用**语法感知的 minimization**，并在达到最小 token 阈值后**停止处理**（减少噪声，同时保留足够的周边结构，使其仍然适合 mutation）。<sup>[[1]](#references)</sup>

针对变异 Fuzzing，一个实用的 corpus 规则是：相比保留大量近似重复样本，**优先选择一小组结构不同且能最大化 coverage 的 seeds**。在实践中，这通常意味着以下几点。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实世界样本**开始（公共 corpora、crawling、捕获的流量、目标生态中的文件集合）。
- 使用**基于 coverage 的 corpus minimization** 对其进行提炼，而不是保留每个有效样本。
- 保持 seeds **足够小**，使 mutations 能够落在有意义的字段上，而不是将大多数 cycles 浪费在无关字节上。
- 在 harness/instrumentation 发生重大变化后重新运行 corpus minimization，因为 reachability 发生变化时，“最佳” corpus 也会随之变化。

## 针对 Magic Values 的 Comparison-Aware Mutation

fuzzers 陷入瓶颈的常见原因不是语法，而是**硬编码比较**：magic bytes、长度检查、enum 字符串、checksums，或由 `memcmp`、switch tables、级联比较保护的 parser dispatch values。纯随机 mutation 会浪费 cycles，逐字节尝试猜测这些值。

对于这类目标，应使用 **comparison tracing**（例如 AFL++ `CMPLOG` / Redqueen-style workflows），使 fuzzer 能够观察失败比较中的 operands，并将 mutations 偏向于能够满足这些比较的值。<sup>[[3]](#references)</sup>
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

- 当目标将深层逻辑置于 **file signatures**、**protocol verbs**、**type tags** 或 **version-dependent feature bits** 之后时，这种方法尤其有用。
- 将其与从真实样本、协议规范或 debug logs 中提取的 **dictionaries** 配合使用。包含语法 token、chunk 名称、verbs 和 delimiters 的小型 dictionary，通常比巨大的通用 wordlist 更有价值。
- 如果目标会执行许多连续检查，先解决最早的“magic”比较，然后再次最小化得到的 corpus，使后续阶段从已经有效的 prefixes 开始。

## Stateful Fuzzing: Sequences Are Seeds

对于 **protocols**、**authenticated workflows** 和 **multi-stage parsers**，有趣的单元通常不是单个 blob，而是一个 **message sequence**。将整个 transcript 拼接到一个文件中并盲目进行 mutation 通常效率很低，因为 fuzzer 会对每个步骤进行同等程度的 mutation，即使只有后续 message 才能到达脆弱状态。<sup>[[4]](#references)</sup>

一种更有效的模式是将 **sequence 本身作为 seed**，并使用 **observable state**（response codes、protocol states、parser phases、returned object types）作为额外反馈。<sup>[[4]](#references)</sup>

- 保持 **valid prefix messages** 稳定，将 mutation 集中在驱动 **transition** 的 message 上。
- 当下一步依赖前面响应中的 identifiers 和 server-generated values 时，将它们缓存下来。
- 优先采用按 message 进行的 mutation/splicing，而不是将整个 serialized transcript 作为不透明的 blob 进行 mutation。
- 如果 protocol 暴露了有意义的 response codes，则将其作为一种**低成本的 state oracle**，优先处理能够更深入推进的 sequences。

这也是为什么 authenticated bugs、隐藏的 transitions 或“仅在 handshake 之后出现”的 parser bugs 经常会被 vanilla file-style fuzzing 遗漏：fuzzer 必须保留 **order、state 和 dependencies**，而不仅仅是 structure。<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

一种将 **generative novelty** 与 **coverage reuse** 结合起来的实用方法，是针对持久化 server 重启短生命周期的 workers。每个 worker 都从空 corpus 开始，在运行 `T` 秒后进行 sync，使用合并后的 corpus 再运行 `T` 秒，再次 sync，然后退出。这样可以在每一代生成 **fresh structures**，同时继续利用累积的 coverage。<sup>[[1]](#references)[[2]](#references)</sup>

**Server：**
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

- `-in empty` 强制每次生成时使用 **fresh corpus**。
- `-server_update_interval T` 用于近似 **delayed sync**（先获取 novelty，之后再复用）。
- 在 grammar fuzzing 模式下，默认会跳过 **initial server sync**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` **取决于目标**；通常在 worker 找到大部分“容易”覆盖率后再切换，效果最佳。

## 针对难以构建 Harness 的目标进行 Snapshot Fuzzing

当你想测试的代码只有在付出较大的设置成本后才可访问（启动 VM、完成登录、接收数据包、解析容器、初始化服务），一种有用的替代方案是 **snapshot fuzzing**：捕获已就绪的进程或 VM 状态，将每个测试用例注入目标输入路径，执行直到崩溃/超时，然后恢复 snapshot。这样可以避免重复初始化或协议前缀，对于 **network services**、**firmware**、**post-auth attack surfaces** 和 **binary-only targets** 很有用。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到感兴趣的状态就绪。
2. 在此时对 **memory + registers** 创建 snapshot。
3. 对于每个测试用例，将变异后的输入直接写入相关的 guest/process buffer。
4. 执行直到崩溃/超时/重置。
5. 恢复 snapshot；对于 VM 目标，在支持的情况下仅恢复 **dirty pages**，然后重复执行。

将 snapshot 放置在尽可能靠近第一次高成本 parse/dispatch 步骤的位置，例如 `recv`/`read` 之后或 packet-deserialization 点，并记录目标使用的 input buffer。这遵循 adaptive-placement 原则：将 snapshot 更深入地放入 input processing 中，以避免重复执行工作。<sup>[[11]](#references)</sup>

## Harness Introspection：及早发现浅层 Fuzzer

当 campaign 陷入停滞时，问题通常不在 mutator，而在 **harness**。使用 **reachability/coverage introspection**，查找从 fuzz target 静态可达、但在动态执行中很少或从未被覆盖的函数。这些函数通常表明存在以下三种问题之一。<sup>[[12]](#references)</sup>

- Harness 进入目标的时机过晚或过早。
- Seed corpus 缺少整个 feature family。
- 目标确实需要 **second harness**，而不是一个庞大的“do everything” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以将静态可达性与运行时覆盖率进行比较，并根据定时运行或 public corpus 生成报告。<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
使用该报告来决定：是为未测试的 parser 路径添加新的 harness、扩展特定 feature 的 corpus，还是将单体式 harness 拆分为更小的 entry point。

## 以 Graph 为先的 Fuzz Target 选择与 Mutation Triage

如果你已经拥有 **静态分析发现**、**mutation testing survivors** 和 **coverage reports**，不要将它们作为相互独立的列表进行 triage。先构建一个 **call graph**，为节点标注 **cyclomatic complexity**、**entrypoint/untrusted-input reachability** 以及任何外部发现，然后提出图相关问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可以从 untrusted input 到达？
- 哪些 mutation survivors 位于从 parser/handler 到 security-critical code 的路径上？
- 哪些函数是具有异常高 **blast radius** 的架构 choke point？

这通常比单纯关注“最低 coverage”能发现更好的 fuzz target。一个具有 **高复杂度** 且已确认 **external reachability** 的 parser/decoder，比一个 coverage 较弱但不存在 attacker-controlled path 的孤立内部 helper，更适合作为 harness 候选。

### Practical triage workflow

1. 从代码库构建 **code graph**，并提取每个函数的复杂度/branch 指标。
2. 枚举接受 attacker-controlled input 的 **entrypoint**：request handler、decoder、importer、protocol parser、CLI/file reader。
3. 从这些 entrypoint 对候选函数运行 **path query**，区分可达的 attack surface 与 dead/internal-only code。
4. 优先处理同时具备以下条件的节点：
- 高 **cyclomatic complexity**
- 已确认可以从 **untrusted input 到达**
- 高 **blast radius** 或拥有大量下游依赖者
- 存在佐证，例如 **SARIF** findings、audit notes 或 mutation survivors
5. 优先为得分最高的节点编写 focused harness，尤其是 **parser/codec**，例如 hex/Base64/IP/message decoder。

### Mutation survivors：equivalent 与 actionable

Mutation testing 通常会产生一份嘈杂的 survivor 列表。在将每个 survivor 都视为 security gap 之前，使用 graph 提出以下问题：

- 被 mutation 的函数是否可以从 attacker-controlled entrypoint 到达？
- 所有 call path 是否受到比被 mutation 的 check 更强的 invariant 约束？
- 该节点是否位于 dead code、仅负责 formatting 的逻辑，或高影响的 arithmetic/parser path 中？

仍然不可达或受结构约束的 survivor，通常是 **equivalent mutants**。仍然 **可达** 且涉及 **boundary conditions**、**overflow/carry paths** 或 **security-critical arithmetic/parsing** 的 survivor，应提升为：

- 新的 fuzz harness
- 直接的 property/invariant tests
- 针对性的 edge-case vectors

### 将 external findings 关联到 graph

如果你的 SAST pipeline 导出 **SARIF**，可以通过 **file + line range** 将 findings 投影到 graph nodes，并使用 graph 扩展其影响范围。<sup>[[6]](#references)</sup>

- 计算被标记函数的 **blast radius**
- 检查该 finding 是否位于从 entrypoint 出发的任一路径上
- 将最终汇聚到同一 choke point 的邻近 findings 聚类

当你决定是否在特定函数上投入 fuzzing 时间时，这非常有用：一个既 **可达**、**复杂** 且已有 **SAST hits** 的节点，通常比一个仅复杂但不存在 attacker path 的节点更适合作为 target。

使用 Trailmark 的示例 workflow。<sup>[[6]](#references)</sup>
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
重要的方法论是三者的交集：**complexity x exposure x impact**。使用该图选择预期安全价值最高的 fuzz targets，然后利用 mutation survivors 来决定 harness 必须重点施压哪些边界和不变量。<sup>[[5]](#references)</sup>

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入与差分检查

如果 Go target 已经有原生的 `testing.F` harness，一个实用的升级路径是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个 fork 的 Go toolchain，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
当原生 Go fuzzer 在 **hard comparisons**、**typed inputs** 或 **parser-heavy formats** 上停滞时，这种方法很有用。方法论保持不变：

- 继续使用 `f.Add(...)` 添加 seeds，并使用 `f.Fuzz(...)` 作为 callback。
- 复用同一个 harness，但使用 gosentry 的 `go` binary，而不是 stock toolchain 运行。
- 将生成的 campaign 视为普通的 coverage-guided 运行，只是使用了 LibAFL 的 scheduling/mutation，以及更完善的周边 detectors。

### 将静默失败转化为 fuzz findings

Go assessment 中经常遇到的问题是，危险行为通常**不会**默认导致 crash。借助 gosentry，可以将几类“有问题但保持静默”的状态提升为 findings。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`：让选定的 logging/error paths 表现得像 crashes（适用于 `log.Fatal` 风格的 code paths；否则它们只会记录日志并继续执行）。
- `--catch-races=true`：使用 Go race detector 重新执行新发现的 queue entries。
- `--catch-leaks=true`：使用 `goleak` 重新执行新的 queue entries，并在发现 goroutine leaks 时停止。
- LibAFL 的 hang handling：将**无限循环 / 执行非常缓慢的 inputs**保留为 fuzz findings，而不是让它们作为 timeouts 消失。
- 默认启用内置 arithmetic overflow checks，并可通过类似 go-panikint 的 instrumentation 启用可选的 truncation checks。

对于安全影响表现为**不会 panic 的 parser failure**、**concurrency bug** 或**仅导致 DoS 的 hang**，而不是 memory corruption 的目标，这尤其有价值。

### 面向 typed Go APIs 的 Struct-aware fuzzing

原生 Go fuzzing 主要期望 `[]byte`、`string` 和数字等 scalars。如果被测试代码接收的是 typed objects，gosentry 可以直接对 **composite values**（structs、slices、arrays、pointers）进行 fuzzing，同时在底层继续 mutation bytes。<sup>[[7]](#references)[[8]](#references)</sup>
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
在构建仅用于 fuzzing 的虚假 wire format 时，harness 专用的解析代码可能会掩盖逻辑错误。对于 differential 或基于 grammar 的 campaign，应将 harness 输入保持为单个 `[]byte` 或 `string`，并在 callback 内部进行解析。

### 基于 grammar 的 parsers 和 protocol 输入 fuzzing

对于 parsers、formats 和输入语言，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。该 grammar 是一个 production rules 的 JSON 数组，harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
方法论笔记：

- 当字节级 mutation 大多在早期语法检查中失效时，使用 grammar mode。
- 将 grammar 聚焦于语言/协议的**与安全相关的子集**，而不是对完整规范进行建模。
- 在 terminals/nonterminals 中使用较大的边界值，以测试整数、长度和状态机边界。
- grammar mode 会使输入保持 grammar-valid，但目标仍会接收**字节/字符串**，因此解析和语义检查仍在 harnessed code 内部进行。

### Differential fuzzing：比较实现，而不仅仅是崩溃

对于 Go 生态系统，一个强大的模式是**grammar-based differential fuzzing**：生成有效的结构化输入，并将其馈送给两个 parser、client 或状态转换引擎。<sup>[[7]](#references)[[8]](#references)</sup>
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

- 一个实现发生 panic，而另一个实现正常拒绝
- 接受/拒绝的输入不匹配
- 解析树或解码对象不同
- 状态转换、nonce、余额或状态根出现分歧

这是一种实用的方法，可用于发现**共识不一致**、**解析器歧义**以及**规范与实现之间的偏差**，而这些问题通常会被纯粹的崩溃 fuzzing 所遗漏。

### 重用 campaign corpus 生成覆盖率报告

campaign 结束后，重新执行保存的 queue corpus，即可生成 Go 覆盖率报告，无需手动导出单独的 corpus。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
从**同一个 package**运行该命令，并使用**相同的 `-fuzz` target**，这样 gosentry 才能解析正确的缓存 campaign 状态。

## References

- [1] [变异语法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ 深入 fuzzing](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 五年后：关于 coverage-guided 协议 fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing 缺少一半工具包。我们 fork 了 toolchain 来修复它。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：一种使用 snapshots 的快速 greybox fuzzer，用于有状态网络协议](https://arxiv.org/abs/2202.03643)
- [10] [没有 grammar，也没有问题：在没有 system-call 描述的情况下 fuzzing Linux kernel](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应和可变 snapshots 进行高效 fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
