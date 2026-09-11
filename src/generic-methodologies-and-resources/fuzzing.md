# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing：Coverage 与语义

在 **mutational grammar fuzzing** 中，输入会在保持 **grammar-valid** 的同时进行变异。在 coverage-guided 模式下，只有触发 **new coverage** 的样本才会作为 corpus seeds 保存。对于 **language targets**（parsers、interpreters、engines），这种方式可能遗漏需要 **semantic/dataflow chains** 的 bug，即某个 construct 的输出会成为另一个 construct 的输入。<sup>[[1]](#references)</sup>

**Failure mode：**fuzzer 找到的 seeds 分别单独执行了 `document()` 和 `generate-id()`（或类似 primitives），但**不会保留 chained dataflow**，因此更接近 bug 的 sample 会因为没有增加 coverage 而被丢弃。当存在 **3+ dependent steps** 时，随机重组的成本会变高，而 coverage feedback 无法引导搜索。<sup>[[1]](#references)</sup>

**Implication：**对于依赖密集型 grammars，可以考虑**混合 mutational 和 generative phases**，或让生成过程偏向 **function chaining** patterns（而不只是 coverage）。<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation 具有**贪婪性**：new-coverage sample 会立即被保存，并且通常会保留大部分未更改区域。随着时间推移，corpora 会变成**低 structural diversity 的近似重复项**。激进的 minimization 可能会删除有用的 context，因此实际可采用的折中方案是 **grammar-aware minimization**：**在达到 minimum token threshold 后停止**（减少噪声，同时保留足够的周边 structure，使其仍然便于 mutation）。<sup>[[1]](#references)</sup>

mutational fuzzing 的一个实用 corpus 规则是：相比保存大量近似重复项，**优先选择一组结构上不同且能够最大化 coverage 的少量 seeds**。实践中通常意味着以下几点。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实世界的 samples** 开始（public corpora、crawling、captured traffic、来自 target ecosystem 的 file sets）。
- 使用 **coverage-based corpus minimization** 对其进行提炼，而不是保留每个 valid sample。
- 保持 seeds **足够小**，使 mutations 能够落在有意义的 fields 上，而不是将大多数 cycles 浪费在无关的 bytes 上。
- 在 harness/instrumentation 发生重大变化后重新运行 corpus minimization，因为 reachability 发生变化时，“最佳” corpus 也会改变。

## 面向 Magic Values 的 Comparison-Aware Mutation

fuzzers 陷入停滞的一个常见原因并不是 syntax，而是**严格比较**：magic bytes、length checks、enum strings、checksums，或由 `memcmp`、switch tables、级联 comparisons 保护的 parser dispatch values。纯随机 mutation 会浪费 cycles，逐字节尝试猜测这些 values。

对于这些 targets，应使用 **comparison tracing**（例如 AFL++ `CMPLOG` / Redqueen-style workflows），使 fuzzer 能够从失败的 comparisons 中观察 operands，并让 mutations 偏向于能够满足这些 comparisons 的 values。<sup>[[3]](#references)</sup>
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
**实用说明：**

- 当目标通过 **文件签名**、**协议动词**、**类型标签**或**依赖版本的功能位**将深层逻辑设为门槛时，这尤其有用。
- 将其与从真实样本、协议规范或调试日志中提取的 **dictionaries** 配合使用。包含语法 token、chunk 名称、动词和分隔符的小型 dictionary，通常比大规模通用 wordlist 更有价值。
- 如果目标会执行许多连续检查，请先解决最早的“magic”比较，然后再次最小化生成的 corpus，使后续阶段从已经有效的前缀开始。

## Edge Coverage 无法区分不同路径时的更丰富反馈

普通的 edge coverage 无法区分以下两种执行情况：它们通过不同的 caller 经过同一个 helper，或在一个函数内部采用不同的 branch 组合。在共享 decoder、协议 dispatcher 和 interpreter helper 中，这一点很重要，因为到达某个 edge 的 **route** 会决定当前的 live state。直接追踪每个 calling context 也很危险：coverage map 和 queue 可能会爆炸式增长。因此，context-sensitive fuzzing 研究建议只细化有潜力的 context，而不是将整个 call graph 都视为 context-sensitive。<sup>[[14]](#references)</sup>

近期的 AFL++ 构建版本除了普通的 edge coverage 外，还提供 **Ball-Larus per-function path coverage**。它会为经过函数的每条无环路径分配一个 feature；loop back-edge 会被移除，因此这种反馈可以区分 branch 组合，但**无法区分 loop iteration 次数**。建议从宽松的 level `1` 开始，然后仅将更严格的模式限定用于可疑的 parser/state-machine 代码，因为路径数量可能呈指数级增长。<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
对于一个从许多与安全相关的位置调用的 helper，LTO mode 可以将每条函数路径与其直接调用点结合起来：<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Campaign guidance：**谨慎应用更丰富的反馈，并监控其 coverage-map/queue 成本。<sup>[[13]](#references)[[14]](#references)</sup>

- 并行运行一个普通的 edge-coverage 实例；只有在额外的 queue/map 成本不会破坏每秒执行次数时，更丰富的反馈才有用。
- 使用 `AFL_LLVM_ALLOWLIST` 限制 path/caller instrumentation，尤其是在大型、模板密集型库或通用 utility code 主导 map 时。
- 具有过多非循环路径的函数可以由 AFL++ 跳过；编译期间的警告表明目标需要 allowlisting 或更宽松的 level。
- Caller + path coverage 仅支持一个 caller depth。不要将其与更深的 context stacks 结合使用。
- Path IDs 可能会在不同的 LLVM major versions 之间发生变化。为一个 campaign 固定 toolchain，不要将基于 PATH 的 corpora 在不同构建之间同步，仿佛它们的 feature IDs 是稳定的。
- 此反馈可以补充 `CMPLOG`：comparison tracing 解决的是 **什么值可以通过 guard**，而 path/caller feedback 保留的是 **哪种 route 和 branch 组合到达了该位置**。

## Stateful Fuzzing：Sequences Are Seeds

对于 **protocols**、**authenticated workflows** 和 **multi-stage parsers**，有趣的单元通常不是单个 blob，而是一个 **message sequence**。将整个 transcript 拼接到一个文件中并盲目 mutation 通常效率很低，因为 fuzzer 会对每个步骤进行同等程度的 mutation，即使只有后续 message 才能到达脆弱状态。<sup>[[4]](#references)</sup>

一种更有效的模式是将 **sequence 本身作为 seed**，并使用 **observable state**（response codes、protocol states、parser phases、returned object types）作为额外反馈。<sup>[[4]](#references)</sup>

- 保持 **valid prefix messages** 稳定，将 mutation 重点放在驱动 **transition** 的 message 上。
- 当下一步依赖此前响应中的 identifier 和 server-generated values 时，将其缓存下来。
- 优先采用 per-message mutation/splicing，而不是将整个 serialized transcript 作为 opaque blob 进行 mutation。
- 如果 protocol 暴露了有意义的 response codes，则将它们用作**低成本的 state oracle**，优先处理能够进一步推进的 sequences。

这也是 authenticated bugs、hidden transitions 或“only-after-handshake” parser bugs 经常被 vanilla file-style fuzzing 遗漏的原因：fuzzer 必须保留 **order、state 和 dependencies**，而不只是 structure。<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

将 **generative novelty** 与 **coverage reuse** 混合的一种实用方式，是针对 persistent server 重启短生命周期的 workers。每个 worker 从 empty corpus 开始，在 `T` 秒后进行 sync，在合并后的 corpus 上再运行 `T` 秒，再次 sync，然后退出。这样可以在每一代产生 **fresh structures**，同时继续利用累积的 coverage。<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` 强制每次生成使用一个**全新的 corpus**。
- `-server_update_interval T` 近似模拟**延迟同步**（先发现 novelty，之后再复用）。
- 在 grammar fuzzing 模式下，默认会跳过**初始 server sync**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` 取决于**目标**；通常在 worker 找到大部分“容易”覆盖率后再切换，效果最好。

## 针对难以建立 Harness 的目标进行 Snapshot Fuzzing

当你想测试的代码只有在付出较大的 setup 成本后才可达（启动 VM、完成登录、接收数据包、解析 container、初始化 service），一种实用的替代方案是 **snapshot fuzzing**：捕获已就绪的 process 或 VM 状态，将每个 test case 注入目标的输入路径，执行直到 crash/timeout，然后恢复 snapshot。这样可以避免重复初始化或 protocol 前缀，适用于**网络服务**、**固件**、**认证后的攻击面**和**仅有 binary 的目标**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到所需的状态就绪。
2. 在此时对**内存 + 寄存器**进行 snapshot。
3. 对于每个 test case，将变异后的输入直接写入相关的 guest/process buffer。
4. 执行直到 crash/timeout/reset。
5. 恢复 snapshot；对于 VM 目标，在支持的情况下仅恢复**脏页**，然后重复执行。

将 snapshot 放置在距离第一个昂贵的 parse/dispatch 步骤尽可能近的位置，例如 `recv`/`read` 之后或 packet-deserialization 的位置，并记录目标使用的 input buffer。这遵循 adaptive-placement 原则：将 snapshot 在 input processing 中向更深处移动，从而避免重复工作。<sup>[[11]](#references)</sup>

## Harness Introspection：及早发现浅层 Fuzzer

当一次 campaign 停滞时，问题通常不在 mutator，而在于 **harness**。使用 **reachability/coverage introspection**，查找从 fuzz target 静态可达、但在动态执行中很少或从未被覆盖的函数。这些函数通常表明存在以下三个问题之一。<sup>[[12]](#references)</sup>

- Harness 进入目标的时机过晚或过早。
- Seed corpus 缺少整个 feature family。
- 目标确实需要一个**第二 harness**，而不是一个庞大的“包办一切” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以将静态可达性与运行时覆盖率进行比较，并根据定时运行或公共 corpus 生成报告。<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
使用该报告来决定：是否为未测试的 parser path 添加新的 harness、为特定 feature 扩展 corpus，或将单体 harness 拆分为更小的 entry points。

## 基于图的 Fuzz Target 选择与 Mutation Triage

如果你已经拥有 **static-analysis findings**、**mutation-testing survivors** 和 **coverage reports**，不要将它们作为相互独立的列表进行 triage。首先构建一个 **call graph**，为节点标注 **cyclomatic complexity**、**entrypoint/untrusted-input reachability** 以及任何外部发现，然后提出图相关问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从不可信输入到达？
- 哪些 mutation survivors 位于从 parsers/handlers 通往安全关键代码的路径上？
- 哪些函数是 **blast radius** 异常大的架构瓶颈？

相比单独关注“最低 coverage”，这种方法通常能发现更好的 fuzz targets。一个具有 **high complexity** 且已确认 **external reachability** 的 parser/decoder，比一个 coverage 较弱但没有攻击者可控路径的孤立内部 helper，更适合作为 harness 候选。

### Practical triage workflow

1. 从代码库构建一个 **code graph**，并提取每个函数的 complexity/branch metrics。
2. 枚举接受攻击者可控输入的 **entrypoints**：request handlers、decoders、importers、protocol parsers、CLI/file readers。
3. 从这些 entrypoints 对候选函数运行 **path queries**，将可达的攻击面与死代码/仅内部代码区分开。
4. 优先处理同时具备以下条件的节点：
- 高 **cyclomatic complexity**
- 已确认可从 **untrusted input** 到达
- 高 **blast radius** 或拥有许多下游依赖项
- 存在佐证，例如 **SARIF** findings、audit notes 或 mutation survivors
5. 首先为得分最高的节点编写专注型 harness，尤其是 **parsers/codecs**，例如 hex/Base64/IP/message decoders。

### Mutation survivors：equivalent vs actionable

Mutation testing 通常会产生嘈杂的 survivor 列表。在将每个 survivor 都视为安全缺口之前，使用该图提出以下问题：

- 被 mutation 的函数是否可从攻击者可控的 entrypoint 到达？
- 所有调用路径是否受到比被 mutation 的检查更强的 invariants 约束？
- 该节点是否位于死代码、仅涉及格式化的逻辑，或高影响的 arithmetic/parser path 中？

仍然不可达或受到结构性约束的 survivors，通常属于 **equivalent mutants**。仍然**可达**且涉及 **boundary conditions**、**overflow/carry paths** 或 **security-critical arithmetic/parsing** 的 survivors，则应提升为：

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### 将外部发现关联到图上

如果你的 SAST pipeline 导出 **SARIF**，可通过 **file + line range** 将 findings 映射到图节点，并使用该图扩展影响范围。<sup>[[6]](#references)</sup>

- 计算被标记函数的 **blast radius**
- 检查该 finding 是否位于从某个 entrypoint 出发的路径上
- 将附近且最终汇聚到同一瓶颈的 findings 聚类

这在决定是否将 fuzzing 时间投入某个特定函数时很有用：一个**可达**、**复杂**且已有 **SAST hits** 的节点，通常比一个仅复杂但不存在攻击者路径的节点更适合作为 target。

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
重要的方法论在于三者的交集：**复杂度 x 暴露面 x 影响**。使用图表选择预期安全价值最高的 fuzz 目标，然后利用 mutation survivors 来确定 harness 必须重点施压的边界和不变量。<sup>[[5]](#references)</sup>

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入和差分检查

如果 Go 目标已经具有原生的 `testing.F` harness，那么一种实用的升级路径是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个 fork 版 Go toolchain，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
当 native Go fuzzer 在 **hard comparisons**、**typed inputs** 或 **parser-heavy formats** 上停滞时，这种方法很有用。整体方法保持不变：

- 继续使用 `f.Add(...)` 添加 seeds，使用 `f.Fuzz(...)` 作为 callback。
- 复用相同的 harness，但使用 gosentry 的 `go` binary，而不是 stock toolchain 运行。
- 将生成的 campaign 视为普通的 coverage-guided run，但其使用 LibAFL 的 scheduling/mutation，以及更完善的周边 detectors。

### 将静默失败转化为 fuzz findings

在 Go assessment 中，一个常见问题是，危险行为通常**默认不会**导致 crash。借助 gosentry，可以将几类“有问题但保持静默”的状态提升为 findings。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` 让选定的 logging/error paths 表现得像 crashes（适用于 `log.Fatal` 风格的 code paths；否则它们只会记录日志并继续执行）。
- `--catch-races=true` 使用 Go race detector 重新执行新发现的 queue entries。
- `--catch-leaks=true` 使用 `goleak` 重新执行新的 queue entries，并在发现 goroutine leaks 时停止。
- LibAFL 的 hang handling 会将 **infinite loops / very slow inputs** 保留为 fuzz findings，而不是让它们作为 timeouts 消失。
- 默认启用内置 arithmetic overflow checks，并可通过 go-panikint 风格的 instrumentation 选择性启用 truncation checks。

对于安全影响表现为 **panicless parser failure**、**concurrency bug** 或仅导致 **DoS-only hang**，而不是 memory corruption 的 targets，这尤其有价值。

### 面向 Struct 的 typed Go APIs fuzzing

Native Go fuzzing 主要接受 `[]byte`、`string` 和 numbers 等 scalars。如果被测试的代码使用 typed objects，gosentry 可以直接对 **composite values**（structs、slices、arrays、pointers）进行 fuzzing，同时继续在底层 mutation bytes。<sup>[[7]](#references)[[8]](#references)</sup>
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
在构建仅用于 fuzzing 的虚假 wire format 时，这样做会将逻辑漏洞隐藏在仅供 harness 使用的解析代码之后。对于 differential 或 grammar-based campaigns，应将 harness 输入保留为单个 `[]byte` 或 `string`，并改为在 callback 内部进行解析。

### 用于 parser 和 protocol input 的 Grammar-based fuzzing

对于 parser、format 和 input language，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。该 grammar 是一个 production rule 的 JSON 数组，harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- 当 byte-level mutations mostly 在 early syntax checks 中失效时，使用 grammar mode。
- 将 grammar 聚焦于语言/协议的 **security-relevant subset**，而不是对完整 specification 建模。
- 在 terminals/nonterminals 中使用较大的 boundary values，以测试 integer、length 和 state-machine 的边界。
- grammar mode 会保持输入符合 grammar，但 target 仍会接收 **bytes/strings**，因此 parsing 和 semantic checks 仍位于 harnessed code 内部。

### Differential fuzzing：比较 implementations，而不仅是 crashes

对于 Go ecosystems，一个强大的模式是 **grammar-based differential fuzzing**：生成有效的结构化输入，并将其交给两个 parsers、clients 或 state-transition engines。<sup>[[7]](#references)[[8]](#references)</sup>
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
- 接受/拒绝的输入不一致
- 解析树或解码后的对象不同
- 状态转换、nonce、余额或 state roots 不一致

这是发现 **consensus mismatches**、**parser ambiguity** 以及 **spec-vs-implementation drift** 的实用方法，而纯粹的 crash fuzzing 通常会遗漏这些问题。

### Reuse the campaign corpus for coverage reporting

campaign 结束后，重新执行保存的 queue corpus，以生成 Go coverage report，而无需手动导出单独的 corpus。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
从**同一个 package**运行该命令，并使用相同的 `-fuzz` target，以便 gosentry 解析正确的缓存 campaign 状态。



## References

- [1] [变异语法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing 深入解析](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 五年后：关于 coverage-guided protocol fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing 缺少一半工具包。我们 fork 了 toolchain 来修复它。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：一种使用 snapshots 的快速 greybox fuzzer，用于有状态网络协议](https://arxiv.org/abs/2202.03643)
- [10] [没有 grammar，也没有问题：探索无需 system-call descriptions 的 Linux kernel fuzzing](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应和可变 snapshots 实现高效 fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation：path 和 caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
