# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

在 **mutational grammar fuzzing** 中，输入会在保持 **grammar-valid** 的同时被变异。在 coverage-guided 模式下，只有触发 **new coverage** 的样本才会被保存为 corpus seeds。对于 **language targets**（parsers、interpreters、engines），这可能会错过需要 **semantic/dataflow chains** 的 bug，也就是一个构造的输出会成为另一个构造的输入。

**Failure mode:** fuzzing 工具找到了分别能触发 `document()` 和 `generate-id()`（或类似 primitive）的 seeds，但 **没有保留串联的数据流**，因此那个“更接近 bug”的样本因为没有增加 coverage 而被丢弃。对于 **3+ dependent steps**，随机重组会变得很昂贵，而且 coverage feedback 也无法引导搜索。

**Implication:** 对于依赖关系很重的 grammar，考虑 **hybridizing mutational and generative phases**，或者让生成更偏向 **function chaining** 模式（而不只是 coverage）。

## Corpus Diversity Pitfalls

Coverage-guided mutation 是 **greedy** 的：一旦有 new-coverage sample 就会立即保存，通常还会保留大量未改动的区域。随着时间推移，corpus 会变成低结构多样性的 **near-duplicates**。激进的最小化可能会移除有用上下文，因此一个实用的折中是 **grammar-aware minimization**，并且在达到最小 token 阈值后 **停止**（减少噪声，同时保留足够的周边结构，以便继续方便变异）。

mutational fuzzing 的一个实用 corpus 规则是：**优先选择少量结构不同、能最大化 coverage 的 seeds**，而不是堆一大批 near-duplicates。实践中，这通常意味着：

- 从 **real-world samples** 开始（public corpora、crawling、captured traffic、来自目标生态的 file sets）。
- 用 **coverage-based corpus minimization** 来提炼它们，而不是保留每个有效样本。
- 保持 seeds **足够小**，这样 mutation 更容易落在有意义的字段上，而不是把大部分 cycles 花在无关字节上。
- 在重大 harness/instrumentation 变更后重新运行 corpus minimization，因为当 reachability 变化时，“最佳” corpus 也会变化。

## Comparison-Aware Mutation For Magic Values

fuzzing 停滞的一个常见原因不是语法，而是 **hard comparisons**：magic bytes、length checks、enum strings、checksums，或者由 `memcmp`、switch tables 或级联比较保护的 parser dispatch values。纯随机变异会浪费 cycles 去逐字节猜这些值。

对于这些目标，使用 **comparison tracing**（例如 AFL++ `CMPLOG` / Redqueen-style workflows），这样 fuzzing 工具就能观察失败比较中的操作数，并将变异偏向于能满足这些比较的值。
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
**实用笔记：**

- 当目标把深层逻辑隐藏在 **file signatures**、**protocol verbs**、**type tags** 或 **version-dependent feature bits** 后面时，这一点尤其有用。
- 将其与从真实样本、protocol 规范或调试日志中提取的 **dictionaries** 配合使用。一个包含 grammar tokens、chunk names、verbs 和 delimiters 的小词典，往往比一个庞大的通用 wordlist 更有价值。
- 如果目标执行许多顺序检查，先解决最早的 “magic” 比较，然后再次最小化生成的 corpus，这样后续阶段就会从已经有效的前缀开始。

## Stateful Fuzzing: Sequences Are Seeds

对于 **protocols**、**authenticated workflows** 和 **multi-stage parsers**，有意思的单位通常不是单个 blob，而是一个 **message sequence**。把整个 transcript 连接成一个文件再盲目变异通常效率很低，因为 fuzzer 会等比例地变异每一步，即使只有后面的消息会到达脆弱状态。

更有效的模式是把 **sequence 本身当作 seed**，并将 **observable state**（response codes、protocol states、parser phases、返回的 object types）作为额外反馈：

- 保持 **valid prefix messages** 稳定，把变异重点放在 **transition-driving** 消息上。
- 当下一步依赖前一步响应时，缓存前序响应中的 identifiers 和 server-generated values。
- 优先对每条 message 单独 mutation/splicing，而不是把整个序列化 transcript 当作一个不可见的 blob 去变异。
- 如果 protocol 暴露了有意义的 response codes，就把它们当作一种 **cheap state oracle**，用来优先处理那些推进得更深的 sequences。

这也正是为什么 authenticated bugs、隐藏的 transitions，或 “only-after-handshake” 的 parser bugs，常常会被普通的 file-style fuzzing 漏掉：fuzzer 必须保留 **顺序、state 和依赖关系**，而不只是结构。

## Single-Machine Diversity Trick (Jackalope-Style)

一种把 **generative novelty** 与 **coverage reuse** 混合起来的实用方法，是针对一个持久化 server **重启短生命周期的 workers**。每个 worker 都从空 corpus 开始，经过 `T` 秒后同步一次，在合并后的 corpus 上再运行 `T` 秒，再同步一次，然后退出。这样可以在保留累计 coverage 的同时，获得 **每一代都更新鲜的结构**。

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

- `-in empty` 强制每次生成都使用一个**全新的语料库**。
- `-server_update_interval T` 近似表示**延迟同步**（先新颖性，后复用）。
- 在 grammar fuzzing 模式下，**初始 server sync 默认会跳过**（不需要 `-skip_initial_server_sync`）。
- 最优的 `T` **取决于目标**；在 worker 找到大部分“简单”coverage 之后再切换，通常效果最好。

## Snapshot Fuzzing For Hard-To-Harness Targets

当你要测试的代码只有在**较大的初始化成本**之后才可达时（启动 VM、完成登录、接收 packet、解析 container、初始化服务），一个有用的替代方案是 **snapshot fuzzing**：

1. 运行 target，直到有趣的状态就绪。
2. 在该时刻 snapshot **memory + registers**。
3. 对于每个测试用例，直接把变异后的输入写入相关的 guest/process buffer。
4. 执行直到 crash/timeout/reset。
5. 仅恢复 **dirty pages**，然后重复。

这样可以避免每次迭代都支付完整的初始化成本，尤其适用于 **network services**、**firmware**、**post-auth attack surfaces**，以及那些很难重构成传统 in-process harness 的 **binary-only targets**。

一个实用技巧是：在 `recv`/`read`/packet-deserialization 点后立即中断，记下 input buffer 地址，在那里做 snapshot，然后在每次迭代中直接变异那个 buffer。这样你就可以 fuzz 深层解析逻辑，而不必每次都重建整个握手过程。

## Harness Introspection: Find Shallow Fuzzers Early

当一次 campaign 停滞时，问题通常不在 mutator，而在 **harness**。使用 **reachability/coverage introspection** 找出那些在静态上可从 fuzz target 到达、但在动态上很少或从未被覆盖的函数。这些函数通常说明三种问题之一：

- harness 进入 target 的时机太晚或太早。
- seed corpus 缺少一个完整的 feature family。
- target 实际上需要一个 **second harness**，而不是一个过大的“do everything” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 对这个分流很有用：
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
关键方法是交集：**复杂性 x 暴露面 x 影响**。使用图表选择具有最高预期安全价值的 fuzz 目标，然后利用 mutation survivors 来决定你的 harness 必须重点施压哪些边界和不变量。

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入和差分检查

如果某个 Go 目标已经有原生的 `testing.F` harness，一个实用的升级路径是用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个分叉的 Go 工具链，保留 `go test -fuzz`，但把后端切换为 **LibAFL**。
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
当原生 Go fuzzer 在 **hard comparisons**、**typed inputs** 或 **parser-heavy formats** 上停滞时，这很有用。方法保持不变：

- 继续使用 `f.Add(...)` 作为 seeds，使用 `f.Fuzz(...)` 作为回调。
- 复用同一个 harness，但改为用 gosentry 的 `go` binary，而不是默认 toolchain 运行它。
- 将生成的 campaign 视为一次普通的 coverage-guided run，但使用 LibAFL scheduling/mutation 以及更好的外围 detectors。

### 将静默失败转化为 fuzz findings

Go assessment 中一个反复出现的问题是，危险行为通常默认**不会** crash。使用 gosentry，你可以把几类“坏但静默”的状态提升为 findings：

- `--panic-on=pkg.Func,...`：让选定的 logging/error 路径表现得像 crash 一样（适用于 `log.Fatal` 风格的代码路径，这类路径通常只会记录并继续）。
- `--catch-races=true`：用 Go race detector 回放新发现的 queue entries。
- `--catch-leaks=true`：用 `goleak` 回放新的 queue entries，并在 goroutine leaks 时停止。
- 默认启用 LibAFL hang handling，把 **无限循环 / 极慢输入** 作为 fuzz findings 保留，而不是让它们以 timeout 形式消失。
- 默认启用算术 overflow 检查，并通过 go-panikint 风格的 instrumentation 可选地进行 truncation 检查。

这对那些安全影响体现为 **panicless parser failure**、**concurrency bug**，或者仅仅是 **DoS-only hang**，而不是 memory corruption 的目标，尤其有价值。

### 面向 typed Go APIs 的 struct-aware fuzzing

原生 Go fuzzing 主要期望 `[]byte`、`string` 和数字等标量。如果被测代码消费的是 typed objects，gosentry 可以直接 fuzz **composite values**（structs、slices、arrays、pointers），同时仍在底层按字节进行 mutation。
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
在构建一个仅用于 fuzzing 的 fake wire format 时这样做，会把逻辑 bug 隐藏在仅供 harness 使用的 parsing 代码后面。对于 differential 或 grammar-based campaigns，应将 harness 输入保持为单个 `[]byte` 或 `string`，并在 callback 中再进行解析。

### 面向 parser 和 protocol 输入的 Grammar-based fuzzing

对于 parser、format 和 input languages，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。grammar 是一个 production rules 的 JSON array，而 harness 通常应只接受一个 `[]byte` 或 `string` 参数。
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
方法论说明：

- 当字节级变异大多在早期语法检查中失效时，使用 grammar mode。
- 保持 grammar 只关注语言/protocol 中**与安全相关的子集**，而不是建模完整规范。
- 在 terminals/nonterminals 中使用较大的边界值，以压测 integer、length 和 state-machine 的边界。
- Grammar mode 会让输入保持 grammar-valid，但目标仍然接收的是 **bytes/strings**，因此 parsing 和 semantic checks 仍然发生在 harnessed code 内部。

### Differential fuzzing：比较 implementations，而不只是 crashes

Go 生态系统中的一个强模式是 **grammar-based differential fuzzing**：生成有效的 structured inputs，并将它们喂给两个 parsers、clients 或 state-transition engines。
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
将以下内容视为发现：

- 一个实现会 panic，而另一个会干净地拒绝
- 接受/拒绝输入不匹配
- 不同的解析树或解码对象
- 不同的状态转换、nonce、余额或 state roots

这是一种实用的方法，可以发现**consensus mismatches**、**parser ambiguity** 和 **spec-vs-implementation drift**，而纯粹的 crash fuzzing 往往会错过这些问题。

### 重用 campaign corpus 进行覆盖率报告

在一次 campaign 之后，重放已保存的 queue corpus，无需手动导出单独的 corpus，即可生成 Go coverage 报告：
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
在**同一个 package**中运行命令，并使用**相同的 `-fuzz` target**，这样 gosentry 才能解析到正确的缓存 campaign state。

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
