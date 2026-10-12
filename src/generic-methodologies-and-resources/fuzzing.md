# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## 变异式文法 Fuzzing：覆盖率与语义

在**变异式文法 fuzzing**中，输入会在保持**文法有效**的同时进行变异。在覆盖率引导模式下，只有触发**新覆盖率**的样本才会作为语料种子保存。对于**语言类目标**（解析器、解释器、引擎），这种方式可能漏掉需要**语义/数据流链**的 bug，即某个构造的输出成为另一个构造的输入。<sup>[[1]](#references)</sup>

**失败模式：**fuzzer 找到的种子会分别触发 `document()` 和 `generate-id()`（或类似原语），但**不会保留链式数据流**，因此更接近 bug 的样本会因没有增加覆盖率而被丢弃。对于包含 **3 个或更多依赖步骤**的情况，随机重组开销会很高，而覆盖率反馈也无法引导搜索。<sup>[[1]](#references)</sup>

**启示：**对于依赖关系密集的文法，可以考虑**结合变异与生成阶段**，或让生成过程偏向**函数链式调用**模式（而不只是关注覆盖率）。<sup>[[1]](#references)</sup>

## 语料多样性的陷阱

覆盖率引导的变异是**贪婪的**：新覆盖率样本会立即保存，而且通常保留大量未变更区域。随着时间推移，语料会变成结构多样性较低的**近似重复样本**。过度最小化可能会删掉有用的上下文，因此实际可行的折中方案是采用**感知文法的最小化**，并在达到最小 token 阈值后**停止**（减少噪声，同时保留足够的周边结构，使其仍适合变异）。<sup>[[1]](#references)</sup>

变异式 fuzzing 的一条实用语料规则是：**优先选择一小组结构各异且能最大化覆盖率的种子，而不是堆积大量近似重复样本**。实践中通常包括以下做法。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实样本**开始（公开语料、爬取内容、捕获的流量、目标生态系统中的文件集）。
- 使用**基于覆盖率的语料最小化**筛选样本，而不是保留每个有效样本。
- 种子要**足够小**，确保变异落在有意义的字段上，而不是把大部分轮次浪费在无关字节上。
- 在 harness 或插桩发生重大变化后，重新运行语料最小化，因为可达性变化会改变“最佳”语料。

## 针对魔术值的比较感知变异

fuzzer 陷入瓶颈的常见原因不是语法，而是**硬编码比较**：魔术字节、长度检查、枚举字符串、校验和或解析器分派值，这些值由 `memcmp`、switch 表或级联比较进行检查。纯随机变异会浪费大量轮次，逐字节猜测这些值。

对于这类目标，可以使用**比较跟踪**（例如 AFL++ `CMPLOG` / Redqueen 风格的工作流），让 fuzzer 观察失败比较中的操作数，并优先变异为能通过这些比较的值。<sup>[[3]](#references)</sup>

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

**实用提示：**

- 当目标将深层逻辑隐藏在 **文件签名**、**协议动词**、**类型标签** 或 **依赖版本的功能位** 之后时，这种方法尤其有用。
- 配合从真实样本、协议规范或调试日志中提取的**字典**使用。包含语法标记、块名称、动词和分隔符的小型字典，往往比庞大的通用词表更有价值。
- 如果目标会执行许多顺序检查，先解决最早出现的“魔数”比较，然后再次精简生成的语料，以便后续阶段从已经有效的前缀开始。

## 当边覆盖无法区分不同路径时获取更丰富的反馈

普通边覆盖无法区分两种执行：它们通过不同调用者遍历同一个辅助函数，或在函数内部采用不同的分支组合。这在共享解码器、协议分派器和解释器辅助函数中很重要，因为到达某条边的**路径**会决定当前状态。若不加区分地跟踪每个调用上下文，也有风险：覆盖率映射和队列可能会急剧膨胀。因此，上下文敏感 fuzzing 研究建议只细化有希望的上下文，而不是让整个调用图都具备上下文敏感性。<sup>[[14]](#references)</sup>

近期的 AFL++ 版本除了普通边覆盖外，还提供 **Ball-Larus 函数级路径覆盖**。它会为函数中的每条无环路径分配一个特征；循环回边会被移除，因此这种反馈可以区分分支组合，但**无法区分循环迭代次数**。先从宽松的级别 `1` 开始，然后只对可疑的解析器或状态机代码启用更严格的模式，因为路径数量可能呈指数级增长。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

对于一个在许多安全相关位置被调用的辅助函数，LTO 模式可以将每条函数路径与其直接调用位置结合起来：<sup>[[13]](#references)</sup>

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

**Campaign guidance：** 保守地使用更丰富的反馈，并监控其 coverage map/队列开销。<sup>[[13]](#references)[[14]](#references)</sup>

- 并行运行一个普通的 edge-coverage 实例；只有额外的队列/map 开销不会显著降低每秒执行次数时，更丰富的反馈才有用。
- 当大型模板库或通用工具代码主导 map 时，使用 `AFL_LLVM_ALLOWLIST` 限制路径/调用方插桩。
- AFL++ 可以跳过无环路径过多的函数；编译期间出现警告，说明目标需要使用 allowlist，或降低严格级别。
- 调用方 + 路径覆盖率只支持一个调用方深度。不要将其与更深的上下文堆栈结合使用。
- 路径 ID 可能会随 LLVM 主版本变化。在整个 campaign 中固定工具链，不要将基于 PATH 的语料库同步起来，仿佛其 feature ID 在不同构建间保持稳定。
- 此反馈可与 `CMPLOG` 互补：比较跟踪解决的是**哪个值能通过 guard**，而路径/调用方反馈保留的是**哪些路线和分支组合到达了该位置**。

## 有状态 Fuzzing：序列就是种子

对于**协议**、**已认证工作流**和**多阶段解析器**，有趣的测试单位往往不是单个 blob，而是一个**消息序列**。将整个交互记录拼接到一个文件中并盲目变异通常效率低下，因为 fuzzer 会同等地变异每个步骤，即使只有后续消息才能到达脆弱状态也是如此。<sup>[[4]](#references)</sup>

更有效的做法是将**序列本身视为种子**，并将**可观测状态**（响应码、协议状态、解析器阶段、返回的对象类型）作为额外反馈。<sup>[[4]](#references)</sup>

- 保持**有效的前缀消息**不变，专注变异驱动**状态转换**的消息。
- 如果下一步依赖先前响应中的标识符和服务器生成的值，就缓存它们。
- 优先按消息进行变异/拼接，而不是将整个序列化交互记录作为不透明 blob 进行变异。
- 如果协议提供有意义的响应码，就将其用作**廉价的状态 oracle**，优先处理能进一步推进状态的序列。

这也解释了为什么已认证场景中的 bug、隐藏状态转换或“仅在握手后出现”的解析器 bug 往往会被普通的文件式 fuzzing 漏掉：fuzzer 必须保留**顺序、状态和依赖关系**，而不只是结构。<sup>[[4]](#references)</sup>

### Android Binder：多客户端驱动 fuzzing

即使 edge coverage 很高，也仍可能漏掉 IPC 驱动 bug，因为覆盖率无法描述**对象所有权、引用计数、待处理消息、清理顺序或线程交错**。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 页面介绍了驱动的对象模型；本例则聚焦于 fuzzer harness。Android Binder 是一个很有用的模型：如果 fuzzer 无法按所需顺序让多个进程操作同一个内核对象，那么仅仅到达分配和释放路径并不足够。<sup>[[15]](#references)</sup>

#### 对协议建模，而不是孤立的 `ioctl` 缓冲区

将测试用例表示为一个有序语法，由**客户端身份 + 操作 + 结构化参数**组成。Binder LKL fuzzer 使用 protobuf 和 `libprotobuf-mutator`，其中包括一个持久化的 context-manager 客户端和两个普通客户端。随后，语义化 harness 会保留盲目字节变异可能破坏的关系。<sup>[[15]](#references)</sup>

- 缓存先前操作返回的值。例如，`BC_FREE_BUFFER` 必须重用之前某次 `ioctl` 返回的事务缓冲区指针。
- 生成有效的默认回复，以便同步事务可以完成，并让后续操作仍可到达。
- 拒绝不可能的状态转换，例如向自身发起事务，或向同一目标发起多个待处理事务。
- 将单例引导状态保留在每次输入重置的范围之外。Binder 每次启动只允许注册一次 `BINDER_SET_CONTEXT_MGR`，因此反复销毁并重建该客户端会导致后续输入无效。

一种实用的生命周期竞态模板是：让一个客户端传递对象，启动线程或进程清理，同时让接收客户端释放事务缓冲区。在 CVE-2020-0423 示例中，传递 `BINDER_TYPE_WEAK_BINDER` 后，`BINDER_THREAD_EXIT` 与 `BC_FREE_BUFFER` 发生竞态，可能导致嵌入的 `binder_work` 被释放，而退出线程的清理路径仍在使用它。<sup>[[15]](#references)</sup>

#### 在用户态内核中重新引入受控交错

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) 将真实内核代码链接到用户态 harness，并通过 `lkl_syscall` 暴露其系统调用接口。这样便于在一个进程中协调 protobuf 状态、覆盖率和 KASAN。不过，LKL 通常会在运行系统调用时避免被其他内核线程打断。对于竞态 campaign，可在选定的锁定/解锁和生命周期边界附近插入 `schedule()` 点，然后让 harness 在每次让出执行权时随机选择下一个客户端。应将这些点限制在目标位置，因为每增加一个点都会扩大调度搜索空间。研究人员描述的随机调度器**并非**上游 Binder fuzzer 的一部分。<sup>[[15]](#references)</sup>

#### 构建并重放序列化回归种子

上游 harness 固定使用兼容的 `libprotobuf-mutator`，通过 `LKL_FUZZING=1` 启用 LKL fuzzing 插桩和 KASAN，并通过 `MMU=1` 为 Binder 启用 `CONFIG_MMU`。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

检出一个故意存在漏洞的版本，或应用上游记录的回滚补丁后，序列化种子即可重现整个多客户端状态转换，无需通过临时编写的 C 概念验证来重构：<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

将 resulting KASAN use-after-free 视为 seed 已到达易受攻击的生命周期路径的确认。它**并不能**证明后续实现 kernel code execution 或 privilege escalation 所需的 primitives。<sup>[[16]](#references)</sup>

## 单机多样性技巧（Jackalope 风格）

将**生成式新颖性**与**覆盖率复用**结合的一种实用方法是：针对持久运行的 server **重启短生命周期的 worker**。每个 worker 从空 corpus 开始，运行 `T` 秒后同步，再基于合并后的 corpus 运行 `T` 秒，再次同步，然后退出。这样可以在每一代产生**新鲜的结构**，同时利用累积的覆盖率。<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**顺序 worker（循环示例）：**

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

**注意：**

- `-in empty` 会在每轮生成时强制使用**全新的语料库**。
- `-server_update_interval T` 可近似实现**延迟同步**（先发现新颖用例，之后再复用）。
- 在 grammar fuzzing 模式下，默认会跳过**初始服务器同步**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` **取决于目标**；当 worker 已发现大部分“容易获得”的覆盖率后再切换，通常效果最好。

## 针对难以构建 Harness 的目标进行 Snapshot Fuzzing

如果要测试的代码只有在**耗费大量准备工作后**才可达（例如启动 VM、完成登录、接收数据包、解析容器或初始化服务），那么 **Snapshot Fuzzing** 是一种实用的替代方案：捕获已就绪的进程或 VM 状态，将每个测试用例注入目标的输入路径，执行直到发生崩溃或超时，然后恢复快照。这种方法无需重复初始化或协议前缀，适用于**网络服务**、**固件**、**认证后的攻击面**和**仅有二进制文件的目标**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到进入所需状态。
2. 在此时对**内存和寄存器**进行快照。
3. 对每个测试用例，将变异后的输入直接写入相关的 guest/进程缓冲区。
4. 执行，直到发生崩溃、超时或重置。
5. 恢复快照；对于 VM 目标，如果支持，则仅恢复**脏页**，然后重复。

尽可能将快照放在首次耗时的解析/分发步骤附近，例如 `recv`/`read` 之后或数据包反序列化的位置，并记录目标使用的输入缓冲区。这符合自适应放置原则：将快照逐渐移至输入处理流程的更深处，以避免重复执行已有工作。<sup>[[11]](#references)</sup>

## Harness 内省：尽早发现浅层 Fuzzer

当 fuzzing 活动停滞时，问题往往不在变异器，而在 **Harness**。使用**可达性/覆盖率内省**，找出从 fuzz 目标静态可达、但动态覆盖率很低或从未覆盖的函数。这些函数通常意味着存在以下三种问题之一。<sup>[[12]](#references)</sup>

- Harness 进入目标的时机过早或过晚。
- 种子语料库缺少一整类功能。
- 目标确实需要**第二个 Harness**，而不是一个过于庞大的“包办一切”Harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以比较静态可达性与运行时覆盖率，并根据限时运行或公开语料库生成报告。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

根据报告决定是为尚未测试的解析器路径新增 harness、扩展特定功能的语料库，还是将单体 harness 拆分为更小的入口点。

## 基于图的 Fuzz 目标选择与变异分类

如果你已经有**静态分析发现**、**变异测试存活项**和**覆盖率报告**，不要把它们当作互不相关的列表来分类。先构建**调用图**，为节点标注**圈复杂度**、**入口点/不可信输入可达性**以及任何外部发现，然后再提出图相关问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从不可信输入到达？
- 哪些变异存活项位于从解析器/处理程序通往安全关键代码的路径上？
- 哪些函数是架构上的瓶颈，其**影响范围**异常广？

这种方法通常比单看“最低覆盖率”更容易找出合适的 fuzz 目标。一个**复杂度高**且已确认**可从外部到达**的解析器/解码器，比一个覆盖率较低、但孤立且没有攻击者可控路径的内部辅助函数，更适合作为 harness 候选。

### 实用分类工作流

1. 从代码库构建**代码图**，并提取每个函数的复杂度/分支指标。
2. 列出接受攻击者可控输入的**入口点**：请求处理程序、解码器、导入器、协议解析器、CLI/文件读取器。
3. 从这些入口点执行**路径查询**，筛选候选函数，区分可达的攻击面与死代码/仅内部可达代码。
4. 优先处理同时具备以下特征的节点：
   - 高**圈复杂度**
   - 已确认**可从不可信输入到达**
   - **影响范围**大或下游依赖项多
   - 有佐证，例如 **SARIF** 发现、审计备注或变异存活项
5. 优先为评分最高的节点编写有针对性的 harness，尤其是 **parser/codec**，例如 hex/Base64/IP/消息解码器。

### 变异存活项：等价项还是可处理项

变异测试经常会产生嘈杂的存活项列表。在将每个存活项都视为安全缺陷之前，可以借助图来判断：

- 变异后的函数是否可从攻击者可控的入口点到达？
- 所有调用路径是否都受到比被变异检查更强的不变量约束？
- 该节点是否位于死代码、仅负责格式处理的逻辑中，还是位于高影响的算术/解析路径上？

仍不可达或在结构上受到约束的存活项通常是**等价变异体**。仍然**可达**且涉及**边界条件**、**溢出/进位路径**或**安全关键算术/解析**的存活项，则应纳入：

- 新的 fuzz harness
- 直接的属性/不变量测试
- 有针对性的边界情况向量

### 将外部发现关联到图上

如果你的 SAST 流水线导出 **SARIF**，可以按**文件 + 行范围**将发现映射到图节点，再借助图扩展影响分析。<sup>[[6]](#references)</sup>

- 计算被标记函数的**影响范围**
- 检查该发现是否位于任何入口点的路径上
- 将附近且最终指向同一瓶颈的发现归类在一起

这有助于决定是否要将 fuzzing 时间投入某个特定函数：一个**可达**、**复杂**且已有 **SAST 命中**的节点，通常比一个只是复杂、却没有攻击路径的节点更值得优先测试。

使用 Trailmark 的工作流示例。<sup>[[6]](#references)</sup>

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

重要的方法论在于交集：**复杂度 x 暴露面 x 影响**。使用图表选择预期安全价值最高的 fuzz 目标，然后根据 mutation 测试中存活的变异，判断 harness 必须重点测试哪些边界和不变量。<sup>[[5]](#references)</sup>

## 使用 gosentry 进行 Go Fuzzing：更强大的引擎、类型化输入与差分检查

如果 Go 目标已经有原生的 `testing.F` harness，一个实用的升级方案是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个分叉的 Go 工具链，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

当原生 Go fuzzer 卡在**难以满足的比较**、**类型化输入**或**解析器密集型格式**上时，这种方法很有用。整体方法不变：

- 继续使用 `f.Add(...)` 添加种子，并使用 `f.Fuzz(...)` 编写回调。
- 复用同一个 harness，但使用 gosentry 的 `go` 二进制文件运行，而不是使用标准工具链。
- 将生成的 campaign 视为常规的 coverage-guided 运行，但它使用 LibAFL 的调度/变异机制，并配有更完善的辅助检测器。

### 将无声失败转化为 fuzz 发现

Go 安全评估中反复出现的一个问题是，危险行为往往默认**不会**导致崩溃。使用 gosentry，可以将几类“有问题但无声”的状态转化为发现项。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`：将选定的日志/错误处理路径转化为类似崩溃的行为（适用于 `log.Fatal` 一类原本只记录日志并继续执行的代码路径）。
- `--catch-races=true`：使用 Go race detector 重放新发现的队列条目。
- `--catch-leaks=true`：使用 `goleak` 重放新的队列条目，并在检测到 goroutine 泄漏时停止。
- LibAFL 的 hang 处理机制会将**无限循环/极慢输入**保留为 fuzz 发现，而不是让它们作为超时消失。
- 默认启用内置算术溢出检查，也可通过类似 go-panikint 的插桩启用截断检查。

对于安全影响表现为**不会触发 panic 的解析器故障**、**并发漏洞**或**仅导致 DoS 的挂起**，而非内存破坏的目标，这尤其有价值。

### 面向类型化 Go API 的结构体感知 fuzzing

原生 Go fuzzing 主要面向 `[]byte`、`string` 和数字等标量。如果被测代码接收的是类型化对象，gosentry 可以直接对**复合值**（struct、slice、array、pointer）进行 fuzzing，同时仍在底层变异字节。<sup>[[7]](#references)[[8]](#references)</sup>

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

如果为了 fuzzing 而构造虚假的 wire format，会让仅存在于 harness 解析代码中的逻辑 bug 被隐藏。对于 differential 或基于 grammar 的 campaign，应将 harness 输入保留为单个 `[]byte` 或 `string`，并在 callback 内进行解析。

### 用于 parser 和 protocol 输入的基于 grammar 的 fuzzing

对于 parser、format 和输入语言，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。grammar 是一个 JSON production rules 数组，而 harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法论笔记：

- 当字节级变异大多在早期语法检查中失败时，使用 grammar mode。
- 将 grammar 限定在语言/协议中**与安全相关的子集**，而不是对完整规范建模。
- 在终结符/非终结符中使用较大的边界值，以测试整数、长度和状态机边界。
- grammar mode 会使输入保持语法有效，但目标仍会接收**字节/字符串**，因此解析和语义检查仍在经过 harness 的代码中执行。

### Differential fuzzing：比较实现，而不只是查找崩溃

Go 生态中一种有效的模式是**基于 grammar 的 differential fuzzing**：生成有效的结构化输入，并将其传给两个解析器、客户端或状态转换引擎。<sup>[[7]](#references)[[8]](#references)</sup>

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

将以下情况视为发现：

- 一个实现发生 panic，而另一个则正常拒绝
- 输入接受/拒绝结果不一致
- 解析树或解码后的对象不同
- 状态转换、nonce、余额或状态根不一致

这是发现**共识不匹配**、**解析器歧义**和**规范与实现偏差**的实用方法，而纯粹的崩溃 fuzzing 往往无法发现这些问题。

### 重用 campaign corpus 生成覆盖率报告

campaign 结束后，重放保存的队列 corpus，即可生成 Go 覆盖率报告，无需手动导出单独的 corpus。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

从**同一个 package**运行命令，并使用**相同的 `-fuzz` 目标**，这样 gosentry 才能解析正确的缓存 campaign 状态。



## References

- [1] [变异语法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [深入了解 AFL++ Fuzzing](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [五年后的 AFLNet：关于覆盖率引导的协议 Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing 缺少一半工具。我们 fork 了工具链来修复这个问题。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：使用快照对有状态网络协议进行快速 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [没有语法也没问题：探索无需系统调用描述的 Linux 内核 Fuzzing](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应和可变快照实现高效 Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 插桩：路径和调用者覆盖率](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [预测式上下文敏感 Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 构建和回归种子文档](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
