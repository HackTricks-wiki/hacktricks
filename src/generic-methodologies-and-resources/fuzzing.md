# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## 变异式语法 Fuzzing：覆盖率与语义

在**变异式语法 Fuzzing**中，输入会在保持**语法有效**的前提下进行变异。在 coverage-guided 模式下，只有触发**新覆盖率**的样本才会被保存为 corpus seeds。对于**语言类目标**（解析器、解释器、引擎），这种方式可能会漏掉需要**语义/数据流链**的 bug，也就是一个构造的输出成为另一个构造的输入。<sup>[[1]](#references)</sup>

**失败模式：**fuzzer 找到的 seeds 分别触发了 `document()` 和 `generate-id()`（或类似原语），但**没有保留链式数据流**，因此“更接近 bug”的样本会因为没有增加覆盖率而被丢弃。存在 **3 个以上相互依赖的步骤**时，随机重组的成本会很高，覆盖率反馈也无法引导搜索。<sup>[[1]](#references)</sup>

**启示：**对于依赖关系密集的语法，可以考虑**结合变异式和生成式阶段**，或让生成过程偏向**函数链式调用**模式（而不只是关注覆盖率）。<sup>[[1]](#references)</sup>

## Corpus 多样性的陷阱

Coverage-guided mutation 是**贪婪的**：一旦样本带来新覆盖率，就会立即保存，且通常保留大量未变更区域。随着时间推移，corpora 会变成结构多样性较低的**近似重复样本**。激进的最小化可能会移除有用上下文，因此一种实用的折中方案是采用**语法感知的最小化**，并在达到最小 token 阈值后**停止**（减少噪声，同时保留足够的周边结构，让变异仍然有效）。<sup>[[1]](#references)</sup>

变异式 fuzzing 的一条实用 corpus 规则是：**优先选择一小组结构各异且能最大化覆盖率的 seeds，而不是堆积大量近似重复样本**。实际操作中，通常包括以下做法。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实样本**开始（公开 corpora、爬取的数据、捕获的流量、目标生态中的文件集）。
- 使用**基于覆盖率的 corpus 最小化**来提炼样本，而不是保留每个有效样本。
- 让 seeds **足够小**，使变异落在有意义的字段上，而不是把大多数 cycles 浪费在无关字节上。
- 在 harness/instrumentation 发生重大变化后，重新运行 corpus 最小化，因为 reachability 变化时，“最佳” corpus 也会变化。

## 针对魔数值的比较感知变异

fuzzer 遇到瓶颈的一个常见原因不是语法，而是**严格比较**：魔数字节、长度检查、枚举字符串、校验和，或由 `memcmp`、switch 表或级联比较保护的解析器分发值。纯随机变异会浪费 cycles，逐字节猜测这些值。

对于这类目标，可以使用**比较追踪**（例如 AFL++ `CMPLOG` / Redqueen 风格的工作流），让 fuzzer 观察失败比较的操作数，并引导变异向满足比较条件的值靠拢。<sup>[[3]](#references)</sup>

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

- 当目标将深层逻辑隐藏在 **文件签名**、**协议动词**、**类型标签** 或 **依赖版本的功能位** 后面时，这种方法尤其有用。
- 配合从真实样本、协议规范或调试日志中提取的**字典**使用。包含语法令牌、块名称、动词和分隔符的小型字典，往往比庞大的通用词表更有价值。
- 如果目标会执行许多连续检查，先解决最早出现的“魔数”比较，然后再次精简生成的语料库，让后续阶段从已经有效的前缀开始。

## Fuzzing 隐藏文件名语言的文件 API

名为 `filename`、`path` 或 `URL` 的参数可能是解释器入口，而非字面意义上的文件查找。例如，CFITSIO Extended Filename Syntax (EFS) 会在返回打开的对象前，先解析括号中的选择器、行/像素表达式、计算列、直方图和转换；某些形式还会创建临时副本。在攻击面映射期间，将每个打开/导入 API 分类为**字面路径**或**解释路径**，然后对应用实际调用的生产入口进行 fuzzing。<sup>[[20]](#references)[[22]](#references)</sup>

有关由此产生的 SSRF、文件复制和协议处理程序原语，以及更安全的字面路径 API，请参阅 [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)。<sup>[[20]](#references)</sup>

### 将底层对象与被 fuzz 的程序分开

当语法位于文件名后缀中时，只修改被引用文件的字节会错过解析器。一个小型 harness 可以改为将单个测试用例读作字符串，并将其传给解释型打开 API；CFITSIO 测试活动通过以只读模式调用 `fits_open_file()`，触达了大多数 EFS 解析器和求值器。单独保留有效的底层文件，这样变异就能集中在选择器/表达式语言上，而不必反复破坏基础路径。<sup>[[22]](#references)</sup>

使用能够分别触达不同语法族的种子，然后结合规范和词法分析器/解析器源码生成精简字典。如果覆盖率停滞，且输入反复在同一语法错误路径中失败，就保留有效前缀，并添加分隔符、运算符、关键字、函数名和有代表性的字段名，而不是只增加随机变异的时间。<sup>[[22]](#references)</sup>

例如，使用语法字典运行 harness：<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 限制“只读”harness 的副作用

只读库标志并不能保证 testcase 不产生副作用：文件名语言可能会重写输入、创建输出文件或实例化临时对象。CFITSIO 测试活动最初破坏了种子文件，并在文件系统各处留下意外文件，因此必须进行清理和隔离。<sup>[[22]](#references)</sup>

- 为每个 worker 分配一个可丢弃的工作目录和独立的临时目录。
- 只公开规范底层文件的副本；绝不让目标程序修改唯一的 corpus 副本。
- 除非远程后端是目标，否则禁用网络访问；并使用容器、mount namespace 或等效沙箱限制可写路径。
- 每次执行或每批 worker 执行后重置目录，并将意外的文件系统更改视为额外发现。

### Crash-to-patch-to-fuzz 循环

修复前先对 crash 进行聚类，避免数千个 artifacts 变成数千项 patch 任务。在 CFITSIO 评估中，AFLTriage 将初始 crash 集合缩减到少数几个根本原因；后续 advisory 展示了不同的故障，包括目标大小检查错误、`realloc()` 后指针失效、算术故障，以及不安全的 parser 清理路径。<sup>[[21]](#references)[[22]](#references)</sup>

1. 为每个 cluster 精简一个代表性输入，并使用 AddressSanitizer 重现问题。
2. 记录导致不变量失效的具体访问、源码位置、分配/释放历史，以及 parser 状态。
3. 应用一个范围严格受限的候选 patch，并使用相同的 coverage 和 sanitizer instrumentation 重新构建。
4. 重放原始 reproducer **以及该 cluster 中的每个输入**；同时启用 leak 检测，因为内存安全修复可能会破坏错误路径上的所有权处理。
5. 使用真实文件运行功能测试，然后从累积的 queue 继续（如果引擎在二进制文件变更后要求使用新的输出目录，则重新导入该 queue）。
6. 重复此过程：移除第一个浅层 crash，往往能让现有种子进入更深层的 parser 状态。

向 LLM 提供崩溃输入、sanitizer 报告、harness 和相关源码后，它可以加快步骤 2，并起草步骤 3，但其 patch 仍不可信。是否接受修复，应由 sanitizer 重放和回归检查决定，而不是由模型的解释决定。<sup>[[22]](#references)</sup>

## 当 Edge Coverage 合并了不同路径时，提供更丰富的反馈

常规 edge coverage 无法区分两种执行：它们经过同一个 helper，但调用者不同，或在函数内采取了不同的分支组合。这在共享 decoder、协议 dispatcher 和 interpreter helper 中尤为重要，因为到达某条 edge 的**路径**决定了当前状态。天真地跟踪每个调用上下文也很危险：coverage map 和 queue 可能会急剧膨胀。因此，context-sensitive fuzzing 研究建议只细化有潜力的上下文，而不是让整个调用图都具备上下文敏感性。<sup>[[14]](#references)</sup>

近期 AFL++ 版本除常规 edge coverage 外，还提供**按函数统计的 Ball-Larus 路径覆盖率**。它会为函数内每条无环路径分配一个 feature；循环回边会被移除，因此这种反馈能区分分支组合，但**不能区分循环迭代次数**。从较宽松的级别 `1` 开始，然后只对可疑的 parser/state-machine 代码启用更严格的模式，因为路径数量可能呈指数增长。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

对于一个在许多与安全相关的位置被调用的辅助函数，LTO 模式可以将每条函数路径与其直接调用点结合起来：<sup>[[13]](#references)</sup>

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

**Campaign guidance：**谨慎使用更丰富的反馈，并监控其 coverage map/queue 开销。<sup>[[13]](#references)[[14]](#references)</sup>

- 并行运行一个普通的 edge-coverage 实例；只有在额外的 queue/map 开销不会导致每秒执行次数大幅下降时，更丰富的反馈才有用。
- 当大型模板库或通用工具代码占据 map 的主要部分时，使用 `AFL_LLVM_ALLOWLIST` 限制 path/caller instrumentation。
- AFL++ 可以跳过无环路径过多的函数；编译期间出现警告，说明目标需要使用 allowlist 或采用较宽松的级别。
- Caller + path coverage 仅支持一个 caller 深度。不要将其与更深的 context stack 结合使用。
- Path ID 可能会因 LLVM major version 改变。在整个 campaign 中固定 toolchain；不要把基于 PATH 的语料库同步到不同构建版本，并假定其 feature ID 稳定。
- 这种反馈可补充 `CMPLOG`：comparison tracing 用于解决**什么值能通过 guard**，而 path/caller feedback 则保留**通过哪条路径和分支组合到达目标**。

## Stateful Fuzzing：序列就是 Seeds

对于**协议**、**认证工作流**和**多阶段解析器**，有趣的测试单元往往不是单个 blob，而是一个**消息序列**。把整个交互记录拼接成一个文件再盲目变异通常效率低下，因为 fuzzer 会同等地变异每一步，即使只有后续消息才能触及脆弱状态。<sup>[[4]](#references)</sup>

更有效的模式是将**序列本身视为 seed**，并将**可观测状态**（响应码、协议状态、解析器阶段、返回的对象类型）用作额外反馈。<sup>[[4]](#references)</sup>

- 保持**有效的前缀消息**不变，将变异重点放在**驱动状态转换**的消息上。
- 如果后续步骤依赖先前响应中的标识符和服务器生成的值，就缓存这些值。
- 优先按消息进行变异/拼接，而不是把整个序列化交互记录当作不透明 blob 来变异。
- 如果协议会返回有意义的响应码，就将其用作**低成本状态 oracle**，优先处理能深入推进的序列。

这也是认证漏洞、隐藏状态转换或“仅在握手后出现”的解析器漏洞常被普通文件式 fuzzing 漏掉的原因：fuzzer 必须保留**顺序、状态和依赖关系**，而不只是结构。<sup>[[4]](#references)</sup>

### Android Binder：多客户端驱动程序 fuzzing

高 edge coverage 仍可能漏掉 IPC 驱动程序漏洞，因为 coverage 无法描述**对象所有权、引用计数、待处理消息、清理顺序或线程交错**。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 页面介绍了驱动程序对象模型；本例重点介绍 fuzzer harness。Android Binder 是一个很好的模型：如果 fuzzer 无法按所需顺序让多个进程操作同一个内核对象，那么仅触及分配和释放路径并不足够。<sup>[[15]](#references)</sup>

#### 对协议建模，而非孤立的 `ioctl` 缓冲区

将测试用例表示为一个有序语法：**客户端标识 + 操作 + 结构化参数**。Binder LKL fuzzer 使用 protobuf 和 `libprotobuf-mutator`，包含一个持久化的 context-manager 客户端和两个普通客户端。语义 harness 能保留盲目字节变异会破坏的关系。<sup>[[15]](#references)</sup>

- 缓存先前操作返回的值。例如，`BC_FREE_BUFFER` 必须复用先前 `ioctl` 返回的 transaction-buffer 指针。
- 生成有效的默认回复，以便同步 transaction 能够完成，后续操作也仍可触达。
- 拒绝不可能的状态转换，例如 self-transaction，或向同一目标发起多个待处理 transaction。
- 将单例 bootstrap 状态保留在每次输入的重置操作之外。Binder 每次启动只允许注册一次 `BINDER_SET_CONTEXT_MGR`，因此反复销毁并重建该客户端会导致后续输入无效。

一个实用的生命周期竞态模板是：让一个客户端传递对象、启动线程或进程清理，同时让接收客户端释放 transaction buffer。在 CVE-2020-0423 示例中，`BINDER_TYPE_WEAK_BINDER` 传递后，`BINDER_THREAD_EXIT` 与 `BC_FREE_BUFFER` 发生竞态，可能在退出线程的清理路径仍在使用嵌入式 `binder_work` 时将其释放。<sup>[[15]](#references)</sup>

#### 在 userspace kernel 中重新引入受控交错

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) 将真实内核代码链接到 userspace harness 中，并通过 `lkl_syscall` 暴露其 syscall 接口。这样便于在一个进程中协调 protobuf 状态、coverage 和 KASAN。不过，LKL 通常会运行 syscall，且期间不会被另一个内核线程中断。对于 race campaign，可在选定的 lock/unlock 和生命周期边界周围插入 `schedule()` 点，然后让 harness 在每次让出执行权时随机选择下一个客户端。这些点应有针对性，因为每增加一个点都会扩大调度搜索空间。研究人员描述的随机调度器**并不属于上游 Binder fuzzer**。<sup>[[15]](#references)</sup>

#### 构建并重放序列化回归 seeds

上游 harness 固定使用兼容的 `libprotobuf-mutator`，通过 `LKL_FUZZING=1` 启用 LKL fuzzing instrumentation 和 KASAN，并通过 `MMU=1` 为 Binder 启用 `CONFIG_MMU`。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

在检出一个特意保留漏洞的版本，或应用上游文档中记载的回滚补丁后，序列化种子即可重现整个多客户端状态转换，无需临时编写 C 概念验证程序：<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

将 resulting KASAN use-after-free 视为 seed 已到达易受攻击的生命周期路径的确认。这**并不能**证明后续实现 kernel code execution 或 privilege escalation 所需的 primitives。<sup>[[16]](#references)</sup>

## 单机多样性技巧（Jackalope 风格）

一种实用方法是：让短生命周期的 worker 针对持久化 server 运行，以此结合**生成新颖性**与**覆盖率复用**。每个 worker 从空 corpus 开始，运行 `T` 秒后同步，再基于合并后的 corpus 运行 `T` 秒，再次同步，然后退出。这样可以在利用累积覆盖率的同时，**在每一代生成全新的结构**。<sup>[[1]](#references)[[2]](#references)</sup>

**Server：**

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

**说明：**

- `-in empty` 会在每次生成时强制使用**全新语料库**。
- `-server_update_interval T` 可近似模拟**延迟同步**（先探索新颖输入，之后再复用）。
- 在 grammar fuzzing 模式下，默认会跳过**初始服务器同步**（无需使用 `-skip_initial_server_sync`）。
- 最佳 `T` 取决于**目标**；通常在 worker 找到大部分“容易获得”的覆盖率后再切换，效果最好。

## Snapshot Fuzzing：针对难以搭建 harness 的目标

当你要测试的代码只有在付出大量初始化成本后才可访问时（启动 VM、完成登录、接收数据包、解析容器、初始化服务），**snapshot fuzzing** 是一种实用的替代方案：捕获已就绪的进程或 VM 状态，将每个测试用例注入目标输入路径，执行至崩溃/超时，然后恢复快照。这样可以避免重复初始化或协议前缀，适用于**网络服务**、**固件**、**认证后的攻击面**和**仅有二进制文件的目标**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到进入所需状态。
2. 在此时对**内存 + 寄存器**进行快照。
3. 对每个测试用例，将变异后的输入直接写入相关的 guest/process 缓冲区。
4. 执行至崩溃/超时/重置。
5. 恢复快照；对于 VM 目标，如果支持，则只恢复**脏页**，然后重复。

尽可能将快照放在第一个耗时的解析/分发步骤之前，例如 `recv`/`read` 之后或数据包反序列化的位置，并记录目标使用的输入缓冲区。这遵循自适应放置原则：将快照点移至输入处理流程的更深处，以避免重复工作。<sup>[[11]](#references)</sup>

## 使用 MAccConc 探索 Linux 内核竞态

[MAccConc](https://github.com/googleprojectzero/MAccConc) 可将时序敏感的 Linux 内核竞态转换为可重复的内存访问调度。它可以自动枚举两个上下文的 **A-B-A** 执行，也允许分析人员在终端 UI/GUI 中施加顺序约束。它属于实验性研究工具，而非完整的并发 fuzzer：目前需要 LLVM 23+ 和项目打过补丁的内核，命令行工具支持两个测试线程，而提议中的 userspace fuzzing 层尚未实现。<sup>[[17]](#references)[[18]](#references)</sup>

### 收集跨上下文通信点

使用 KASAN outline callbacks 和打过补丁的 KCOV memory-record 支持来构建插桩内核。项目 README 还建议禁用 sibling-call optimization，以便保留可用的调用栈。<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

KASAN outline 模式（`asan-instrumentation-with-call-threshold=0`）会将插桩访问转换为 helper 调用。MAccConc kernel 补丁会禁用 `asan-opt-same-temp`，避免合并连续访问；当必须观察到全局变量竞态时，也要禁用 `asan-opt-globals` 优化。KCOV 会将生成的记录传递到 userspace。比较不同执行上下文中的访问，并保留字节范围重叠且至少一方执行写操作的访问对；将 `kfree()` 视为写操作，以便也能将生命周期转换列为候选项。<sup>[[17]](#references)</sup>

对于脱离发起任务执行的工作，例如数据包处理或 RCU 回调，子系统必须传递 KCOV remote-coverage handle。上游 remote KCOV 需要显式启用，且不会自动用于任意后台工作，因此，未传递 handle 可能导致真实交互无法被观察到。<sup>[[17]](#references)[[19]](#references)</sup>

### 在每次运行中识别相同的动态访问

不要使用具体的 heap 地址进行重放，因为每次分配后地址都可能变化；也不要只使用指令地址，因为在 `memcpy()` 和 `spin_lock()` 等 helper 中，指令地址可能有歧义。MAccConc 使用**计数增强型调用栈**：每个栈帧标识一个被调用函数及其在调用者中的调用次数，最后一个元素则标识内存访问指令。SanitizerCoverage 的函数进入/退出记录让 userspace 能够重建这个动态标识符；即使地址变化或出现无关的控制流噪声，该标识符仍保持稳定。<sup>[[17]](#references)</sup>

### 将候选访问对转换为强制调度

经过补丁修改的 `KCOV_SET_DI` ioctl 会将计数增强型访问标识符与 shared-flag 操作关联起来。<sup>[[17]](#references)</sup>

| 操作 | 语义 |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 在选定访问之前立即设置标志 *N*。 |
| `DI_STACK_WAIT` | 在选定访问之前，持续等待标志 *N* 被设置，或直到配置的等待上限耗尽。 |
| `DI_STACK_WAKE_POST` | 在选定访问之后立即设置标志 *N*。 |

对于部分 **A-happens-before-B** 约束，在 A 上设置 `DI_STACK_WAKE_POST`，并在 B 上设置 `DI_STACK_WAIT`，两者使用同一个标志。对于完全指定的双上下文调度，先阻塞 B，然后让 A 唤醒 B，并在第一个交接点等待；B 在下一个交接点执行反向操作。后者类似于确定性上下文切换，也是自动 A-B-A 探索器使用的方式。<sup>[[17]](#references)</sup>

最小化测试流程是：将四个 hook 的测试用例（`test_setup`、两个线程函数和 `test_end`）编译为共享库，收集不带约束的跟踪记录，然后枚举 A-B-A 候选项，或在可疑访问周围添加手动约束。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

将超时与成功的重排区分开来：请求的顺序可能无法实现，因为锁或初始化/发布依赖会阻止第二个上下文到达其注入点。还要牢记 KASAN 的盲区：除非直接栈访问可能越界，否则通常不会被 hook；默认优化下会省略全局变量；而且当前编译器无法同时生成 ASAN 和 TSAN hooks。最后，原型在 guest panic 时会丢失其 KCOV 缓冲区，因此请保留独立的 crash console/oracle。<sup>[[17]](#references)</sup>

对于未来由并发引导的 fuzzing，可以记录每个输入或 syscall 的内存访问摘要，配对可能形成跨上下文通信点的操作，然后只探索这些组合。VM snapshots 可稳定全局状态和地址；如果没有 snapshots，则可使用分配点元数据在多次运行中抽象对象。这是一项拟议的扩展，并非当前 MAccConc userspace 工具的功能。<sup>[[17]](#references)</sup>

## Harness Introspection：尽早发现浅层 fuzzer

当 campaign 停滞时，问题往往不在 mutator，而在 **harness**。使用 **可达性/覆盖率自省**，找出从 fuzz target 静态可达、但在动态运行中很少或从未覆盖的函数。这类函数通常表明存在以下三种问题之一。<sup>[[12]](#references)</sup>

- harness 进入 target 的时机太早或太晚。
- seed corpus 缺少整个功能类别。
- target 实际上需要**第二个 harness**，而不是一个臃肿的“包办一切” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以将静态可达性与运行时覆盖率进行比较，并根据定时运行或公开 corpus 生成报告。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

使用报告来决定：是否为尚未测试的 parser 路径新增 harness、针对某项特性扩充 corpus，或将单体 harness 拆分为更小的入口点。

## 基于图的 Fuzz 目标选择与变异测试分类

如果你已有**静态分析结果**、**变异测试存活项**和**覆盖率报告**，不要把它们当作彼此独立的列表来分类。先构建**调用图**，为节点标注**圈复杂度**、**入口点/不可信输入可达性**以及任何外部发现，然后提出图相关问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从不可信输入到达？
- 哪些变异测试存活项位于从 parser/handler 到安全关键代码的路径上？
- 哪些函数是架构上的瓶颈点，且具有异常大的**影响范围**？

这通常能找出比单看“覆盖率最低”更好的 fuzz 目标。一个**复杂度高**且已确认**可从外部到达**的 parser/decoder，比一个覆盖率低但没有攻击者可控路径的孤立内部 helper 更适合作为 harness 候选。

### 实用分类工作流

1. 根据代码库构建**代码图**，并提取每个函数的复杂度/分支指标。
2. 枚举接受攻击者可控输入的**入口点**：request handler、decoder、importer、protocol parser、CLI/file reader。
3. 从这些入口点运行路径查询，筛出候选函数，以区分可达的攻击面与死代码/仅内部可达代码。
4. 优先处理满足以下条件的节点：
   - **圈复杂度**高
   - 已确认**可从不可信输入到达**
   - **影响范围**大，或有许多下游依赖项
   - 有佐证，例如 **SARIF** 发现、审计记录或变异测试存活项
5. 优先为得分最高的节点编写有针对性的 harness，尤其是 **parser/codec**，例如 hex/Base64/IP/message decoder。

### 变异测试存活项：等价还是可操作

变异测试通常会产生嘈杂的存活项列表。在将每个存活项都视为安全缺陷之前，先借助图来判断：

- 被变异的函数是否可从攻击者可控的入口点到达？
- 所有调用路径是否都受比被变异检查更强的不变量约束？
- 该节点是否位于死代码、纯格式处理逻辑，还是高影响的算术/parser 路径中？

仍不可达或受结构性约束的存活项通常属于**等价变异体**。仍然**可达**且涉及**边界条件**、**溢出/进位路径**或**安全关键算术/解析**的存活项，应提升为：

- 新的 fuzz harness
- 直接的属性/不变量测试
- 有针对性的边界情况向量

### 将外部发现关联到图上

如果你的 SAST 流水线导出 **SARIF**，可按**文件 + 行范围**将发现投影到图节点上，再利用图扩展影响范围。<sup>[[6]](#references)</sup>

- 计算被标记函数的**影响范围**
- 检查该发现是否位于任何从入口点出发的路径上
- 将附近的发现聚类，找出最终汇聚到同一瓶颈点的情况

这有助于决定是否值得在某个特定函数上投入 fuzzing 时间：一个**可达**、**复杂**且已有 **SAST 命中**的节点，通常比一个仅仅复杂、但没有攻击者可达路径的节点更值得测试。

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

重要的方法论在于三者的交集：**复杂度 x 暴露面 x 影响**。使用图表选择预期安全价值最高的 fuzz targets，再根据未被变异淘汰的样本，确定 harness 必须重点测试哪些边界和不变量。<sup>[[5]](#references)</sup>

## 加密密钥编码的 Differential fuzzing

从有效的序列化密钥或标准测试向量开始。在不破坏长度和结构、确保能够进入导入和操作路径的前提下，变异编码字段，然后将相同字节提交给相互独立的实现。比较它们是否接受输入以及返回的错误。对于随机化签名和密文，需要使用正确性预言机，而不是逐字节比较：验证签名，或比较封装/解封装往返过程中的共享密钥。测试向量用于确认已知用例是否符合标准；差分变异则用于探测超出这些用例范围的格式错误编码。<sup>[[23]](#references)[[26]](#references)</sup>

针对这些密钥格式，使用特定格式的预言机：<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA 扩展签名密钥：**在保持密钥可解析的同时，将打包后的 `s1` 或 `s2` 系数变异到 `[-η, η]` 范围之外。检查导入或签名操作是否拒绝该密钥，以及生成的签名是否能通过验证。仅存在接受行为差异并不代表违反标准，因为 FIPS 204 并未强制要求额外的私钥检查。参见[条件泄漏机制](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)。
- **ML-KEM 密钥对：**将必需的封装密钥和解封装输入检查，与导入密钥对时可选的成对一致性检查（PCT）区分开来。使用公钥进行封装，再使用私钥进行解封装，并比较共享密钥；即使单个密钥通过了输入检查，共享密钥不匹配仍可能导致加密通信中断。检查 API 是在操作期间验证输入，还是通过单独的调用进行验证；libcrux 提供 `validate_public_key(pk)` 和 `validate_private_key(sk, ct)`，但它们不能取代 PCT。
- **XMSS/XMSSMT 原始密钥：**针对不同参数集，测试序列化的**签名和验证**密钥往返过程，而不只是使用内存中的密钥执行操作。XMSS 和 XMSSMT 使用独立的四字节 OID 命名空间，因此，如果 OID 专用解析器优先尝试 XMSS，可能会将 OID 冲突的 XMSSMT 密钥误判为 XMSS 密钥并拒绝导入。报告中提及的 RustCrypto 解析器展示的是互操作性/可用性故障，而非签名伪造。

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入和差分检查

如果 Go 目标已经有原生的 `testing.F` harness，一种实用的升级方式是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个分叉的 Go 工具链，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

当原生 Go fuzzer 在 **hard comparisons**、**typed inputs** 或 **parser-heavy formats** 上停滞时，这很有用。方法保持不变：

- 继续使用 `f.Add(...)` 添加 seeds，并使用 `f.Fuzz(...)` 设置回调函数。
- 复用相同的 harness，但使用 gosentry 的 `go` binary 而不是 stock toolchain 运行。
- 将生成的 campaign 视为常规的 coverage-guided run，但使用 LibAFL 的调度/变异机制和更完善的外围检测器。

### 将静默故障转化为 fuzz 发现

Go 评估中的一个常见问题是，危险行为通常默认**不会**导致崩溃。使用 gosentry，可以将多类“有问题但静默”的状态转化为发现项。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` 可将选定的日志/错误处理路径转化为类似崩溃的行为（适用于 `log.Fatal` 风格的代码路径，这类路径通常只记录日志并继续运行）。
- `--catch-races=true` 可使用 Go race detector 重放新发现的 queue entries。
- `--catch-leaks=true` 可使用 `goleak` 重放新的 queue entries，并在发现 goroutine 泄漏时停止。
- LibAFL 的 hang 处理机制会将 **无限循环 / 非常慢的输入**保留为 fuzz 发现项，而不是让它们作为超时消失。
- 默认内置算术溢出检查，并可通过 go-panikint 风格的插桩启用可选的截断检查。

对于安全影响表现为**不会触发 panic 的解析器故障**、**并发 bug** 或**仅导致 DoS 的挂起**，而非内存破坏的目标，这尤其有价值。

### 面向 Go 类型化 API 的 struct-aware fuzzing

原生 Go fuzzing 主要面向 `[]byte`、`string` 和数字等标量。如果被测代码使用类型化对象，gosentry 可以直接对**复合值**（struct、slice、array、pointer）进行 fuzzing，同时仍在底层变异字节。<sup>[[7]](#references)[[8]](#references)</sup>

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

在构建仅用于 fuzzing 的虚假 wire format 时，harness 专用的解析代码会掩盖逻辑 bug。对于 differential 或基于 grammar 的 campaign，请将 harness 输入保持为单个 `[]byte` 或 `string`，并在 callback 内解析。

### 用于 parser 和 protocol 输入的基于 grammar 的 fuzzing

对于 parser、格式和输入语言，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。grammar 是一个 JSON production rule 数组，harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法论说明：

- 当字节级变异大多在早期语法检查中失败时，使用 grammar mode。
- 将 grammar 限定在语言/协议中**与安全相关的子集**，而不是对完整规范建模。
- 在终结符/非终结符中使用较大的边界值，以测试整数、长度和状态机边界。
- grammar mode 会让输入保持语法有效，但目标仍会接收**字节/字符串**，因此解析和语义检查仍在被 harness 的代码中进行。

### Differential fuzzing：比较实现，而不只是崩溃

Go 生态系统中的一种有效模式是**基于 grammar 的 differential fuzzing**：生成有效的结构化输入，并将其传给两个解析器、客户端或状态转换引擎。<sup>[[7]](#references)[[8]](#references)</sup>

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

- 一个实现发生 panic，而另一个实现能正常拒绝输入
- 接受/拒绝输入的结果不一致
- 解析树或解码后的对象不同
- 状态转换、nonce、余额或状态根不一致

这是发现**共识不匹配**、**解析器歧义**和**规范与实现之间的偏差**的一种实用方法，而这些问题往往会被纯崩溃 fuzzing 遗漏。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 使用 campaign corpus 生成覆盖率报告

campaign 结束后，重新运行已保存的队列 corpus，即可生成 Go 覆盖率报告，无需手动导出单独的 corpus。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

从**同一个 package**运行命令，并使用**相同的 `-fuzz` target**，以便 gosentry 能解析正确的缓存 campaign 状态。

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [变异语法 Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing 深入解析](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [五年后的 AFLNet：关于覆盖率引导的协议 Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转化为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go Fuzzing 缺少了一半工具集。我们 fork 了工具链来解决这个问题。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：一种使用快照进行有状态网络协议 Fuzzing 的快速 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [没有语法也没问题：尝试在没有系统调用描述的情况下对 Linux 内核进行 Fuzzing](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应且可变的快照实现高效 Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 插桩：路径和调用者覆盖率](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [预测式上下文敏感 Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 构建和回归种子文档](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：通过受控的内存访问交错探索 Linux 内核竞争条件](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：用于 Fuzzing 的代码覆盖率](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 扩展文件名语法](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 安全公告：CFITSIO 2025 年第四季度](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [对 CFITSIO 扩展文件名语法进行 Fuzzing：16 个内存安全漏洞及 Codex 辅助分类](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [面向密码学的差分 Fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203：基于模格的密钥封装机制标准](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID 解析错误 - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [后量子密码实现现状](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
