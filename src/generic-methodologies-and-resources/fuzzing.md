# 模糊测试方法论

{{#include ../banners/hacktricks-training.md}}

## 变异式语法模糊测试：覆盖率与语义

在**变异式语法模糊测试**中，输入会在保持**语法有效**的前提下进行变异。在覆盖率引导模式下，只有触发**新覆盖率**的样本才会作为语料库种子保存。对于**语言类目标**（解析器、解释器、引擎），这种方式可能会漏掉需要**语义/数据流链**的漏洞，即一个构造的输出成为另一个构造的输入。<sup>[[1]](#references)</sup>

**失效模式：**fuzzer 找到的种子分别触发了 `document()` 和 `generate-id()`（或类似原语），但**没有保留链式数据流**，因此更接近漏洞的样本会因为没有增加覆盖率而被丢弃。当存在 **3 个以上相互依赖的步骤**时，随机重组会变得成本高昂，而覆盖率反馈也无法引导搜索。<sup>[[1]](#references)</sup>

**启示：**对于依赖关系繁重的语法，可以考虑**结合变异式与生成式阶段**，或让生成过程偏向**函数链式调用**模式（而不只关注覆盖率）。<sup>[[1]](#references)</sup>

## 语料库多样性陷阱

覆盖率引导的变异是**贪心的**：新覆盖率样本会立即保存，通常保留大量未修改的区域。随着时间推移，语料库会变成**结构多样性较低的近似重复样本**。过度精简可能会删除有用的上下文，因此一个实用的折中办法是采用**语法感知的精简**，并在达到最小 token 数阈值后**停止**（减少噪声，同时保留足够的周边结构，使其仍适合变异）。<sup>[[1]](#references)</sup>

变异式模糊测试的一条实用语料库准则是：相比一大堆近似重复样本，**优先选择一小组结构各异且能最大化覆盖率的种子**。实际上，这通常意味着以下几点。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实世界样本**开始（公开语料库、爬取内容、捕获的流量、目标生态系统中的文件集）。
- 使用**基于覆盖率的语料库精简**对其提炼，而不是保留每个有效样本。
- 保持种子**足够小**，使变异落在有意义的字段上，而不是把大部分周期耗费在无关字节上。
- 在 harness/插桩发生重大变化后，重新运行语料库精简，因为可达性发生变化时，“最佳”语料库也会随之变化。

## 针对魔数值的比较感知变异

fuzzer 陷入瓶颈的一个常见原因不是语法，而是**严格比较**：魔数字节、长度检查、枚举字符串、校验和，或由 `memcmp`、switch 表或级联比较保护的解析器分派值。纯随机变异会浪费大量周期，逐字节猜测这些值。

对于这类目标，可使用**比较跟踪**（例如 AFL++ `CMPLOG` / Redqueen 风格的工作流），让 fuzzer 观察失败比较中的操作数，并引导变异朝满足这些比较的值靠拢。<sup>[[3]](#references)</sup>

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

- 当目标将深层逻辑隐藏在 **file signatures**、**protocol verbs**、**type tags** 或 **version-dependent feature bits** 之后时，这种方法尤其有用。
- 将其与从真实样本、协议规范或调试日志中提取的**字典**配合使用。包含语法 token、块名称、动词和分隔符的小型字典，往往比庞大的通用词表更有价值。
- 如果目标会执行许多连续检查，先解决最早的“magic”比较，然后再次精简生成的语料库，让后续阶段从已经有效的前缀开始。

## 对隐藏文件名语言的文件 API 进行 Fuzzing

名为 `filename`、`path` 或 `URL` 的参数可能是解释器入口，而不是字面意义上的文件查找。例如，CFITSIO Extended Filename Syntax (EFS) 会在返回打开的对象之前，先处理方括号选择器、行/像素表达式、计算列、直方图和转换；某些形式还会创建临时副本。在攻击面映射期间，将每个打开/导入 API 分类为**字面路径**或**解释路径**，然后对应用实际调用的生产入口进行 fuzzing。<sup>[[20]](#references)[[22]](#references)</sup>

有关由此产生的 SSRF、文件复制和协议处理程序原语，以及更安全的字面路径 API，请参阅 [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)。<sup>[[20]](#references)</sup>

### 将底层对象与被 fuzz 的程序分开

当语法位于文件名后缀中时，只修改引用文件的字节会错过解析器。可以使用一个小型 harness，将每个 testcase 作为字符串读取，并传递给解释型 open API；CFITSIO 测试通过以只读模式调用 `fits_open_file()`，覆盖了大多数 EFS 解析器和求值器。单独准备有效的底层文件，让变异集中在选择器/表达式语言上，而不是不断破坏基础路径。<sup>[[22]](#references)</sup>

使用能够分别触达不同语法族的种子，然后根据规范和词法分析器/解析器源码生成精简的字典。如果覆盖率停滞，且输入反复在同一语法错误路径中失败，就保留有效前缀，并添加分隔符、运算符、关键字、函数名和有代表性的字段名，而不是只增加随机变异时间。<sup>[[22]](#references)</sup>

使用语法字典运行 harness，例如：<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 限制“只读” harness 的副作用

库的只读标志并不能保证测试用例不会产生副作用：文件名语法可能会重写输入、创建输出文件或实例化临时对象。CFITSIO 测试活动最初会销毁种子文件，并在文件系统中留下意外文件，因此必须进行清理和隔离。<sup>[[22]](#references)</sup>

- 为每个 worker 分配一个可丢弃的工作目录和专用临时目录。
- 只提供规范后端文件的副本；绝不能让目标程序修改语料库中的唯一副本。
- 除非远程后端是预期测试目标，否则禁用网络访问，并使用容器、mount namespace 或等效沙箱限制可写路径。
- 每次执行或每批 worker 执行后重置目录，并将意外的文件系统更改视为额外发现。

### Crash-to-patch-to-fuzz 循环

修复前先对崩溃进行聚类，以免数千个产物变成数千项修复任务。在 CFITSIO 评估中，AFLTriage 将初始崩溃集缩减为少数几个根本原因；由此产生的公告展示了多种不同故障，包括目标大小检查错误、`realloc()` 后的陈旧指针、算术错误，以及不安全的解析器清理路径。<sup>[[21]](#references)[[22]](#references)</sup>

1. 为每个集群精简一个代表性输入，并在 AddressSanitizer 下复现。
2. 记录导致不变量失效的具体访问、源码位置、分配/释放历史和解析器状态。
3. 应用一个范围严格限定的候选补丁，并使用相同的覆盖率和 sanitizer 插桩重新构建。
4. 重放原始复现输入和**集群中的每个输入**；同时启用 leak 检测，因为内存安全修复可能破坏错误路径上的所有权处理。
5. 使用真实文件运行功能测试，然后从累积的队列继续（如果引擎在二进制文件更改后要求使用全新的输出目录，则重新导入该队列）。
6. 重复此过程：移除第一个浅层崩溃后，现有种子往往能继续进入更深层的解析器状态。

向 LLM 提供崩溃输入、sanitizer 报告、harness 和相关源码后，它可以加快步骤 2 并起草步骤 3 的补丁，但该补丁仍不可信。是否接受修复，应由 sanitizer 重放和回归检查决定，而不是模型的解释。<sup>[[22]](#references)</sup>

## 当边覆盖率无法区分不同路径时提供更丰富的反馈

常规边覆盖率无法区分两种执行：它们通过不同调用者遍历同一个 helper，或在函数内部采用不同的分支组合。在共享解码器、协议分发器和解释器 helper 中，这一点很重要，因为通往某条边的**路径**决定了当前状态。天真地跟踪每个调用上下文也很危险：覆盖率映射和队列可能会急剧膨胀。因此，具有上下文敏感性的 fuzzing 研究建议仅细化有希望的上下文，而不是让整个调用图都具备上下文敏感性。<sup>[[14]](#references)</sup>

近期的 AFL++ 版本除了常规边覆盖率外，还提供 **Ball-Larus 函数级路径覆盖率**。它会为函数中每条无环路径分配一个特征；循环回边会被移除，因此这种反馈可以区分分支组合，但**不能区分循环迭代次数**。先从宽松级别 `1` 开始，然后仅对可疑的解析器/状态机代码启用更严格的模式，因为路径数量可能呈指数级增长。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

对于从许多安全相关位置调用的辅助函数，LTO 模式可以将每条函数路径与其直接调用点结合起来：<sup>[[13]](#references)</sup>

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

**Campaign guidance：**谨慎使用更丰富的反馈，并监控其覆盖率映射/队列开销。<sup>[[13]](#references)[[14]](#references)</sup>

- 并行运行一个普通的 edge-coverage 实例；只有额外的队列/映射开销不会导致每秒执行次数大幅下降时，更丰富的反馈才有用。
- 当大型模板库或通用工具代码主导映射时，使用 `AFL_LLVM_ALLOWLIST` 限制 path/caller instrumentation。
- 对于无环路径过多的函数，AFL++ 可以跳过；编译期间的警告表明目标需要设置 allowlist 或降低严格级别。
- Caller + path coverage 只支持一个 caller 深度。不要将其与更深的 context stack 结合使用。
- Path ID 可能会因 LLVM 主版本而变化。在整个 campaign 中固定工具链，不要将基于 PATH 的 corpus 跨不同构建同步，仿佛其 feature ID 是稳定的。
- 此反馈与 `CMPLOG` 互为补充：comparison tracing 可解决**什么值能通过 guard**，而 path/caller feedback 则保留**通过哪条路径以及哪种分支组合到达此处**。

## Stateful Fuzzing：序列即 Seed

对于**协议**、**经过身份验证的工作流**和**多阶段解析器**，有趣的单位往往不是单个 blob，而是一个**消息序列**。把整个交互记录串接到一个文件中并盲目变异通常效率低下，因为 fuzzer 会平等地变异每个步骤，即使只有后续消息能触及脆弱状态也是如此。<sup>[[4]](#references)</sup>

更有效的模式是将**序列本身视为 seed**，并将**可观测状态**（响应码、协议状态、解析器阶段、返回的对象类型）用作额外反馈。<sup>[[4]](#references)</sup>

- 保持**有效的前缀消息**稳定，并专注于变异**驱动状态转换**的消息。
- 如果后续步骤依赖先前响应中的标识符和服务器生成的值，就将其缓存。
- 优先采用逐消息变异/拼接，而不是把整个序列化交互记录当作不透明 blob 来变异。
- 如果协议提供有意义的响应码，就将其用作**低成本状态 oracle**，优先处理能推进到更深阶段的序列。

这也解释了为什么经过身份验证的 bug、隐藏状态转换或“仅在握手后出现”的解析器 bug 经常被 vanilla file-style fuzzing 漏掉：fuzzer 必须保留**顺序、状态和依赖关系**，而不仅仅是结构。<sup>[[4]](#references)</sup>

### Android Binder：多客户端驱动程序 fuzzing

高 edge coverage 仍可能漏掉 IPC 驱动程序 bug，因为覆盖率无法描述**对象所有权、引用计数、待处理消息、清理顺序或线程交错**。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md)页面介绍了驱动程序对象模型；此示例聚焦于 fuzzer harness。Android Binder 是一个很有用的模型：如果 fuzzer 无法按所需顺序让多个进程操作同一个内核对象，那么即使同时触及分配和释放路径也不够。<sup>[[15]](#references)</sup>

#### 对协议建模，而不是孤立的 `ioctl` 缓冲区

将测试用例表示为有序语法：**客户端身份 + 操作 + 结构化参数**。Binder LKL fuzzer 使用 protobuf 和 `libprotobuf-mutator`，包含一个持久化的 context-manager 客户端和两个普通客户端。随后，语义 harness 会保留盲目字节变异可能破坏的关联关系。<sup>[[15]](#references)</sup>

- 缓存先前操作返回的值。例如，`BC_FREE_BUFFER` 必须复用先前 `ioctl` 返回的 transaction-buffer 指针。
- 生成有效的默认回复，以便同步事务能够完成，并让后续操作仍可触达。
- 拒绝不可能的状态转换，例如自我事务，或向同一目标发起多个待处理事务。
- 将单例引导状态保留在每次输入重置之外。Binder 每次启动只允许一次 `BINDER_SET_CONTEXT_MGR` 注册，因此反复销毁并重新创建该客户端会导致后续输入无效。

一个有用的生命周期竞态模板是：让一个客户端传递对象，启动线程或进程清理，同时让接收客户端释放事务缓冲区。在 CVE-2020-0423 示例中，`BINDER_TYPE_WEAK_BINDER` 传递后，`BINDER_THREAD_EXIT` 与 `BC_FREE_BUFFER` 发生竞态，可能会释放嵌入的 `binder_work`，而退出线程的清理路径仍在使用它。<sup>[[15]](#references)</sup>

#### 在用户态内核中重新引入受控交错

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) 将真实内核代码链接到用户态 harness 中，并通过 `lkl_syscall` 暴露其系统调用接口。这使得 protobuf 状态、覆盖率和 KASAN 能够轻松地在一个进程中协调。不过，LKL 通常会在运行系统调用时避免被另一个内核线程中断。对于竞态 campaign，可在选定的锁/解锁和生命周期边界周围插入 `schedule()` 点，然后让 harness 在每次让出执行权时随机选择下一个客户端。应针对性地设置这些点，因为每个点都会扩大调度搜索空间。研究人员描述的随机调度器**并非**上游 Binder fuzzer 的一部分。<sup>[[15]](#references)</sup>

#### 构建并重放序列化回归 seed

上游 harness 固定使用兼容的 `libprotobuf-mutator`，通过 `LKL_FUZZING=1` 启用 LKL fuzzing instrumentation 和 KASAN，并通过 `MMU=1` 为 Binder 启用 `CONFIG_MMU`。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

在检出一个故意存在漏洞的版本，或应用上游文档中记录的回滚补丁后，序列化的 seed 就能重现整个多客户端状态转换，无需临时编写 C 概念验证程序：<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

将由此产生的 KASAN use-after-free 视为确认 seed 已到达易受攻击的生命周期路径。它**并不能**证明后续实现 kernel code execution 或 privilege escalation 所需的原语。<sup>[[16]](#references)</sup>

## 单机多样性技巧（Jackalope 风格）

一种实用的混合**生成式新颖性**与**coverage 复用**的方法，是让短生命周期的 worker 针对持久化 server 运行并定期重启。每个 worker 从空 corpus 开始，运行 `T` 秒后同步，再基于合并后的 corpus 运行 `T` 秒，再次同步，然后退出。这样，**每一代都能生成全新的结构**，同时仍可利用累积的 coverage。<sup>[[1]](#references)[[2]](#references)</sup>

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

**说明：**

- `-in empty` 会在每次生成时强制使用**全新的语料库**。
- `-server_update_interval T` 可近似模拟**延迟同步**（先发现新内容，之后再复用）。
- 在 grammar fuzzing 模式下，默认会跳过**初始服务器同步**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` **取决于目标**；通常在 worker 找到大部分“容易获得”的覆盖率后再切换效果最好。

## Snapshot Fuzzing：针对难以搭建测试环境的目标

如果要测试的代码只有在付出大量初始化成本后才可达（启动 VM、完成登录、接收数据包、解析容器、初始化服务），一种实用的替代方案是 **snapshot fuzzing**：捕获就绪状态下的进程或 VM 状态，将每个测试用例注入目标输入路径，执行直至崩溃/超时，然后恢复快照。这样无需重复初始化或协议前缀，适用于**网络服务**、**固件**、**认证后的攻击面**以及**仅有二进制的目标**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到进入所需状态。
2. 在该时刻对**内存和寄存器**进行快照。
3. 对每个测试用例，将变异后的输入直接写入相关的 guest/process 缓冲区。
4. 执行直到崩溃/超时/重置。
5. 恢复快照；对于 VM 目标，如果支持，则仅恢复**脏页**，然后重复。

尽可能将快照放在首次高成本解析/分发步骤附近，例如 `recv`/`read` 之后或数据包反序列化的位置，并记录目标使用的输入缓冲区。这遵循自适应放置原则：将快照向输入处理流程的深处移动，以避免重复执行已完成的工作。<sup>[[11]](#references)</sup>

## 使用 MAccConc 探索 Linux 内核竞态

[MAccConc](https://github.com/googleprojectzero/MAccConc) 可将对时序敏感的 Linux 内核竞态转换为可重复的内存访问调度。它可以自动枚举双上下文 **A-B-A** 执行序列，也可以让分析人员通过终端 UI/GUI 指定顺序约束。这是实验性的研究工具，而非完整的并发 fuzzer：目前需要 LLVM 23+ 和项目修补过的内核；命令行工具支持两个测试线程，而计划中的用户空间 fuzzing 层尚未实现。<sup>[[17]](#references)[[18]](#references)</sup>

### 收集跨上下文通信点

使用 KASAN outline callbacks 和修补过的 KCOV 内存记录支持构建插桩内核。项目 README 还建议禁用 sibling-call optimization，以便保留可用的调用栈。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）会将插桩访问转换为 helper 调用。MAccConc 内核补丁会禁用 `asan-opt-same-temp`，避免合并连续访问；当需要检测全局变量竞争时，也要禁用 `asan-opt-globals` 优化。KCOV 会将生成的记录传递到 userspace。比较不同执行上下文中的访问，并保留字节范围重叠且至少一方执行写操作的访问对；将 `kfree()` 建模为写操作，这样生命周期转换也会成为候选项。<sup>[[17]](#references)</sup>

对于脱离发起任务的工作（例如数据包处理或 RCU 回调），子系统必须传递 KCOV remote-coverage 句柄。上游的 remote KCOV 需要显式启用，不会自动覆盖任意后台工作，因此未传递句柄可能导致真实交互无法被检测到。<sup>[[17]](#references)[[19]](#references)</sup>

### 在每次运行中识别同一个动态访问

不要针对具体的堆地址重放，因为每次分配后地址都可能变化；也不要只针对指令地址，因为在 `memcpy()` 和 `spin_lock()` 等 helper 中，指令地址无法唯一标识访问。MAccConc 使用**计数增强型调用栈**：每个栈帧标识一个被调用函数，以及该函数在其调用者中的调用次数；最后一个元素标识内存访问指令。SanitizerCoverage 的函数进入/退出记录让 userspace 能够重建这个动态标识符；即使地址变化或出现无关的控制流扰动，该标识符仍保持稳定。<sup>[[17]](#references)</sup>

### 将候选访问对转换为强制调度

补丁版的 `KCOV_SET_DI` ioctl 会将计数增强型访问标识符与共享标志操作关联起来。<sup>[[17]](#references)</sup>

| 操作 | 语义 |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 在选定访问之前立即设置标志 *N*。 |
| `DI_STACK_WAIT` | 在选定访问之前自旋等待，直到标志 *N* 被设置或达到配置的时限。 |
| `DI_STACK_WAKE_POST` | 在选定访问之后立即设置标志 *N*。 |

要施加部分 **A-happens-before-B** 约束，请将 `DI_STACK_WAKE_POST` 关联到 A，并将 `DI_STACK_WAIT` 关联到 B，两者使用相同的标志。要指定完整的双上下文调度，先让 B 阻塞，然后让 A 唤醒 B，并在第一个交接点等待；B 在下一个交接点执行相反操作。后一种方式类似于确定性上下文切换，也是自动 A-B-A 探索器采用的方式。<sup>[[17]](#references)</sup>

一个最小化测试流程是：将包含四个钩子（`test_setup`、两个线程函数和 `test_end`）的测试用例编译为共享库，收集不受约束的跟踪记录，然后枚举 A-B-A 候选项，或在可疑访问附近添加手动约束。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

将超时与成功的重排区分开来：请求的顺序可能无法实现，因为锁或初始化/发布依赖关系会阻止第二个上下文到达其注入点。同时也要注意 KASAN 的盲点：除非直接栈访问可能越界，否则通常不会被 hook；默认优化下会省略全局变量；当前编译器无法同时生成 ASAN 和 TSAN hooks。最后，原型在 guest panic 时会丢失其 KCOV 缓冲区，因此请保留独立的 crash console/oracle。<sup>[[17]](#references)</sup>

对于未来由并发引导的 fuzzing，可以记录每个输入或 syscall 的内存访问摘要，配对可能形成跨上下文通信点的操作，然后只探索这些组合。VM 快照可以稳定全局状态和地址；没有快照时，可以通过分配点元数据在多次运行间抽象对象。这是一项拟议的扩展，并非当前 MAccConc userspace 工具的功能。<sup>[[17]](#references)</sup>

## Harness Introspection: 尽早发现浅层 Fuzzer

当 fuzzing 活动停滞时，问题往往不在 mutator，而在 **harness**。使用**可达性/覆盖率内省**，找出从 fuzz target 静态可达、但动态覆盖率很低或从未覆盖的函数。这些函数通常意味着以下三种问题之一。<sup>[[12]](#references)</sup>

- harness 进入 target 的时机过早或过晚。
- seed corpus 缺少一整类功能。
- target 实际上需要**第二个 harness**，而不是一个臃肿的“全能”harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以对比静态可达性与运行时覆盖率，并根据限时运行或公开 corpus 生成报告。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

使用报告来决定是为未测试的 parser 路径添加新的 harness、扩充特定功能的 corpus，还是将单体 harness 拆分为更小的入口。

## 基于调用图的 Fuzz 目标选择与变异分类

如果你已经有**静态分析发现**、**变异测试存活项**和**覆盖率报告**，不要将它们当作互不相关的列表来分类。先构建**调用图**，为节点标注**圈复杂度**、**入口点/不可信输入可达性**以及任何外部发现，然后针对图提出问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从不可信输入到达？
- 哪些变异存活项位于从 parser/handler 到安全关键代码的路径上？
- 哪些函数是架构上的瓶颈点，具有异常大的**影响范围**？

这通常比单看“最低覆盖率”能发现更好的 fuzz 目标。一个**复杂度高**且确认**可从外部到达**的 parser/decoder，比覆盖率较低但没有攻击者可控路径的孤立内部 helper 更适合作为 harness 目标。

### 实用分类流程

1. 从代码库构建**代码图**，并提取每个函数的复杂度/分支指标。
2. 列举接受攻击者可控输入的**入口点**：request handler、decoder、importer、协议 parser、CLI/文件读取器。
3. 从这些入口点执行**路径查询**，筛选候选函数，区分可达的攻击面与死代码/仅内部可达代码。
4. 优先处理同时具备以下特征的节点：
   - 高**圈复杂度**
   - 确认可从不可信输入**到达**
   - **影响范围**大或有许多下游依赖项
   - 有佐证，例如 **SARIF** 发现、审计备注或变异存活项
5. 优先为评分最高的节点编写有针对性的 harness，尤其是 **parser/codec**，例如 hex/Base64/IP/message decoder。

### 变异存活项：等价还是可操作

变异测试往往会产生嘈杂的存活项列表。在将每个存活项都视为安全缺陷之前，先用调用图检查：

- 变异后的函数是否可从攻击者可控的入口点到达？
- 所有调用路径是否都受比被变异检查更强的不变量约束？
- 该节点是否处于死代码、仅用于格式处理的逻辑，还是高影响的算术/parser 路径中？

仍不可达或受结构性约束的存活项通常是**等价变异体**。仍然**可达**且涉及**边界条件**、**溢出/进位路径**或**安全关键算术/解析**的存活项，应提升为：

- 新的 fuzz harness
- 直接的属性/不变量测试
- 有针对性的边界用例向量

### 将外部发现关联到图上

如果你的 SAST 流水线导出 **SARIF**，可按**文件 + 行范围**将发现投射到图节点上，并用调用图扩展影响范围。<sup>[[6]](#references)</sup>

- 计算被标记函数的**影响范围**
- 检查该发现是否位于任何从入口点出发的路径上
- 将附近且归并到同一瓶颈点的发现聚类

在决定是否为某个特定函数投入 fuzzing 时间时，这很有用：一个**可达**、**复杂**且已有 **SAST 命中**的节点，通常比一个仅仅复杂但没有攻击者可达路径的节点更值得优先测试。

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

重要的方法论是三者的交集：**复杂度 x 暴露面 x 影响**。利用图表挑选预期安全价值最高的 fuzz 目标，然后根据 mutation survivors 判断 harness 必须重点测试哪些边界和不变量。<sup>[[5]](#references)</sup>

## 使用 gosentry 进行 Go Fuzzing：更强大的引擎、类型化输入与差分检查

如果 Go 目标已经有原生的 `testing.F` harness，一个实用的升级路径是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个分叉的 Go 工具链，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

当原生 Go fuzzer 卡在**难以满足的比较**、**类型化输入**或**解析器密集型格式**上时，这种方法很有用。整体方法不变：

- 继续使用 `f.Add(...)` 添加种子，并使用 `f.Fuzz(...)` 设置回调。
- 复用相同的 harness，但使用 gosentry 的 `go` 二进制文件运行，而不是使用标准工具链。
- 将生成的 fuzz campaign 视为常规的 coverage-guided 运行，只是使用了 LibAFL 的调度/变异机制，以及更完善的周边检测器。

### 将静默失败转化为 fuzz 发现

Go 安全评估中反复遇到的一个问题是，危险行为通常**不会**默认导致崩溃。使用 gosentry，可以将几类“有问题但静默”的状态转化为发现项。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` 可让选定的日志/错误处理路径表现得像崩溃一样（适用于 `log.Fatal` 这类通常只记录日志并继续执行的代码路径）。
- `--catch-races=true` 可使用 Go race detector 重放新发现的队列条目。
- `--catch-leaks=true` 可使用 `goleak` 重放新队列条目，并在发现 goroutine 泄漏时停止。
- LibAFL 的 hang 处理机制会将**无限循环/极慢输入**保留为 fuzz 发现项，而不是让它们作为超时被忽略。
- 默认启用内置算术溢出检查，还可以通过 go-panikint 风格的插桩启用截断检查。

对于安全影响表现为**不会引发 panic 的解析器故障**、**并发 bug** 或**仅导致 DoS 的挂起**，而非内存破坏的目标，这尤其有价值。

### 面向类型化 Go API 的结构体感知 fuzzing

原生 Go fuzzing 主要面向 `[]byte`、`string` 和数字等标量。如果被测代码接收类型化对象，gosentry 可以直接 fuzz **复合值**（struct、slice、array、pointer），同时仍在底层变异字节。<sup>[[7]](#references)[[8]](#references)</sup>

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

仅仅为了 fuzzing 而构建虚假的 wire format，会让逻辑 bug 被仅存在于 harness 中的解析代码掩盖。对于 differential 或基于 grammar 的 fuzzing campaign，应将 harness 输入保持为单个 `[]byte` 或 `string`，并在 callback 内解析。

### 面向 parser 和 protocol 输入的基于 grammar 的 fuzzing

对于 parser、format 和输入语言，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。grammar 是一个 JSON production rule 数组，harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法论笔记：

- 如果字节级变异大多在早期语法检查中失败，请使用 grammar mode。
- 将语法限定在语言/协议中与安全相关的子集，而不是对完整规范建模。
- 在终结符/非终结符中使用较大的边界值，以触发整数、长度和状态机边界问题。
- grammar mode 会使输入保持语法有效，但目标仍会收到**字节/字符串**，因此解析和语义检查仍在经过 harness 的代码中进行。

### Differential fuzzing：比较实现，而不仅仅是崩溃

Go 生态中一种有效的模式是**基于语法的 differential fuzzing**：生成有效的结构化输入，并将其提供给两个解析器、客户端或状态转换引擎。<sup>[[7]](#references)[[8]](#references)</sup>

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
- 接受/拒绝输入不一致
- 解析树或解码后的对象不同
- 状态转换、nonce、余额或状态根出现分歧

这是发现**共识不一致**、**解析器歧义**以及**规范与实现偏差**的实用方法，而纯粹的崩溃 fuzzing 往往会漏掉这些问题。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 复用 campaign corpus 生成覆盖率报告

campaign 结束后，重新运行已保存的队列 corpus，即可生成 Go 覆盖率报告，无需手动导出单独的 corpus。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

从**同一个 package** 运行命令，并使用**相同的 `-fuzz` target**，这样 gosentry 才能解析正确的缓存 campaign 状态。



## References

- [1] [变异语法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing 深入解析](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [五年后的 AFLNet：基于覆盖率引导的协议 fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing 缺少一半工具包。我们 fork 了工具链来修复它。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：一种使用快照对有状态网络协议进行快速 Greybox Fuzzer 的方法](https://arxiv.org/abs/2202.03643)
- [10] [没有语法？没问题：尝试在没有系统调用描述的情况下对 Linux 内核进行 fuzzing](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应和可变快照实现高效 fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 插桩：路径和调用者覆盖率](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [预测式上下文敏感 fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 构建和回归种子文档](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：通过受控内存访问交错探索 Linux 内核竞态条件](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：用于 fuzzing 的代码覆盖率](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 扩展文件名语法](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 公告：CFITSIO 2025 年第四季度](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [对 CFITSIO 扩展文件名语法进行 fuzzing：16 个内存安全漏洞及 Codex 辅助分诊](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
