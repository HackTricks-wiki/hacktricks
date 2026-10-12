# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing：Coverage 与语义

在 **mutational grammar fuzzing** 中，输入会在保持 **grammar-valid** 的前提下进行变异。在 coverage-guided 模式下，只有触发 **new coverage** 的样本才会保存为 corpus seeds。对于**语言类目标**（parsers、interpreters、engines），这种方式可能会漏掉需要**语义/dataflow 链**的漏洞，即一个构造的输出成为另一个构造的输入。<sup>[[1]](#references)</sup>

**失败模式：**fuzzer 找到的 seeds 分别触发了 `document()` 和 `generate-id()`（或类似原语），但**没有保留链式 dataflow**，因此“更接近漏洞”的样本会被丢弃，因为它没有增加 coverage。当存在 **3 个以上相互依赖的步骤**时，随机重组的成本会变高，而 coverage 反馈也无法引导搜索。<sup>[[1]](#references)</sup>

**启示：**对于依赖关系复杂的 grammars，可以考虑**结合 mutational 和 generative 阶段**，或让生成过程倾向于**函数链式调用**模式（而不仅仅是 coverage）。<sup>[[1]](#references)</sup>

## Corpus 多样性的陷阱

Coverage-guided mutation 是**贪心的**：触发新 coverage 的样本会立即保存，且往往保留大量未变更区域。随着时间推移，corpora 会充斥**近似重复**的样本，结构多样性较低。过度 minimization 可能会移除有用的上下文，因此一种实用的折中方案是采用 **grammar-aware minimization**，并在达到最小 token 数量阈值后**停止**（减少噪声，同时保留足够的周边结构，使其仍便于 mutation）。<sup>[[1]](#references)</sup>

mutational fuzzing 的一条实用 corpus 规则是：**优先选择一小组结构各异、能最大化 coverage 的 seeds，而不是堆积大量近似重复样本**。在实践中，通常意味着以下几点。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实样本**入手（公开 corpora、爬取内容、捕获的流量、目标生态系统中的文件集合）。
- 使用**基于 coverage 的 corpus minimization**筛选这些样本，而不是保留所有有效样本。
- Seeds 应当**足够小**，确保 mutations 能作用于有意义的字段，而不是把大多数周期浪费在无关字节上。
- 在 harness/instrumentation 发生重大变更后，重新运行 corpus minimization，因为 reachability 改变时，“最佳” corpus 也会随之变化。

## 针对 Magic Values 的 Comparison-Aware Mutation

fuzzers 遇到瓶颈的一个常见原因不是语法，而是**严格比较**：magic bytes、长度检查、枚举字符串、checksums，或由 `memcmp`、switch tables 或级联比较保护的 parser dispatch 值。纯随机 mutation 会浪费周期，逐字节猜测这些值。

对于这类目标，应使用 **comparison tracing**（例如 AFL++ `CMPLOG` / Redqueen 风格的工作流），让 fuzzer 能够观察比较失败时的操作数，并将 mutations 引导至更可能满足比较条件的值。<sup>[[3]](#references)</sup>

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

- 当目标将深层逻辑隐藏在 **文件签名**、**协议动词**、**类型标签**或**依赖版本的功能位**之后时，这种方法尤其有用。
- 将其与从真实样本、协议规范或调试日志中提取的**字典**搭配使用。包含语法 token、块名称、动词和分隔符的小型字典，通常比庞大的通用词表更有价值。
- 如果目标会执行许多连续检查，先解决最早的“magic”比较，然后再次精简生成的语料库，让后续阶段从已验证的前缀开始。

## 当边覆盖将不同路径合并时获取更丰富的反馈

普通边覆盖无法区分两种执行：它们通过不同调用方经过同一个辅助函数，或在函数内部采用不同的分支组合。在共享解码器、协议分发器和解释器辅助函数中，这一点很重要，因为到达某条边的**路径**决定了当前状态。天真地跟踪每个调用上下文也很危险：覆盖映射和队列可能会急剧膨胀。因此，上下文敏感 fuzzing 研究建议只细化有希望的上下文，而不是将整个调用图都视为上下文敏感。<sup>[[14]](#references)</sup>

近期的 AFL++ 版本除了普通边覆盖，还提供**Ball-Larus 函数内路径覆盖**。它会为通过函数的每条无环路径分配一个特征；循环回边会被移除，因此这种反馈可以区分分支组合，但**无法区分循环迭代次数**。先从宽松级别 `1` 开始，然后仅对可疑的解析器/状态机代码启用更严格的模式，因为路径数量可能呈指数增长。<sup>[[13]](#references)</sup>

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

**Campaign guidance：**谨慎采用更丰富的反馈，并监控其覆盖率 map/队列成本。<sup>[[13]](#references)[[14]](#references)</sup>

- 并行运行一个普通的 edge-coverage 实例；只有在额外的队列/map 成本不会导致每秒执行次数大幅下降时，更丰富的反馈才有用。
- 如果大型模板库或通用工具代码占据 map 的主要部分，请使用 `AFL_LLVM_ALLOWLIST` 限制 path/caller instrumentation。
- AFL++ 可以跳过无环路径过多的函数；编译期间的警告表明目标需要 allowlisting 或较低的严格级别。
- Caller + path coverage 仅支持一个 caller 深度。不要将它与更深的 context stacks 结合使用。
- Path ID 可能会随 LLVM 主版本变化。整个 campaign 应固定工具链；不要把基于 PATH 的语料库同步起来，仿佛不同构建间的 feature ID 稳定不变。
- 这类反馈可以补充 `CMPLOG`：comparison tracing 用于解决**什么值能通过 guard**，而 path/caller feedback 则保留**哪条路径以及哪种分支组合抵达了这里**。

## 有状态 Fuzzing：序列就是种子

对于**协议**、**经过身份验证的工作流**和**多阶段解析器**，有趣的测试单元往往不是单个 blob，而是一个**消息序列**。将整个交互记录拼接到一个文件中再盲目变异通常效率不高，因为 fuzzer 会平均变异每一步，即使只有后续消息才能触达脆弱状态也是如此。<sup>[[4]](#references)</sup>

更有效的做法是将**序列本身视为种子**，并将**可观测状态**（响应码、协议状态、解析器阶段、返回的对象类型）作为额外反馈。<sup>[[4]](#references)</sup>

- 保持**有效的前缀消息**稳定，并将变异集中在**驱动状态转换**的消息上。
- 如果后续步骤依赖先前响应中的标识符和服务器生成的值，请缓存这些值。
- 优先逐条消息进行变异/拼接，而不是将整个序列化的交互记录当作不透明 blob 变异。
- 如果协议提供有意义的响应码，请将其用作**低成本状态 oracle**，优先处理能推进到更深状态的序列。

这也解释了为什么经过身份验证的漏洞、隐藏状态转换或“仅在握手后触发”的解析器漏洞经常被普通的文件式 fuzzing 遗漏：fuzzer 必须保留**顺序、状态和依赖关系**，而不仅仅是结构。<sup>[[4]](#references)</sup>

### Android Binder：多客户端驱动程序 fuzzing

高 edge coverage 仍可能遗漏 IPC 驱动程序漏洞，因为 coverage 无法描述**对象所有权、引用计数、待处理消息、清理顺序或线程交错**。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 页面介绍了驱动程序对象模型；本例重点介绍 fuzzer harness。Android Binder 是一个很有用的模型：如果 fuzzer 无法按所需顺序让多个进程操作同一个内核对象，那么仅仅触达分配和释放路径还不够。<sup>[[15]](#references)</sup>

#### 对协议建模，而不是处理孤立的 `ioctl` 缓冲区

将测试用例表示为一个有序语法，其中包含**客户端身份 + 操作 + 结构化参数**。Binder LKL fuzzer 使用 protobuf 和 `libprotobuf-mutator`，包含一个持久的 context-manager 客户端和两个普通客户端。语义 harness 会保留盲目字节变异可能破坏的关系。<sup>[[15]](#references)</sup>

- 缓存先前操作返回的值。例如，`BC_FREE_BUFFER` 必须重用先前 `ioctl` 返回的事务缓冲区指针。
- 生成有效的默认回复，使同步事务能够完成，并让后续操作仍可触达。
- 拒绝不可能的状态转换，例如向自身发起事务，或向同一目标发起多个待处理事务。
- 将单例引导状态保留在每次输入重置之外。Binder 每次启动只允许注册一个 `BINDER_SET_CONTEXT_MGR`，因此反复销毁并重建该客户端会使后续输入无效。

一种实用的生命周期竞态模板是：让一个客户端传递对象，启动线程或进程清理，同时让接收客户端释放事务缓冲区。在 CVE-2020-0423 示例中，`BINDER_TYPE_WEAK_BINDER` 传递后，`BINDER_THREAD_EXIT` 与 `BC_FREE_BUFFER` 发生竞态，可能释放内嵌的 `binder_work`，而退出线程的清理路径仍在使用它。<sup>[[15]](#references)</sup>

#### 在用户态内核中重新引入受控交错

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) 将真实内核代码链接到用户态 harness，并通过 `lkl_syscall` 暴露其系统调用接口。这样便于在同一进程中协调 protobuf 状态、coverage 和 KASAN。不过，LKL 通常会在运行一个系统调用时阻止其他内核线程中断它。对于竞态 campaign，可在选定的锁定/解锁和生命周期边界周围插入 `schedule()` 点，然后让 harness 在每次让出执行时随机选择下一个客户端。应将这些点限定在目标位置，因为每增加一个点都会扩大调度搜索空间。研究人员所描述的随机调度器**不属于**上游 Binder fuzzer。<sup>[[15]](#references)</sup>

#### 构建并重放序列化的回归种子

上游 harness 固定使用兼容的 `libprotobuf-mutator`，通过 `LKL_FUZZING=1` 启用 LKL fuzzing instrumentation 和 KASAN，并通过 `MMU=1` 为 Binder 启用 `CONFIG_MMU`。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

在检出一个故意存在漏洞的版本，或应用上游文档中记录的回滚补丁后，序列化的种子即可重现整个多客户端状态转换，无需通过临时编写的 C 概念验证来重建：<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

将由此产生的 KASAN use-after-free 视为 seed 已到达易受攻击的生命周期路径的确认。它**并不能**证明后续实现 kernel code execution 或 privilege escalation 所需的原语。<sup>[[16]](#references)</sup>

## 单机多样性技巧（Jackalope 风格）

一种将**生成式新颖性**与**覆盖率复用**结合的实用方法是：针对持久运行的 server 重启短生命周期的 worker。每个 worker 从空 corpus 开始，运行 `T` 秒后同步，再基于合并后的 corpus 运行 `T` 秒，然后再次同步并退出。这样每一代都会产生**新的结构**，同时仍能利用累积的覆盖率。<sup>[[1]](#references)[[2]](#references)</sup>

**服务器：**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**顺序工作进程（循环示例）：**

<details>
<summary>Jackalope 工作进程重启循环</summary>

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

- `-in empty` 会在每次生成时强制使用**全新的语料库**。
- `-server_update_interval T` 可近似模拟**延迟同步**（先发现新颖输入，之后再复用）。
- 在语法 fuzzing 模式下，默认会跳过**初始服务器同步**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` **取决于目标**；通常在 worker 找到大部分“容易获得”的覆盖率后再切换效果最好。

## 针对难以搭建测试环境的目标进行 Snapshot Fuzzing

如果要测试的代码只有在付出大量初始化成本后（启动 VM、完成登录、接收数据包、解析容器、初始化服务）才可访问，那么一种实用的替代方法是 **snapshot fuzzing**：捕获就绪状态下的进程或 VM 状态，将每个测试用例注入目标输入路径，执行至崩溃/超时，然后恢复快照。这样可以避免重复初始化或协议前缀，适用于**网络服务**、**固件**、**身份验证后的攻击面**和**仅有二进制文件的目标**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到进入所需状态。
2. 在此时对**内存 + 寄存器**创建快照。
3. 对每个测试用例，将变异后的输入直接写入相关的 guest/进程缓冲区。
4. 执行，直到发生崩溃/超时/重置。
5. 恢复快照；对于 VM 目标，如果支持，则仅恢复**脏页**，然后重复。

尽可能将快照放在接近第一个高开销解析/分发步骤的位置，例如 `recv`/`read` 之后或数据包反序列化的位置，并记录目标使用的输入缓冲区。这遵循自适应放置原则：将快照深入输入处理流程，以避免重复执行已有工作。<sup>[[11]](#references)</sup>

## 使用 MAccConc 探索 Linux 内核竞态

[MAccConc](https://github.com/googleprojectzero/MAccConc) 能将对时序敏感的 Linux 内核竞态转换为可重复的内存访问调度。它可以自动枚举双上下文 **A-B-A** 执行，也允许分析人员在终端 UI/GUI 中设定顺序约束。这是实验性研究工具，而非完整的并发 fuzzing 工具：目前需要 LLVM 23+ 和项目修补过的内核，命令行工具支持两个测试线程，且提议中的用户态 fuzzing 层尚未实现。<sup>[[17]](#references)[[18]](#references)</sup>

### 收集跨上下文通信点

使用 KASAN outline 回调和经过修补、支持 KCOV 内存记录的内核来构建插桩内核。项目 README 还建议禁用 sibling-call 优化，以便保留可用的调用栈。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）会将插桩访问转换为 helper 调用。MAccConc 内核补丁会禁用 `asan-opt-same-temp`，以避免合并连续访问；当需要检测全局变量竞争时，也要禁用 `asan-opt-globals` 优化。KCOV 会将生成的记录传递到用户空间。比较来自不同执行上下文的访问，并保留字节范围重叠且至少一方执行写操作的访问对；将 `kfree()` 建模为写操作，以便也能将生命周期转换纳入候选项。<sup>[[17]](#references)</sup>

对于脱离发起任务的工作（例如数据包处理或 RCU 回调），子系统必须传播 KCOV remote-coverage 句柄。上游 remote KCOV 需要显式启用，不会自动覆盖任意后台工作，因此未传播句柄可能导致真实交互无法被检测到。<sup>[[17]](#references)[[19]](#references)</sup>

### 在每次运行中识别同一个动态访问

不要针对具体堆地址进行重放，因为每次分配后地址可能改变；也不要只针对指令地址，因为在 `memcpy()` 和 `spin_lock()` 等 helper 内部，指令地址并不能唯一标识访问。MAccConc 使用**计数增强型栈跟踪**：每一帧标识一个被调用函数及其在调用者中的调用次数，最后一个元素标识内存访问指令。SanitizerCoverage 函数入口/出口记录让用户空间能够重建这一动态标识符；即使地址发生变化，或出现无关的控制流噪声，该标识符仍保持稳定。<sup>[[17]](#references)</sup>

### 将候选访问对转换为强制调度

修补后的 `KCOV_SET_DI` ioctl 会将计数增强型访问标识符与共享标志操作关联起来。<sup>[[17]](#references)</sup>

| 操作 | 语义 |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 在选定访问之前立即设置标志 *N*。 |
| `DI_STACK_WAIT` | 在选定访问之前循环等待，直到标志 *N* 被设置或达到配置的限制。 |
| `DI_STACK_WAKE_POST` | 在选定访问之后立即设置标志 *N*。 |

对于部分 **A-happens-before-B** 约束，将 `DI_STACK_WAKE_POST` 关联到 A，将 `DI_STACK_WAIT` 关联到 B，并使用相同的标志。对于完全指定的双上下文调度，让 B 初始处于阻塞状态，然后让 A 唤醒 B，并在第一个交接点等待；B 则在下一个交接点执行相反操作。后一种方式类似于确定性上下文切换，也是自动 A-B-A 探索器使用的方式。<sup>[[17]](#references)</sup>

一个最小化的测试流程是：将包含四个钩子（`test_setup`、两个线程函数和 `test_end`）的测试用例编译为共享库，收集不受约束的跟踪，然后枚举 A-B-A 候选项，或在可疑访问周围添加手动约束。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

将超时与成功的重排分别处理：请求的顺序可能无法实现，因为锁或初始化/发布依赖会阻止第二个上下文到达其注入点。还要牢记 KASAN 的盲区：除非可能越界，否则通常不会 hook 直接的栈访问；默认优化下会省略全局变量；而且当前编译器无法同时生成 ASAN 和 TSAN hook。最后，原型会在 guest panic 时丢失其 KCOV 缓冲区，因此应保留独立的 crash console/oracle。<sup>[[17]](#references)</sup>

对于未来由并发引导的 fuzzing，可记录每个输入或 syscall 的内存访问摘要，配对那些能够形成跨上下文通信点的操作，然后只探索这些组合。VM snapshot 可稳定全局状态和地址；没有 snapshot 时，可使用分配点元数据在不同运行之间抽象对象。这是一项提议的扩展，并非当前 MAccConc 用户态工具的功能。<sup>[[17]](#references)</sup>

## Harness 内省：尽早发现浅层 Fuzzer

当 campaign 停滞时，问题往往不在 mutator，而在 **harness**。使用 **可达性/覆盖率内省**，找出那些从 fuzz target 静态可达、但动态覆盖很少或从未覆盖的函数。这些函数通常表明存在以下三种问题之一。<sup>[[12]](#references)</sup>

- harness 进入目标的时机过早或过晚。
- seed corpus 缺少一整类功能。
- 目标确实需要**第二个 harness**，而不是一个过于庞大的“包办一切” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以比较静态可达性与运行时覆盖率，并根据定时运行或公开 corpus 生成报告。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

根据报告，判断是为尚未测试的解析器路径新增 harness、扩充特定功能的 corpus，还是将单体 harness 拆分为更小的入口点。

## 基于图的 fuzz 目标选择与变异测试分类

如果你已经有**静态分析结果**、**变异测试存活项**和**覆盖率报告**，不要把它们当作互不相关的列表来分类。先构建**调用图**，为节点标注**圈复杂度**、**入口点/不可信输入可达性**以及任何外部发现，然后从图的角度提出问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从不可信输入到达？
- 哪些变异测试存活项位于从解析器/处理器通往安全关键代码的路径上？
- 哪些函数是架构上的瓶颈，且具有异常大的**影响范围**？

与仅看“最低覆盖率”相比，这通常能找出更合适的 fuzz 目标。一个**复杂度高**且已确认**可从外部到达**的解析器/解码器，比一个覆盖率低、但没有攻击者可控路径的孤立内部辅助函数更适合作为 harness 候选。

### 实用分类工作流

1. 从代码库构建**代码图**，并提取每个函数的复杂度/分支指标。
2. 枚举接受攻击者可控输入的**入口点**：请求处理器、解码器、导入器、协议解析器、CLI/文件读取器。
3. 从这些入口点运行**路径查询**，筛选候选函数，区分可达的攻击面与仅内部使用或死代码。
4. 优先处理同时具备以下特征的节点：
   - 高**圈复杂度**
   - 已确认可从不可信输入**到达**
   - 具有较大**影响范围**或许多下游依赖项
   - 有**SARIF**发现、审计记录或变异测试存活项等佐证
5. 优先为得分最高的节点编写有针对性的 harness，尤其是 **parser/codec**，例如 hex/Base64/IP/消息解码器。

### 变异测试存活项：等价还是可采取行动

变异测试往往会产生噪声很大的存活项列表。在将每个存活项都视为安全缺陷之前，先借助图来判断：

- 变异后的函数是否可从攻击者可控的入口点到达？
- 所有调用路径是否都受比被变异检查更强的不变量约束？
- 该节点是否位于死代码、纯格式处理逻辑，还是影响重大的算术/解析路径中？

仍不可达或受结构性约束的存活项通常是**等价变异体**。仍然**可达**且涉及**边界条件**、**溢出/进位路径**或**安全关键算术/解析**的存活项，应纳入：

- 新的 fuzz harness
- 直接的属性/不变量测试
- 有针对性的边界情况向量

### 将外部发现关联到图上

如果你的 SAST 流水线会导出 **SARIF**，请按**文件 + 行范围**将发现映射到图节点，并利用图扩展影响分析。<sup>[[6]](#references)</sup>

- 计算被标记函数的**影响范围**
- 检查该发现是否位于从某个入口点出发的路径上
- 将附近、最终都指向同一瓶颈的发现归为一组

这有助于决定是否要投入 fuzzing 时间测试某个函数：一个**可达**、**复杂**且已有 **SAST 命中**的节点，通常比一个仅复杂、但不存在攻击者路径的节点更值得优先测试。

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

重要的方法论是三者的交集：**复杂度 x 暴露面 x 影响**。使用图表挑选预期安全价值最高的 fuzz 目标，然后根据 mutation 后仍存活的样本，确定 harness 必须重点测试哪些边界和不变量。<sup>[[5]](#references)</sup>

## 使用 gosentry 进行 Go Fuzzing：更强大的引擎、类型化输入与差分检查

如果 Go 目标已经有原生的 `testing.F` harness，一个实用的升级路径是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一 harness。gosentry 是一个分支版 Go 工具链，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

当原生 Go fuzzer 卡在**难以满足的比较**、**类型化输入**或**解析器密集型格式**上时，这种方法很有用。方法保持不变：

- 继续使用 `f.Add(...)` 添加种子，并用 `f.Fuzz(...)` 设置回调。
- 复用相同的 harness，但使用 gosentry 的 `go` binary，而不是标准工具链运行。
- 将生成的 fuzz campaign 视为常规的 coverage-guided 运行，但使用 LibAFL 调度/变异，并配备更完善的辅助检测器。

### 将静默故障转化为 fuzz 发现

Go 安全评估中一个反复出现的问题是，危险行为通常默认**不会**导致崩溃。借助 gosentry，可以将几类“糟糕但静默”的状态升级为发现项。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` 可将选定的日志/错误处理路径转为类似崩溃的行为（适用于 `log.Fatal` 风格的代码路径；这类路径通常只记录日志并继续运行）。
- `--catch-races=true` 可使用 Go race detector 重放新发现的队列条目。
- `--catch-leaks=true` 可使用 `goleak` 重放新队列条目，并在发生 goroutine 泄漏时停止。
- LibAFL 的 hang 处理机制可将**无限循环/极慢输入**保留为 fuzz 发现项，而不是让它们作为超时被丢弃。
- 默认内置算术溢出检查，并可通过 go-panikint 风格的插桩启用可选的截断检查。

对于安全影响表现为**不会触发 panic 的解析器故障**、**并发错误**或**仅导致 DoS 的 hang**，而非内存损坏的目标，这尤其有价值。

### 面向类型化 Go API 的结构感知 fuzzing

原生 Go fuzzing 主要针对 `[]byte`、`string` 和数字等标量。如果被测代码接收的是类型化对象，gosentry 可以直接 fuzz **复合值**（struct、slice、array、pointer），同时仍在底层变异字节。<sup>[[7]](#references)[[8]](#references)</sup>

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

仅在构造专用于 fuzzing 的虚假 wire format 时使用；否则，harness 专属的解析代码会掩盖逻辑 bug。对于 differential 或 grammar-based campaign，请将 harness 输入保留为单个 `[]byte` 或 `string`，并在 callback 内进行解析。

### 面向 parser 和 protocol input 的 grammar-based fuzzing

对于 parser、format 和 input language，gosentry 可以在 LibAFL 上运行 **Nautilus grammar fuzzing**。grammar 是一个 JSON production rule 数组，harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法论说明：

- 如果字节级变异大多在早期语法检查中就失败，请使用 grammar mode。
- 将 grammar 限定在语言/协议中与安全相关的子集，而不是对完整规范建模。
- 在终结符/非终结符中使用较大的边界值，以测试整数、长度和状态机边界。
- grammar mode 会使输入保持语法有效，但目标仍会接收**字节/字符串**，因此解析和语义检查仍在 harness 中的代码内进行。

### 差分 fuzzing：比较实现，而不只是崩溃

Go 生态系统中一种有效的模式是**基于语法的差分 fuzzing**：生成有效的结构化输入，并将其传递给两个解析器、客户端或状态转换引擎。<sup>[[7]](#references)[[8]](#references)</sup>

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

- 一个实现发生 panic，而另一个实现正常拒绝
- 对输入的接受/拒绝结果不一致
- 解析树或解码后的对象不同
- 状态转换、nonce、余额或状态根不一致

这是发现**共识不匹配**、**解析器歧义**和**规范与实现偏差**的实用方法，而纯粹的崩溃 fuzzing 往往会漏掉这些问题。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 复用 campaign corpus 生成覆盖率报告

campaign 结束后，重放保存的队列 corpus，即可生成 Go 覆盖率报告，无需手动导出单独的 corpus。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

从**同一个 package**运行命令，并使用**相同的 `-fuzz` 目标**，以便 gosentry 解析正确的缓存 campaign 状态。



## References

- [1] [变异语法模糊测试](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ 深入模糊测试](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [五年后的 AFLNet：基于覆盖率引导的协议模糊测试](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go 模糊测试缺少一半工具包。我们 fork 了工具链来解决这个问题。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：一种使用快照的快速有状态网络协议 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [没有语法也没问题：探索在没有系统调用描述的情况下对 Linux 内核进行模糊测试](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应和可变快照实现高效模糊测试](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 插桩：路径和调用者覆盖率](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [预测式上下文敏感模糊测试](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder 模糊测试](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 构建和回归种子文档](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：通过受控的内存访问交错探索 Linux 内核竞态条件](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：用于模糊测试的代码覆盖率](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
