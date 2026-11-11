# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing：覆盖率与语义

在 **mutational grammar fuzzing** 中，输入会在保持 **grammar-valid** 的前提下进行变异。在 coverage-guided 模式下，只有触发 **新覆盖率** 的样本才会被保存为 corpus seeds。对于 **语言类目标**（解析器、解释器、引擎），这种方法可能会漏掉需要 **语义/数据流链** 的漏洞，即一种构造的输出会成为另一种构造的输入。<sup>[[1]](#references)</sup>

**失败模式：**fuzzer 找到了分别触发 `document()` 和 `generate-id()`（或类似原语）的 seeds，但 **没有保留链式数据流**，因此更“接近漏洞”的样本会因未增加覆盖率而被丢弃。存在 **3 个或更多相互依赖的步骤** 时，随机重组的成本会变高，而覆盖率反馈也无法引导搜索。<sup>[[1]](#references)</sup>

**启示：**对于依赖关系繁重的 grammar，可以考虑 **结合变异阶段与生成阶段**，或让生成过程偏向 **函数链式调用** 模式（而不只是追求覆盖率）。<sup>[[1]](#references)</sup>

## Corpus 多样性陷阱

Coverage-guided mutation 具有 **贪心性**：触发新覆盖率的样本会立即保存，且通常保留大块未变化的区域。随着时间推移，corpus 会变成结构多样性较低的 **近似重复样本**。过度精简可能会删除有用的上下文，因此一种实用的折中方案是采用 **grammar-aware minimization**，并在达到最小 token 阈值后 **停止精简**（减少噪声，同时保留足够的周边结构，使样本仍适合变异）。<sup>[[1]](#references)</sup>

mutational fuzzing 的一条实用 corpus 规则是：**优先选择一小组结构各异、能最大化覆盖率的 seeds**，而不是堆积大量近似重复样本。实际上，这通常意味着以下做法。<sup>[[1]](#references)[[3]](#references)</sup>

- 从 **真实世界样本** 开始（公开 corpora、爬取内容、捕获的流量、目标生态系统中的文件集）。
- 使用 **基于覆盖率的 corpus 精简** 来提炼样本，而不是保留所有有效样本。
- 让 seeds **足够小**，使变异落在有意义的字段上，而不是把大多数周期浪费在无关字节上。
- 在 harness 或 instrumentation 发生重大变化后，重新运行 corpus 精简，因为可达性变化时，“最佳” corpus 也会改变。

## 针对 Magic Values 的比较感知变异

fuzzer 陷入瓶颈的一个常见原因不是语法，而是 **严格比较**：magic bytes、长度检查、枚举字符串、校验和，或由 `memcmp`、switch 表或级联比较保护的解析器分派值。纯随机变异会浪费周期，逐字节猜测这些值。

对于这类目标，可使用 **比较跟踪**（例如 AFL++ `CMPLOG` / Redqueen 风格的工作流），让 fuzzer 观察失败比较中的操作数，并引导变异朝满足比较条件的值靠近。<sup>[[3]](#references)</sup>

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

- 当目标将深层逻辑置于 **文件签名**、**协议动词**、**类型标签** 或 **依赖版本的功能位** 之后时，这种方法尤其有用。
- 将其与从真实样本、协议规范或调试日志中提取的 **字典** 配合使用。包含语法标记、块名称、动词和分隔符的小型字典，通常比庞大的通用词表更有价值。
- 如果目标会执行许多连续检查，先解决最早的“魔法值”比较，然后再次精简生成的语料库，让后续阶段从已通过验证的前缀开始。

## 对隐藏文件名语言的文件 API 进行 Fuzzing

名为 `filename`、`path` 或 `URL` 的参数可能是解释器入口，而不是字面意义上的文件查找。例如，CFITSIO Extended Filename Syntax (EFS) 会在返回打开的对象之前，先计算括号中的选择器、行/像素表达式、计算列、直方图和变换；某些形式还会创建临时副本。在攻击面映射期间，将每个 open/import API 分类为 **字面路径** 或 **解释路径**，然后针对应用实际调用的生产入口进行 fuzzing。<sup>[[20]](#references)[[22]](#references)</sup>

有关由此产生的 SSRF、文件复制和协议处理程序原语，以及更安全的字面路径 API，请参见 [作为 SSRF/文件原语的文件名迷你语言](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)。<sup>[[20]](#references)</sup>

### 将底层对象与被 fuzz 的程序分开

当语法位于文件名后缀中时，只修改被引用文件的字节会遗漏解析器。可以改用一个小型 harness，将每个测试用例作为字符串读取，并传给解释型 open API；CFITSIO 测试通过以只读模式调用 `fits_open_file()`，覆盖了大多数 EFS 解析器和求值器。单独保留有效的底层文件，以便修改可以专注于选择器/表达式语言，而不是不断破坏基础路径。<sup>[[22]](#references)</sup>

使用能够分别触达不同语法类别的种子，然后根据规范和词法/语法分析器源代码生成精简的字典。如果覆盖率停滞，且输入反复在同一语法错误路径中失败，应保留有效前缀，并添加分隔符、运算符、关键字、函数名和有代表性的字段名，而不是只增加随机变异的运行时间。<sup>[[22]](#references)</sup>

例如，使用语法字典运行 harness：<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 限制“只读”harness 的副作用

库的只读标志并不能保证 testcase 不产生副作用：文件名语言可能会重写输入、创建输出文件，或实例化临时对象。CFITSIO 测试活动最初破坏了种子文件，并在文件系统中留下意外文件，因此必须进行清理和隔离。<sup>[[22]](#references)</sup>

- 为每个 worker 分配一次性工作目录和私有临时目录。
- 仅提供规范后备文件的副本；绝不能让目标程序修改唯一的语料库副本。
- 除非目标是远程后端，否则禁用网络访问，并使用容器、挂载命名空间或同等沙箱限制可写路径。
- 每次执行或每批 worker 后重置目录，并将意外的文件系统更改视为额外发现。

### 从崩溃到补丁再到 fuzz 的循环

修复前先对崩溃进行聚类，避免数千个产物变成数千项补丁任务。在 CFITSIO 评估中，AFLTriage 将最初的崩溃集合缩减到少数几个根本原因；最终的安全公告展示了多种不同故障，包括目标大小检查错误、`realloc()` 后的过期指针、算术错误以及不安全的解析器清理路径。<sup>[[21]](#references)[[22]](#references)</sup>

1. 为每个聚类最小化一个代表性输入，并在 AddressSanitizer 下复现。
2. 记录导致不变量失效的确切访问、源代码位置、分配/释放历史和解析器状态。
3. 应用一个范围明确的候选补丁，并使用相同的覆盖率和 sanitizer 检测配置重新构建。
4. 重放原始复现输入**以及该聚类中的每个输入**；同时启用 leak 检测，因为内存安全修复可能破坏错误路径上的所有权处理。
5. 使用真实文件运行功能测试，然后从累积的队列继续（或者，如果引擎在二进制文件更改后要求使用新的输出目录，则重新导入该队列）。
6. 重复上述过程：消除第一个浅层崩溃后，现有种子往往能进入更深层的解析器状态。

如果向 LLM 提供崩溃输入、sanitizer 报告、harness 和相关源代码，它可以加快步骤 2 并起草步骤 3，但其补丁仍不可信。是否接受修复，应由 sanitizer 重放和回归门槛决定，而不是模型的解释。<sup>[[22]](#references)</sup>

## 边覆盖无法区分不同路径时的更丰富反馈

普通边覆盖无法区分两种执行：它们通过不同调用方遍历同一个 helper，或在函数内部采取不同的分支组合。这在共享解码器、协议分发器和解释器 helper 中尤其重要，因为到达某条边的**路径**决定了当前有效状态。天真地跟踪每个调用上下文也很危险：覆盖率映射和队列可能会急剧膨胀。因此，上下文敏感 fuzzing 研究建议只细化有希望的上下文，而不是将整个调用图都视为上下文敏感。<sup>[[14]](#references)</sup>

近期的 AFL++ 版本除了普通边覆盖外，还提供**Ball-Larus 函数级路径覆盖**。它会为函数中的每条无环路径分配一个特征；循环回边会被移除，因此这种反馈可以区分分支组合，但**不能区分循环迭代次数**。先从宽松的级别 `1` 开始，然后只在可疑的解析器/状态机代码中启用更严格的模式，因为路径数量可能呈指数级增长。<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

对于一个从许多安全相关位置调用的 helper，LTO 模式可以将每条函数路径与其直接调用位置结合起来：<sup>[[13]](#references)</sup>

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

**Campaign guidance：**谨慎使用更丰富的反馈，并监控其 coverage-map/queue 成本。<sup>[[13]](#references)[[14]](#references)</sup>

- 并行运行一个普通的 edge-coverage 实例；只有在额外的 queue/map 成本不会导致每秒执行次数大幅下降时，更丰富的反馈才有用。
- 当大型模板密集型库或通用工具代码占据 map 的主要部分时，使用 `AFL_LLVM_ALLOWLIST` 限制路径/调用者插桩。
- 存在过多无环路径的函数可以由 AFL++ 跳过；编译期间的警告表明目标需要 allowlisting 或较宽松的级别。
- Caller + path coverage 仅支持一层调用者深度。不要将它与更深的上下文栈结合使用。
- Path ID 可能随 LLVM 主版本变化。一次 campaign 中应固定工具链；不要把基于 PATH 的语料库同步起来，仿佛其 feature ID 在不同构建间保持稳定。
- 此反馈可补充 `CMPLOG`：比较跟踪解决的是**什么值可以通过 guard**，而路径/调用者反馈保留的是**哪些路径和分支组合到达了那里**。

## Stateful Fuzzing：序列就是 Seed

对于**协议**、**经过身份验证的工作流**和**多阶段解析器**，有趣的单元往往不是单个 blob，而是一个**消息序列**。把整段交互记录拼接到一个文件中并盲目变异，通常效率不高，因为 fuzzer 会对每一步进行同等程度的变异，即使只有后续消息才能到达脆弱状态也是如此。<sup>[[4]](#references)</sup>

更有效的做法是将**序列本身视为 seed**，并将**可观测状态**（响应码、协议状态、解析器阶段、返回的对象类型）作为额外反馈。<sup>[[4]](#references)</sup>

- 保持**有效的前缀消息**稳定，并专注于变异**驱动状态转换**的消息。
- 如果下一步依赖先前响应中的标识符和服务器生成的值，就缓存这些值。
- 优先采用逐条消息的变异/拼接，而不是将整个序列化交互记录视为不透明 blob 来变异。
- 如果协议提供有意义的响应码，就将其用作**低成本状态判定器**，优先处理能推进到更深阶段的序列。

这也解释了为什么经过身份验证的 bug、隐藏的状态转换或“仅在握手后触发”的解析器 bug 常被 vanilla 文件式 fuzzing 漏掉：fuzzer 必须保留**顺序、状态和依赖关系**，而不只是结构。<sup>[[4]](#references)</sup>

### Android Binder：多客户端驱动器 fuzzing

高 edge coverage 仍可能漏掉 IPC 驱动器 bug，因为 coverage 无法描述**对象所有权、引用计数、待处理消息、清理顺序或线程交错**。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 页面介绍了驱动器对象模型；此示例则聚焦于 fuzzer harness。Android Binder 是一个很有用的模型：即使到达了分配和释放路径，如果 fuzzer 无法按所需顺序让多个进程操作同一个内核对象，也仍然不够。<sup>[[15]](#references)</sup>

#### 对协议建模，而非孤立的 `ioctl` 缓冲区

将测试用例表示为有序语法：**客户端标识 + 操作 + 结构化参数**。Binder LKL fuzzer 使用 protobuf 和 `libprotobuf-mutator`，包含一个持久化的 context-manager 客户端和两个普通客户端。语义 harness 会保留盲目按字节变异可能破坏的关系。<sup>[[15]](#references)</sup>

- 缓存先前操作返回的值。例如，`BC_FREE_BUFFER` 必须复用先前 `ioctl` 返回的事务缓冲区指针。
- 生成有效的默认回复，使同步事务能够完成，并确保后续操作仍可到达。
- 拒绝不可能的状态转换，例如向自身发起事务，或向同一目标发起多个待处理事务。
- 将单例引导状态保留在每次输入重置之外。Binder 每次启动只允许注册一次 `BINDER_SET_CONTEXT_MGR`；因此反复销毁并重建该客户端会导致后续输入无效。

一种实用的生命周期竞态模板是：让一个客户端传递对象，启动线程或进程清理，同时让接收客户端释放事务缓冲区。在 CVE-2020-0423 示例中，`BINDER_TYPE_WEAK_BINDER` 传递后，`BINDER_THREAD_EXIT` 与 `BC_FREE_BUFFER` 发生竞态，可能导致嵌入的 `binder_work` 被释放，而退出线程的清理路径仍在使用它。<sup>[[15]](#references)</sup>

#### 在用户态内核中重新引入可控交错

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) 将真实内核代码链接到用户态 harness 中，并通过 `lkl_syscall` 提供其系统调用接口。这样便于在同一进程中协调 protobuf 状态、coverage 和 KASAN。不过，LKL 通常会在没有其他内核线程中断的情况下运行系统调用。对于竞态 campaign，可在选定的加锁/解锁和生命周期边界周围插入 `schedule()` 点，然后让 harness 在每次让出执行权时随机选择下一个客户端。应将这些点控制在必要范围内，因为每增加一个点都会扩大调度搜索空间。研究人员描述的随机调度器**并非**上游 Binder fuzzer 的一部分。<sup>[[15]](#references)</sup>

#### 构建并重放序列化回归 seed

上游 harness 固定使用兼容的 `libprotobuf-mutator`，通过 `LKL_FUZZING=1` 启用 LKL fuzzing 插桩和 KASAN，并通过 `MMU=1` 为 Binder 启用 `CONFIG_MMU`。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

在检出一个故意存在漏洞的修订版本，或应用上游文档中记录的回滚补丁后，序列化种子即可重现整个多客户端状态转换，无需临时编写 C 概念验证：<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

将由此产生的 KASAN use-after-free 视为 seed 已到达易受攻击的生命周期路径的确认。这**并不能**证明后续所需的内核代码执行或权限提升原语已实现。<sup>[[16]](#references)</sup>

## 单机多样性技巧（Jackalope 风格）

将**生成式新颖性**与**覆盖率复用**结合的一种实用方法是：针对持久化服务器重启短生命周期 worker。每个 worker 从空 corpus 开始，运行 `T` 秒后同步，再基于合并后的 corpus 运行 `T` 秒，再次同步，然后退出。这样既能在**每一代生成新结构**，又能利用累积的覆盖率。<sup>[[1]](#references)[[2]](#references)</sup>

**服务器：**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**顺序 workers（循环示例）：**

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

- `-in empty` 会在每轮生成时强制使用**全新的 corpus**。
- `-server_update_interval T` 可近似实现**延迟同步**（先探索新路径，之后再复用）。
- 在 grammar fuzzing 模式下，默认会跳过**初始服务器同步**（无需使用 `-skip_initial_server_sync`）。
- 最优的 `T` **取决于目标**；通常在 worker 找到大部分“容易”覆盖率后切换效果最好。

## 针对难以搭建测试环境的目标进行 Snapshot Fuzzing

当你想测试的代码只有在**耗费大量准备工作后**才可访问（启动 VM、完成登录、接收数据包、解析容器、初始化服务），一种实用的替代方案是 **snapshot fuzzing**：捕获已就绪的进程或 VM 状态，将每个测试用例注入目标输入路径，执行直到崩溃/超时，然后恢复快照。这样可以避免重复初始化或协议前缀，适用于**网络服务**、**firmware**、**认证后的攻击面**和**仅有二进制文件的目标**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到进入所需状态。
2. 在此时对**内存 + 寄存器**进行快照。
3. 对每个测试用例，直接将变异后的输入写入相关的 guest/进程缓冲区。
4. 执行，直到崩溃/超时/重置。
5. 恢复快照；对于 VM 目标，在支持的情况下只恢复**脏页**，然后重复。

尽可能将快照放在第一个耗时的解析/分发步骤附近，例如 `recv`/`read` 之后或数据包反序列化的位置，并记录目标使用的输入缓冲区。这遵循自适应放置原则：将快照点移入输入处理流程的更深处，以避免重复执行工作。<sup>[[11]](#references)</sup>

### 协议状态的增量快照

固定快照可以避免准备开销，但本身无法探索需要多条有效消息才能完成的状态转换。LibAFL-Qemu harness 可以监视对协议状态字段的写入，并在状态改变时保存新快照。在 [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) 中，它会监视 `tcpcb.t_state`，对状态和响应标志进行哈希以去重快照，并相对于父快照存储脏页。在变异下一条结构化消息前，它会沿父快照链恢复所选快照。测试用例会保留一个 `SnapshotId` 和生成的输入字节（`gen_bytes`）；快照管理器则会跟踪重放所需的父子关系。<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu 的 user-mode `SnapshotModule` 会保存映射和目标内存，但不会保存 CPU 寄存器；必要时需单独保留寄存器。所述管理器支持单个根快照树，无法在多个 worker 之间共享快照 ID。其多快照模式也无法直接复用 QASAN shadow state。对于离线 triage，请在单独的 instrumented 进程中重建输入链。使用 `AsanHostModule` 和 `DrCovModule` 时，`fuzzer.evaluate_input` 会运行所需的 `pre_exec`/`post_exec` callbacks；单独调用 `qemu.run` 则不会。<sup>[[27]](#references)[[28]](#references)</sup>

### 捕获逻辑上的 ring-buffer 越界读取

读取超出缓冲区*有效数据计数*的内容时，如果仍在其宿主分配区域内，可能逃过常规 ASAN 检测。[libslirp 紧急数据示例](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes)还会导致无符号字节计数下溢。如果有源代码，带符号/无符号整数溢出 instrumentation 可以检测到这一副作用；在抑制报告前，应区分有意的 TCP 序列号回绕。一个更强的候选 oracle 是：对自定义 ring 分配区域进行 poison，仅在其内部 allocator 前进时取消有效范围的 poison，并重新 poison 已释放的范围。对于不便进行源码 instrumentation 的目标，LibAFL-Qemu 提供 ASAN poisoning API。<sup>[[27]](#references)</sup>

## 使用 MAccConc 探索 Linux Kernel Race

[MAccConc](https://github.com/googleprojectzero/MAccConc) 可将时序敏感的 Linux kernel race 转换为可重复的内存访问调度。它可以自动枚举两个上下文的 **A-B-A** 执行，也可以让分析人员通过终端 UI/GUI 指定顺序约束。这是实验性的研究工具，并非完整的并发 fuzzer：目前需要 LLVM 23+ 和该项目打过补丁的 kernel；命令行工具支持两个测试线程，提议中的 userspace fuzzing 层尚未实现。<sup>[[17]](#references)[[18]](#references)</sup>

### 收集跨上下文通信点

构建 instrumented kernel 时，启用 KASAN outline callbacks 和打过补丁的 KCOV memory-record 支持。项目 README 还建议禁用 sibling-call optimization，以确保调用栈仍可用。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）会将经过插桩的访问转换为 helper 调用。MAccConc 内核补丁会禁用 `asan-opt-same-temp`，避免合并连续访问；如果必须检测全局变量竞争，也要禁用 `asan-opt-globals` 优化。KCOV 会将生成的记录传递到用户态。比较来自不同执行上下文的访问，并保留字节范围重叠且至少一方执行写操作的访问对；将 `kfree()` 视为写操作，以便也能将生命周期转换纳入候选范围。<sup>[[17]](#references)</sup>

对于脱离发起任务执行的工作（例如数据包处理或 RCU 回调），子系统必须传递 KCOV remote-coverage 句柄。上游 remote KCOV 需要显式启用，不会自动覆盖任意后台工作，因此未传递句柄可能导致真实交互无法被检测到。<sup>[[17]](#references)[[19]](#references)</sup>

### 在每次运行中识别相同的动态访问

不要针对具体堆地址进行重放，因为每次分配后地址都可能变化；也不要只针对指令地址，因为在 `memcpy()` 和 `spin_lock()` 等 helper 中，指令地址可能存在歧义。MAccConc 使用**计数增强型栈跟踪**：每个栈帧标识被调用函数及其在调用者中的调用次数，最后一个元素标识内存访问指令。SanitizerCoverage 函数入口/出口记录让用户态能够重建此动态标识；即使地址变化或出现无关的控制流噪声，该标识仍保持稳定。<sup>[[17]](#references)</sup>

### 将候选访问对转换为强制调度

补丁版 `KCOV_SET_DI` ioctl 会将计数增强型访问标识与共享标志操作关联起来。<sup>[[17]](#references)</sup>

| 操作 | 语义 |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 在选定访问之前立即设置标志 *N*。 |
| `DI_STACK_WAIT` | 在选定访问之前自旋等待，直到标志 *N* 被设置或达到配置的限制。 |
| `DI_STACK_WAKE_POST` | 在选定访问之后立即设置标志 *N*。 |

要施加部分 **A 先于 B** 约束，请在 A 上附加 `DI_STACK_WAKE_POST`，并在 B 上附加 `DI_STACK_WAIT`，两者使用相同的标志。对于完全指定的双上下文调度，先让 B 处于阻塞状态，然后让 A 在第一个交接点唤醒 B 并等待；B 在下一个交接点执行相反操作。后一种方式相当于确定性上下文切换，也是自动 A-B-A 探索器采用的方法。<sup>[[17]](#references)</sup>

一种最简测试方案是：将包含四个钩子（`test_setup`、两个线程函数和 `test_end`）的测试用例编译为共享库，收集不带约束的跟踪，然后枚举 A-B-A 候选，或在可疑访问周围添加手动约束。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

将超时与成功的重排序区分开来：由于锁或初始化/发布依赖，第二个 context 可能无法到达其注入点，因此请求的顺序可能无法实现。还要注意 KASAN 的盲点：通常不会 hook 直接的栈访问，除非它们可能越界；默认优化下会省略全局变量；而且当前编译器无法同时生成 ASAN 和 TSAN hooks。最后，原型在 guest panic 时会丢失 KCOV buffer，因此要保留独立的 crash console/oracle。<sup>[[17]](#references)</sup>

对于未来的并发引导 fuzzing，可以记录每个输入或 syscall 的内存访问摘要，配对可能形成跨 context 通信点的操作，然后仅探索这些组合。VM snapshots 可以稳定全局状态和地址；不使用 snapshots 时，可以通过分配点元数据在多次运行之间抽象对象。这是一个提议的扩展，并非当前 MAccConc userspace tools 的功能。<sup>[[17]](#references)</sup>

## Harness Introspection: 尽早发现浅层 Fuzzer

当 campaign 停滞时，问题往往不在 mutator，而在 **harness**。使用 **reachability/coverage introspection**，找出从 fuzz target 静态可达、但动态覆盖很少或从未覆盖的函数。这些函数通常表明存在以下三种问题之一。<sup>[[12]](#references)</sup>

- harness 进入 target 的时机过早或过晚。
- seed corpus 缺少一整类功能。
- target 实际上需要一个**第二个 harness**，而不是一个过于庞大的“包办一切” harness。

如果使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以对比静态可达性与运行时覆盖率，并根据定时运行或公开 corpus 生成报告。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

使用报告来决定是为未测试的解析器路径添加新的 harness、扩展特定功能的语料库，还是将单体 harness 拆分为更小的入口点。

## 基于图的 Fuzz 目标选择与变异测试分诊

如果你已有**静态分析结果**、**变异测试存活项**和**覆盖率报告**，不要将它们视为互不相关的列表进行分诊。先构建**调用图**，为节点标注**圈复杂度**、**入口点/不可信输入可达性**以及任何外部发现，然后从图的角度提出问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从不可信输入到达？
- 哪些变异测试存活项位于从解析器/处理器到安全关键代码的路径上？
- 哪些函数是架构上的瓶颈点，具有异常大的**影响范围**？

这种方法通常比单看“覆盖率最低”更能找出合适的 fuzz 目标。一个**复杂度高**且确认可从外部到达的解析器/解码器，比一个覆盖率较低但没有攻击者可控路径的孤立内部辅助函数更适合作为 harness 候选。

### 实用分诊工作流

1. 从代码库构建**代码图**，并提取每个函数的复杂度/分支指标。
2. 列出接受攻击者可控输入的**入口点**：请求处理器、解码器、导入器、协议解析器、CLI/文件读取器。
3. 从这些入口点运行到候选函数的**路径查询**，以区分可达的攻击面与死代码/仅内部可达代码。
4. 优先处理同时具备以下特征的节点：
   - 高**圈复杂度**
   - 确认可从不可信输入**到达**
   - **影响范围**大或有许多下游依赖项
   - 有佐证，例如 **SARIF** 发现、审计备注或变异测试存活项
5. 优先为得分最高的节点编写有针对性的 harness，尤其是 **parser/codec**，例如 hex/Base64/IP/消息解码器。

### 变异测试存活项：等价项与可采取行动项

变异测试经常产生嘈杂的存活项列表。在将每个存活项都视为安全漏洞之前，先利用图来判断：

- 变异后的函数是否可从攻击者可控的入口点到达？
- 所有调用路径是否都受到比被变异检查更强的不变量约束？
- 该节点是否位于死代码、仅负责格式处理的逻辑，还是高影响的算术/解析路径上？

仍不可达或受结构性约束的存活项通常是**等价变异体**。仍然**可达**且涉及**边界条件**、**溢出/进位路径**或**安全关键算术/解析**的存活项，应提升为：

- 新的 fuzz harness
- 直接的属性/不变量测试
- 有针对性的边界案例向量

### 将外部发现关联到图上

如果你的 SAST 流水线导出 **SARIF**，可按**文件 + 行范围**将发现映射到图节点，并利用图扩展影响范围。<sup>[[6]](#references)</sup>

- 计算被标记函数的**影响范围**
- 检查该发现是否位于从某个入口点出发的路径上
- 将附近且最终指向同一瓶颈点的发现聚类

这有助于决定是否将 fuzzing 时间投入某个特定函数：一个**可达**、**复杂**且已有 **SAST 命中项**的节点，通常比一个仅仅复杂但不存在攻击者路径的节点更值得优先处理。

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

重要的方法论在于三者的交集：**复杂度 x 暴露面 x 影响**。使用图表选出预期安全价值最高的 fuzz 目标，然后根据 mutation survivors 判断 harness 必须重点测试哪些边界和不变量。<sup>[[5]](#references)</sup>

## 密码学密钥编码的差分 fuzzing

从有效的序列化密钥或标准测试向量开始。修改编码字段，同时保留到达导入和操作路径所需的长度和结构，然后将相同的字节提交给相互独立的实现。比较它们是否接受输入以及返回的错误。随机化签名和密文需要正确性 oracle，而不是逐字节比较：验证签名，或比较封装/解封装往返过程中得到的共享密钥。测试向量用于确认已知用例是否符合规范；差分 mutation 则用于探测超出这些用例范围的格式错误编码。<sup>[[23]](#references)[[26]](#references)</sup>

对于这些密钥格式，请使用特定于格式的 oracle：<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA 展开后的签名密钥：**修改打包后的 `s1` 或 `s2` 系数，使其超出 `[-η, η]`，同时保持密钥可解析。检查导入或签名操作是否拒绝该密钥，以及由此生成的签名是否能够通过验证。仅有接受与否的差异并不代表违反标准，因为 FIPS 204 并未强制要求额外的私钥检查。参见 [conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)。
- **ML-KEM 密钥对：**区分对封装密钥和解封装输入的必要检查，以及对导入密钥对执行的可选成对一致性检查（PCT）。使用其公钥进行封装，再使用其私钥进行解封装，并比较共享密钥；即使单个密钥通过了输入检查，共享密钥不匹配也可能导致加密通信中断。检查 API 是在操作中验证输入，还是通过单独的调用进行验证；libcrux 提供 `validate_public_key(pk)` 和 `validate_private_key(sk, ct)`，但它们不能替代 PCT。
- **XMSS/XMSSMT 原始密钥：**针对不同参数集测试序列化的**签名和验证**密钥往返，而不只是使用内存中的密钥执行操作。XMSS 和 XMSSMT 使用不同的四字节 OID 命名空间，因此，如果仅依据 OID 的解析器优先尝试 XMSS，就可能将 OID 冲突的 XMSSMT 密钥误判为 XMSS 密钥并拒绝导入。所报告的 RustCrypto 解析器问题体现的是互操作性/可用性故障，而不是签名伪造。

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入与差分检查

如果某个 Go 目标已有原生 `testing.F` harness，一个实用的升级方法是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一个 harness。gosentry 是一个分叉的 Go 工具链，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

当原生 Go fuzzer 在**难以满足的比较条件**、**带类型的输入**或**解析器密集型格式**上停滞时，这种方法很有用。方法保持不变：

- 继续使用 `f.Add(...)` 添加种子，并使用 `f.Fuzz(...)` 编写回调。
- 复用同一个 harness，但改用 gosentry 的 `go` 二进制文件运行，而不是使用标准工具链。
- 将生成的 campaign 视为普通的覆盖率引导运行，只是使用了 LibAFL 的调度和变异机制，以及更完善的周边检测器。

### 将静默失败转化为 fuzz findings

Go 安全评估中一个常见问题是，危险行为通常**不会**默认导致崩溃。使用 gosentry，可以将几类“有问题但静默”的状态转化为 findings。<sup>[[7]](#references)[[8]](#references)</sup>

- 使用 `--panic-on=pkg.Func,...`，让指定的日志/错误处理路径表现得像崩溃一样（适用于 `log.Fatal` 风格的代码路径；这类路径通常只会记录日志并继续执行）。
- 使用 `--catch-races=true`，通过 Go race detector 重放新发现的队列条目。
- 使用 `--catch-leaks=true`，通过 `goleak` 重放新的队列条目，并在发现 goroutine 泄漏时停止。
- 使用 LibAFL 的挂起处理机制，将**无限循环/非常慢的输入**保留为 fuzz findings，而不是让它们作为超时被丢弃。
- 默认启用内置算术溢出检查；还可以通过 go-panikint 风格的插桩进行截断检查。

对于安全影响表现为**不会引发 panic 的解析器故障**、**并发 bug**或**仅导致 DoS 的挂起**，而非内存破坏的目标，这尤其有价值。

### 面向 Go 强类型 API 的结构感知 fuzzing

原生 Go fuzzing 主要面向 `[]byte`、`string` 和数字等标量。如果被测代码使用带类型的对象，gosentry 可以直接 fuzz **复合值**（struct、slice、array、pointer），同时仍在底层变异字节。<sup>[[7]](#references)[[8]](#references)</sup>

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

在构建仅用于 fuzzing 的虚假 wire format 时，这样做会让逻辑漏洞被仅供 harness 使用的解析代码掩盖。对于差分或基于语法的测试活动，应将 harness 输入保留为单个 `[]byte` 或 `string`，并在回调中进行解析。

### 面向解析器和协议输入的基于语法的 fuzzing

对于解析器、格式和输入语言，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。语法是一个 JSON 产生式规则数组，harness 通常应接收单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法论说明：

- 当字节级变异大多在早期语法检查中失败时，使用 grammar mode。
- 将 grammar 限定为语言/协议中与**安全相关的子集**，而不是对完整规范建模。
- 在终结符/非终结符中使用较大的边界值，以测试整数、长度和状态机边界。
- grammar mode 能确保输入符合语法，但目标仍会收到**字节/字符串**，因此解析和语义检查仍在被 harness 的代码中进行。

### 差分 fuzzing：比较实现，而不只是崩溃

对于 Go 生态系统，一种有效模式是**基于语法的差分 fuzzing**：生成有效的结构化输入，并将其传递给两个解析器、客户端或状态转换引擎。<sup>[[7]](#references)[[8]](#references)</sup>

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
- 输入的接受/拒绝结果不一致
- 解析树或解码后的对象不同
- 状态转换、nonce、余额或状态根不一致

这是发现**共识不匹配**、**解析器歧义**和**规范与实现之间的偏差**的实用方法，而纯粹的崩溃 fuzzing 往往无法发现这些问题。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 复用 campaign 语料库进行覆盖率报告

campaign 结束后，重放保存的队列语料库以生成 Go 覆盖率报告，无需手动导出单独的语料库。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

从**同一个 package** 运行命令，并使用相同的 `-fuzz` target，以便 gosentry 解析正确的缓存 campaign 状态。

## References

- [1] [变异语法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ 深入了解 Fuzzing](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 五年后：基于覆盖率引导的协议 Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing 缺少一半工具链。我们 fork 了工具链来解决这个问题。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：一种使用快照的快速状态化网络协议 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [没有语法也没关系：探索在没有系统调用描述的情况下对 Linux 内核进行 Fuzzing](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应可变快照实现高效 Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation：路径和调用者覆盖率](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [预测式上下文敏感 Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security 博客 - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 构建和回归 seed 文档](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：通过受控的内存访问交错探索 Linux 内核竞争条件](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：用于 Fuzzing 的代码覆盖率](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 扩展文件名语法](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 安全公告：CFITSIO 2025 年第四季度](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing CFITSIO 扩展文件名语法：16 个内存安全漏洞及 Codex 辅助分类](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [针对密码学的差分 Fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203：基于模块格的密钥封装机制标准](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID 解析错误 - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [后量子密码学实现现状](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [通过快照实现 CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
