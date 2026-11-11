# Fuzzing 方法论

{{#include ../banners/hacktricks-training.md}}

## 变异语法 Fuzzing：覆盖率与语义

在**变异语法 Fuzzing**中，输入会在保持**语法有效**的前提下进行变异。在覆盖率引导模式下，只有触发**新覆盖率**的样本才会保存为语料种子。对于**语言目标**（解析器、解释器、引擎），这种方式可能会漏掉需要**语义/数据流链**的 bug，也就是一个构造的输出成为另一个构造输入的情况。<sup>[[1]](#references)</sup>

**失败模式：**fuzzer 找到的种子分别触发了 `document()` 和 `generate-id()`（或类似原语），但**没有保留链式数据流**，因此“更接近 bug”的样本会被丢弃，因为它没有增加覆盖率。当存在 **3 个或更多依赖步骤**时，随机重组的成本会变得很高，而且覆盖率反馈无法引导搜索。<sup>[[1]](#references)</sup>

**启示：**对于依赖关系繁重的语法，可以考虑**结合变异和生成阶段**，或让生成过程更偏向**函数链式调用**模式（而不只是关注覆盖率）。<sup>[[1]](#references)</sup>

## 语料多样性的陷阱

覆盖率引导的变异是**贪心的**：新覆盖率样本会立即保存，通常保留大量未变更区域。随着时间推移，语料会变成结构多样性较低的**近似重复样本**。过度精简可能会移除有用上下文，因此一种实用的折中方案是采用**语法感知的精简**，并在达到最小 token 阈值后**停止**（减少噪声，同时保留足够的周边结构以便进行有效变异）。<sup>[[1]](#references)</sup>

变异 Fuzzing 的一条实用语料规则是：与其保留大量近似重复样本，不如**优先选择一小组结构各异且能最大化覆盖率的种子**。在实践中，这通常意味着以下做法。<sup>[[1]](#references)[[3]](#references)</sup>

- 从**真实样本**开始（公开语料、爬取数据、捕获的流量、目标生态系统中的文件集）。
- 使用**基于覆盖率的语料精简**来提炼样本，而不是保留每个有效样本。
- 保持种子**足够小**，让变异落在有意义的字段上，而不是把大部分循环浪费在无关字节上。
- 在 harness/插桩发生重大变化后，重新运行语料精简，因为可达性变化时，“最佳”语料也会随之变化。

## 大型生成程序与超时偏差

在编译器和解释器 Fuzzing 中，输入可能需要达到**生成代码大小阈值**，而不是触发新的解析器分支。在 V8 的[异常处理器偏移示例](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size)中，只有当字节码超过 256 MiB 后，截断的处理器偏移才会产生影响。重复的 `yield*` 构造可以达到该边界，但在 debug build 上编译该测试用例需要数秒。即使语法覆盖率很高，对小输入的偏好和较短的执行超时也可能不利于发现这类问题。审计打包偏移或其他对长度敏感的元数据时，应分别考虑大小阈值和超时策略；这项测试活动建议是根据所报告的失败模式推断得出的。<sup>[[29]](#references)</sup>

## 面向 Magic Values 的比较感知变异

fuzzer 停滞的一个常见原因不是语法，而是**硬比较**：magic bytes、长度检查、枚举字符串、校验和，或由 `memcmp`、switch 表或级联比较保护的解析器分发值。纯随机变异会浪费大量循环，逐字节猜测这些值。

对于这类目标，可以使用**比较跟踪**（例如 AFL++ `CMPLOG` / Redqueen 风格的工作流），让 fuzzer 观察失败比较中的操作数，并引导变异朝满足这些比较的值靠拢。<sup>[[3]](#references)</sup>

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

- 当目标将深层逻辑隐藏在 **文件签名**、**协议动词**、**类型标签** 或 **依赖版本的功能位** 后面时，这种方法尤其有用。
- 配合从真实样本、协议规范或调试日志中提取的 **字典** 使用。包含语法 token、块名称、动词和分隔符的小型字典，通常比庞大的通用词表更有价值。
- 如果目标会执行许多连续检查，先解决最早的“magic”比较，然后再次精简生成的语料库，让后续阶段从已经有效的前缀开始。

## 模糊测试隐藏文件名语言的文件 API

名为 `filename`、`path` 或 `URL` 的参数可能是解释器入口，而不是直接查找文件。例如，CFITSIO Extended Filename Syntax (EFS) 会在返回打开的对象之前，解析方括号选择器、行/像素表达式、计算列、直方图和转换；某些形式还会创建临时副本。在攻击面映射期间，将每个打开/导入 API 分类为 **字面路径** 或 **解释路径**，然后对应用程序实际调用的生产入口进行模糊测试。<sup>[[20]](#references)[[22]](#references)</sup>

有关由此产生的 SSRF、文件复制和协议处理程序原语，以及更安全的字面路径 API，请参阅 [作为 SSRF/文件原语的文件名小型语言](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)。<sup>[[20]](#references)</sup>

### 将后端对象与模糊测试程序分开

当语法位于文件名后缀中时，只修改引用文件的字节会漏掉解析器。可以编写一个小型 harness，将单个测试用例作为字符串读取，并传递给解释型打开 API；CFITSIO 模糊测试通过以只读模式调用 `fits_open_file()`，覆盖了大多数 EFS 解析器和求值器。单独准备有效的后端文件，这样变异就能专注于选择器/表达式语言，而不是不断破坏基础路径。<sup>[[22]](#references)</sup>

使用能分别触达不同语法家族的种子，然后结合规范和词法分析器/解析器源码生成精简字典。如果覆盖率停滞，且输入反复在同一语法错误路径中失败，应保留有效前缀，并添加分隔符、运算符、关键字、函数名和有代表性的字段名，而不是只增加随机变异时间。<sup>[[22]](#references)</sup>

例如，使用语法字典运行 harness：<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### 限制“只读”harness 的副作用

只读库标志并不能保证 testcase 不产生副作用：文件名语言可能会重写输入、创建输出文件或实例化临时对象。CFITSIO campaign 最初破坏了 seed 文件，并在文件系统中留下意外文件，因此必须进行清理和隔离。<sup>[[22]](#references)</sup>

- 为每个 worker 分配一次性工作目录和私有临时目录。
- 仅提供规范 backing 文件的副本；绝不允许目标程序修改唯一的 corpus 副本。
- 除非远程 backend 是预期目标，否则禁用网络访问，并使用容器、mount namespace 或等效 sandbox 限制可写路径。
- 每次执行或每批 worker 运行后重置目录，并将意外的文件系统变更视为额外发现。

### Crash-to-patch-to-fuzz 循环

修复前先对 crashes 聚类，避免成千上万个 artifacts 演变成成千上万个 patch 任务。在 CFITSIO 评估中，AFLTriage 将最初的 crash 集缩减到少数根本原因；最终的 advisory 展示了多种不同故障，包括目标缓冲区大小检查错误、`realloc()` 后指针过期、算术故障，以及不安全的 parser 清理路径。<sup>[[21]](#references)[[22]](#references)</sup>

1. 为每个 cluster 精简出一个代表性输入，并在 AddressSanitizer 下复现。
2. 记录导致 invariant 失效的具体访问、源码位置、分配/释放历史和 parser 状态。
3. 应用一个范围狭窄的候选 patch，并使用相同的 coverage 和 sanitizer instrumentation 重新构建。
4. 重放原始 reproducer **以及该 cluster 中的每个输入**；同时启用 leak 检测，因为内存安全修复可能会破坏错误路径上的所有权处理。
5. 使用真实文件运行功能测试，然后从累积的 queue 继续（如果引擎要求在二进制变更后使用全新的输出目录，则重新导入该 queue）。
6. 重复上述过程：移除第一个浅层 crash 后，已有 seeds 往往能进入更深层的 parser 状态。

如果向 LLM 提供崩溃输入、sanitizer 报告、harness 和相关源码，它可以加快步骤 2 并起草步骤 3，但其 patch 仍不可信。是否接受修复，应由 sanitizer 重放和回归检查决定，而不是由模型的解释决定。<sup>[[22]](#references)</sup>

## Edge Coverage 无法区分不同路径时提供更丰富的反馈

常规 edge coverage 无法区分两种执行：它们通过同一个 helper，但调用者不同，或在函数内部采用不同的分支组合。这在共享 decoder、协议 dispatcher 和 interpreter helper 中尤为重要，因为到达某条 edge 的 **route** 决定了当前状态。朴素地追踪每个调用上下文也有风险：coverage map 和 queue 可能急剧膨胀。因此，context-sensitive fuzzing 研究建议只细化有希望的上下文，而不是将整个调用图都视为 context-sensitive。<sup>[[14]](#references)</sup>

近期的 AFL++ 构建版本除了常规 edge coverage，还提供 **Ball-Larus 函数级路径 coverage**。它会为函数中每条无环路径分配一个 feature；循环回边会被移除，因此此反馈可以区分分支组合，但**无法区分循环迭代次数**。先从宽松的 level `1` 开始，然后仅对可疑的 parser/state-machine 代码启用更严格的模式，因为路径数量可能呈指数级增长。<sup>[[13]](#references)</sup>

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

**Campaign 指南：**谨慎使用更丰富的反馈，并监控其 coverage map/queue 开销。<sup>[[13]](#references)[[14]](#references)</sup>

- 并行运行一个普通的 edge-coverage 实例；只有在额外的 queue/map 开销不会降低每秒执行数时，更丰富的反馈才有用。
- 如果大型模板密集型库或通用实用代码占据了大部分 map，请使用 `AFL_LLVM_ALLOWLIST` 限制 path/caller instrumentation。
- AFL++ 可以跳过无环路径过多的函数；编译期间出现警告，说明目标需要 allowlisting 或更宽松的级别。
- Caller + path coverage 只支持一个 caller depth。不要将其与更深的 context stacks 结合使用。
- Path IDs 可能因 LLVM 主版本不同而改变。一次 campaign 中应固定 toolchain；不要像认为 feature IDs 在不同构建间稳定那样同步基于 PATH 的 corpora。
- 这种反馈可补充 `CMPLOG`：comparison tracing 用于解决**什么值可以通过 guard**，而 path/caller feedback 则保留**通过哪条路径及哪种分支组合到达**的信息。

## Stateful Fuzzing：序列就是 Seed

对于**协议**、**经过身份验证的工作流**和**多阶段解析器**，有趣的单元往往不是单个 blob，而是一个**消息序列**。将整个交互记录拼接到一个文件中并盲目变异通常效率低下，因为 fuzzer 会对每一步进行同等变异，即便只有后续消息才能到达脆弱状态也是如此。<sup>[[4]](#references)</sup>

更有效的模式是将**序列本身视为 seed**，并把**可观测状态**（响应代码、协议状态、解析器阶段、返回的对象类型）用作额外反馈。<sup>[[4]](#references)</sup>

- 保持**有效的前缀消息**稳定，重点变异驱动**状态转换**的消息。
- 如果后续步骤依赖先前响应中的标识符和服务器生成的值，就缓存这些值。
- 优先采用逐条消息的变异/拼接，而不是把整个序列化交互记录当作不透明 blob 来变异。
- 如果协议提供有意义的响应代码，就将其用作**低成本的状态预言机**，优先处理能够深入推进的序列。

这也是经过身份验证的漏洞、隐藏状态转换或“仅在握手后出现”的解析器漏洞常被 vanilla 文件式 fuzzing 漏掉的原因：fuzzer 必须保留**顺序、状态和依赖关系**，而不只是结构。<sup>[[4]](#references)</sup>

### Android Binder：多客户端驱动 fuzzing

较高的 edge coverage 仍可能漏掉 IPC 驱动漏洞，因为 coverage 无法描述**对象所有权、引用计数、待处理消息、清理顺序或线程交错**。[Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 页面介绍了驱动对象模型；本例重点介绍 fuzzer harness。Android Binder 是一个很好的模型：如果 fuzzer 无法按所需顺序让多个进程操作同一个内核对象，那么即使到达了分配和释放路径也不够。<sup>[[15]](#references)</sup>

#### 对协议建模，而不是孤立的 `ioctl` 缓冲区

将测试用例表示为按序排列的语法：**客户端身份 + 操作 + 结构化参数**。Binder LKL fuzzer 使用 protobuf 和 `libprotobuf-mutator`，包含一个持久的 context-manager 客户端和两个普通客户端。语义 harness 会保留盲目字节变异可能破坏的关系。<sup>[[15]](#references)</sup>

- 缓存先前操作返回的值。例如，`BC_FREE_BUFFER` 必须复用之前一次 `ioctl` 返回的 transaction-buffer 指针。
- 生成有效的默认回复，以便同步事务能够完成，并让后续操作仍可到达。
- 拒绝不可能的状态转换，例如向自身发起事务，或向同一目标发送多个待处理事务。
- 将单例引导状态保留在每次输入重置之外。Binder 每次启动只允许一次 `BINDER_SET_CONTEXT_MGR` 注册，因此反复销毁并重新创建该客户端会导致后续输入无效。

一种实用的生命周期竞态模板是：让一个客户端传递对象，同时启动线程或进程清理，并让接收客户端并发释放 transaction buffer。在 CVE-2020-0423 示例中，传递一个 `BINDER_TYPE_WEAK_BINDER` 后，`BINDER_THREAD_EXIT` 与 `BC_FREE_BUFFER` 发生竞态，可能会释放嵌入的 `binder_work`，而退出线程的清理路径仍在使用它。<sup>[[15]](#references)</sup>

#### 在用户态内核中重新引入可控的交错执行

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) 将真实内核代码链接到用户态 harness，并通过 `lkl_syscall` 暴露其 syscall 接口。这样可以轻松地在一个进程中协调 protobuf 状态、coverage 和 KASAN。不过，LKL 通常会在运行 syscall 时阻止其他内核线程中断它。对于竞态 campaign，可在选定的加锁/解锁和生命周期边界周围插入 `schedule()` 点，然后让 harness 在每次让出执行权时随机选择下一个客户端。应有针对性地设置这些点，因为每个点都会扩大调度搜索空间。研究人员描述的随机调度器**并不是**上游 Binder fuzzer 的一部分。<sup>[[15]](#references)</sup>

#### 构建并重放序列化的回归 seeds

上游 harness 固定使用兼容的 `libprotobuf-mutator`，通过 `LKL_FUZZING=1` 启用 LKL fuzzing instrumentation 和 KASAN，并通过 `MMU=1` 为 Binder 启用 `CONFIG_MMU`。<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

在检出一个故意包含漏洞的修订版本，或应用上游记录的回滚补丁后，序列化的种子便可重现整个多客户端状态转换，无需通过临时编写的 C 概念验证来重建它：<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

将 resulting KASAN use-after-free 视为 seed 已到达易受攻击的生命周期路径的确认。它**并不能**证明后续实现内核代码执行或权限提升所需的原语。<sup>[[16]](#references)</sup>

## 单机多样性技巧（Jackalope 风格）

一种实用方法是将**生成新颖性**与**覆盖率复用**结合起来：针对持久化服务器重启短生命周期 worker。每个 worker 从空 corpus 开始，运行 `T` 秒后同步，再基于合并后的 corpus 运行 `T` 秒，再次同步，然后退出。这样既能在每一代生成**新鲜结构**，又能利用累积的覆盖率。<sup>[[1]](#references)[[2]](#references)</sup>

**服务器：**

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

- `-in empty` 会在每轮生成时强制使用**全新的 corpus**。
- `-server_update_interval T` 可近似实现**延迟同步**（先发现新内容，之后再复用）。
- 在 grammar fuzzing 模式下，默认会跳过**初始服务器同步**（无需使用 `-skip_initial_server_sync`）。
- 最优 `T` **取决于目标**；通常在 worker 找到大部分“容易发现”的覆盖率后再切换效果最好。

## 针对难以构建 harness 的目标进行快照 Fuzzing

如果要测试的代码只有在付出大量初始化成本后才可达（例如启动 VM、完成登录、接收数据包、解析容器或初始化服务），一种实用的替代方案是**快照 fuzzing**：捕获就绪状态下的进程或 VM 状态，将每个测试用例注入目标输入路径，执行至崩溃/超时，然后恢复快照。这可以避免重复初始化或协议前缀处理，适用于**网络服务**、**固件**、**认证后的攻击面**和**仅有二进制文件的目标**。<sup>[[9]](#references)[[10]](#references)</sup>

1. 运行目标，直到到达所需状态。
2. 在此时对**内存 + 寄存器**进行快照。
3. 对每个测试用例，将变异后的输入直接写入相关的 guest/process 缓冲区。
4. 执行至崩溃/超时/重置。
5. 恢复快照；对于 VM 目标，如果支持，则只恢复**脏页**，然后重复。

尽可能将快照放在第一个高成本解析/分发步骤附近，例如 `recv`/`read` 之后或数据包反序列化的位置，并记录目标使用的输入缓冲区。这遵循自适应放置原则：将快照逐渐移入输入处理流程，以避免重复执行已有工作。<sup>[[11]](#references)</sup>

### 协议状态的增量快照

固定快照可以避免初始化成本，但无法单独探索需要多条有效消息才能完成的状态转换。LibAFL-Qemu harness 可以监视对协议状态字段的写入，并在状态变化时保存新快照。在 [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) 中，它会监视 `tcpcb.t_state`，对状态和响应标志进行哈希以去重快照，并将脏页相对于父快照存储。变异下一条结构化消息前，它会沿父快照链恢复选定的快照。测试用例会保存一个 `SnapshotId` 和生成的输入字节（`gen_bytes`）；快照管理器则跟踪重放所需的父子关系。<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu 的 user-mode `SnapshotModule` 会保存映射和目标内存，但不会保存 CPU 寄存器；必要时需单独保存寄存器。所述管理器支持一个根快照树，且不能在 worker 之间共享快照 ID。其多快照模式也不能直接复用 QASAN shadow state。离线分类时，应在单独的插桩进程中重建输入链。使用 `AsanHostModule` 和 `DrCovModule` 时，`fuzzer.evaluate_input` 会运行所需的 `pre_exec`/`post_exec` 回调；单独调用 `qemu.run` 则不会。<sup>[[27]](#references)[[28]](#references)</sup>

### 检测逻辑环形缓冲区越界读取

读取超过缓冲区*有效数据数量*的数据时，如果读取位置仍在主机分配的内存范围内，就可能逃过常规 ASAN 检测。[libslirp 紧急数据示例](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes)还会导致无符号字节计数下溢。如果有源代码，带符号/无符号整数溢出插桩可以检测到这一副作用；在抑制报告前，应先区分有意的 TCP 序列号回绕。一种更强的拟议 oracle 是对自定义环形分配区进行 poison，只在其内部 allocator 推进时取消对有效范围的 poison，并重新 poison 已释放范围。对于难以进行源代码插桩的目标，LibAFL-Qemu 提供了 ASAN poisoning API。<sup>[[27]](#references)</sup>

## 使用 MAccConc 探索 Linux Kernel 竞态

[MAccConc](https://github.com/googleprojectzero/MAccConc) 可将对时序敏感的 Linux-kernel 竞态转化为可重复的内存访问调度。它可以自动枚举双上下文 **A-B-A** 执行，也可以让分析人员在终端 UI/GUI 中施加顺序约束。这是实验性研究工具，而非完整的并发 fuzzing 工具：目前需要 LLVM 23+ 和项目修改过的 kernel，命令行工具支持两个测试线程，拟议中的 userspace fuzzing 层尚未实现。<sup>[[17]](#references)[[18]](#references)</sup>

### 收集跨上下文通信点

使用 KASAN outline callbacks 和修改过的 KCOV 内存记录支持构建插桩 kernel。项目 README 还建议禁用 sibling-call optimization，以便调用栈保持可用。<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode（`asan-instrumentation-with-call-threshold=0`）会将插桩访问转换为 helper 调用。MAccConc 内核补丁会禁用 `asan-opt-same-temp`，防止连续访问被合并；当需要检测全局变量竞态时，也要禁用 `asan-opt-globals` 优化。KCOV 会将生成的记录传递到用户态。比较不同执行上下文中的访问，并保留字节范围重叠且至少一方执行写操作的访问对；将 `kfree()` 建模为写操作，这样生命周期转换也会成为候选项。<sup>[[17]](#references)</sup>

对于脱离发起任务的工作，例如数据包处理或 RCU 回调，子系统必须传递 KCOV remote-coverage 句柄。上游 remote KCOV 需显式启用，不会自动覆盖任意后台工作，因此未传递句柄可能导致真实交互无法被检测到。<sup>[[17]](#references)[[19]](#references)</sup>

### 在每次运行中识别相同的动态访问

不要基于具体堆地址重放，因为每次分配后地址都可能变化；也不要只基于指令地址，因为在 `memcpy()` 和 `spin_lock()` 等 helper 中，指令地址无法唯一标识访问。MAccConc 使用**带计数的调用栈**：每个栈帧标识一个被调用函数及其在调用者中的调用次数，最后一个元素则标识内存访问指令。SanitizerCoverage 函数入口/出口记录让用户态能够重建这个动态标识符；即使地址发生变化或控制流中出现无关波动，该标识符仍保持稳定。<sup>[[17]](#references)</sup>

### 将候选访问对转换为强制调度

补丁版 `KCOV_SET_DI` ioctl 会将带计数的访问标识符关联到共享标志操作。<sup>[[17]](#references)</sup>

| 操作 | 语义 |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 在选定访问之前立即设置标志 *N*。 |
| `DI_STACK_WAIT` | 在选定访问之前自旋等待，直到标志 *N* 被设置或达到配置的上限。 |
| `DI_STACK_WAKE_POST` | 在选定访问之后立即设置标志 *N*。 |

对于部分 **A happens-before B** 约束，在 A 上附加 `DI_STACK_WAKE_POST`，并在 B 上附加 `DI_STACK_WAIT`，两者使用同一标志。对于完全指定的双上下文调度，先让 B 进入阻塞状态，然后让 A 唤醒 B，并在第一个交接点等待；B 在下一个交接点执行相反的操作。后一种方式类似确定性上下文切换，也是自动 A-B-A 探索器所使用的方式。<sup>[[17]](#references)</sup>

一个最简测试方案是将四个 hook 的测试用例（`test_setup`、两个线程函数和 `test_end`）编译为共享库，先收集不受约束的跟踪，然后枚举 A-B-A 候选项，或在可疑访问附近添加手动约束。<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

将超时与成功的重排序区分开来：由于锁或初始化/发布依赖，第二个上下文可能无法到达其注入点，因此请求的顺序可能无法实现。同时要注意 KASAN 的盲区：除非直接栈访问可能越界，否则通常不会被 hook；默认优化下会省略全局变量；当前编译器无法同时生成 ASAN 和 TSAN hook。最后，原型在 guest panic 时会丢失 KCOV 缓冲区，因此应保留独立的 crash 控制台/oracle。<sup>[[17]](#references)</sup>

对于未来由并发引导的 fuzzing，可记录每个输入或 syscall 的内存访问摘要，配对可能形成跨上下文通信点的操作，然后只探索这些组合。VM 快照可以稳定全局状态和地址；如果不使用快照，则可通过分配点元数据在不同运行之间抽象对象。这是一个拟议的扩展，并非当前 MAccConc 用户态工具的功能。<sup>[[17]](#references)</sup>

## Harness Introspection：尽早发现浅层 Fuzzer

当 campaign 陷入停滞时，问题往往不在 mutator，而在 **harness**。使用 **可达性/覆盖率内省**，找出从 fuzz target 静态可达、但动态覆盖很少或从未覆盖的函数。这些函数通常表明存在以下三种问题之一。<sup>[[12]](#references)</sup>

- harness 进入目标的时机过晚或过早。
- seed corpus 缺少一整类功能。
- 目标确实需要**第二个 harness**，而不是一个臃肿的“包办一切” harness。

如果你使用 OSS-Fuzz / ClusterFuzz 风格的工作流，Fuzz Introspector 可以比较静态可达性与运行时覆盖率，并根据定时运行或公开 corpus 生成报告。<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

使用报告来决定是否为未测试的 parser 路径添加新的 harness、扩展特定功能的 corpus，或将单体 harness 拆分为更小的入口。

## 基于图的 Fuzz 目标选择与 Mutation 分流

如果你已经有**静态分析结果**、**mutation testing 未能杀死的 mutant**和**覆盖率报告**，不要把它们当作互不相关的列表来分流。先构建**调用图**，为节点标注**圈复杂度**、**入口点/不可信输入可达性**以及任何外部发现，然后针对图提出问题。<sup>[[5]](#references)[[6]](#references)</sup>

- 哪些高复杂度函数可从不可信输入到达？
- 哪些 mutation survivor 位于从 parser/handler 到安全关键代码的路径上？
- 哪些函数是架构上的关键节点，具有异常大的**影响范围**？

这种方法通常比单看“覆盖率最低”能找到更好的 fuzz 目标。一个**复杂度高**且已确认可从外部到达的 parser/decoder，比一个覆盖率较低、但没有攻击者可控路径的孤立内部 helper 更适合作为 harness 候选。

### 实用分流工作流

1. 根据代码库构建**代码图**，并提取每个函数的复杂度/分支指标。
2. 列出接受攻击者可控输入的**入口点**：request handler、decoder、importer、协议 parser、CLI/文件读取器。
3. 从这些入口点执行路径查询，将可达的攻击面与仅在死代码/内部代码中出现的部分区分开来。
4. 优先处理同时具备以下特征的节点：
   - 高**圈复杂度**
   - 已确认可从不可信输入**到达**
   - **影响范围**大或有许多下游依赖项
   - 有佐证，例如 **SARIF** 发现、审计备注或 mutation survivor
5. 优先为得分最高的节点编写专用 harness，尤其是 **parser/codec**，例如 hex/Base64/IP/message decoder。

### Mutation survivor：等价还是可操作

Mutation testing 往往会产生嘈杂的 survivor 列表。在将每个 survivor 都视为安全缺陷之前，先用图来确认：

- 被 mutation 的函数是否可从攻击者可控的入口点到达？
- 所有调用路径是否都受到比被 mutation 的检查更强的不变量约束？
- 该节点是否位于死代码、仅负责格式处理的逻辑，或影响较大的算术/parser 路径中？

仍不可达或受到结构性约束的 survivor 通常是**等价 mutant**。仍然**可达**且涉及**边界条件**、**溢出/进位路径**或**安全关键算术/解析**的 survivor，则应纳入：

- 新的 fuzz harness
- 直接的属性/不变量测试
- 有针对性的边界情况向量

### 将外部发现关联到图上

如果你的 SAST pipeline 导出 **SARIF**，可按**文件 + 行范围**将发现映射到图节点，并利用该图扩展影响分析范围。<sup>[[6]](#references)</sup>

- 计算被标记函数的**影响范围**
- 检查该发现是否位于从某个入口点出发的路径上
- 将附近且最终汇聚到同一关键节点的发现归为一组

这在决定是否为特定函数投入 fuzzing 时间时很有用：一个**可达**、**复杂**且已有 **SAST 命中**的节点，通常比一个仅仅复杂、但没有攻击者可达路径的节点更值得优先测试。

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

关键方法论在于三者的交集：**复杂度 x 暴露面 x 影响**。使用图表挑选预期安全价值最高的 fuzz 目标，再根据变异后仍存活的样本，确定 harness 必须重点测试哪些边界和不变量。<sup>[[5]](#references)</sup>

## 加密密钥编码的差分 fuzzing

从有效的序列化密钥或标准测试向量开始。在不破坏到达导入和操作路径所需的长度与结构的前提下，变异编码字段，然后将相同字节提交给多个独立实现。比较它们是否接受输入以及返回的错误。随机化签名和密文需要正确性 oracle，而不是逐字节比较：验证签名，或比较一次封装/解封装往返过程得到的共享密钥。测试向量用于确认已知用例符合规范；差分变异则用于探测超出这些用例范围的格式错误编码。<sup>[[23]](#references)[[26]](#references)</sup>

对于这些密钥格式，请使用针对格式的 oracle：<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA 扩展签名密钥：**在保持密钥可解析的同时，将打包后的 `s1` 或 `s2` 系数变异到 `[-η, η]` 范围之外。检查导入或签名操作是否拒绝该密钥，以及生成的任何签名是否能通过验证。仅有接受行为的差异并不构成违反标准，因为 FIPS 204 并未要求进行额外的私钥检查。参见[条件泄漏机制](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)。
- **ML-KEM 密钥对：**将必需的封装密钥检查和解封装输入检查，与导入密钥对时可选的成对一致性检查（PCT）区分开。使用其公钥进行封装，再使用其私钥进行解封装，并比较共享密钥；即使单个密钥都通过输入检查，密钥不匹配仍可能导致加密通信中断。检查 API 是在操作过程中验证输入，还是通过单独的调用进行验证；libcrux 提供 `validate_public_key(pk)` 和 `validate_private_key(sk, ct)`，但它们不能替代 PCT。
- **XMSS/XMSSMT 原始密钥：**针对不同参数集测试序列化的**签名和验证**密钥往返，而不只是使用内存中的密钥执行操作。XMSS 和 XMSSMT 使用各自独立的四字节 OID 命名空间，因此，如果仅依据 OID 进行解析的解析器先尝试 XMSS，就可能将 OID 冲突的 XMSSMT 密钥错误分类并拒绝导入。报告中的 RustCrypto 解析器展示的是互操作性/可用性故障，而非签名伪造。

## 使用 gosentry 进行 Go Fuzzing：更强的引擎、类型化输入与差分检查

如果 Go 目标已有原生 `testing.F` harness，一个实用的升级方式是使用 [gosentry](https://github.com/trailofbits/gosentry) 运行同一 harness。gosentry 是一个 fork 版 Go 工具链，保留了 `go test -fuzz`，但将后端替换为 **LibAFL**。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

当原生 Go fuzzer 卡在**难以满足的比较**、**类型化输入**或**解析器密集型格式**上时，这种方法很有用。方法保持不变：

- 继续使用 `f.Add(...)` 添加种子，并使用 `f.Fuzz(...)` 设置回调。
- 重用相同的 harness，但使用 gosentry 的 `go` 二进制文件运行，而不是使用标准工具链。
- 将生成的 campaign 视为普通的 coverage-guided 运行，但使用 LibAFL 的调度/变异机制和更完善的周边检测器。

### 将静默故障转化为 fuzz 发现

Go 安全评估中一个反复出现的问题是，危险行为通常默认**不会**导致崩溃。使用 gosentry，可以将几类“有问题但静默”的状态提升为发现项。<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` 可让选定的日志/错误处理路径表现得像崩溃（适用于 `log.Fatal` 风格的代码路径，否则它们只会记录日志并继续执行）。
- `--catch-races=true` 可使用 Go race detector 重放新发现的队列条目。
- `--catch-leaks=true` 可使用 `goleak` 重放新队列条目，并在发现 goroutine 泄漏时停止。
- LibAFL 的挂起处理机制会将**无限循环/极慢输入**保留为 fuzz 发现，而不是让它们作为超时被丢弃。
- 默认内置算术溢出检查，并可通过 go-panikint 风格的插桩启用可选的截断检查。

对于安全影响表现为**不会引发 panic 的解析器故障**、**并发错误**或**仅导致 DoS 的挂起**，而非内存破坏的目标，这尤其有价值。

### 面向类型化 Go API 的结构体感知 fuzzing

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

在构建仅用于 fuzzing 的虚假 wire format 时，如果这样做会让 harness 专用解析代码掩盖逻辑 bug，就使用这种方式。对于 differential 或 grammar-based 测试活动，应将 harness 输入保持为单个 `[]byte` 或 `string`，并在 callback 内进行解析。

### 面向解析器和协议输入的基于语法的 fuzzing

对于解析器、格式和输入语言，gosentry 可以在 LibAFL 之上运行 **Nautilus grammar fuzzing**。语法是一个 JSON 生成规则数组，harness 通常应接受单个 `[]byte` 或 `string` 参数。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

方法论备注：

- 当字节级变异大多在早期语法检查中失效时，使用 grammar mode。
- 将 grammar 聚焦于语言/协议中与**安全相关的子集**，而不是对完整规范建模。
- 在终结符/非终结符中使用较大的边界值，以测试整数、长度和状态机边界。
- grammar mode 会使输入保持语法有效，但目标仍接收**字节/字符串**，因此解析和语义检查仍在经过 harness 处理的代码中进行。

### Differential fuzzing：比较实现，而不只是查找崩溃

Go 生态系统中一种有效的模式是**基于 grammar 的 differential fuzzing**：生成有效的结构化输入，并将其提供给两个解析器、客户端或状态转换引擎。<sup>[[7]](#references)[[8]](#references)</sup>

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

- 一个实现发生 panic，而另一个则干净地拒绝输入
- 接受/拒绝输入的结果不一致
- 解析树或解码后的对象不同
- 状态转换、nonce、余额或状态根出现差异

这是一种实用方法，可用于发现纯崩溃 fuzzing 经常遗漏的**共识不匹配**、**解析器歧义**和**规范与实现之间的偏差**。

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 复用 campaign 语料库生成覆盖率报告

campaign 结束后，重新运行已保存的队列语料库，即可生成 Go 覆盖率报告，无需手动导出单独的语料库。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

从**同一个 package**运行命令，并使用相同的 `-fuzz` 目标，以便 gosentry 解析正确的缓存 campaign 状态。

## References

- [1] [变异语法 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing 深入解析](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [五年后的 AFLNet：覆盖率引导的协议 fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark 将代码转换为图](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing 缺少一半工具集。我们 fork 了工具链来解决这个问题。](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer：一种使用快照的快速有状态网络协议 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [没有语法也没关系：探索在没有系统调用描述的情况下 fuzzing Linux 内核](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy：使用自适应可变快照实现高效 fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 插桩：路径和调用者覆盖率](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [预测式上下文敏感 fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 构建和回归种子文档](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc：通过受控的内存访问交错探索 Linux 内核竞态条件](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV：用于 fuzzing 的代码覆盖率](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 扩展文件名语法](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 安全公告：CFITSIO 2025 年第四季度](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [fuzzing CFITSIO 扩展文件名语法：16 个内存安全漏洞及 Codex 辅助分类](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [密码学的差分 fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203：基于模块格的密钥封装机制标准](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID 解析错误 - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [后量子密码实现现状](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [通过快照捕获 CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzer 对决 AI：比较 Fuzzilli 和 BigSleep 在 JavaScript 引擎上的表现](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
