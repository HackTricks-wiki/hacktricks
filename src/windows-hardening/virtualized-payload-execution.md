# Virtualized Payload Execution and Custom VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization 将 offensive logic 编译为 guest 指令集，并通过 native interpreter 执行。与最终必须在内存中暴露原始 native 指令的 packer 不同，virtualized payload 可在其整个生命周期中将受保护的逻辑保持为 bytecode。这消除了特定的 unpacking 窗口，但**不会**隐藏 host 可见的行为，例如 syscalls、网络活动或 VM-to-native 调用边界。<sup>[[2]](#references)[[3]](#references)</sup>

## Execution model

精简的 virtualized loader 可将执行分为以下层次。<sup>[[3]](#references)</sup>

1. 通过 LLVM 将 freestanding C、BOF source 或 runtime libraries 编译为 custom bytecode ISA。
2. 启动一个小型 native interpreter，并初始化特定于 build 的 opcode mapping。
3. 将 PE linker-loader 本身作为 bytecode 运行：解析 headers、映射 sections、应用 relocations、解析 imports，并填充 IAT。
4. 在 interpreter 内部处理 guest-to-guest 调用。对于 bytecode 区域之外的目标（例如导入的 DLL functions），则通过 native host-call thunk 路由。
5. 将 HTTP framing、TLS 和部分 C runtime 等支持功能也放到同一个 interpretation 边界内。

这种模型无需为每个 plugin 分配单独的 native code 区域，也能避免原始 payload 以可识别的 x86-64 指令流形式出现。但它仍然只是一个 evasion/obfuscation 边界，而非安全边界：native interpreter 和所有外部效果仍然可被观察到。<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

隔离的 VM 会将 pointers 表示为 guest buffer 中的 offsets，因此每次调用 host API 都需要转换 pointers，并对 output parameters 进行特殊处理。而 shared-memory VM 会让 guest addresses 成为有效的 host-process addresses。因此，读取和写入可以使用类似 `memcpy` 的操作，而 native allocation ECALL 返回的 pointer 也可由 bytecode 直接解引用。RISC-Y Business 展示了这种设计如何将 bridge 简化为获取 PEB 并发起任意 host calls。<sup>[[1]](#references)</sup>

对于 Windows x64，virtual register file 可以与 ABI 保持一致：将前四个整数或 pointer arguments 放入 `RCX`、`RDX`、`R8` 和 `R9`，其余 arguments 和 shadow space 放在 stack 上。当 virtual `CALL` 解析到 bytecode 范围之外时，通用 thunk 会将该状态编组为 native call，并将返回值复制回 VM。这样无需修正 pointers，就能调用 IAT、分配 heap 内存以及执行 socket 操作。<sup>[[2]](#references)[[3]](#references)</sup>

这种方式的代价是完全失去隔离。Guest memory corruption 会直接影响 host，native callees 可以保留或修改 guest pointers，而 interpreter 必须将 bytecode 视为完全可信。Native-to-VM callbacks 也需要反向 bridge；仅支持 outbound calls 的 VM 无法直接满足 `EnumWindows` 等基于 callbacks 的 API。<sup>[[1]](#references)[[3]](#references)</sup>

## Per-build ISA polymorphism

固定宽度的 custom ISA 可简化 decoding、dispatch、relocation 和 virtual-register mapping。Centurion 使用 18-byte、受 x86-64 启发的指令格式，以牺牲 code density 换取可预测的解析方式，同时也为将现有 x86-64 artifacts 转换为 bytecode 留下可能的路径。<sup>[[3]](#references)</sup>

为每个 build 随机化 opcode-to-handler mapping，可使相同的 guest logic 生成不同的 byte sequences。对 mapping table 加密并仅在 runtime 恢复，还能进一步消除稳定的磁盘 opcode dictionary。这会妨碍固定 signatures 和可复用的 disassembly rules，但不会自动改变 native dispatcher、table-decryption routine 或 host-call 边界的形态。<sup>[[3]](#references)</sup>

## Bringing the execution environment into the VM

Host process 可以精简为 memory、syscall 和 socket primitives，而由 freestanding libraries 在 VM 内提供更高级的服务。例如，FreeRTOS coreHTTP 可以实现 HTTP framing，mbedTLS 可以实现 TLS，而无需调用 WinHTTP 或 operating-system TLS API。通过 `afd.sys` 或类似接口使用 raw sockets，便构成了范围较窄的 native networking 边界。<sup>[[3]](#references)</sup>

这种 **Bring Your Own Execution Environment (BYOEE)** 设计还可以将 PE loading、runtime support 和 in-memory filesystem 放到 interpreter 后面。它减少的是可识别的 native implementations，而不是 telemetry：raw socket 操作仍然可见；此外，要求使用 explicit proxies 或 TLS interception 的环境也可能导致这种 networking 设计无法运行。<sup>[[3]](#references)</sup>

## Selective native acceleration

解释执行每条指令在 public-key cryptography 中尤其耗时。一种实用的拆分方式是将 mbedTLS 的 `MBEDTLS_ALT` hooks 作为 software-coprocessor interface：在 bytecode 中保留 TLS state、certificate parsing、negotiation、allocation 和高层 bignum code，但通过 native ECALLs 调用 `bignum_core.c` 中的热点 arithmetic kernels。在 Centurion prototype 中，`bignum.c`、`bignum_mod.c` 和 `bignum_mod_raw.c` 保持 virtualized，而内层循环由 native code 执行，将 ECDHE handshake 的耗时从数分钟缩短到数秒。<sup>[[3]](#references)</sup>

应将 accelerators 设为可选，以便不需要 TLS 的 payloads 可以省略额外的 native entry points。这一模式适用于任何 interpreter workload：先进行 profiling，再暴露尽可能小的 native primitive，而不是将整个 subsystem 移出 VM。<sup>[[3]](#references)</sup>

Centurion 使用 TLS 1.2 bind shell 验证了完整链路：bytecode loader 映射 PE，socket calls 通过通用 thunk，mbedTLS 在 VM 内处理 protocol，而 native ECALLs 加速 ECDHE arithmetic。因此，这个约 18 KB 的 native interpreter 无需将 payload 物化为 native x86-64 code，就能支持加密的 command channel。<sup>[[3]](#references)</sup>

## Reversing and detection anchors

以下是根据架构推导出的实用分析切入点；virtualization 会改变分析人员观察行为的位置，但不会消除行为本身。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- 识别 fetch/decode/dispatch loop、virtual program counter、register file，以及重复的固定宽度指令步进。
- 在 runtime decryption 后 dump opcode table，并将 handler addresses 映射回语义操作，而不是匹配磁盘上的加密 bytecode。
- 在通用 thunk 或 ECALL dispatcher 处设置断点，记录 native target、virtual argument registers、stack arguments 和返回值。
- 即使 loader implementation 本身是 bytecode，也要追踪 PEB 访问、export resolution、PE-header parsing、relocation writes 和 IAT population。
- 将 socket creation 和 `afd.sys` traffic 与缺少预期的 WinHTTP 或 native TLS calls 相关联；缺少高层 imports 是线索，而非无害行为的证明。
- 将 native arithmetic accelerators 视为语义上的 chokepoints：即使周围的 TLS state machine 仍是 virtualized，其 callers 也可能揭示 key exchange 和 certificate-validation 活动。

对于从 dispatcher 而非原始 control-flow graph 开始的分析工作流，请参阅[关于 virtualizing packers 的 malware-analysis 指南](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation)。

## Operational constraints

Virtualization 会带来 interpretation overhead，增加 toolchain 和 ABI 的复杂性，也无法解决 behavioral detection。Shared memory 在设计上并不安全，raw-socket networking 在强制使用 proxies 的环境中可能失效，而 callback 密集型 Win32 APIs 需要 native-to-VM trampolines。Interpreter、syscall bridge 和任何 native accelerators 也仍然构成常规的 native footprint，防御方可以对其进行 signature 匹配或 instrument。<sup>[[2]](#references)[[3]](#references)</sup>

## Related pages

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business：构建用于 Payload Obfuscation 的 RISC-V Virtual Machine](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT：EDR 时代的 Red Teaming——通过 Malware Virtualisation 实现 Evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian：Centurion——自带 Execution Environment](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
