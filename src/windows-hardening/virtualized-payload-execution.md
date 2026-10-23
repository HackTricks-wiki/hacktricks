# 虚拟化 Payload 执行与自定义 VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization 会将 offensive logic 编译为 guest 指令集，并由 native interpreter 执行。与最终必须在内存中暴露原始 native 指令的 packer 不同，virtualized payload 可以在整个生命周期中将受保护的逻辑保留为 bytecode。这样就消除了特定的解包窗口，但**不会**隐藏 host 可见的行为，例如 syscalls、网络活动或 VM-to-native 调用边界。<sup>[[2]](#references)[[3]](#references)</sup>

## 利用 WebAssembly re-hosting 绕过静态分析

无需修改具有大量特征签名的 Go 工具，可以将其编译为 `wasip1` guest，并嵌入另一个 native loader。构建 guest 时使用经过补丁修改的 GOROOT，其中 `net.Dial`、`net.Listen`、`os/exec` 和 `os.Pipe` 等不受支持的操作会通过 `//go:wasmimport` 进行委托；随后由 Wazero host module 实现 sockets、process 操作、Win32 调用和 macOS framework 调用。这样既保留了原始项目的 Go API 用法，又将大部分逻辑移入加密的 WASM module，使静态 PE 工具可能无法理解这些逻辑。<sup>[[4]](#references)</sup>

### 将 linear memory 桥接至 native API

Guest pointer 是指向 WASM linear memory 的 32 位偏移量，而不是 host virtual address。进行 native 调用前，只有当参数被标记为 local pointer 且位于 `0x10000 <= value < wasmMemorySize` 范围内时，桥接层才会转换该参数，生成 `wasmMemoryBase + value`。下限可避免改写较小的 handles、flags 和 `nil`；根据 `win32metadata` 生成的每 API mask 可区分真正的 pointers、handles、sizes 和 remote-process addresses，并通过覆盖规则处理不准确或含糊的 metadata。<sup>[[4]](#references)</sup>

Native API 也可能通过 guest output buffer 返回 host pointers。Mirror table 可以为这类对象分配 guest-memory 表示，并保留指向原始 host address 的反向映射。COM 需要同时镜像 interface 和 vtable：可以跟随并镜像 data pointers；而 `MEM_IMAGE` 区域中的 executable pointers 必须保留为不透明 tokens，因为 WASM 无法执行 native 指令。此模型不直接支持 `EnumWindows` 或 `SetWindowsHookEx` 等 host-to-guest callback API。<sup>[[4]](#references)</sup>

### 每次构建进行 WASM VM polymorphism

每次构建时都可以一并转换 runtime 和 payload：打乱 opcode-to-handler table，将每个 guest opcode 改写为新的映射，随机化 section identifiers，将标准 `\0asm` magic 替换为构建专属 marker，并更改 runtime cache magic。同一份源代码由此会生成字节级不同的 modules；在分析者从 host loader 中恢复自定义映射和 framing 之前，普通 WASM 工具无法解析 payload。<sup>[[4]](#references)</sup>

进行 reverse engineering 时，应从 native host 入手，而不是只通过 `\0asm` 特征提取文件：识别编译后的 marker、module 解密路径、opcode dispatch table 和 `env` host-function registrations，然后重建标准 module，或对 import 边界进行插桩。即使嵌入的 bytecode 在不同构建间发生变化，桥接层仍是有用的行为观测点，因为网络、进程创建、registry 访问、动态加载和通用 Win32 dispatch 调用都会经过此处。<sup>[[4]](#references)</sup>

### 伪装外层 Go executable

仅修改 guest 仍会留下易识别的 loader。示例中的外层 binary 转换会将从合法 Go 项目中提取的密集 symbol profiles 拼接进 `gopclntab`，轮换一小组看似合理的 DLL imports，并变更 PE `VERSIONINFO` 和 Authenticode identity strings。这些转换针对的是 container 的静态特征和机器学习特征；它们不会移除 host shims 暴露的 runtime 行为。<sup>[[4]](#references)</sup>

## 执行模型

紧凑的 virtualized loader 可将执行划分为以下几层。<sup>[[3]](#references)</sup>

1. 通过 LLVM 将 freestanding C、BOF source 或 runtime libraries 编译为自定义 bytecode ISA。
2. 启动小型 native interpreter，并初始化构建专属的 opcode mapping。
3. 将 PE linker-loader 本身作为 bytecode 运行：解析 headers、映射 sections、应用 relocations、解析 imports，并填充 IAT。
4. 将 guest-to-guest 调用保留在 interpreter 内部。对于 bytecode 区域之外的目标（例如导入的 DLL functions），则通过 native host-call thunk 路由调用。
5. 将 HTTP framing、TLS 和部分 C runtime 等支持设施也置于同一 interpretation 边界之后。

这种模型无需为每个 plugin 分配单独的 native code region，也能避免原始 payload 以易识别的 x86-64 指令流形式出现。但它仍是 evasion/obfuscation 边界，而非安全边界：native interpreter 和每一种外部效应仍可被观察到。<sup>[[2]](#references)[[3]](#references)</sup>

## 共享内存 Host Bridge

隔离 VM 会将 pointers 表示为 guest buffer 中的偏移量，因此每次跨越 host API 时都需要转换 pointers，并特殊处理 output parameters。共享内存 VM 则让 guest addresses 成为有效的 host-process addresses。因此，读写可使用 `memcpy` 风格的操作，native allocation ECALL 返回的 pointer 也可以直接由 bytecode 解引用。RISC-Y Business 展示了这种设计可以将桥接层简化为获取 PEB 并执行任意 host calls。<sup>[[1]](#references)</sup>

对于 Windows x64，virtual register file 可以匹配 ABI：将前四个整数或 pointer 参数放入 `RCX`、`RDX`、`R8` 和 `R9`，后续参数和 shadow space 则放在 stack 上。当 virtual `CALL` 解析到 bytecode 范围之外时，通用 thunk 会将该状态编组为 native call，并将返回值复制回 VM。这样无需修正 pointers 即可调用 IAT、分配 heap，以及执行 socket 操作。<sup>[[2]](#references)[[3]](#references)</sup>

代价是完全失去隔离。Guest memory corruption 可直接影响 host；native callees 可以保留或修改 guest pointers；interpreter 必须将 bytecode 视为完全可信。Native-to-VM callbacks 也需要反向桥接；只支持 outbound calls 的 VM 无法直接满足 `EnumWindows` 等基于 callback 的 API。<sup>[[1]](#references)[[3]](#references)</sup>

## 每次构建进行 ISA polymorphism

固定宽度的自定义 ISA 可简化解码、dispatch、relocation 和 virtual-register mapping。Centurion 使用 18 字节、受 x86-64 启发的指令格式，以降低代码密度为代价换取可预测的解析方式，同时也为将现有 x86-64 artifacts 转换为 bytecode 留下了可能性。<sup>[[3]](#references)</sup>

每次构建随机化 opcode-to-handler mapping，可使相同的 guest logic 生成不同的字节序列。进一步加密 mapping table，并仅在 runtime 恢复它，就能移除磁盘上稳定的 opcode 字典。这会干扰固定特征签名和可复用的反汇编规则，但不会自动改变 native dispatcher、table-decryption routine 或 host-call boundary 的多态性。<sup>[[3]](#references)</sup>

## 将执行环境纳入 VM

Host process 可以缩减为 memory、syscall 和 socket primitives，由 freestanding libraries 在 VM 内提供更高层的服务。例如，FreeRTOS coreHTTP 可以处理 HTTP framing，mbedTLS 可以实现 TLS，而无需调用 WinHTTP 或 operating-system TLS API。通过 `afd.sys` 或类似接口使用 raw sockets，便可形成较窄的 native networking boundary。<sup>[[3]](#references)</sup>

这种 **Bring Your Own Execution Environment (BYOEE)** 设计还可以将 PE loading、runtime support 和 in-memory filesystem 放在 interpreter 之后。它减少了易识别的 native implementations，但不会消除 telemetry：raw socket 操作仍可见；此外，需要显式 proxies 或 TLS interception 的环境可能会导致这种网络设计无法工作。<sup>[[3]](#references)</sup>

## 选择性 Native 加速

解释执行每条指令的开销在 public-key cryptography 中尤其高。一种实用的拆分方式是将 mbedTLS 的 `MBEDTLS_ALT` hooks 用作 software-coprocessor interface：将 TLS state、certificate parsing、negotiation、allocation 和高层 bignum code 留在 bytecode 中，但通过 native ECALLs dispatch `bignum_core.c` 中的热点 arithmetic kernels。在 Centurion prototype 中，`bignum.c`、`bignum_mod.c` 和 `bignum_mod_raw.c` 保持虚拟化，而内部循环由 native code 执行，将 ECDHE handshake 的耗时从几分钟缩短至几秒。<sup>[[3]](#references)</sup>

应将 accelerators 设为可选，这样不需要 TLS 的 payload 就可以省略额外的 native entry points。这种模式适用于任何 interpreter workload：先进行性能分析，然后只开放尽可能小的 native primitive，而不是将整个 subsystem 移出 VM。<sup>[[3]](#references)</sup>

Centurion 使用 TLS 1.2 bind shell 验证了完整链路：bytecode loader 映射 PE，socket calls 通过 universal thunk，mbedTLS 在 VM 内处理 protocol，native ECALLs 则加速 ECDHE arithmetic。因此，这个约 18 KB 的 native interpreter 能够支持加密的 command channel，而无需将 payload 物化为 native x86-64 code。<sup>[[3]](#references)</sup>

## Reverse Engineering 与检测切入点

以下是根据架构推导出的实用分析切入点；virtualization 会改变分析人员观察行为的位置，但不会消除行为本身。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- 找出 fetch/decode/dispatch loop、virtual program counter、register file，以及重复的固定宽度指令步进过程。
- 在 runtime 解密后 dump opcode table，并将 handler addresses 映射回语义操作，而不是匹配磁盘上的加密 bytecode。
- 在 universal thunk 或 ECALL dispatcher 处设置断点，记录 native target、virtual argument registers、stack arguments 和返回值。
- 即使 loader implementation 本身是 bytecode，也要追踪 PEB 访问、export resolution、PE-header parsing、relocation writes 和 IAT population。
- 将 socket 创建和 `afd.sys` 流量与缺少预期的 WinHTTP 或 native TLS 调用联系起来；缺少高层 imports 是线索，但不能证明行为无害。
- 将 native arithmetic accelerators 视为语义瓶颈：其调用者可以揭示 key exchange 和 certificate-validation 活动，即便周围的 TLS state machine 仍处于虚拟化状态。

对于从 dispatcher 而非原始 control-flow graph 入手的分析工作流程，请参阅[有关 virtualizing packers 的 malware-analysis 指南](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation)。

## 运行约束

Virtualization 会带来 interpretation overhead，增加 toolchain 和 ABI 的复杂性，也无法解决基于行为的检测。共享内存从设计上就不安全；raw-socket networking 可能无法通过强制代理工作；callback 密集型 Win32 API 需要 native-to-VM trampolines。Interpreter、syscall bridge 和任何 native accelerators 也仍会留下常规的 native footprint，防御者可以对其进行特征检测或插桩。<sup>[[2]](#references)[[3]](#references)</sup>

## 相关页面

有关 VMProtect 3.x packing 的分析，请参阅 [emulated unpacking and import repair](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair)。

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business：构建用于 Payload Obfuscation 的 RISC-V Virtual Machine](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT：EDR 时代的 Red Teaming——通过 Malware Virtualisation 实现 Evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian：Centurion——自带执行环境](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian：进入 WasmForge：将 Sliver 编译为 WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
