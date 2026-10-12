# 虚拟化 Payload 执行与自定义 VM evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization 会将 offensive logic 编译为 guest instruction set，并通过 native interpreter 执行。与最终必须在内存中暴露原始 native instructions 的 packer 不同，虚拟化 payload 可以在整个生命周期中将受保护逻辑保留为 bytecode。这样可以消除特定的 unpacking 窗口，但**不会**隐藏 host 可见的行为，例如 syscalls、网络活动或 VM-to-native 调用边界。<sup>[[2]](#references)[[3]](#references)</sup>

## 用 WebAssembly re-hosting 绕过静态分析

不必修改带有大量特征签名的 Go 工具，可以将其编译为 `wasip1` guest，并嵌入独立的 native loader。Guest 基于经过修补的 GOROOT 构建，其中 `net.Dial`、`net.Listen`、`os/exec` 和 `os.Pipe` 等不受支持的操作会通过 `//go:wasmimport` 委托执行；Wazero host module 则实现 sockets、进程操作、Win32 calls 和 macOS framework calls。这样既保留了原项目对 Go API 的使用，又将大部分逻辑移入加密的 WASM module，而静态 PE 工具可能无法理解该 module。<sup>[[4]](#references)</sup>

### 将 linear memory 桥接到 native APIs

Guest pointer 是指向 WASM linear memory 的 32 位 offset，而不是 host virtual address。在 native 调用之前，bridge 只会在参数被标记为 local pointer，且位于 `0x10000 <= value < wasmMemorySize` 范围内时转换该参数，结果为 `wasmMemoryBase + value`。较低的边界可避免改写小型 handles、flags 和 `nil`；根据 `win32metadata` 生成的每个 API 的 mask 用于区分实际 pointers、handles、sizes 和 remote-process addresses，并可针对不准确或含糊的 metadata 设置覆盖项。<sup>[[4]](#references)</sup>

Native APIs 也可能通过 guest output buffers 返回 host pointers。Mirror table 可以为这类对象分配 guest-memory 表示，并保留到原始 host address 的反向映射。COM 需要同时镜像 interface 和 vtable：可以跟踪并镜像 data pointers，但 `MEM_IMAGE` 区域中的 executable pointers 必须保持为不透明 token，因为 WASM 无法执行 native instructions。此模型不直接支持 `EnumWindows` 或 `SetWindowsHookEx` 等 host-to-guest callback APIs。<sup>[[4]](#references)</sup>

### 每次构建都进行 WASM VM polymorphism

每次构建时都可以同时转换 runtime 和 payload：打乱 opcode-to-handler table，将每个 guest opcode 重写为新映射，随机化 section identifiers，用特定于构建的 marker 替换标准 `\0asm` magic，并更改 runtime cache magic。这样，即使源代码相同，生成的 modules 在字节层面也会不同；分析人员必须先从 host loader 中恢复自定义映射和 framing，普通 WASM 工具才能解析 payload。<sup>[[4]](#references)</sup>

进行 reverse engineering 时，应从 native host 入手，而不是只通过搜索 `\0asm` 来提取内容：识别编译后的 marker、module-decryption 路径、opcode dispatch table 和 `env` host-function registrations，然后重建标准 module 或对 import 边界进行插桩。即使内嵌 bytecode 在不同构建间发生变化，bridge 仍是有用的行为 choke point，因为网络、进程创建、registry 访问、动态加载和通用 Win32 dispatch 调用都会经过它。<sup>[[4]](#references)</sup>

### 伪装外层 Go executable

只更改 guest 仍会留下容易识别的 loader。已演示的外层 binary transformations 会将从合法 Go 项目中提取的密集 symbol profiles 拼接到 `gopclntab` 中，轮换一小组看似合理的 DLL imports，并更改 PE `VERSIONINFO` 和 Authenticode identity strings。这些转换针对容器的静态特征和机器学习特征；它们不会移除 host shims 暴露的 runtime 行为。<sup>[[4]](#references)</sup>

## 执行模型

一个精简的虚拟化 loader 可以将执行拆分为以下层次。<sup>[[3]](#references)</sup>

1. 通过 LLVM 将 freestanding C、BOF source 或 runtime libraries 编译为自定义 bytecode ISA。
2. 启动小型 native interpreter，并初始化特定于构建的 opcode mapping。
3. 将 PE linker-loader 本身作为 bytecode 运行：解析 headers、映射 sections、应用 relocations、解析 imports，并填充 IAT。
4. 在 interpreter 内部处理 guest-to-guest 调用。对于 bytecode 区域之外的目标（例如 imported DLL functions），则通过 native host-call thunk 进行调用。
5. 将 HTTP framing、TLS 和部分 C runtime 等辅助功能移至相同的 interpretation boundary 之后。

这种模型无需为每个 plugin 分配单独的 native code region，并能避免原始 payload 以可识别的 x86-64 instruction stream 形式出现。它仍然只是一个 evasion/obfuscation 边界，而非安全边界：native interpreter 和所有外部行为仍然可被观察。<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

隔离 VM 会将 pointers 表示为 guest buffer 中的 offsets，因此每次跨越 host API 都需要转换 pointers，并对 output parameters 进行特殊处理。Shared-memory VM 则会让 guest addresses 成为有效的 host-process addresses。因此，读取和写入可以使用 `memcpy` 风格的操作，而 native allocation ECALL 返回的 pointer 可由 bytecode 直接解引用。RISC-Y Business 展示了这种设计可以将 bridge 简化为获取 PEB 并发起任意 host calls。<sup>[[1]](#references)</sup>

对于 Windows x64，virtual register file 可以与 ABI 保持一致：前四个整数或 pointer 参数放入 `RCX`、`RDX`、`R8` 和 `R9`，后续参数和 shadow space 放在 stack 上。当 virtual `CALL` 解析到 bytecode 范围之外时，通用 thunk 会将状态编组为 native call，并将返回值复制回 VM。这样便可调用 IAT、分配 heap 和执行 socket 操作，而无需进行 pointer fixups。<sup>[[2]](#references)[[3]](#references)</sup>

这种设计的代价是完全失去隔离。Guest memory corruption 会直接影响 host，native callees 可以保留或修改 guest pointers，而 interpreter 必须将 bytecode 视为完全可信。Native-to-VM callbacks 也需要反向 bridge；只支持 outbound calls 的 VM 无法直接满足 `EnumWindows` 这类基于 callback 的 API。<sup>[[1]](#references)[[3]](#references)</sup>

## 每次构建都进行 ISA polymorphism

固定宽度的自定义 ISA 可简化 decoding、dispatch、relocation 和 virtual-register mapping。Centurion 使用 18 字节、受 x86-64 启发的 instruction format，以牺牲代码密度换取可预测的解析方式，同时也为将现有 x86-64 artifacts 转换为 bytecode 提供了可能。<sup>[[3]](#references)</sup>

每次构建都随机化 opcode-to-handler mapping，可以让相同的 guest logic 生成不同的字节序列。加密 mapping table 并仅在 runtime 恢复它，还能进一步消除磁盘上稳定存在的 opcode dictionary。这会干扰固定 signatures 和可复用的 disassembly rules，但不会自动改变 native dispatcher、table-decryption routine 或 host-call boundary。<sup>[[3]](#references)</sup>

## 将执行环境移入 VM

Host process 可以精简为 memory、syscall 和 socket primitives，而 freestanding libraries 则在 VM 内提供更高级别的服务。例如，FreeRTOS coreHTTP 可以处理 HTTP framing，mbedTLS 可以实现 TLS，而无需调用 WinHTTP 或操作系统的 TLS API。此时，通过 `afd.sys` 或类似接口使用 raw sockets，便成为范围较窄的 native networking boundary。<sup>[[3]](#references)</sup>

这种 **Bring Your Own Execution Environment (BYOEE)** 设计还可以将 PE loading、runtime support 和 in-memory filesystem 放在 interpreter 之后。它减少了容易识别的 native implementations，但不会消除 telemetry：raw socket 操作仍然可见；此外，要求显式代理或 TLS interception 的环境也可能导致该网络设计无法工作。<sup>[[3]](#references)</sup>

## 选择性 native 加速

解释执行每条指令在公钥加密中尤其耗时。一种实用的拆分方式是将 mbedTLS 的 `MBEDTLS_ALT` hooks 用作 software-coprocessor interface：将 TLS state、certificate parsing、negotiation、allocation 和高层 bignum code 保留在 bytecode 中，但通过 native ECALLs 调用 `bignum_core.c` 中的热点算术内核。在 Centurion prototype 中，`bignum.c`、`bignum_mod.c` 和 `bignum_mod_raw.c` 保持虚拟化，而内层循环由 native 代码执行，使 ECDHE handshake 从数分钟缩短至数秒。<sup>[[3]](#references)</sup>

应将 accelerators 设计为可选项，让不需要 TLS 的 payloads 可以省略额外的 native entry points。这种模式适用于任何 interpreter workload：先进行性能分析，再开放尽可能小的 native primitive，而不是将整个子系统移出 VM。<sup>[[3]](#references)</sup>

Centurion 使用 TLS 1.2 bind shell 验证了完整链路：bytecode loader 映射 PE，socket calls 通过 universal thunk，mbedTLS 在 VM 内处理协议，而 native ECALLs 加速 ECDHE 算术。因此，这个约 18 KB 的 native interpreter 无需将 payload 还原为 native x86-64 代码，就能支持加密命令通道。<sup>[[3]](#references)</sup>

## Reverse engineering 与检测切入点

以下是根据架构总结出的实用分析切入点；virtualization 改变了分析人员观察行为的位置，但不会消除行为本身。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- 识别 fetch/decode/dispatch loop、virtual program counter、register file 和重复的固定宽度指令步进。
- 在 runtime decryption 后 dump opcode table，并将 handler addresses 映射回语义操作，而不是匹配磁盘上的加密 bytecode。
- 在 universal thunk 或 ECALL dispatcher 处设置断点，记录 native target、virtual argument registers、stack arguments 和返回值。
- 即使 loader 实现本身是 bytecode，也要跟踪 PEB 访问、export resolution、PE-header parsing、relocation writes 和 IAT population。
- 将 socket creation 和 `afd.sys` traffic 与缺少预期的 WinHTTP 或 native TLS calls 关联起来；缺少高级别 imports 是一条线索，但不能证明行为良性。
- 将 native arithmetic accelerators 视为语义 choke points：即使周围的 TLS state machine 保持虚拟化，它们的调用方仍可能揭示 key exchange 和 certificate-validation 活动。

如果分析流程从 dispatcher 而非原始 control-flow graph 开始，请参阅[关于虚拟化 packers 的 malware-analysis 指南](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation)。

## 操作限制

Virtualization 会带来解释执行开销，增加 toolchain 和 ABI 的复杂性，而且无法解决行为检测问题。Shared memory 从设计上就不安全，raw-socket networking 可能无法通过强制代理，而 callback 密集型 Win32 APIs 需要 native-to-VM trampolines。Interpreter、syscall bridge 和任何 native accelerators 仍会留下常规的 native footprint，防御方可以对它们进行签名检测或插桩。<sup>[[2]](#references)[[3]](#references)</sup>

## 相关页面

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
- [4] [Praetorian - 进入 WasmForge：将 Sliver 编译为 WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
