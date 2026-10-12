# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## 为什么基于元数据的栈展开可以被欺骗

一些 macOS 安全工具会将线程栈采集工作交给 `/usr/sbin/spindump`，或以其他方式信任常规的、基于元数据的栈展开器。implant 可以利用这一信任边界，在自己的栈上放置符合 ABI 的合成记录，使敏感 API 看起来像是经由攻击者选定的 dyld 和已加载的 Apple 框架中的函数调用，而不是由没有后备映像的 implant 代码直接调用。这属于遥测欺骗，不会更改可执行文件或其展开元数据。<sup>[[1]](#references)</sup>

关于采集端的背景，请参阅 [macOS stackshots 和 `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots)。

栈展开器无法证明某条记录是由编译器生成的序言创建的。它会反复使用当前 `PC` 选择一个 Mach-O 规则，将该规则应用于 `SP`、`x29`、`x30`、栈内存以及任何声明的非易失寄存器，然后使用恢复出的调用者 `PC` 选择下一条规则。如果攻击者控制的内存满足每条选定规则，那么即使这些调用从未发生，生成的调用链在结构上仍然有效，也能解析出符号。<sup>[[1]](#references)</sup>

## ARM64 帧状态

[ARM64 汇编概览](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)介绍了寄存器的作用和调用约定。对于通过 `stp x29, x30, [sp, #-16]!` 后接 `mov x29, sp` 创建的常规栈帧，表示调用者入口 `SP` 的规范帧地址（CFA）为 `FP+0x10`：<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Frame records 通过 `[FP]` 构成链表，但盲目沿着该链表遍历并不足够：叶函数可能没有帧，尾调用可能移除逻辑上的调用转换，而特殊布局会使用 DWARF CFI。当前地址对应的 recipe 决定 unwinder 是否会读取 FP 链。<sup>[[1]](#references)[[4]](#references)</sup>

## 选择 Mach-O unwind recipe

最终链接的映像会在 `__TEXT,__unwind_info` 中存储 compact unwind 数据。该 section 的 header 指向一个一级函数索引；每个索引范围指向常规（`kind=2`）或压缩（`kind=3`）二级页面。compact unwind 无法描述的布局会使用 `__eh_frame` 中的 FDE 和 call-frame instructions。<sup>[[1]](#references)[[2]](#references)</sup>

对于每个候选运行时 PC：<sup>[[1]](#references)[[2]](#references)</sup>

1. 仅为查找而去除或规范化 ARM64e PAC 位。
2. 找出其可执行 `__TEXT` 范围包含该地址的已加载 Mach-O。
3. 计算 `functionOffset = normalizedPC - loadedImageBase`，并拒绝负值或大于 `UINT32_MAX` 的结果。
4. 选择满足 `index[i].functionOffset <= functionOffset < index[i+1].functionOffset` 的一级范围。
5. 解析所引用的二级页面，选择起始位置不大于该 offset 的最接近条目，并验证地址低于下一个条目或一级范围的末尾。
6. 解码该条目，并构造其描述的精确状态。

当地址来自已保存的 LR 时，查找可能会使用 `PC-1`，使紧跟在调用之后的地址仍落在调用者覆盖的范围内。这会改变 recipe 的选择，而不会改变任何栈偏移。<sup>[[1]](#references)</sup>

解析器必须对每个 header 和数组执行边界检查，要求 section version 为 `1`，处理最后一个一级哨兵项，拒绝为零的二级页面 offset，并区分常规页面和压缩页面。在常规页面中，`entryPageOffset` 相对于该页面的起始位置，而一级页面 offset 则相对于 `__unwind_info` 的起始位置。<sup>[[1]](#references)[[2]](#references)</sup>

宽泛模式由 `encoding & 0x0F000000` 决定。当前 LLVM 定义包含以下模式；解析器不应将所有非 DWARF 值都视为经典帧：<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Value | Caller recovery |
| --- | --- | --- |
| 无 compact recipe | `0x00000000` | 停止或使用独立的 fallback。 |
| 无帧 | `0x02000000` | 将编码的栈大小加到当前 `SP`；调用者 PC 为 live LR。 |
| DWARF | `0x03000000` | 执行由低 24 位标识的 FDE/CFI。 |
| 帧 | `0x04000000` | 读取常规 `x29` frame record。 |
| 带认证 LR 范围的 arm64e 帧 | `0x05000000` | 处理 `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`；其 offset 字段用于定位覆盖范围内的 `pacibsppc`。 |

对于无帧模式，`stackSize = ((encoding & 0x00FFF000) >> 12) * 16`。对于帧模式，最低五位声明连续保存的 GPR 对，从 `x19/x20` 到 `x27/x28`；`0x100-0x800` 位则以类似方式声明 `d8-d15` 对。要找到下一个 PC，可能不需要这些已保存的寄存器，但可信的虚拟调用者状态必须满足 consumer 重建的每个字段。<sup>[[1]](#references)[[2]](#references)</sup>

## 构造合成的帧模式记录

构造过程是反向推导 unwinder 的行为，而不是在栈中扫描看似地址的值：<sup>[[1]](#references)</sup>

1. 选择当前已加载映像中的一个真实可执行 PC。
2. 解码覆盖该精确 PC 或调用点地址的 recipe。
3. 分配满足所需对齐要求和 CFA 关系的合成记录。
4. 将下一个合成 FP 存入 `[FP]`，将该帧已保存的调用者 PC 存入 `[FP+8]`，并在 FP 下方存储编码声明的所有 GPR/FPR。
5. 链接多条记录，并将第一条记录放入 live `x29`。
6. 安排 live LR 和 API 返回路径，使 unwinding 进入所选链，同时确保执行可以安全恢复。

例如，`0x04000001` 表示帧模式加上 `x19/x20` 对。对应的状态转换和所需内存如下：<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

因此，仅有一个看起来合法的地址还不够。每个恢复出的 PC 都会成为下一次查找的键，因此，只要有一个地址的编码与伪造布局不一致，就会破坏整个链条，或导致使用方重建出不一致的寄存器状态。<sup>[[1]](#references)</sup>

## ARM64e PAC 要求

PAC 会在指针中原本空闲的位上存储带密钥的完整性值；它不会加密地址。Clang 的 arm64e 返回地址 schema 使用指令密钥 B，以及函数入口处的栈指针作为区分值。对于常规栈帧，该入口 `SP` 就是 CFA，因此 `[FP+8]` 处保存的 LR 会绑定到 `FP+0x10`。<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

每个合成 LR 都必须单独签名，因为将已签名的 LR 移到 CFA 不同的栈帧会改变 discriminator，导致认证失败。`ptrauth_strip()` 适用于地址规范化和符号查找，但**不能**证明真实性；任何实际的返回或经认证的间接分支，都必须使用该确切转换预期的密钥和 modifier。<sup>[[1]](#references)[[3]](#references)</sup>

典型的非叶 arm64e 函数会在存储 LR 之前对其签名，并在恢复入口 SP 后进行认证：<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline 与 restore bridge

合成记录只需满足 unwinder 的要求；它们不包含完整的执行上下文。从敏感 API 直接返回到伪造的调用者通常会导致崩溃。因此，实际设计会将一个 gadget frame 放在 API 紧下方：API 返回到已加载 framework 中的可执行代码，而该 gadget 则通过受控的 callee-saved register 跳转到 implant 中的 restore bridge。<sup>[[1]](#references)</sup>

一个有用的 gadget 会保留 LR，并通过受控寄存器转移控制流，例如使用合适的 `br`、`braa` 或 `brab` 序列。restore bridge 必须在恢复 implant 执行前还原原始的 `x19-x30` 值和 `SP`。在 arm64e 上，API 到 gadget、gadget 到 bridge，以及 bridge 到 implant 这几段路径中的每次认证返回或跳转，都需要使用针对该指令所用 key 和 discriminator 签名的指针。<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

结果表明，基于 stack 的检测存在重要的信任边界失效：调用链可能仅包含已映射且可符号化的 Apple framework PC，却仍不代表真实的控制流。因此，不应将 Unwind 输出视为执行跟踪，而应结合线程可执行内存来源以及敏感 API 周围真实控制流转换的独立证据进行佐证。<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Apple Silicon 上的 ARM64 stack 内部机制与混淆](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Mach-O compact unwind 编码定义](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - 指针认证](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Arm 64 位架构过程调用标准](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
