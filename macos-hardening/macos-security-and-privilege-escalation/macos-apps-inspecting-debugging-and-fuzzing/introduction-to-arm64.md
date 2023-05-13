# Introduction to ARM64

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Introduction to ARM64**

ARM64, also known as ARMv8-A, is a 64-bit processor architecture used in various types of devices including smartphones, tablets, servers, and even some high-end personal computers (macOS). It's a product of ARM Holdings, a company known for its energy-efficient processor designs.

### **Registers**

ARM64 has **31 general-purpose registers**, labeled `x0` through `x30`. Each can store a **64-bit** (8-byte) value. For operations that require only 32-bit values, the same registers can be accessed in a 32-bit mode using the names w0 through w30.

1. **`x0`** to **`x7`** - These are typically used as scratch registers and for passing parameters to subroutines.
2. **`x8`** - In the Linux kernel, `x8` is used as the system call number for the `svc` instruction.
3. **`x9`** to **`x15`** - More temporary registers, often used for local variables.
4. **`x16`** and **`x17`** - Temporary registers, also used for indirect function calls and PLT (Procedure Linkage Table) stubs.
5. **`x18`** - Platform register. On some platforms, this register is reserved for platform-specific uses.
6. **`x19`** to **`x28`** - These are callee-saved registers. A function must preserve these registers' values for its caller.
7. **`x29`** - **Frame pointer**.
8. **`x30`** - Link register. It holds the return address when a `BL` (Branch with Link) or `BLR` (Branch with Link to Register) instruction is executed.
9. **`sp`** - **Stack pointer**, used to keep track of the top of the stack.
10. **`pc`** - **Program counter**, which points to the next instruction to be executed.

### **Calling Convention**

The ARM64 calling convention specifies that the **first eight parameters** to a function are passed in registers **`x0` through `x7`**. **Additional** parameters are passed on the **stack**. The **return** value is passed back in register **`x0`**, or in **`x1`** as well **if it's 128 bits**. The **`x19`** to **`x30`** and **`sp`** registers must be **preserved** across function calls.

When reading a function in assembly, look for the **function prologue and epilogue**. The **prologue** usually involves **saving the frame pointer (`x29`)**, **setting** up a **new frame pointer**, and a**llocating stack space**. The **epilogue** usually involves **restoring the saved frame pointer** and **returning** from the function.

### **Common Instructions**

ARM64 instructions generally have the **format `opcode dst, src1, src2`**, where **`opcode`** is the **operation** to be performed (such as `add`, `sub`, `mov`, etc.), **`dst`** is the **destination** register where the result will be stored, and **`src1`** and **`src2`** are the **source** registers. Immediate values can also be used in place of source registers.

* **`mov`**: **Move** a value from one **register** to another.
  * Example: `mov x0, x1` — This moves the value from `x1` to `x0`.
* **`ldr`**: **Load** a value from **memory** into a **register**.
  * Example: `ldr x0, [x1]` — This loads a value from the memory location pointed to by `x1` into `x0`.
* **`str`**: **Store** a value from a **register** into **memory**.
  * Example: `str x0, [x1]` — This stores the value in `x0` into the memory location pointed to by `x1`.
* **`ldp`**: **Load Pair of Registers**. This instruction **loads two registers** from **consecutive memory** locations. The memory address is typically formed by adding an offset to the value in another register.
  * Example: `ldp x0, x1, [x2]` — This loads `x0` and `x1` from the memory locations at `x2` and `x2 + 8`, respectively.
* **`stp`**: **Store Pair of Registers**. This instruction **stores two registers** to **consecutive memory** locations. The memory address is typically formed by adding an offset to the value in another register.
  * Example: `stp x0, x1, [x2]` — This stores `x0` and `x1` to the memory locations at `x2` and `x2 + 8`, respectively.
* **`add`**: **Add** the values of two registers and store the result in a register.
  * Example: `add x0, x1, x2` — This adds the values in `x1` and `x2` together and stores the result in `x0`.
* **`sub`**: **Subtract** the values of two registers and store the result in a register.
  * Example: `sub x0, x1, x2` — This subtracts the value in `x2` from `x1` and stores the result in `x0`.
* **`mul`**: **Multiply** the values of **two registers** and store the result in a register.
  * Example: `mul x0, x1, x2` — This multiplies the values in `x1` and `x2` and stores the result in `x0`.
* **`div`**: **Divide** the value of one register by another and store the result in a register.
  * Example: `div x0, x1, x2` — This divides the value in `x1` by `x2` and stores the result in `x0`.
* **`bl`**: **Branch** with link, used to **call** a **subroutine**. Stores the **return address in `x30`**.
  * Example: `bl myFunction` — This calls the function `myFunction` and stores the return address in `x30`.
* **`blr`**: **Branch** with Link to Register, used to **call** a **subroutine** where the target is **specified** in a **register**. Stores the return address in `x30`.
  * Example: `blr x1` — This calls the function whose address is contained in `x1` and stores the return address in `x30`.
* **`ret`**: **Return** from **subroutine**, typically using the address in **`x30`**.
  * Example: `ret` — This returns from the current subroutine using the return address in `x30`.
* **`cmp`**: **Compare** two registers and set condition flags.
  * Example: `cmp x0, x1` — This compares the values in `x0` and `x1` and sets the condition flags accordingly.
* **`b.eq`**: **Branch if equal**, based on the previous `cmp` instruction.
  * Example: `b.eq label` — If the previous `cmp` instruction found two equal values, this jumps to `label`.
* **`b.ne`**: **Branch if Not Equal**. This instruction checks the condition flags (which were set by a previous comparison instruction), and if the compared values were not equal, it branches to a label or address.
  * Example: After a `cmp x0, x1` instruction, `b.ne label` — If the values in `x0` and `x1` were not equal, this jumps to `label`.
* **`cbz`**: **Compare and Branch on Zero**. This instruction compares a register with zero, and if they are equal, it branches to a label or address.
  * Example: `cbz x0, label` — If the value in `x0` is zero, this jumps to `label`.
* **`cbnz`**: **Compare and Branch on Non-Zero**. This instruction compares a register with zero, and if they are not equal, it branches to a label or address.
  * Example: `cbnz x0, label` — If the value in `x0` is non-zero, this jumps to `label`.
* **`adrp`**: Compute the **page address of a symbol** and store it in a register.
  * Example: `adrp x0, symbol` — This computes the page address of `symbol` and stores it in `x0`.
* **`ldrsw`**: **Load** a signed **32-bit** value from memory and **sign-extend it to 64** bits.
  * Example: `ldrsw x0, [x1]` — This loads a signed 32-bit value from the memory location pointed to by `x1`, sign-extends it to 64 bits, and stores it in `x0`.
* **`stur`**: **Store a register value to a memory location**, using an offset from another register.
  * Example: `stur x0, [x1, #4]` — This stores the value in `x0` into the memory ddress that is 4 bytes greater than the address currently in `x1`.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
