# Inyección de hilos en macOS a través del puerto de tareas

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Este post fue copiado de [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/) (que contiene más información)

### Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. Secuestro de hilos

Lo primero que hacemos es llamar a **`task_threads()`** en el puerto de tareas para obtener una lista de hilos en la tarea remota y luego elegir uno de ellos para secuestrar. A diferencia de los marcos de inyección de código tradicionales, **no podemos crear un nuevo hilo remoto** porque `thread_create_running()` será bloqueado por la nueva mitigación.

Luego, podemos llamar a **`thread_suspend()`** para detener el hilo.

En este punto, el único control útil que tenemos sobre el hilo remoto es **detenerlo**, **iniciarlo**, **obtener** sus valores de **registro** y **establecer** sus valores de registro. Así, podemos **iniciar una llamada a función remota** configurando los **registros** `x0` a `x7` en el hilo remoto para los **argumentos**, **estableciendo** **`pc`** en la función que queremos ejecutar e iniciando el hilo. En este punto, necesitamos detectar el retorno y asegurarnos de que el hilo no se bloquee.

Hay varias formas de hacer esto. Una manera sería **registrar un manejador de excepciones** para el hilo remoto usando `thread_set_exception_ports()` y establecer el registro de dirección de retorno, `lr`, en una dirección no válida antes de llamar a la función; de esa manera, después de que la función se ejecute se generaría una excepción y se enviaría un mensaje a nuestro puerto de excepción, momento en el cual podemos inspeccionar el estado del hilo para recuperar el valor de retorno. Sin embargo, por simplicidad copié la estrategia utilizada en el exploit triple\_fetch de Ian Beer, que consistía en **establecer `lr` en la dirección de una instrucción que haría un bucle infinito** y luego sondear repetidamente los registros del hilo hasta que **`pc` apuntara a esa instrucción**.

### 2. Puertos Mach para comunicación

El siguiente paso es **crear puertos Mach sobre los cuales podamos comunicarnos con el hilo remoto**. Estos puertos Mach serán útiles más adelante para ayudar a transferir derechos de envío y recepción arbitrarios entre las tareas.

Para establecer comunicación bidireccional, necesitaremos crear dos derechos de recepción Mach: uno en la **tarea local y otro en la tarea remota**. Luego, necesitaremos **transferir un derecho de envío** a cada puerto **a la otra tarea**. Esto le dará a cada tarea una forma de enviar un mensaje que puede ser recibido por la otra.

Primero nos enfocaremos en configurar el puerto local, es decir, el puerto al que la tarea local tiene el derecho de recepción. Podemos crear el puerto Mach como cualquier otro, llamando a `mach_port_allocate()`. El truco está en conseguir un derecho de envío a ese puerto en la tarea remota.

Un truco conveniente que podemos usar para copiar un derecho de envío de la tarea actual a una tarea remota usando solo un primitivo de ejecución básico es guardar un **derecho de envío a nuestro puerto local en el puerto especial `THREAD_KERNEL_PORT` del hilo remoto** usando `thread_set_special_port()`; luego, podemos hacer que el hilo remoto llame a `mach_thread_self()` para recuperar el derecho de envío.

A continuación, configuraremos el puerto remoto, que es prácticamente lo inverso de lo que acabamos de hacer. Podemos hacer que el **hilo remoto asigne un puerto Mach llamando a `mach_reply_port()`**; no podemos usar `mach_port_allocate()` porque este último devuelve el nombre del puerto asignado en memoria y aún no tenemos un primitivo de lectura. Una vez que tenemos un puerto, podemos crear un derecho de envío llamando a `mach_port_insert_right()` en el hilo remoto. Luego, podemos guardar el puerto en el kernel llamando a `thread_set_special_port()`. Finalmente, de vuelta en la tarea local, podemos recuperar el puerto llamando a `thread_get_special_port()` en el hilo remoto, **dándonos un derecho de envío al puerto Mach recién asignado en la tarea remota**.

En este punto, hemos creado los puertos Mach que utilizaremos para comunicación bidireccional.

### 3. Lectura/escritura básica de memoria <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

Ahora usaremos el primitivo de ejecución para crear primitivos básicos de lectura y escritura de memoria. Estos primitivos no se usarán para mucho (pronto los actualizaremos a primitivos mucho más poderosos), pero son un paso clave para ayudarnos a expandir nuestro control del proceso remoto.

Para leer y escribir memoria usando nuestro primitivo de ejecución, buscaremos funciones como estas:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Podrían corresponder al siguiente ensamblaje:
```
_read_func:
ldr     x0, [x0]
ret
_write_func:
str     x1, [x0]
ret
```
Un rápido análisis de algunas bibliotecas comunes reveló algunos buenos candidatos. Para leer memoria, podemos usar la función `property_getName()` de la [biblioteca de tiempo de ejecución de Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html):
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
Como resulta, `prop` es el primer campo de `objc_property_t`, por lo que esto corresponde directamente a la hipotética `read_func` mencionada anteriormente. Solo necesitamos realizar una llamada a función remota con el primer argumento siendo la dirección que queremos leer, y el valor de retorno será los datos en esa dirección.

Encontrar una función preestablecida para escribir en memoria es un poco más difícil, pero aún hay excelentes opciones sin efectos secundarios no deseados. En libxpc, la función `_xpc_int64_set_value()` tiene el siguiente desensamblado:
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
Por lo tanto, para realizar una escritura de 64 bits en la dirección `address`, podemos realizar la llamada remota:
```c
_xpc_int64_set_value(address - 0x18, value)
```
### 4. Memoria compartida

Nuestro siguiente paso es crear memoria compartida entre la tarea remota y local. Esto nos permitirá transferir datos entre los procesos más fácilmente: con una región de memoria compartida, la lectura y escritura de memoria arbitraria es tan simple como una llamada remota a `memcpy()`. Además, tener una región de memoria compartida nos permitirá configurar fácilmente una pila para que podamos llamar a funciones con más de 8 argumentos.

Para facilitar las cosas, podemos reutilizar las características de memoria compartida de libxpc. Libxpc proporciona un tipo de objeto XPC, `OS_xpc_shmem`, que permite establecer regiones de memoria compartida a través de XPC. Al revertir libxpc, determinamos que `OS_xpc_shmem` se basa en entradas de memoria Mach, que son puertos Mach que representan una región de memoria virtual. Y dado que ya hemos mostrado cómo enviar puertos Mach a la tarea remota, podemos usar esto para configurar fácilmente nuestra propia memoria compartida.

Primero que nada, necesitamos asignar la memoria que compartiremos usando `mach_vm_allocate()`. Necesitamos usar `mach_vm_allocate()` para que podamos usar `xpc_shmem_create()` para crear un objeto `OS_xpc_shmem` para la región. `xpc_shmem_create()` se encargará de crear la entrada de memoria Mach por nosotros y almacenará el derecho de envío Mach a la entrada de memoria en el objeto opaco `OS_xpc_shmem` en el desplazamiento `0x18`.

Una vez que tengamos el puerto de entrada de memoria, crearemos un objeto `OS_xpc_shmem` en el proceso remoto que represente la misma región de memoria, lo que nos permitirá llamar a `xpc_shmem_map()` para establecer el mapeo de memoria compartida. Primero, realizamos una llamada remota a `malloc()` para asignar memoria para el `OS_xpc_shmem` y usamos nuestro primitivo básico de escritura para copiar el contenido del objeto `OS_xpc_shmem` local. Desafortunadamente, el objeto resultante no es del todo correcto: su campo de entrada de memoria Mach en el desplazamiento `0x18` contiene el nombre de la tarea local para la entrada de memoria, no el nombre de la tarea remota. Para solucionar esto, usamos el truco de `thread_set_special_port()` para insertar un derecho de envío a la entrada de memoria Mach en la tarea remota y luego sobrescribir el campo `0x18` con el nombre de la entrada de memoria remota. En este punto, el objeto `OS_xpc_shmem` remoto es válido y el mapeo de memoria se puede establecer con una llamada remota a `xpc_shmem_remote()`.

### 5. Control total <a href="#step-5-full-control" id="step-5-full-control"></a>

Con memoria compartida en una dirección conocida y un primitivo de ejecución arbitrario, básicamente hemos terminado. Las lecturas y escrituras de memoria arbitrarias se implementan llamando a `memcpy()` hacia y desde la región compartida, respectivamente. Las llamadas a funciones con más de 8 argumentos se realizan colocando argumentos adicionales más allá de los primeros 8 en la pila de acuerdo con la convención de llamadas. La transferencia de puertos Mach arbitrarios entre las tareas se puede hacer enviando mensajes Mach a través de los puertos establecidos anteriormente. Incluso podemos transferir descriptores de archivos entre los procesos utilizando fileports (¡agradecimientos especiales a Ian Beer por demostrar esta técnica en triple_fetch!).

En resumen, ahora tenemos control total y fácil sobre el proceso víctima. Puedes ver la implementación completa y la API expuesta en la biblioteca [threadexec](https://github.com/bazad/threadexec).

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
