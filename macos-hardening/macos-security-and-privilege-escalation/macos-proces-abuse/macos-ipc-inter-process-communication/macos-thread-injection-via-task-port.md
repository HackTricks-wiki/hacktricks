# Inyección de hilos en macOS a través del puerto de tarea

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Este post fue copiado de [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/) (que contiene más información)

### Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. Secuestro de hilos

Lo primero que hacemos es llamar a **`task_threads()`** en el puerto de tarea para obtener una lista de hilos en la tarea remota y luego elegir uno de ellos para secuestrar. A diferencia de los marcos de inyección de código tradicionales, **no podemos crear un nuevo hilo remoto** porque `thread_create_running()` será bloqueado por la nueva mitigación.

Luego, podemos llamar a **`thread_suspend()`** para detener el hilo de ejecución.

En este punto, el único control útil que tenemos sobre el hilo remoto es **detenerlo**, **iniciarlo**, **obtener** sus **valores de registro** y **establecer** sus valores de registro. Por lo tanto, podemos **iniciar una llamada de función remota** estableciendo los registros `x0` a través de `x7` en el hilo remoto a los **argumentos**, estableciendo **`pc`** en la función que queremos ejecutar y comenzando el hilo. En este punto, necesitamos detectar el retorno y asegurarnos de que el hilo no se bloquee.

Hay algunas formas de hacer esto. Una forma sería **registrar un manejador de excepciones** para el hilo remoto usando `thread_set_exception_ports()` y establecer el registro de dirección de retorno, `lr`, en una dirección no válida antes de llamar a la función; de esta manera, después de que se ejecute la función, se generará una excepción y se enviará un mensaje a nuestro puerto de excepción, momento en el que podemos inspeccionar el estado del hilo para recuperar el valor de retorno. Sin embargo, por simplicidad, copié la estrategia utilizada en la explotación triple\_fetch de Ian Beer, que consistía en **establecer `lr` en la dirección de una instrucción que entraría en un bucle infinito** y luego sondear repetidamente los registros del hilo hasta que **`pc` apuntara a esa instrucción**.

### 2. Puertos Mach para la comunicación

El siguiente paso es **crear puertos Mach a través de los cuales podemos comunicarnos con el hilo remoto**. Estos puertos Mach serán útiles más adelante para ayudar a transferir derechos de envío y recepción arbitrarios entre las tareas.

Para establecer una comunicación bidireccional, necesitaremos crear dos derechos de recepción Mach: uno en la **tarea local y otro en la tarea remota**. Luego, necesitaremos **transferir un derecho de envío** a cada puerto **a la otra tarea**. Esto dará a cada tarea una forma de enviar un mensaje que puede ser recibido por la otra.

Enfoquémonos primero en configurar el puerto local, es decir, el puerto al que la tarea local tiene el derecho de recepción. Podemos crear el puerto Mach como cualquier otro, llamando a `mach_port_allocate()`. El truco es obtener un derecho de envío a ese puerto en la tarea remota.

Un truco conveniente que podemos usar para copiar un derecho de envío desde la tarea actual a una tarea remota usando solo una primitiva de ejecución básica es almacenar un **derecho de envío a nuestro puerto local en el puerto especial `THREAD_KERNEL_PORT` del hilo remoto** usando `thread_set_special_port()`; luego, podemos hacer que el hilo remoto llame a `mach_thread_self()` para recuperar el derecho de envío.

A continuación, configuraremos el puerto remoto, que es prácticamente lo contrario de lo que acabamos de hacer. Podemos hacer que el **hilo remoto asigne un puerto Mach llamando a `mach_reply_port()`**; no podemos usar `mach_port_allocate()` porque este último devuelve el nombre del puerto asignado en la memoria y aún no tenemos una primitiva de lectura. Una vez que tenemos un puerto, podemos crear un derecho de envío llamando a `mach_port_insert_right()` en el hilo remoto. Luego, podemos almacenar el puerto en el kernel llamando a `thread_set_special_port()`. Finalmente, de vuelta en la tarea local, podemos recuperar el puerto llamando a `thread_get_special_port()` en el hilo remoto, **dándonos un derecho de envío al puerto Mach recién asignado en la tarea remota**.

En este punto, hemos creado los puertos Mach que usaremos para la comunicación bidireccional.
### 3. Lectura/Escritura básica de memoria <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

Ahora usaremos el primitivo de ejecución para crear primitivos básicos de lectura y escritura de memoria. Estos primitivos no se utilizarán mucho (pronto actualizaremos a primitivos mucho más poderosos), pero son un paso clave para ayudarnos a expandir nuestro control del proceso remoto.

Para leer y escribir memoria usando nuestro primitivo de ejecución, buscaremos funciones como estas:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Podrían corresponder al siguiente ensamblador:
```
_read_func:
ldr     x0, [x0]
ret
_write_func:
str     x1, [x0]
ret
```
Un escaneo rápido de algunas bibliotecas comunes reveló algunos buenos candidatos. Para leer la memoria, podemos usar la función `property_getName()` de la [biblioteca de tiempo de ejecución Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html):
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
Result:

Resulta que `prop` es el primer campo de `objc_property_t`, por lo que esto corresponde directamente a la hipotética `read_func` anterior. Solo necesitamos realizar una llamada de función remota con el primer argumento siendo la dirección que queremos leer, y el valor de retorno será los datos en esa dirección.

Encontrar una función prehecha para escribir en la memoria es un poco más difícil, pero aún hay excelentes opciones sin efectos secundarios no deseados. En libxpc, la función `_xpc_int64_set_value()` tiene el siguiente desensamblado:
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
Por lo tanto, para realizar una escritura de 64 bits en la dirección `address`, podemos realizar la llamada remota:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Con estas primitivas en mano, estamos listos para crear memoria compartida.

### 4. Memoria compartida

Nuestro siguiente paso es crear memoria compartida entre la tarea remota y local. Esto nos permitirá transferir datos entre los procesos más fácilmente: con una región de memoria compartida, la lectura y escritura de memoria arbitraria es tan simple como una llamada remota a `memcpy()`. Además, tener una región de memoria compartida nos permitirá configurar fácilmente una pila para que podamos llamar a funciones con más de 8 argumentos.

Para hacer las cosas más fáciles, podemos reutilizar las características de memoria compartida de libxpc. Libxpc proporciona un tipo de objeto XPC, `OS_xpc_shmem`, que permite establecer regiones de memoria compartida sobre XPC. Al revertir libxpc, determinamos que `OS_xpc_shmem` se basa en entradas de memoria Mach, que son puertos Mach que representan una región de memoria virtual. Y como ya hemos mostrado cómo enviar puertos Mach a la tarea remota, podemos usar esto para configurar fácilmente nuestra propia memoria compartida.

Lo primero es lo primero, necesitamos asignar la memoria que compartiremos usando `mach_vm_allocate()`. Necesitamos usar `mach_vm_allocate()` para que podamos usar `xpc_shmem_create()` para crear un objeto `OS_xpc_shmem` para la región. `xpc_shmem_create()` se encargará de crear la entrada de memoria Mach por nosotros y almacenará el derecho de envío Mach a la entrada de memoria en el objeto `OS_xpc_shmem` opaco en el desplazamiento `0x18`.

Una vez que tenemos el puerto de entrada de memoria, crearemos un objeto `OS_xpc_shmem` en el proceso remoto que representa la misma región de memoria, lo que nos permitirá llamar a `xpc_shmem_map()` para establecer el mapeo de memoria compartida. Primero, realizamos una llamada remota a `malloc()` para asignar memoria para el `OS_xpc_shmem` y usamos nuestra primitiva de escritura básica para copiar el contenido del objeto `OS_xpc_shmem` local. Desafortunadamente, el objeto resultante no es del todo correcto: su campo de entrada de memoria Mach en el desplazamiento `0x18` contiene el nombre de la tarea local para la entrada de memoria, no el nombre de la tarea remota. Para solucionar esto, usamos el truco `thread_set_special_port()` para insertar un derecho de envío a la entrada de memoria Mach en la tarea remota y luego sobrescribimos el campo `0x18` con el nombre de la entrada de memoria remota. En este punto, el objeto `OS_xpc_shmem` remoto es válido y se puede establecer el mapeo de memoria con una llamada remota a `xpc_shmem_remote()`.

### 5. Control total <a href="#step-5-full-control" id="step-5-full-control"></a>

Con la memoria compartida en una dirección conocida y una primitiva de ejecución arbitraria, estamos básicamente listos. Las lecturas y escrituras de memoria arbitrarias se implementan llamando a `memcpy()` hacia y desde la región compartida, respectivamente. Las llamadas a funciones con más de 8 argumentos se realizan colocando argumentos adicionales más allá de los primeros 8 en la pila según la convención de llamada. La transferencia de puertos Mach arbitrarios entre las tareas se puede hacer enviando mensajes Mach sobre los puertos establecidos anteriormente. Incluso podemos transferir descriptores de archivos entre los procesos mediante el uso de fileports (un agradecimiento especial a Ian Beer por demostrar esta técnica en triple\_fetch!).

En resumen, ahora tenemos un control total y fácil sobre el proceso víctima. Puede ver la implementación completa y la API expuesta en la biblioteca [threadexec](https://github.com/bazad/threadexec).\
