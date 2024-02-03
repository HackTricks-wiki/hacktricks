# Inyección de hilos en macOS a través del puerto de tareas

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Secuestro de hilos

Inicialmente, se invoca la función **`task_threads()`** en el puerto de tareas para obtener una lista de hilos de la tarea remota. Se selecciona un hilo para el secuestro. Este enfoque se desvía de los métodos convencionales de inyección de código ya que la creación de un nuevo hilo remoto está prohibida debido a la nueva mitigación que bloquea `thread_create_running()`.

Para controlar el hilo, se llama a **`thread_suspend()`**, deteniendo su ejecución.

Las únicas operaciones permitidas en el hilo remoto implican **detenerlo** y **arrancarlo**, **recuperar** y **modificar** sus valores de registro. Las llamadas a funciones remotas se inician configurando los registros `x0` a `x7` para los **argumentos**, configurando **`pc`** para apuntar a la función deseada y activando el hilo. Asegurar que el hilo no se caiga después del retorno requiere detectar el retorno.

Una estrategia implica **registrar un manejador de excepciones** para el hilo remoto usando `thread_set_exception_ports()`, estableciendo el registro `lr` en una dirección inválida antes de la llamada a la función. Esto desencadena una excepción después de la ejecución de la función, enviando un mensaje al puerto de excepción, lo que permite inspeccionar el estado del hilo para recuperar el valor de retorno. Alternativamente, como se adopta del exploit triple\_fetch de Ian Beer, `lr` se configura para bucle infinito. Luego, se monitorean continuamente los registros del hilo hasta que **`pc` apunte a esa instrucción**.

## 2. Puertos Mach para comunicación

La fase subsiguiente implica establecer puertos Mach para facilitar la comunicación con el hilo remoto. Estos puertos son fundamentales para transferir derechos de envío y recepción arbitrarios entre tareas.

Para la comunicación bidireccional, se crean dos derechos de recepción Mach: uno en la tarea local y otro en la tarea remota. Posteriormente, se transfiere un derecho de envío para cada puerto a la tarea contraparte, permitiendo el intercambio de mensajes.

Centrándose en el puerto local, el derecho de recepción lo mantiene la tarea local. El puerto se crea con `mach_port_allocate()`. El desafío radica en transferir un derecho de envío a este puerto a la tarea remota.

Una estrategia implica aprovechar `thread_set_special_port()` para colocar un derecho de envío al puerto local en el `THREAD_KERNEL_PORT` del hilo remoto. Luego, se instruye al hilo remoto para que llame a `mach_thread_self()` para recuperar el derecho de envío.

Para el puerto remoto, el proceso es esencialmente inverso. Se dirige al hilo remoto para generar un puerto Mach a través de `mach_reply_port()` (ya que `mach_port_allocate()` no es adecuado debido a su mecanismo de retorno). Tras la creación del puerto, se invoca `mach_port_insert_right()` en el hilo remoto para establecer un derecho de envío. Este derecho se almacena luego en el kernel usando `thread_set_special_port()`. De vuelta en la tarea local, se utiliza `thread_get_special_port()` en el hilo remoto para adquirir un derecho de envío al puerto Mach recién asignado en la tarea remota.

La finalización de estos pasos resulta en el establecimiento de puertos Mach, sentando las bases para la comunicación bidireccional.

## 3. Primitivas básicas de lectura/escritura de memoria

En esta sección, el enfoque está en utilizar la primitiva de ejecución para establecer primitivas básicas de lectura y escritura de memoria. Estos pasos iniciales son cruciales para obtener más control sobre el proceso remoto, aunque las primitivas en esta etapa no servirán para muchos propósitos. Pronto, se mejorarán a versiones más avanzadas.

### Lectura y escritura de memoria utilizando la primitiva de ejecución

El objetivo es realizar la lectura y escritura de memoria utilizando funciones específicas. Para leer memoria, se utilizan funciones con la siguiente estructura:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Y para escribir en la memoria, se utilizan funciones similares a esta estructura:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Estas funciones corresponden a las siguientes instrucciones de ensamblaje:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificación de Funciones Adecuadas

Un escaneo de bibliotecas comunes reveló candidatos apropiados para estas operaciones:

1. **Lectura de Memoria:**
La función `property_getName()` de la [biblioteca de tiempo de ejecución de Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) se identifica como una función adecuada para la lectura de memoria. La función se describe a continuación:

```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```

Esta función actúa efectivamente como la `read_func` al devolver el primer campo de `objc_property_t`.

2. **Escritura de Memoria:**
Encontrar una función preconstruida para escribir en memoria es más desafiante. Sin embargo, la función `_xpc_int64_set_value()` de libxpc es un candidato adecuado con el siguiente desensamblado:
```
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar una escritura de 64 bits en una dirección específica, la llamada remota se estructura como:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Con estas primitivas establecidas, se prepara el escenario para crear memoria compartida, marcando un progreso significativo en el control del proceso remoto.

## 4. Configuración de Memoria Compartida

El objetivo es establecer memoria compartida entre tareas locales y remotas, simplificando la transferencia de datos y facilitando la llamada de funciones con múltiples argumentos. El enfoque implica aprovechar `libxpc` y su tipo de objeto `OS_xpc_shmem`, que se construye sobre entradas de memoria Mach.

### Resumen del Proceso:

1. **Asignación de Memoria**:
- Asignar la memoria para compartir usando `mach_vm_allocate()`.
- Utilizar `xpc_shmem_create()` para crear un objeto `OS_xpc_shmem` para la región de memoria asignada. Esta función gestionará la creación de la entrada de memoria Mach y almacenará el derecho de envío Mach en el desplazamiento `0x18` del objeto `OS_xpc_shmem`.

2. **Creando Memoria Compartida en el Proceso Remoto**:
- Asignar memoria para el objeto `OS_xpc_shmem` en el proceso remoto con una llamada remota a `malloc()`.
- Copiar el contenido del objeto `OS_xpc_shmem` local al proceso remoto. Sin embargo, esta copia inicial tendrá nombres de entradas de memoria Mach incorrectos en el desplazamiento `0x18`.

3. **Corrigiendo la Entrada de Memoria Mach**:
- Utilizar el método `thread_set_special_port()` para insertar un derecho de envío para la entrada de memoria Mach en la tarea remota.
- Corregir el campo de entrada de memoria Mach en el desplazamiento `0x18` sobrescribiéndolo con el nombre de la entrada de memoria remota.

4. **Finalizando la Configuración de Memoria Compartida**:
- Validar el objeto `OS_xpc_shmem` remoto.
- Establecer el mapeo de memoria compartida con una llamada remota a `xpc_shmem_remote()`.

Siguiendo estos pasos, la memoria compartida entre las tareas locales y remotas se configurará de manera eficiente, permitiendo transferencias de datos sencillas y la ejecución de funciones que requieren múltiples argumentos.

## Fragmentos de Código Adicionales

Para la asignación de memoria y la creación de objetos de memoria compartida:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Para crear y corregir el objeto de memoria compartida en el proceso remoto:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Recuerde manejar correctamente los detalles de los puertos Mach y los nombres de entrada de memoria para asegurar que la configuración de memoria compartida funcione adecuadamente.

## 5. Logrando Control Total

Al establecer con éxito la memoria compartida y obtener capacidades de ejecución arbitraria, hemos ganado esencialmente control total sobre el proceso objetivo. Las funcionalidades clave que permiten este control son:

1. **Operaciones de Memoria Arbitrarias**:
- Realizar lecturas de memoria arbitrarias invocando `memcpy()` para copiar datos desde la región compartida.
- Ejecutar escrituras de memoria arbitrarias utilizando `memcpy()` para transferir datos a la región compartida.

2. **Manejo de Llamadas a Funciones con Múltiples Argumentos**:
- Para funciones que requieren más de 8 argumentos, organizar los argumentos adicionales en la pila de acuerdo con la convención de llamadas.

3. **Transferencia de Puerto Mach**:
- Transferir puertos Mach entre tareas a través de mensajes Mach mediante puertos previamente establecidos.

4. **Transferencia de Descriptor de Archivo**:
- Transferir descriptores de archivo entre procesos utilizando fileports, una técnica destacada por Ian Beer en `triple_fetch`.

Este control comprensivo está encapsulado dentro de la biblioteca [threadexec](https://github.com/bazad/threadexec), proporcionando una implementación detallada y una API amigable para la interacción con el proceso víctima.

## Consideraciones Importantes:

- Asegúrese de usar correctamente `memcpy()` para operaciones de lectura/escritura de memoria para mantener la estabilidad del sistema y la integridad de los datos.
- Al transferir puertos Mach o descriptores de archivo, siga los protocolos adecuados y maneje los recursos de manera responsable para prevenir fugas o accesos no intencionados.

Siguiendo estas pautas y utilizando la biblioteca `threadexec`, se puede gestionar e interactuar eficientemente con procesos a un nivel granular, logrando control total sobre el proceso objetivo.

# Referencias
* https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
