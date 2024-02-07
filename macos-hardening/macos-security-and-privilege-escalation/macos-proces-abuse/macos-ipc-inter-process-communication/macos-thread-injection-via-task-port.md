# Inyección de hilos en macOS a través del puerto de tarea

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**artículos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Secuestro de hilos

Inicialmente, se invoca la función **`task_threads()`** en el puerto de tarea para obtener una lista de hilos de la tarea remota. Se selecciona un hilo para secuestrar. Este enfoque difiere de los métodos convencionales de inyección de código, ya que la creación de un nuevo hilo remoto está prohibida debido a la nueva mitigación que bloquea `thread_create_running()`.

Para controlar el hilo, se llama a **`thread_suspend()`**, deteniendo su ejecución.

Las únicas operaciones permitidas en el hilo remoto implican **detenerlo** y **iniciarlo**, **recuperar** y **modificar** sus valores de registro. Las llamadas a funciones remotas se inician configurando los registros `x0` a `x7` con los **argumentos**, configurando **`pc`** para apuntar a la función deseada y activando el hilo. Asegurar que el hilo no se bloquee después del retorno requiere la detección del retorno.

Una estrategia implica **registrar un manejador de excepciones** para el hilo remoto usando `thread_set_exception_ports()`, estableciendo el registro `lr` en una dirección inválida antes de la llamada a la función. Esto desencadena una excepción después de la ejecución de la función, enviando un mensaje al puerto de excepción, lo que permite la inspección del estado del hilo para recuperar el valor de retorno. Alternativamente, como se adoptó del exploit triple\_fetch de Ian Beer, `lr` se establece en un bucle infinito. Luego, los registros del hilo se monitorean continuamente hasta que **`pc` apunte a esa instrucción**.

## 2. Puertos Mach para comunicación

La fase siguiente implica establecer puertos Mach para facilitar la comunicación con el hilo remoto. Estos puertos son fundamentales para transferir derechos de envío y recepción arbitrarios entre tareas.

Para la comunicación bidireccional, se crean dos derechos de recepción Mach: uno en la tarea local y otro en la tarea remota. Posteriormente, se transfiere un derecho de envío para cada puerto a la tarea contraparte, permitiendo el intercambio de mensajes.

Centrándose en el puerto local, el derecho de recepción lo tiene la tarea local. El puerto se crea con `mach_port_allocate()`. El desafío radica en transferir un derecho de envío a este puerto a la tarea remota.

Una estrategia implica aprovechar `thread_set_special_port()` para colocar un derecho de envío al puerto local en el `THREAD_KERNEL_PORT` del hilo remoto. Luego, se instruye al hilo remoto a llamar a `mach_thread_self()` para recuperar el derecho de envío.

Para el puerto remoto, el proceso es esencialmente al revés. Se dirige al hilo remoto a generar un puerto Mach a través de `mach_reply_port()` (ya que `mach_port_allocate()` no es adecuado debido a su mecanismo de retorno). Tras la creación del puerto, se invoca `mach_port_insert_right()` en el hilo remoto para establecer un derecho de envío. Este derecho se guarda en el kernel usando `thread_set_special_port()`. De vuelta en la tarea local, se utiliza `thread_get_special_port()` en el hilo remoto para adquirir un derecho de envío al puerto Mach recién asignado en la tarea remota.

La finalización de estos pasos resulta en el establecimiento de puertos Mach, sentando las bases para la comunicación bidireccional.

## 3. Primitivas básicas de lectura/escritura de memoria

En esta sección, el enfoque se centra en utilizar la primitiva de ejecución para establecer primitivas básicas de lectura y escritura de memoria. Estos pasos iniciales son cruciales para obtener más control sobre el proceso remoto, aunque las primitivas en esta etapa no servirán para muchos propósitos. Pronto, se actualizarán a versiones más avanzadas.

### Lectura y escritura de memoria utilizando la primitiva de ejecución

El objetivo es realizar la lectura y escritura de memoria utilizando funciones específicas. Para leer memoria, se utilizan funciones con una estructura similar a la siguiente:
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
Estas funciones corresponden a las instrucciones de ensamblaje proporcionadas:
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
La función `property_getName()` de la [biblioteca de tiempo de ejecución Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) se identifica como una función adecuada para la lectura de memoria. La función se describe a continuación:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Este función actúa efectivamente como la `read_func` al devolver el primer campo de `objc_property_t`.

2. **Escribiendo en la memoria:**
Encontrar una función preconstruida para escribir en la memoria es más desafiante. Sin embargo, la función `_xpc_int64_set_value()` de libxpc es un candidato adecuado con el siguiente desensamblado:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar una escritura de 64 bits en una dirección específica, la llamada remota se estructura de la siguiente manera:
```c
_xpc_int64_set_value(address - 0x18, value)
```
## 4. Configuración de Memoria Compartida

El objetivo es establecer memoria compartida entre tareas locales y remotas, simplificando la transferencia de datos y facilitando la llamada de funciones con múltiples argumentos. El enfoque implica aprovechar `libxpc` y su tipo de objeto `OS_xpc_shmem`, el cual se basa en entradas de memoria Mach.

### Resumen del Proceso:

1. **Asignación de Memoria**:
- Asignar la memoria para compartir utilizando `mach_vm_allocate()`.
- Utilizar `xpc_shmem_create()` para crear un objeto `OS_xpc_shmem` para la región de memoria asignada. Esta función gestionará la creación de la entrada de memoria Mach y almacenará el derecho de envío Mach en el desplazamiento `0x18` del objeto `OS_xpc_shmem`.

2. **Creación de Memoria Compartida en el Proceso Remoto**:
- Asignar memoria para el objeto `OS_xpc_shmem` en el proceso remoto con una llamada remota a `malloc()`.
- Copiar el contenido del objeto `OS_xpc_shmem` local al proceso remoto. Sin embargo, esta copia inicial tendrá nombres incorrectos de entradas de memoria Mach en el desplazamiento `0x18`.

3. **Corrección de la Entrada de Memoria Mach**:
- Utilizar el método `thread_set_special_port()` para insertar un derecho de envío para la entrada de memoria Mach en la tarea remota.
- Corregir el campo de entrada de memoria Mach en el desplazamiento `0x18` sobrescribiéndolo con el nombre de la entrada de memoria remota.

4. **Finalización de la Configuración de Memoria Compartida**:
- Validar el objeto `OS_xpc_shmem` remoto.
- Establecer el mapeo de memoria compartida con una llamada remota a `xpc_shmem_remote()`.

Siguiendo estos pasos, la memoria compartida entre las tareas locales y remotas se configurará eficientemente, permitiendo transferencias de datos sencillas y la ejecución de funciones que requieran múltiples argumentos.

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
## 5. Logrando Control Total

Al establecer correctamente la memoria compartida y obtener capacidades de ejecución arbitraria, hemos logrado control total sobre el proceso objetivo. Las funcionalidades clave que permiten este control son:

1. **Operaciones de Memoria Arbitrarias**:
   - Realizar lecturas de memoria arbitrarias invocando `memcpy()` para copiar datos desde la región compartida.
   - Ejecutar escrituras de memoria arbitrarias utilizando `memcpy()` para transferir datos a la región compartida.

2. **Manejo de Llamadas a Funciones con Múltiples Argumentos**:
   - Para funciones que requieren más de 8 argumentos, organizar los argumentos adicionales en la pila de acuerdo con la convención de llamada.

3. **Transferencia de Puertos Mach**:
   - Transferir puertos Mach entre tareas a través de mensajes Mach mediante los puertos previamente establecidos.

4. **Transferencia de Descriptores de Archivo**:
   - Transferir descriptores de archivo entre procesos utilizando fileports, una técnica destacada por Ian Beer en `triple_fetch`.

Este control integral está encapsulado dentro de la biblioteca [threadexec](https://github.com/bazad/threadexec), que proporciona una implementación detallada y una API fácil de usar para interactuar con el proceso víctima.

## Consideraciones Importantes:

- Asegurar el uso adecuado de `memcpy()` para operaciones de lectura/escritura de memoria para mantener la estabilidad del sistema y la integridad de los datos.
- Al transferir puertos Mach o descriptores de archivo, seguir protocolos adecuados y manejar los recursos de manera responsable para evitar fugas o accesos no deseados.

Al seguir estas pautas y utilizar la biblioteca `threadexec`, uno puede gestionar e interactuar eficientemente con procesos a un nivel granular, logrando control total sobre el proceso objetivo.

# Referencias
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
