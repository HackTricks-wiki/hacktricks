# Inyección de threads de macOS mediante el task port

{{#include ../../../../banners/hacktricks-training.md}}

## Código

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Inicialmente, la función `task_threads()` se invoca en el task port para obtener una lista de threads de la tarea remota. Se selecciona un thread para realizar el hijacking. Este enfoque difiere de los métodos convencionales de code injection, ya que crear un nuevo thread remoto está prohibido debido a la mitigación que bloquea `thread_create_running()`.<sup>[[1]](#references)</sup>

Para controlar el thread, se llama a `thread_suspend()`, deteniendo su ejecución.<sup>[[1]](#references)</sup>

Las únicas operaciones permitidas en el thread remoto consisten en **detenerlo** y **iniciarlo**, además de **obtener**/**modificar** los valores de sus registros. Las llamadas a funciones remotas se inician estableciendo los registros `x0` a `x7` con los **argumentos**, configurando `pc` para que apunte a la función deseada y reanudando el thread. Para evitar que el thread se bloquee después del retorno, es necesario detectar dicho retorno.<sup>[[1]](#references)</sup>

Una estrategia consiste en registrar un **exception handler** para el thread remoto mediante `thread_set_exception_ports()`, estableciendo el registro `lr` en una dirección no válida antes de la llamada a la función. Esto provoca una excepción después de la ejecución de la función y envía un mensaje al exception port, lo que permite inspeccionar el estado del thread para recuperar el valor de retorno. Como alternativa, siguiendo el enfoque adoptado del exploit *triple_fetch* de Ian Beer, `lr` se configura para realizar un bucle infinito; a continuación, los registros del thread se monitorizan continuamente hasta que `pc` apunta a esa instrucción.<sup>[[1]](#references)</sup>

## 2. Mach ports para la comunicación

La siguiente fase consiste en establecer Mach ports para facilitar la comunicación con el thread remoto. Estos ports son fundamentales para transferir derechos arbitrarios de envío/recepción entre tareas.<sup>[[1]](#references)</sup>

Para permitir la comunicación bidireccional, se crean dos receive rights de Mach: uno en la tarea local y otro en la tarea remota. Posteriormente, se transfiere un send right de cada port a la tarea correspondiente, lo que permite intercambiar mensajes.<sup>[[1]](#references)</sup>

En el caso del port local, el receive right está en posesión de la tarea local. El port se crea mediante `mach_port_allocate()`. El desafío consiste en transferir un send right de este port a la tarea remota.<sup>[[1]](#references)</sup>

Una estrategia consiste en aprovechar `thread_set_special_port()` para colocar un send right del port local en el `THREAD_KERNEL_PORT` del thread remoto. A continuación, se indica al thread remoto que llame a `mach_thread_self()` para recuperar el send right.<sup>[[1]](#references)</sup>

Para el port remoto, el proceso se invierte esencialmente. Se indica al thread remoto que genere un Mach port mediante `mach_reply_port()` (ya que `mach_port_allocate()` no es adecuado debido a su mecanismo de retorno). Una vez creado el port, se invoca `mach_port_insert_right()` en el thread remoto para establecer un send right. Este derecho se almacena en el kernel mediante `thread_set_special_port()`. De vuelta en la tarea local, se utiliza `thread_get_special_port()` sobre el thread remoto para obtener un send right al Mach port recién asignado en la tarea remota.<sup>[[1]](#references)</sup>

La finalización de estos pasos da como resultado el establecimiento de Mach ports, sentando las bases para la comunicación bidireccional.<sup>[[1]](#references)</sup>

## 3. Primitivas básicas de lectura/escritura de memoria

En esta sección, el objetivo es utilizar la execute primitive para establecer primitivas básicas de lectura/escritura de memoria. Estos pasos iniciales son cruciales para obtener un mayor control sobre el proceso remoto, aunque las primitivas en esta fase no tendrán muchos usos. Pronto se actualizarán a versiones más avanzadas.<sup>[[1]](#references)</sup>

### Lectura y escritura de memoria mediante la execute primitive

El objetivo es realizar lecturas y escrituras de memoria utilizando funciones específicas. Para **leer memoria**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Para escribir en memoria:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Estas funciones corresponden al siguiente código ensamblador:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificación de funciones adecuadas

Un análisis de libraries comunes reveló candidates adecuados para estas operaciones:<sup>[[1]](#references)</sup>

1. **Lectura de memoria — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Escritura de memoria — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar una escritura de 64 bits en una dirección arbitraria:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Con estos primitives establecidos, el escenario está preparado para crear memoria compartida, lo que representa un avance significativo en el control del proceso remoto.<sup>[[1]](#references)</sup>

## 4. Configuración de la memoria compartida

El objetivo es establecer memoria compartida entre las tareas local y remota, simplificando la transferencia de datos y facilitando la llamada a funciones con múltiples argumentos. El enfoque aprovecha `libxpc` y su tipo de objeto `OS_xpc_shmem`, basado en Mach memory entries.<sup>[[1]](#references)</sup>

### Descripción general del proceso

1. **Asignación de memoria**
* Asignar memoria para compartir mediante `mach_vm_allocate()`.
* Usar `xpc_shmem_create()` para crear un objeto `OS_xpc_shmem` para la región asignada.
2. **Creación de memoria compartida en el proceso remoto**
* Asignar memoria para el objeto `OS_xpc_shmem` en el proceso remoto (`remote_malloc`).
* Copiar el objeto plantilla local; todavía es necesario realizar el fix-up del Mach send right incrustado en el offset `0x18`.
3. **Corrección de la Mach memory entry**
* Insertar un send right con `thread_set_special_port()` y sobrescribir el campo `0x18` con el nombre de la entry remota.
4. **Finalización**
* Validar el objeto remoto y mapearlo mediante una llamada remota a `xpc_shmem_remote()`.

## 5. Obtención del control total

Una vez disponibles la ejecución arbitraria y un back-channel de memoria compartida, el proceso objetivo queda efectivamente bajo tu control:<sup>[[1]](#references)</sup>

* **Lectura/escritura arbitraria de memoria** — usar `memcpy()` entre las regiones local y compartida.
* **Llamadas a funciones con > 8 argumentos** — colocar los argumentos adicionales en la stack siguiendo la convención de llamadas arm64.
* **Transferencia de Mach ports** — pasar rights en mensajes Mach a través de los ports establecidos.
* **Transferencia de file descriptors** — aprovechar fileports (consulta *triple_fetch*).

Todo esto está incluido en la library [`threadexec`](https://github.com/bazad/threadexec) para facilitar su reutilización.

---

## 6. Particularidades de Apple Silicon (arm64e)

En dispositivos Apple Silicon (arm64e), los **Pointer Authentication Codes (PAC)** protegen todas las direcciones de retorno y muchos punteros a funciones. Las técnicas de thread-hijacking que *reutilizan código existente* continúan funcionando porque los valores originales en `lr`/`pc` ya contienen firmas PAC válidas. Los problemas aparecen cuando intentas saltar a memoria controlada por el atacante:

1. Asignar memoria ejecutable dentro del objetivo (`mach_vm_allocate` remoto + `mprotect(PROT_EXEC)`).
2. Copiar tu payload.
3. Firmar el puntero dentro del proceso *remoto*:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Establece `pc = ptr` en el estado del thread secuestrado.

Como alternativa, mantén la compatibilidad con PAC encadenando gadgets/funciones existentes (ROP tradicional).

## 7. Detection & Hardening with EndpointSecurity

El framework **EndpointSecurity (ES)** expone eventos del kernel que permiten a los defensores observar o bloquear intentos de thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – se activa cuando un proceso solicita el port de task de otro proceso (por ejemplo, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – se emite cada vez que se crea un thread en una *task* diferente.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (añadido en macOS 14 Sonoma) – indica la manipulación de registros de un thread existente.

Cliente Swift mínimo que imprime eventos de remote thread:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Consultando con **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Consideraciones del hardened runtime

Distribuir tu aplicación **sin** el entitlement `com.apple.security.get-task-allow` impide que los atacantes que no son root obtengan su task-port. System Integrity Protection (SIP) todavía bloquea el acceso a muchos binarios de Apple, pero el software de terceros debe excluirse explícitamente.

## 8. Herramientas públicas recientes (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compacto que demuestra el thread hijacking compatible con PAC en Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Helper de EndpointSecurity utilizado por varios proveedores de EDR para detectar eventos `REMOTE_THREAD_CREATE` |

> Leer el código fuente de estos proyectos es útil para comprender los cambios en las API introducidos en macOS 13/14 y mantener la compatibilidad entre Intel ↔ Apple Silicon.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
