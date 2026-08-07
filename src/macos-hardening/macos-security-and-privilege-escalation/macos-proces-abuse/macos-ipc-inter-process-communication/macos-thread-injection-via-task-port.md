# Thread Injection en macOS mediante Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Inicialmente, se invoca la función `task_threads()` en el task port para obtener una lista de threads del task remoto. Se selecciona un thread para realizar el hijacking. Este enfoque difiere de los métodos convencionales de code injection, ya que crear un nuevo thread remoto está prohibido debido a la mitigación que bloquea `thread_create_running()`.<sup>[[1]](#references)</sup>

Para controlar el thread, se llama a `thread_suspend()`, deteniendo su ejecución.<sup>[[1]](#references)</sup>

Las únicas operaciones permitidas sobre el thread remoto consisten en **detenerlo** e **iniciarlo**, además de **obtener**/**modificar** los valores de sus registros. Las llamadas a funciones remotas se inician estableciendo los registros `x0` a `x7` con los **argumentos**, configurando `pc` para apuntar a la función deseada y reanudando el thread. Para garantizar que el thread no se bloquee después del retorno, es necesario detectar dicho retorno.<sup>[[1]](#references)</sup>

Una estrategia consiste en registrar un **exception handler** para el thread remoto mediante `thread_set_exception_ports()`, estableciendo el registro `lr` en una dirección no válida antes de la llamada a la función. Esto provoca una excepción después de ejecutar la función y envía un mensaje al exception port, lo que permite inspeccionar el estado del thread para recuperar el valor de retorno. Como alternativa, siguiendo el enfoque adoptado del exploit *triple_fetch* de Ian Beer, `lr` se establece para realizar un bucle infinito; después, los registros del thread se supervisan continuamente hasta que `pc` apunta a esa instrucción.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

La siguiente fase consiste en establecer Mach ports para facilitar la comunicación con el thread remoto. Estos ports son fundamentales para transferir send/receive rights arbitrarios entre tasks.<sup>[[1]](#references)</sup>

Para permitir la comunicación bidireccional, se crean dos receive rights de Mach: uno en el task local y otro en el task remoto. Después, se transfiere un send right de cada port al task correspondiente, lo que permite intercambiar mensajes.<sup>[[1]](#references)</sup>

En el caso del port local, el receive right pertenece al task local. El port se crea mediante `mach_port_allocate()`. El desafío consiste en transferir un send right de este port al task remoto.<sup>[[1]](#references)</sup>

Una estrategia consiste en utilizar `thread_set_special_port()` para colocar un send right del port local en el `THREAD_KERNEL_PORT` del thread remoto. A continuación, se indica al thread remoto que llame a `mach_thread_self()` para recuperar el send right.<sup>[[1]](#references)</sup>

Para el port remoto, el proceso se invierte esencialmente. Se indica al thread remoto que genere un Mach port mediante `mach_reply_port()` (ya que `mach_port_allocate()` no es adecuado debido a su mecanismo de retorno). Una vez creado el port, se invoca `mach_port_insert_right()` en el thread remoto para establecer un send right. Este right se almacena temporalmente en el kernel mediante `thread_set_special_port()`. De vuelta en el task local, se utiliza `thread_get_special_port()` sobre el thread remoto para adquirir un send right al Mach port recién asignado en el task remoto.<sup>[[1]](#references)</sup>

La finalización de estos pasos establece los Mach ports y prepara la comunicación bidireccional.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

En esta sección, el objetivo es utilizar el execute primitive para establecer primitives básicas de lectura/escritura de memoria. Estos pasos iniciales son esenciales para obtener un mayor control sobre el proceso remoto, aunque las primitives de esta fase no tendrán muchos usos. Pronto se actualizarán a versiones más avanzadas.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

El objetivo es realizar lecturas y escrituras de memoria utilizando funciones específicas. Para **leer memoria**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Para **escribir en la memoria**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Estas funciones corresponden al siguiente código assembly:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificación de funciones adecuadas

Un análisis de bibliotecas comunes reveló candidatos adecuados para estas operaciones:<sup>[[1]](#references)</sup>

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
Con estas primitivas establecidas, el escenario está preparado para crear memoria compartida, lo que supone un avance significativo en el control del proceso remoto.<sup>[[1]](#references)</sup>

## 4. Configuración de la memoria compartida

El objetivo es establecer memoria compartida entre las tasks locales y remotas, simplificando la transferencia de datos y facilitando la llamada a funciones con múltiples argumentos. El enfoque utiliza `libxpc` y su tipo de objeto `OS_xpc_shmem`, basado en memory entries de Mach.<sup>[[1]](#references)</sup>

### Descripción general del proceso

1. **Asignación de memoria**
* Asignar memoria para compartir mediante `mach_vm_allocate()`.
* Usar `xpc_shmem_create()` para crear un objeto `OS_xpc_shmem` para la región asignada.
2. **Creación de memoria compartida en el proceso remoto**
* Asignar memoria para el objeto `OS_xpc_shmem` en el proceso remoto (`remote_malloc`).
* Copiar el objeto de plantilla local; todavía es necesario corregir el Mach send right integrado en el offset `0x18`.
3. **Corrección del Mach memory entry**
* Insertar un send right con `thread_set_special_port()` y sobrescribir el campo `0x18` con el name de la entry remota.
4. **Finalización**
* Validar el objeto remoto y mapearlo mediante una llamada remota a `xpc_shmem_remote()`.

## 5. Obtención del control total

Una vez disponible la ejecución arbitraria y un back-channel de memoria compartida, el proceso objetivo queda efectivamente bajo tu control:<sup>[[1]](#references)</sup>

* **Lectura/escritura (R/W) de memoria arbitraria** — usar `memcpy()` entre las regiones locales y compartidas.
* **Llamadas a funciones con > 8 argumentos** — colocar los argumentos adicionales en el stack siguiendo la convención de llamada arm64.
* **Transferencia de Mach ports** — pasar rights en mensajes de Mach mediante los ports establecidos.
* **Transferencia de descriptores de archivo** — utilizar fileports (ver *triple_fetch*).

Todo esto está incluido en la librería [`threadexec`](https://github.com/bazad/threadexec) para facilitar su reutilización.

---

## 6. Particularidades de Apple Silicon (arm64e)

En los dispositivos Apple Silicon (arm64e), los **Pointer Authentication Codes (PAC)** protegen todas las direcciones de retorno y muchos function pointers. Las técnicas de Thread-hijacking que *reutilizan código existente* siguen funcionando porque los valores originales de `lr`/`pc` ya contienen firmas PAC válidas. Los problemas aparecen al intentar saltar a memoria controlada por el atacante:

1. Asignar memoria ejecutable dentro del objetivo (`mach_vm_allocate` remoto + `mprotect(PROT_EXEC)`).
2. Copiar el payload.
3. Firmar el puntero dentro del proceso *remoto*:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Establece `pc = ptr` en el estado del thread secuestrado.

Como alternativa, mantén el cumplimiento con PAC encadenando gadgets/funciones existentes (ROP tradicional).

## 7. Detección y hardening con EndpointSecurity

El framework **EndpointSecurity (ES)** expone eventos del kernel que permiten a los defensores observar o bloquear intentos de thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – se activa cuando un proceso solicita el port de task de otro proceso (por ejemplo, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – se emite cada vez que se crea un thread en un task *diferente*.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (añadido en macOS 14 Sonoma) – indica la manipulación de registros de un thread existente.

Cliente mínimo de Swift que muestra eventos de remote-thread:
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
Consulta con **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Consideraciones sobre Hardened Runtime

Distribuir tu aplicación **sin** el entitlement `com.apple.security.get-task-allow` impide que los atacantes que no son root obtengan su task-port. System Integrity Protection (SIP) sigue bloqueando el acceso a muchos binarios de Apple, pero el software de terceros debe optar por no participar explícitamente.

## 8. Herramientas públicas recientes (2023-2025)

| Herramienta | Año | Observaciones |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compacta que demuestra thread hijacking compatible con PAC en Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Helper de EndpointSecurity utilizado por varios proveedores de EDR para mostrar eventos `REMOTE_THREAD_CREATE` |

> Leer el código fuente de estos proyectos resulta útil para comprender los cambios en la API introducidos en macOS 13/14 y mantener la compatibilidad entre Intel y Apple Silicon.

## Referencias

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
