# Windows Process Injection mediante nombres de threads y threads en espera

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) transfiere bytes a un proceso en ejecución sin `WriteProcessMemory`; Waiting Thread Hijacking (WTH) los ejecuta en un thread existente sin `SetThreadContext` ni crear un thread remoto.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Estas son **primitivas de process injection, no vulnerabilidades de escalada de privilegios**: el injector sigue necesitando acceso al proceso y al thread de destino. Las APIs de descripción de threads requieren Windows 10, versión 1607 o posterior.<sup>[[1]](#references)[[3]](#references)</sup> Consulta [Antivirus (AV) Bypass](av-bypass.md) para conocer otros métodos de injection y evasión.

## Thread Name-Calling: copia del payload en el lado del destino

`NtSetInformationThread(ThreadNameInformation)` copia una `UNICODE_STRING` proporcionada al almacenamiento del nombre del thread. Llamar a `GetThreadDescription` **dentro del destino** crea una copia del nombre en el heap de modo usuario. Esto separa la transferencia del payload de la copia final en memoria: el injector puede leer el **puntero** del heap devuelto, mientras que un APC que ejecuta `RtlMoveMemory` dentro del destino copia los bytes a su destino.<sup>[[1]](#references)</sup> La técnica original también admite APC especiales de usuario; la implementación de WhisperHijack usa, en cambio, `NtQueueApcThread` ordinario en un thread en espera.<sup>[[1]](#references)[[3]](#references)</sup>

Para cada fragmento de hasta `0xFFFE` bytes, el PoC sigue este orden. Un evento duplicado de reinicio automático señala que la operación ha terminado solo después de que el destino haya rellenado la ranura temporal; el injector espera esa señal antes de leer el puntero. El evento confirma el APC del puntero del heap, no el APC de copia posterior. El PoC alerta al mismo thread después de poner en cola la copia y se basa en el orden de los APC, en lugar de usar una segunda señal de finalización.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

La dirección scratch debe ser escribible en el proceso objetivo y conocida por el injector sin escribirla previamente. El PoC original usa `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack también ofrece `PEB.PostProcessInitRoutine` y, de forma predeterminada, usa `TEB.TlsSlots[63]` (ubicado con `NtQueryInformationThread(ThreadBasicInformation)`). No se garantiza que el slot TLS esté libre en todos los procesos objetivo; sobrescribir un slot activo puede interrumpir ese thread. Habilita exactamente una opción en `Main.c`. Las comprobaciones en tiempo de compilación rechazan selecciones PEB/TEB ausentes o incompatibles.<sup>[[4]](#references)</sup>

Una llamada normal a `RtlInitUnicodeString` se detendría ante un nulo wide incrustado. Para transportar datos binarios, inicializa la longitud de `UNICODE_STRING` usando un búfer de relleno no nulo del mismo tamaño, reemplaza los bytes de `Buffer` por el fragmento real y luego pásalo a `NtSetInformationThread`. Esta transferencia basada en la longitud es distinta de pasar el shellcode directamente a `SetThreadDescription` como una cadena terminada.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: retorno desde una espera de cola

Enumera los threads con `NtQuerySystemInformation(SystemProcessInformation)` y busca `ThreadState == Waiting` con `WaitReason == WrQueue`. Un thread bloqueado en un wrapper de syscall como `NtWaitForWorkViaWorkerFactory` tiene la dirección de retorno guardada del caller en `[Rsp]`. Reemplazar ese slot de la pila redirige el `ret` del wrapper a un stub sin cambiar `Rip` mediante `SetThreadContext`. El stub debe guardar los flags y los registros, **llamar** a un payload que retorne, restaurar el estado y luego saltar a la dirección de retorno original guardada.<sup>[[2]](#references)[[3]](#references)</sup>

En el PoC x64, el stub tiene un slot de retorno guardado de 8 bytes en `+0x00`, instrucciones en `+0x08` y el payload en `+0x45`. El slot de la pila recibe `allocation_base + 0x08`, no la dirección del slot de datos. `WrQueue` por sí solo **no demuestra** que se trate de una espera de worker factory: la investigación original también identifica `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` como una ruta de espera de cola. Comprueba la pila real de espera/llamadas y que `[Rsp]` sea el slot de retorno previsto antes de confiar en este diseño.<sup>[[2]](#references)[[3]](#references)</sup>

## Combinación de TNC y WTH sin escrituras entre procesos

WhisperHijack demuestra el flujo combinado contra un proceso nativo x64 existente. Su Writer selecciona un proceso/thread candidato, mientras que un proceso hijo Flipper hereda los handles necesarios para la transferencia final. El handle del proceso solicita `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **no** `PROCESS_VM_WRITE`; aun así, el PoC actual abre el thread con `THREAD_ALL_ACCESS`. Siguen aplicándose las comprobaciones de acceso y las mitigaciones del proceso.<sup>[[3]](#references)[[4]](#references)</sup>

El PoC combinado sigue esta secuencia; las APC que copian memoria se ejecutan en el proceso objetivo, no mediante un handle con permisos de escritura remota.<sup>[[4]](#references)</sup>

1. Reserva bloques libres alineados a 64 KB en el proceso objetivo y luego confirma sus páginas de 4 KB como `PAGE_READWRITE`. El PoC sondea direcciones candidatas fijas con `NtQueryVirtualMemory`; estas direcciones son decisiones de implementación, no un requisito de TNC o WTH.
2. Ensambla `[stub WTH de 0x45 bytes][payload x64 con retorno][puntero de entrada al stub de 8 bytes]`, donde el último puntero es `allocation_base + 0x08`. Entrega este búfer mediante el bucle de fragmentos de TNC.
3. En el Flipper, obtiene el `Rsp` del thread en espera con `NtGetContextThread(CONTEXT_CONTROL)`. Encola una APC de `RtlMoveMemory` dentro del proceso objetivo para copiar el valor original de 8 bytes en `[Rsp]` al slot de datos del stub.
4. Cambia la región preparada a ejecutable con `NtProtectVirtualMemory`. Este PoC elige `PAGE_EXECUTE_READWRITE` porque su payload polimórfico se decodifica a sí mismo; WTH no requiere por sí mismo un payload que se modifique a sí mismo.
5. Encola otra APC de `RtlMoveMemory` dentro del proceso objetivo para copiar el **puntero final preparado de antemano** a `[Rsp]` y luego llama a `NtAlertThread`. El orden FIFO de las APC guarda el retorno original antes de reemplazarlo; el retorno del wrapper entra en el stub y, después de que el payload retorna, reanuda el caller original.

La ausencia de `NtWriteVirtualMemory` **no** significa que no haya escrituras en el proceso objetivo: `GetThreadDescription` y `RtlMoveMemory` las realizan dentro del proceso objetivo.<sup>[[1]](#references)[[3]](#references)</sup> La entrega normal de APC a user mode también depende de que el thread seleccionado atienda su cola de APC; una captura de `WrQueue` y una alerta no garantizan que se ejecuten de inmediato en todos los casos.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> El ejemplo evita la creación de remote threads, la suspensión y el reemplazo directo del contexto, pero sigue siendo observable por sus APC y el cambio de protección.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Llamada mediante el nombre del thread](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Secuestro de un thread en espera](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – PoC y README de WhisperHijack](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – Implementación de WhisperHijack en Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
