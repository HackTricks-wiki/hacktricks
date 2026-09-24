# Windows Kernel Rootkits y DKOM

{{#include ../../banners/hacktricks-training.md}}

## Alcance

Un implant post-compromise puede cargar un kernel driver firmado como un servicio y exponer un plano de control en user mode mediante `IRP_MJ_DEVICE_CONTROL`. La firma del driver solo establece que Windows acepta la imagen; no hace que la autorización de IOCTL, las operaciones de memoria, los callbacks o los hooks sean seguros. Un rootkit analizado utilizaba tres handlers durante el funcionamiento normal, pero exponía docenas de primitivas adicionales de post-exploitation, por lo que el reverse engineering debe cubrir el dispatcher completo en lugar de limitarse a las solicitudes observadas en un malware trace.<sup>[[1]](#references)</sup>

## Triage de signed-driver e IOCTL

Comienza en `DriverEntry`, registra los objetos de dispositivo y los enlaces simbólicos de DOS, localiza la rutina `MajorFunction[IRP_MJ_DEVICE_CONTROL]` y mapea cada comparación/entrada de tabla que llegue a un handler. Compara los nombres abiertos por user mode con los nombres que realmente crea el driver: una cadena observada abría `\\.\msagent`, mientras que su driver creaba `\Device\ToolTool` y `\DosDevices\ToolTool`. Esta discrepancia puede identificar otra muestra/configuración, lógica de configuración ausente o una inconsistencia del análisis.<sup>[[1]](#references)</sup>

Decodifica cada control code antes de reconstruir su estructura de entrada.<sup>[[1]](#references)</sup>
```python
def decode_ioctl(code):
return {
"device_type": code >> 16,
"access": (code >> 14) & 3,
"function": (code >> 2) & 0xfff,
"method": code & 3,
}

for code in (0x2220F0, 0x222120, 0x2221E0):
print(hex(code), decode_ioctl(code))
```
Estos tres códigos se decodifican como `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` y `METHOD_BUFFERED`. Eso **no** demuestra que un caller sin privilegios pueda acceder a ellos: inspecciona también la DACL del dispositivo, el dispatch de creación/apertura, las comprobaciones del caller por solicitud, las longitudes de buffer esperadas, los punteros incrustados, la gestión del ciclo de vida de los PID y si el handler confía en un PID o flag proporcionado por el caller.<sup>[[1]](#references)</sup>

Cuando el implant utiliza solo un subconjunto de comandos, agrupa los handlers restantes por primitive en lugar de descartarlos como dead code. Un único driver multifunción ha expuesto todas las siguientes clases:<sup>[[1]](#references)</sup>

- **Control/configuración:** alternar el estado del rootkit; añadir, eliminar, consultar o borrar paths, procesos y direcciones C2 protegidos.
- **Manipulación de procesos:** terminar un PID, desmapear su imagen, inyectar con `NtCreateThreadEx`, ocultar/restaurar procesos o módulos de usuario y eliminar la protección PPL.
- **Manipulación del kernel:** desvincular un driver cargado, enumerar/deshabilitar/restaurar callbacks de notificación, mapear manualmente otro driver y escribir en una dirección arbitraria del kernel.
- **Manipulación de objetos:** eliminar/descifrar archivos y crear o modificar valores del registro.

## Exenciones de procesos de confianza

Un patrón de diseño útil es un IOCTL que registra un PID junto con un flag **trusted**. La misma consulta de confianza se utiliza después en los filtros de archivos, registro, procesos e hilos: las herramientas no confiables reciben resultados de enumeración filtrados, derechos de handle reducidos o `STATUS_ACCESS_DENIED`, mientras el implant aún puede actualizar sus propios objetos ocultos. Trátalo como un límite de autorización y verifica cómo se autentican, sincronizan y eliminan las entradas después de la salida del proceso o la reutilización del PID.<sup>[[1]](#references)</sup>

Los rootkits pueden persistir la policy en valores `REG_MULTI_SZ` y compilar listas de archivos, directorios, claves del registro, valores del registro, imágenes ignoradas, imágenes protegidas e imágenes ocultas en árboles AVL. Durante el análisis, rastrea cada lector y escritor de estos árboles compartidos; esto vincula la configuración del registro, los IOCTLs, los callbacks y la lógica de filtrado incluso cuando los nombres de las funciones han sido eliminados.<sup>[[1]](#references)</sup>

## Ocultación de procesos y módulos mediante DKOM

### `EPROCESS.ActiveProcessLinks`

Los offsets de `ActiveProcessLinks` varían según el build de Windows. Un rootkit tolerante a versiones puede probar candidatos conocidos y después explorar `EPROCESS` en busca de un `LIST_ENTRY` autoconsistente cuyos vecinos apunten de vuelta al candidato. Conserva el offset descubierto, oculta un proceso reconectando los `Flink`/`Blink` de sus vecinos y preserva el estado para volver a enlazar la entrada posteriormente. El proceso continúa ejecutándose, pero desaparece de los enumeradores que recorren la lista de procesos activos.<sup>[[1]](#references)</sup>

Esto es **DKOM**, no una terminación. La detección debe comparar los resultados basados en listas con evidencias independientes, como exploraciones de pool/objetos, ownership de hilos, tablas de handles, artefactos del scheduler e inspección de la memoria del kernel. Un proceso visible para una exploración pero ausente de la lista canónica es más significativo que cualquiera de las dos vistas por separado.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

La primitive equivalente de ocultación de módulos encuentra la entrada objetivo en `PsLoadedModuleList` y parchea los punteros `Flink`/`Blink` adyacentes. El driver permanece mapeado y ejecutable, pero las consultas de módulos basadas en listas lo omiten. Compara la lista del loader con los mapeos ejecutables del kernel, los pool tags, los objetos de dispositivo/driver, las claves de servicio, las direcciones de callbacks y los punteros de dispatch que apunten fuera de una imagen listada.<sup>[[1]](#references)</sup>

## Protección y cloaking basados en callbacks

Un rootkit puede combinar frameworks de callbacks documentados con DKOM y hooks:<sup>[[1]](#references)</sup>

- Los handlers pre-operation de `ObRegisterCallbacks` para `PsProcessType` y `PsThreadType` eliminan los derechos utilizados para la terminación, el acceso a la VM, la duplicación o la manipulación de hilos cuando un caller no confiable abre un objetivo protegido. Registra el callback altitude y resuelve cada dirección de callback hasta su módulo propietario.
- `PsSetCreateProcessNotifyRoutineEx` y `PsSetLoadImageNotifyRoutine` mantienen el estado de procesos protegidos/ignorados/ocultos a medida que aparecen procesos e imágenes; un recorrido de procesos realizado una sola vez puede completar los objetos que existían antes del registro.
- Un filesystem minifilter deniega el acceso a los paths configurados. Una implementación inusual puede crear su clave `Instances`, elegir un altitude dinámicamente e incrementarlo/reintentarlo cuando `FltRegisterFilter` informa de una colisión.
- Una rutina `CmRegisterCallbackEx` puede suprimir nombres protegidos de la enumeración y denegar operaciones directas de apertura, renombrado, establecimiento o eliminación, mientras exime a los procesos trusted registrados.

Correlaciona los registros de `ObRegisterCallbacks`, los altitudes de los callbacks del registro, la salida de `fltmc filters`, las claves de servicio `Instances` y las direcciones de los callbacks. Si las herramientas normales están siendo filtradas, inspecciona estas estructuras desde una imagen de memoria offline u otra trusted acquisition layer.<sup>[[1]](#references)</sup>

## Filtrado de resultados de Nsiproxy

La ocultación de red puede dirigirse a `\Driver\Nsiproxy`: obtener el objeto driver con `ObReferenceObjectByName`, guardar un puntero al handler, reemplazarlo por un wrapper y eliminar los registros IPv4 devueltos que coincidan con una lista C2 gestionada mediante IOCTL antes de que lleguen al user mode. Es posible que las aplicaciones respaldadas por los datos NSI filtrados dejen de mostrar la conexión aunque el tráfico siga existiendo.<sup>[[1]](#references)</sup>

Compara las vistas de conexiones del host con la captura de paquetes, la telemetría WFP/ETW y los objetos de red de la memoria del kernel. Inspecciona también los punteros de dispatch/handler de `Nsiproxy` y confirma que cada uno se resuelve dentro del módulo firmado esperado; un puntero hacia un mapping no listado puede conectar el filtrado de red con el DKOM de `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Checklist de investigación

La señal más sólida es el desacuerdo entre capas, no un único nombre de archivo o hash. Correlaciona:<sup>[[1]](#references)</sup>

1. La creación de servicios del kernel y un driver firmado cuyo certificado, publisher o path no sean coherentes con el producto instalado.
2. La creación de dispositivos, los enlaces DOS y el tráfico IOCTL, incluidos los nombres de dispositivo de user mode y del kernel que no coincidan.
3. Una solicitud de registro de un PID seguida de fallos de otros procesos al abrir, enumerar, modificar o eliminar los mismos objetos.
4. Callbacks de objetos/registro/procesos/imágenes, instancias de minifilter y hooks cuyas direcciones no pertenezcan a un driver enumerado normalmente.
5. Diferencias entre los inventarios de procesos, módulos, callbacks y redes basados en listas y los basados en exploraciones.

## References

- [1] [Kaspersky Securelist - HoneyMyte mejora CoolClient con un Windows Kernel Rootkit firmado](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
