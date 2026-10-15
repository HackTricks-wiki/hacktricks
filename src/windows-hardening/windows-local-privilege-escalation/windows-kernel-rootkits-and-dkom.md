# Rootkits de kernel de Windows y DKOM

{{#include ../../banners/hacktricks-training.md}}

## Alcance

Un implante instalado tras comprometer el sistema puede cargar un driver de kernel firmado como servicio y exponer un plano de control en modo usuario mediante `IRP_MJ_DEVICE_CONTROL`. La firma del driver solo establece que Windows acepta la imagen; no hace que la autorización de IOCTL, las operaciones de memoria, las callbacks ni los hooks sean seguros. Un rootkit analizado usaba tres handlers durante el funcionamiento normal, pero exponía decenas de primitivas adicionales de post-explotación, por lo que la ingeniería inversa debe abarcar el dispatcher completo y no solo las solicitudes observadas en un registro de malware.<sup>[[1]](#references)</sup>

## Triage de drivers firmados e IOCTL

Empieza por `DriverEntry`, registra los objetos de dispositivo y los enlaces simbólicos DOS, localiza la rutina `MajorFunction[IRP_MJ_DEVICE_CONTROL]` y mapea todas las comparaciones o entradas de tabla que conducen a un handler. Compara los nombres que abre el modo usuario con los que crea realmente el driver: en una cadena observada se abrió `\\.\msagent`, mientras que el driver creó `\Device\ToolTool` y `\DosDevices\ToolTool`. Esta discrepancia puede indicar otra muestra o configuración, lógica de configuración ausente o una inconsistencia en el análisis.<sup>[[1]](#references)</sup>

Decodifica cada código de control antes de reconstruir su estructura de entrada.<sup>[[1]](#references)</sup>

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

Estos tres códigos se decodifican como `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` y `METHOD_BUFFERED`. Eso **no** demuestra que un usuario sin privilegios pueda acceder a ellos: inspecciona también la DACL del dispositivo, las rutinas de despacho de creación/apertura, las comprobaciones del solicitante en cada solicitud, las longitudes de búfer esperadas, los punteros incrustados, el manejo del ciclo de vida de los PID y si el controlador confía en un PID o una bandera proporcionados por el solicitante.<sup>[[1]](#references)</sup>

Cuando el implant solo utiliza un subconjunto de comandos, agrupa los demás handlers según la primitiva que implementan, en lugar de descartarlos como código muerto. Un único controlador multifunción ha expuesto todas estas clases:<sup>[[1]](#references)</sup>

- **Control/configuración:** alternar el estado del rootkit; añadir, quitar, consultar o borrar rutas, procesos y direcciones C2 protegidos.
- **Manipulación de procesos:** terminar un PID, desmapear su imagen, inyectar con `NtCreateThreadEx`, ocultar/restaurar procesos o módulos de usuario y quitar la protección PPL.
- **Manipulación del kernel:** desvincular un controlador cargado, enumerar/deshabilitar/restaurar callbacks de notificación, mapear manualmente otro controlador y escribir en una dirección arbitraria del kernel.
- **Manipulación de objetos:** eliminar/descifrar archivos y crear o modificar valores del registro.

## Mapeo manual del kernel mediante un controlador firmado vulnerable

Un controlador firmado con operaciones de lectura/escritura de memoria del kernel puede servir como cargador para una imagen de controlador sin firmar, sin pedir a Windows que la cargue como un controlador normal.<sup>[[2]](#references)[[7]](#references)</sup> El ejemplo de LocalStranger abre un dispositivo `\\.\WinNotify` existente; su código fuente no demuestra que un usuario sin privilegios pueda instalar, iniciar o abrir el controlador en un host cualquiera.<sup>[[2]](#references)[[3]](#references)</sup> El mapper recibe una ruta de imagen, consulta la base del kernel cargado y utiliza los IOCTL de lectura/escritura de memoria virtual del dispositivo.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Para convertir ese acceso de lectura/escritura en una llamada al kernel, el mapper lee un valor inmediato de la base PTE desde `MmGetVirtualForPhysical` y recorre las entradas de paginación que cubren `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> El cálculo de la PTE es `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; el código también comprueba si hay una PDE de página grande.<sup>[[5]](#references)[[7]](#references)</sup> Hace temporalmente escribible la entrada que cubre la dirección, reemplaza la entrada del syscall por un salto a la función del kernel deseada, invoca el stub de usuario `NtAddAtom` y luego restaura tanto los bytes originales como la entrada de página.<sup>[[6]](#references)</sup>

El mapper utiliza esa ruta de llamada para `ExAllocatePool`, mapea las secciones PE, las importaciones y las reubicaciones en la imagen, la escribe en la asignación y llama a su punto de entrada.<sup>[[7]](#references)[[8]](#references)</sup> Esta implementación solo acepta imágenes PE x64 reubicables; además, la lectura de la base PTE presupone un diseño fijo de `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Considéralo dependiente de la compilación, no una evasión de KASLR independiente ni una prueba de que HVCI o PatchGuard permitan el mapeo.<sup>[[5]](#references)[[8]](#references)</sup> Para un uso de solo datos de kernel R/W, consulta [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md).

## Exenciones para procesos de confianza

Un patrón de diseño útil es un IOCTL que registra un PID junto con una bandera de **confianza**. La misma consulta de confianza se utiliza luego en los filtros de archivos, registro, procesos e hilos: las herramientas no confiables reciben resultados de enumeración filtrados, derechos de acceso a handles reducidos o `STATUS_ACCESS_DENIED`, mientras que el implant aún puede actualizar sus propios objetos ocultos. Trátalo como un límite de autorización y verifica cómo se autentican y sincronizan las entradas, y cómo se eliminan tras la salida del proceso o la reutilización del PID.<sup>[[1]](#references)</sup>

Los rootkits pueden guardar políticas en valores `REG_MULTI_SZ` y compilar listas de archivos, directorios, claves del registro, valores del registro, imágenes ignoradas, imágenes protegidas e imágenes ocultas en árboles AVL. Durante el análisis, rastrea todos los lectores y escritores de estos árboles compartidos; conectan la configuración del registro, los IOCTL, los callbacks y la lógica de filtrado, incluso cuando se han eliminado los nombres de las funciones.<sup>[[1]](#references)</sup>

## Ocultamiento de procesos y módulos mediante DKOM

### `EPROCESS.ActiveProcessLinks`

Los offsets de `ActiveProcessLinks` varían según la compilación de Windows. Un rootkit tolerante a las versiones puede probar offsets conocidos y luego recorrer `EPROCESS` buscando un `LIST_ENTRY` coherente consigo mismo cuyos vecinos apunten de vuelta a la entrada candidata. Conserva el offset descubierto, oculta un proceso reconectando los `Flink`/`Blink` de sus vecinos y guarda el estado necesario para volver a enlazar la entrada más adelante. El proceso sigue ejecutándose, pero desaparece de los enumeradores que recorren la lista de procesos activos.<sup>[[1]](#references)</sup>

Esto es **DKOM**, no terminación. La detección debería comparar los resultados basados en listas con evidencia independiente, como análisis de pool/objetos, propiedad de hilos, tablas de handles, artefactos del planificador e inspección de memoria del kernel. Que un proceso aparezca en un análisis, pero no en la lista canónica, es más significativo que cualquiera de las dos observaciones por sí sola.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

La primitiva equivalente para ocultar módulos busca la entrada objetivo en `PsLoadedModuleList` y modifica los punteros `Flink`/`Blink` adyacentes. El controlador sigue mapeado y ejecutándose, pero las consultas de módulos basadas en listas lo omiten. Compara la lista del cargador con los mapeos ejecutables del kernel, las etiquetas de pool, los objetos de dispositivo/controlador, las claves de servicio, las direcciones de callback y los punteros de despacho que apunten fuera de una imagen enumerada.<sup>[[1]](#references)</sup>

## Protección y camuflaje basados en callbacks

Un rootkit puede combinar frameworks de callbacks documentados con DKOM y hooks:<sup>[[1]](#references)</sup>

- Los handlers de preoperación de `ObRegisterCallbacks` para `PsProcessType` y `PsThreadType` eliminan derechos utilizados para terminar, acceder a la VM, duplicar o manipular hilos cuando un solicitante no confiable abre un objetivo protegido. Registra el nivel de altitud del callback y resuelve cada dirección de callback para identificar el módulo al que pertenece.
- `PsSetCreateProcessNotifyRoutineEx` y `PsSetLoadImageNotifyRoutine` mantienen el estado de procesos protegidos/ignorados/ocultos a medida que aparecen procesos e imágenes; un recorrido único de procesos puede completar los objetos que existían antes del registro.
- Un minifiltro del sistema de archivos deniega el acceso a las rutas configuradas. Una implementación inusual puede crear su clave `Instances`, elegir una altitud dinámicamente e incrementarla y volver a intentarlo cuando `FltRegisterFilter` notifique una colisión.
- Una rutina `CmRegisterCallbackEx` puede suprimir nombres protegidos de la enumeración y denegar operaciones directas de apertura, cambio de nombre, modificación o eliminación, mientras exime a los procesos de confianza registrados.

Correlaciona los registros de `ObRegisterCallbacks`, las altitudes de callbacks del registro, la salida de `fltmc filters`, las claves de servicio `Instances` y las direcciones de callbacks. Si las herramientas normales están siendo filtradas, inspecciona estas estructuras desde una imagen de memoria sin conexión u otra capa de adquisición confiable.<sup>[[1]](#references)</sup>

## Filtrado de resultados de Nsiproxy

El ocultamiento de red puede apuntar a `\Driver\Nsiproxy`: obtiene el objeto del controlador con `ObReferenceObjectByName`, guarda un puntero a un handler, lo reemplaza por un wrapper y elimina los registros IPv4 devueltos que coincidan con una lista C2 administrada mediante IOCTL antes de que lleguen al modo de usuario. Es posible que las aplicaciones basadas en los datos NSI filtrados ya no muestren la conexión, aunque el tráfico siga existiendo.<sup>[[1]](#references)</sup>

Compara las vistas de conexiones del host con la captura de paquetes, la telemetría WFP/ETW y los objetos de red en memoria del kernel. Inspecciona también los punteros de despacho/handler de `Nsiproxy` y confirma que cada uno resuelva dentro del módulo firmado esperado; un puntero a un mapeo no enumerado puede conectar el filtrado de red con el DKOM de `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Lista de comprobación para la investigación

La señal más sólida es el desacuerdo entre capas, no un único nombre de archivo o hash. Correlaciona:<sup>[[1]](#references)</sup>

1. La creación de servicios del kernel y un controlador firmado cuyo certificado, editor o ruta sean incoherentes con el producto instalado.
2. La creación de dispositivos, los enlaces DOS y el tráfico IOCTL, incluidos los nombres de dispositivo de modo de usuario y del kernel que no coincidan.
3. Una solicitud de registro de PID seguida de errores en otros procesos al intentar abrir, enumerar, modificar o eliminar esos mismos objetos.
4. Callbacks de objetos/registro/procesos/imágenes, instancias de minifiltros y hooks cuyas direcciones no pertenezcan a un controlador enumerado normalmente.
5. Diferencias entre inventarios de procesos, módulos, callbacks y redes basados en listas y los basados en análisis.

## References

- [1] [Kaspersky Securelist: HoneyMyte mejora CoolClient con un rootkit firmado para el kernel de Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [README de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Inicialización del controlador de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Línea de comandos del mapper de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Resolución de exportaciones del kernel y la base PTE en LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Trampolín de llamada al kernel de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Asignación del mapper y llamada al punto de entrada en LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [Mapeo PE de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Contexto del kernel y de los syscalls en LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrappers de IOCTL de memoria virtual de LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
