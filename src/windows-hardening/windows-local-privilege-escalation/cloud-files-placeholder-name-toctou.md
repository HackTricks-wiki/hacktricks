# Double-Fetch de búfer de usuario mapeado mediante MDL en Windows

{{#include ../../banners/hacktricks-training.md}}

Un driver del kernel de Windows provoca un double-fetch cuando valida datos en páginas respaldadas por el llamador y luego pasa un puntero a esas mismas páginas a una API sensible desde el punto de vista de la seguridad. Bloquear y mapear las páginas no vuelve inmutable su contenido. CVE-2025-55680 en `cldflt.sys` ilustra este patrón: el driver validaba el nombre relativo de un placeholder de Cloud Files y luego creaba el objeto mientras seguía haciendo referencia al búfer mutable del llamador.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` crea archivos o directorios dentro de una raíz de sincronización registrada de Cloud Files. En la ruta vulnerable, cambiar el nombre después de validarlo podía redirigir la creación privilegiada fuera de esa raíz.<sup>[[1]](#references)[[2]](#references)</sup>

## Por qué bloquear las páginas no bloqueó los datos

La ruta vulnerable `HsmpOpCreatePlaceholders()` asignaba un MDL para la carga útil del llamador, llamaba a `ProbeForRead()` y `MmProbeAndLockPages()`, y mapeaba esas páginas en el espacio de direcciones virtuales del kernel. Un MDL describe y bloquea las páginas físicas para que permanezcan residentes. **No** toma una instantánea de sus bytes. Por lo tanto, el modo usuario puede modificar la misma memoria física mientras el driver la lee a través del mapeo del sistema.<sup>[[1]](#references)[[3]](#references)</sup>

La ruta pertinente de solicitud y uso era:<sup>[[1]](#references)</sup>

1. `cldapi.dll` enviaba el código de control de Cloud Files `0x903BC` con la etiqueta `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) y la operación de creación de placeholders `0xC0000001`.
2. Cada registro de la carga útil contenía pares de desplazamiento/longitud de 16 bits para el nombre relativo y la identidad del archivo. La mayoría de los campos fijos se copiaban a un registro de la pila, pero el nombre de longitud variable permanecía en las páginas de usuario mapeadas.
3. El driver recorría el nombre UTF-16 y rechazaba una barra invertida o dos puntos.
4. Luego creaba un `UNICODE_STRING` cuyo `Buffer` seguía apuntando a la carga útil mapeada y lo asignaba a `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` volvía a leer ese puntero. Por lo tanto, un escritor concurrente podía hacer que la validación observara una cadena y la creación del archivo otra.

Esto es un **double-fetch**, aunque ambas lecturas usen una dirección virtual del kernel: el límite de seguridad depende del almacenamiento subyacente, no del mapeo virtual que desreferencia el driver.<sup>[[1]](#references)</sup>

## Escenario de carrera de Cloud Files

La estrategia de explotación divulgada usaba solicitudes repetidas, hilos modificadores y una junction para convertir el double-fetch en una redirección de ruta:<sup>[[1]](#references)</sup>

1. Registrar un directorio controlado por el atacante con `CfRegisterSyncRoot()` y crear dentro de él `JUSTASTRING` como una junction a un destino protegido.
2. Preparar un registro de placeholder compartido con el nombre válido de un único componente `JUSTASTRINGDnewfile.dll`.
3. Hacer que los hilos modificadores alternen la unidad de código UTF-16 `D` entre `D` y `\`. La segunda representación es `JUSTASTRING\newfile.dll`.
4. En paralelo, hacer que los hilos de trabajo envíen repetidamente solicitudes de creación de placeholders que hagan referencia a la misma carga útil, mientras un monitor comprueba el destino protegido.
5. Una iteración exitosa valida la representación sin separadores y luego sigue la junction cuando la creación posterior encuentra la representación que contiene `\`.

La primitiva solo permite crear archivos o directorios protegidos. Para convertirla en ejecución de código, todavía se necesita controlar el contenido del archivo creado y disponer de un consumidor privilegiado, como un objetivo adecuado para DLL side-loading. El análisis original utilizó esta última clase de cadena, pero no publicó el loader, la carga útil ni un exploit independiente completo.<sup>[[1]](#references)</sup>

Para ver técnicas complementarias que amplían deliberadamente las carreras de búsqueda de rutas de Windows, consulta [Explotación de condiciones de carrera del kernel mediante rutas lentas del Object Manager](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Escalada de privilegios TOCTOU en el minifiltro Cloud Files de Microsoft Windows](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - función CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - función MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
