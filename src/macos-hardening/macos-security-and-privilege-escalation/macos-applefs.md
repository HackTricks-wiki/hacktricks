# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Sistema de archivos propietario de Apple (APFS)

**Apple File System (APFS)** es un sistema de archivos moderno diseñado para reemplazar Hierarchical File System Plus (HFS+). Su desarrollo estuvo impulsado por la necesidad de obtener **un mejor rendimiento, seguridad y eficiencia**.

Algunas características destacadas de APFS incluyen:<sup>[[1]](#references)</sup>

1. **Compartición de espacio**: APFS permite que varios volúmenes **compartan el mismo almacenamiento libre subyacente** en un único dispositivo físico. Esto permite utilizar el espacio de forma más eficiente, ya que los volúmenes pueden crecer y reducirse dinámicamente sin necesidad de cambiar su tamaño manualmente ni volver a particionar.
1. Esto significa que, en comparación con las particiones tradicionales de los discos, **en APFS las distintas particiones (volúmenes) comparten todo el espacio del disco**, mientras que una partición normal suele tener un tamaño fijo.
2. **Snapshots**: APFS permite **crear snapshots**, que son instancias del sistema de archivos **de solo lectura** correspondientes a un momento determinado. Los snapshots permiten realizar backups eficientes y restaurar fácilmente el sistema, ya que consumen muy poco almacenamiento adicional y se pueden crear o revertir rápidamente.
3. **Clones**: APFS puede **crear clones de archivos o directorios que comparten el mismo almacenamiento** que el original hasta que se modifica el clon o el archivo original. Esta funcionalidad ofrece una forma eficiente de crear copias de archivos o directorios sin duplicar el espacio de almacenamiento.
4. **Cifrado**: APFS **admite de forma nativa el cifrado de disco completo**, así como el cifrado por archivo y por directorio, lo que mejora la seguridad de los datos en distintos casos de uso.
5. **Protección frente a fallos**: APFS utiliza un **esquema de metadatos copy-on-write que garantiza la coherencia del sistema de archivos** incluso en casos de pérdida repentina de energía o fallos del sistema, reduciendo el riesgo de corrupción de datos.

En general, APFS ofrece un sistema de archivos más moderno, flexible y eficiente para dispositivos Apple, centrado en mejorar el rendimiento, la fiabilidad y la seguridad.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

El volumen `Data` está montado en **`/System/Volumes/Data`** (puedes comprobarlo con `diskutil apfs list`).

La lista de firmlinks se encuentra en el archivo **`/usr/share/firmlinks`**.
```bash

```
## Referencias

- [1] [Guía de APFS - Funciones - Documentación para desarrolladores de Apple](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
