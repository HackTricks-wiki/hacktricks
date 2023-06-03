## Sistema de archivos propietario de Apple (APFS)

APFS, o Apple File System, es un sistema de archivos moderno desarrollado por Apple Inc. que fue diseñado para reemplazar el antiguo Hierarchical File System Plus (HFS+) con énfasis en **mejorar el rendimiento, la seguridad y la eficiencia**.

Algunas características destacadas de APFS incluyen:

1. **Compartición de espacio**: APFS permite que varios volúmenes **compartan el mismo almacenamiento libre subyacente** en un solo dispositivo físico. Esto permite una utilización de espacio más eficiente ya que los volúmenes pueden crecer y disminuir dinámicamente sin necesidad de redimensionamiento o reparticionamiento manual.
   1. Esto significa, en comparación con las particiones tradicionales en discos de archivos, que en APFS diferentes particiones (volúmenes) comparten todo el espacio en disco, mientras que una partición regular generalmente tenía un tamaño fijo.
2. **Instantáneas**: APFS admite la **creación de instantáneas**, que son instancias **de solo lectura** del sistema de archivos en un momento determinado. Las instantáneas permiten copias de seguridad eficientes y fácilmente reversibles, ya que consumen un almacenamiento adicional mínimo y se pueden crear o revertir rápidamente.
3. **Clones**: APFS puede **crear clones de archivos o directorios que comparten el mismo almacenamiento** que el original hasta que se modifica el clon o el archivo original. Esta característica proporciona una forma eficiente de crear copias de archivos o directorios sin duplicar el espacio de almacenamiento.
4. **Cifrado**: APFS **admite nativamente el cifrado de disco completo** así como el cifrado de archivo y directorio, mejorando la seguridad de los datos en diferentes casos de uso.
5. **Protección contra fallos**: APFS utiliza un **esquema de metadatos de copia en escritura que garantiza la consistencia del sistema de archivos** incluso en casos de pérdida de energía repentina o fallos del sistema, reduciendo el riesgo de corrupción de datos.

En general, APFS ofrece un sistema de archivos más moderno, flexible y eficiente para dispositivos Apple, con un enfoque en mejorar el rendimiento, la confiabilidad y la seguridad.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

El volumen `Data` se monta en **`/System/Volumes/Data`** (puedes comprobar esto con `diskutil apfs list`).

La lista de firmlinks se puede encontrar en el archivo **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
En la **izquierda**, se encuentra la ruta del directorio en el **volumen del sistema**, y en la **derecha**, la ruta del directorio donde se mapea en el **volumen de datos**. Así, `/library` --> `/system/Volumes/data/library`.
