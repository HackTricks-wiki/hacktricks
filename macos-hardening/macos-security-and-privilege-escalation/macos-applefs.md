# macOS AppleFS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Sistema de Archivos Propietario de Apple (APFS)

**Apple File System (APFS)** es un sistema de archivos moderno diseñado para reemplazar al Sistema de Archivos Jerárquico Plus (HFS+). Su desarrollo fue impulsado por la necesidad de **mejorar el rendimiento, la seguridad y la eficiencia**.

Algunas características destacadas de APFS incluyen:

1. **Compartición de Espacio**: APFS permite que múltiples volúmenes **compartan el mismo almacenamiento libre subyacente** en un solo dispositivo físico. Esto permite una utilización de espacio más eficiente, ya que los volúmenes pueden crecer y reducirse dinámicamente sin necesidad de redimensionamiento o reparticionamiento manual.
1. Esto significa, en comparación con las particiones tradicionales en discos de archivos, **que en APFS diferentes particiones (volúmenes) comparten todo el espacio del disco**, mientras que una partición regular generalmente tenía un tamaño fijo.
2. **Instantáneas**: APFS admite **crear instantáneas**, que son instancias **de solo lectura** del sistema de archivos en un momento específico. Las instantáneas permiten copias de seguridad eficientes y fácil reversión del sistema, ya que consumen un almacenamiento adicional mínimo y se pueden crear o revertir rápidamente.
3. **Clones**: APFS puede **crear clones de archivos o directorios que comparten el mismo almacenamiento** que el original hasta que se modifique el clon o el archivo original. Esta función proporciona una forma eficiente de crear copias de archivos o directorios sin duplicar el espacio de almacenamiento.
4. **Cifrado**: APFS **admite nativamente el cifrado de disco completo** así como el cifrado por archivo y por directorio, mejorando la seguridad de los datos en diferentes casos de uso.
5. **Protección contra Fallas**: APFS utiliza un esquema de metadatos de **copia en escritura que garantiza la consistencia del sistema de archivos** incluso en casos de pérdida repentina de energía o bloqueos del sistema, reduciendo el riesgo de corrupción de datos.

En general, APFS ofrece un sistema de archivos más moderno, flexible y eficiente para dispositivos Apple, con un enfoque en mejorar el rendimiento, la confiabilidad y la seguridad.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

El volumen `Data` se monta en **`/System/Volumes/Data`** (puedes verificar esto con `diskutil apfs list`).

La lista de firmlinks se puede encontrar en el archivo **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
En la **izquierda**, se encuentra la ruta del directorio en el **volumen del Sistema**, y en la **derecha**, la ruta del directorio donde se mapea en el **volumen de Datos**. Entonces, `/library` --> `/system/Volumes/data/library`
