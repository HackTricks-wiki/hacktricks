# macOS AppleFS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Sistema de Archivos Propietario de Apple (APFS)

APFS, o Apple File System, es un sistema de archivos moderno desarrollado por Apple Inc. diseñado para reemplazar el antiguo Sistema de Archivos Jerárquico Plus (HFS+) con énfasis en **mejor rendimiento, seguridad y eficiencia**.

Algunas características notables de APFS incluyen:

1. **Compartición de Espacio**: APFS permite que múltiples volúmenes **compartan el mismo almacenamiento libre subyacente** en un solo dispositivo físico. Esto permite una utilización del espacio más eficiente, ya que los volúmenes pueden crecer y reducirse dinámicamente sin necesidad de redimensionamiento manual o reparticionamiento.
2. Esto significa, en comparación con las particiones tradicionales en discos de archivos, **que en APFS diferentes particiones (volúmenes) comparten todo el espacio del disco**, mientras que una partición regular solía tener un tamaño fijo.
3. **Instantáneas**: APFS soporta **la creación de instantáneas**, que son instancias del sistema de archivos **solo lectura** y de un punto en el tiempo específico. Las instantáneas permiten realizar copias de seguridad eficientes y restauraciones del sistema fáciles, ya que consumen un almacenamiento adicional mínimo y pueden ser creadas o revertidas rápidamente.
4. **Clones**: APFS puede **crear clones de archivos o directorios que comparten el mismo almacenamiento** que el original hasta que se modifique el clon o el archivo original. Esta característica proporciona una manera eficiente de crear copias de archivos o directorios sin duplicar el espacio de almacenamiento.
5. **Encriptación**: APFS **soporta de forma nativa la encriptación completa del disco** así como la encriptación por archivo y por directorio, mejorando la seguridad de los datos en diferentes casos de uso.
6. **Protección contra fallos**: APFS utiliza un esquema de metadatos de **escritura por copia que asegura la consistencia del sistema de archivos** incluso en casos de pérdida de energía súbita o fallos del sistema, reduciendo el riesgo de corrupción de datos.

En general, APFS ofrece un sistema de archivos más moderno, flexible y eficiente para dispositivos Apple, con un enfoque en el mejor rendimiento, fiabilidad y seguridad.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

El volumen `Data` está montado en **`/System/Volumes/Data`** (puedes verificar esto con `diskutil apfs list`).

La lista de firmlinks se puede encontrar en el archivo **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
A la **izquierda**, está la ruta del directorio en el **volumen del sistema**, y a la **derecha**, la ruta del directorio donde se mapea en el **volumen de datos**. Entonces, `/library` --> `/system/Volumes/data/library`

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
