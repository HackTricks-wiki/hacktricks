# macOS AppleFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Sistema de archivos propietario de Apple (APFS)

APFS, o Apple File System, es un sistema de archivos moderno desarrollado por Apple Inc. que fue diseñado para reemplazar el antiguo Hierarchical File System Plus (HFS+) con énfasis en **mejorar el rendimiento, la seguridad y la eficiencia**.

Algunas características destacadas de APFS incluyen:

1. **Compartición de espacio**: APFS permite que múltiples volúmenes **compartan el mismo almacenamiento libre subyacente** en un solo dispositivo físico. Esto permite una utilización más eficiente del espacio, ya que los volúmenes pueden crecer y reducirse dinámicamente sin necesidad de redimensionamiento o reparticionamiento manual.
1. Esto significa, en comparación con las particiones tradicionales en discos de archivos, **que en APFS diferentes particiones (volúmenes) comparten todo el espacio en disco**, mientras que una partición regular generalmente tenía un tamaño fijo.
2. **Instantáneas**: APFS admite **crear instantáneas**, que son instancias **de solo lectura** del sistema de archivos en un momento específico. Las instantáneas permiten realizar copias de seguridad eficientes y revertir fácilmente el sistema, ya que consumen un almacenamiento adicional mínimo y se pueden crear o revertir rápidamente.
3. **Clones**: APFS puede **crear clones de archivos o directorios que comparten el mismo almacenamiento** que el original hasta que se modifique el clon o el archivo original. Esta función proporciona una forma eficiente de crear copias de archivos o directorios sin duplicar el espacio de almacenamiento.
4. **Cifrado**: APFS **admite nativamente el cifrado de disco completo**, así como el cifrado por archivo y por directorio, mejorando la seguridad de los datos en diferentes casos de uso.
5. **Protección contra fallos**: APFS utiliza un **esquema de metadatos de copia en escritura que garantiza la consistencia del sistema de archivos** incluso en casos de pérdida repentina de energía o bloqueo del sistema, reduciendo el riesgo de corrupción de datos.

En general, APFS ofrece un sistema de archivos más moderno, flexible y eficiente para dispositivos Apple, con un enfoque en mejorar el rendimiento, la confiabilidad y la seguridad.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

El volumen `Data` se monta en **`/System/Volumes/Data`** (puedes verificar esto con `diskutil apfs list`).

La lista de firmlinks se encuentra en el archivo **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
En la **izquierda**, se encuentra la ruta del directorio en el **volumen del sistema**, y en la **derecha**, la ruta del directorio donde se mapea en el **volumen de datos**. Por lo tanto, `/library` --> `/system/Volumes/data/library`

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
