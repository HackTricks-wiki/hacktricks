## Información básica

Un paquete de instalación de macOS (también conocido como archivo `.pkg`) es un formato de archivo utilizado por macOS para **distribuir software**. Estos archivos son como una **caja que contiene todo lo que un software necesita para instalarse y ejecutarse correctamente**.

El archivo del paquete en sí es un archivo que contiene una **jerarquía de archivos y directorios que se instalarán en el equipo de destino**. También puede incluir **scripts** para realizar tareas antes y después de la instalación, como configurar archivos de configuración o limpiar versiones antiguas del software.

### Jerarquía

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribución (xml)**: Personalizaciones (título, texto de bienvenida...) y comprobaciones de script/instalación
* **PackageInfo (xml)**: Información, requisitos de instalación, ubicación de instalación, rutas a scripts para ejecutar
* **Lista de materiales (bom)**: Lista de archivos para instalar, actualizar o eliminar con permisos de archivo
* **Carga útil (archivo CPIO comprimido con gzip)**: Archivos para instalar en la `ubicación de instalación` de PackageInfo
* **Scripts (archivo CPIO comprimido con gzip)**: Scripts de pre y post instalación y más recursos extraídos a un directorio temporal para su ejecución.

### Descompresión
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## Privesc a través del abuso de paquetes pkg

### Ejecución desde directorios públicos

Si un script de pre o post instalación se está ejecutando, por ejemplo, desde **`/var/tmp/Installerutil`**, un atacante podría controlar ese script para escalar privilegios cada vez que se ejecute. Otro ejemplo similar:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

## Referencias

* [https://www.youtube.com/watch?v=iASSG0\_zobQ](https://www.youtube.com/watch?v=iASSG0\_zobQ)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
