# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Información básica**

**System Integrity Protection (SIP)** es una tecnología de seguridad en macOS que protege ciertos directorios del sistema contra accesos no autorizados, incluso para el usuario root. Evita modificaciones en estos directorios, incluyendo la creación, alteración o eliminación de archivos. Los principales directorios que SIP protege son:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Las reglas de protección para estos directorios y sus subdirectorios se especifican en el archivo **`/System/Library/Sandbox/rootless.conf`**. En este archivo, las rutas que comienzan con un asterisco (\*) representan excepciones a las restricciones de SIP.

Por ejemplo, la siguiente configuración:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
indica que el directorio **`/usr`** generalmente está protegido por SIP. Sin embargo, se permiten modificaciones en los tres subdirectorios especificados (`/usr/libexec/cups`, `/usr/local` y `/usr/share/man`), ya que están listados con un asterisco (\*) al principio.

Para verificar si un directorio o archivo está protegido por SIP, puedes usar el comando **`ls -lOd`** para verificar la presencia de la bandera **`restricted`** o **`sunlnk`**. Por ejemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
En este caso, la bandera **`sunlnk`** indica que el directorio `/usr/libexec/cups` en sí mismo **no puede ser eliminado**, aunque se pueden crear, modificar o eliminar archivos dentro de él.

Por otro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aquí, la bandera **`restricted`** indica que el directorio `/usr/libexec` está protegido por SIP. En un directorio protegido por SIP, no se pueden crear, modificar o eliminar archivos.

### Estado de SIP

Puede verificar si SIP está habilitado en su sistema con el siguiente comando:
```bash
csrutil status
```
Si necesitas desactivar SIP, debes reiniciar tu computadora en modo de recuperación (presionando Command+R durante el inicio), luego ejecuta el siguiente comando:
```bash
csrutil disable
```
Si deseas mantener SIP habilitado pero eliminar las protecciones de depuración, puedes hacerlo con:
```bash
csrutil enable --without debug
```
### Otras restricciones

SIP también impone varias restricciones adicionales. Por ejemplo, prohíbe la **carga de extensiones de kernel no firmadas** (kexts) y evita la **depuración** de los procesos del sistema macOS. También impide que herramientas como dtrace inspeccionen los procesos del sistema.

## Bypass de SIP

### Precios

Si un atacante logra eludir SIP, esto es lo que obtendrá:

* Leer correos electrónicos, mensajes, historial de Safari... de todos los usuarios
* Conceder permisos para la cámara web, el micrófono o cualquier otra cosa (escribiendo directamente en la base de datos TCC protegida por SIP)
* Persistencia: podría guardar un malware en una ubicación protegida por SIP y ni siquiera el root podrá eliminarlo. También podría manipular MRT.
* Facilidad para cargar extensiones de kernel (aún se aplican otras protecciones más avanzadas para esto).

### Paquetes de instalación

Los **paquetes de instalación firmados con el certificado de Apple** pueden eludir sus protecciones. Esto significa que incluso los paquetes firmados por desarrolladores estándar serán bloqueados si intentan modificar los directorios protegidos por SIP.

### Archivo SIP inexistente

Una posible laguna es que si se especifica un archivo en **`rootless.conf` pero no existe actualmente**, se puede crear. El malware podría aprovechar esto para **establecer persistencia** en el sistema. Por ejemplo, un programa malicioso podría crear un archivo .plist en `/System/Library/LaunchDaemons` si está listado en `rootless.conf` pero no está presente.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
El permiso **`com.apple.rootless.install.heritable`** permite eludir SIP.
{% endhint %}

[**Investigadores de esta publicación de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descubrieron una vulnerabilidad en el mecanismo de Protección de Integridad del Sistema (SIP) de macOS, llamada vulnerabilidad 'Shrootless'. Esta vulnerabilidad se centra en el demonio **`system_installd`**, que tiene un permiso, **`com.apple.rootless.install.heritable`**, que permite que cualquiera de sus procesos secundarios eluda las restricciones del sistema de archivos de SIP.

El demonio **`system_installd`** instalará paquetes que hayan sido firmados por **Apple**.

Los investigadores descubrieron que durante la instalación de un paquete firmado por Apple (.pkg), **`system_installd`** **ejecuta** cualquier script **post-instalación** incluido en el paquete. Estos scripts son ejecutados por la shell predeterminada, **`zsh`**, que automáticamente **ejecuta** comandos del archivo **`/etc/zshenv`**, si existe, incluso en modo no interactivo. Este comportamiento podría ser aprovechado por los atacantes: al crear un archivo malicioso `/etc/zshenv` y esperar a que **`system_installd` invoque `zsh`**, podrían realizar operaciones arbitrarias en el dispositivo.

Además, se descubrió que **`/etc/zshenv` podría ser utilizado como una técnica de ataque general**, no solo para eludir SIP. Cada perfil de usuario tiene un archivo `~/.zshenv`, que se comporta de la misma manera que `/etc/zshenv` pero no requiere permisos de root. Este archivo podría ser utilizado como un mecanismo de persistencia, activándose cada vez que `zsh` se inicia, o como un mecanismo de elevación de privilegios. Si un usuario administrador se eleva a root usando `sudo -s` o `sudo <comando>`, se activaría el archivo `~/.zshenv`, elevándose efectivamente a root.

En [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) se descubrió que el mismo proceso **`system_installd`** aún podía ser abusado porque colocaba el **script post-instalación dentro de una carpeta con nombre aleatorio protegida por SIP dentro de `/tmp`**. La cuestión es que **`/tmp` en sí no está protegido por SIP**, por lo que era posible **montar** una **imagen virtual en él**, luego el **instalador** colocaría en ella el **script post-instalación**, **desmontaría** la imagen virtual, **recrearía** todas las **carpetas** y **agregaría** el **script de post-instalación** con la **carga útil** a ejecutar.

### **com.apple.rootless.install**

{% hint style="danger" %}
El permiso **`com.apple.rootless.install`** permite eludir SIP.
{% endhint %}

Desde [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/), el servicio XPC del sistema `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` tiene el permiso **`com.apple.rootless.install`**, que otorga al proceso el permiso para eludir las restricciones de SIP. También **expone un método para mover archivos sin ninguna verificación de seguridad**.

## Instantáneas selladas del sistema

Las instantáneas selladas del sistema son una característica introducida por Apple en **macOS Big Sur (macOS 11)** como parte de su mecanismo de Protección de Integridad del Sistema (SIP) para proporcionar una capa adicional de seguridad y estabilidad del sistema. Son versiones de solo lectura del volumen del sistema.

Aquí tienes un vistazo más detallado:

1. **Sistema inmutable**: las instantáneas selladas del sistema hacen que el volumen del sistema macOS sea "inmutable", lo que significa que no se puede modificar. Esto evita cualquier cambio no autorizado o accidental en el sistema que pueda comprometer la seguridad o la estabilidad del sistema.
2. **Actualizaciones de software del sistema**: cuando instalas actualizaciones o mejoras de macOS, macOS crea una nueva instantánea del sistema. El volumen de inicio de macOS utiliza **APFS (Apple File System)** para cambiar a esta nueva instantánea. Todo el proceso de aplicación de actualizaciones se vuelve más seguro y confiable, ya que el sistema siempre puede volver a la instantánea anterior si algo sale mal durante la actualización.
3. **Separación de datos**: en conjunto con el concepto de separación de volúmenes de datos y sistema introducido en macOS Catalina, la función de instantáneas selladas del sistema se asegura de que todos tus datos y configuraciones se almacenen en un volumen "**Data**" separado. Esta separación hace que tus datos sean independientes del sistema, lo que simplifica el proceso de actualización del sistema y mejora la seguridad del sistema.

Recuerda que estas instantáneas son administradas automáticamente por macOS y no ocupan espacio adicional en tu disco, gracias a las capacidades de uso compartido de espacio de APFS. También es importante tener en cuenta que estas instantáneas son diferentes de las **instantáneas de Time Machine**, que son copias de seguridad accesibles por el usuario de todo el sistema.

### Verificar instantáneas

El comando **`diskutil apfs list`** muestra los **detalles de los volúmenes APFS** y su distribución:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Instantánea:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disco de la instantánea:             disk3s1s1
<strong>|   |   Punto de montaje de la instantánea:      /
</strong><strong>|   |   Instantánea sellada:           Sí
</strong>[...]
+-> Volumen disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Disco del volumen APFS (Rol):   disk3s5 (Datos)
|   Nombre:                      Macintosh HD - Datos (No distingue mayúsculas y minúsculas)
<strong>    |   Punto de montaje:               /System/Volumes/Datos
</strong><strong>    |   Capacidad consumida:         412071784448 B (412.1 GB)
</strong>    |   Sellada:                    No
|   FileVault:                 Sí (Desbloqueado)
</code></pre>

En la salida anterior se puede ver que las **ubicaciones accesibles por el usuario** están montadas en `/System/Volumes/Datos`.

Además, la **instantánea del volumen del sistema macOS** está montada en `/` y está **sellada** (firmada criptográficamente por el sistema operativo). Por lo tanto, si se omite el SIP y se modifica, el **sistema operativo no se iniciará**.

También es posible **verificar que el sellado está habilitado** ejecutando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Además, el disco de instantáneas también se monta como **solo lectura**:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
