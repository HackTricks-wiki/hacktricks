# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres acceder a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Información Básica**

**System Integrity Protection (SIP)** es una tecnología de seguridad en macOS que protege ciertos directorios del sistema contra accesos no autorizados, incluso para el usuario root. Impide modificaciones en estos directorios, incluyendo la creación, alteración o eliminación de archivos. Los principales directorios que SIP protege son:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Las reglas de protección para estos directorios y sus subdirectorios están especificadas en el archivo **`/System/Library/Sandbox/rootless.conf`**. En este archivo, las rutas que comienzan con un asterisco (\*) representan excepciones a las restricciones de SIP.

Por ejemplo, la siguiente configuración:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
indica que el directorio **`/usr`** generalmente está protegido por SIP. Sin embargo, se permiten modificaciones en los tres subdirectorios especificados (`/usr/libexec/cups`, `/usr/local` y `/usr/share/man`), ya que están listados con un asterisco inicial (\*).

Para verificar si un directorio o archivo está protegido por SIP, puedes usar el comando **`ls -lOd`** para comprobar la presencia de la bandera **`restricted`** o **`sunlnk`**. Por ejemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
En este caso, la bandera **`sunlnk`** significa que el directorio `/usr/libexec/cups` **no puede ser eliminado**, aunque los archivos dentro de él pueden ser creados, modificados o eliminados.

Por otro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aquí, la bandera **`restricted`** indica que el directorio `/usr/libexec` está protegido por SIP. En un directorio protegido por SIP, no se pueden crear, modificar o eliminar archivos.

Además, si un archivo contiene el atributo extendido **`com.apple.rootless`**, ese archivo también estará **protegido por SIP**.

**SIP también limita otras acciones de root** como:

* Cargar extensiones de kernel no confiables
* Obtener task-ports para procesos firmados por Apple
* Modificar variables NVRAM
* Permitir depuración del kernel

Las opciones se mantienen en la variable nvram como un bitflag (`csr-active-config` en Intel y `lp-sip0` se lee del Árbol de Dispositivos arrancado para ARM). Puedes encontrar las banderas en el código fuente de XNU en `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### Estado de SIP

Puedes verificar si SIP está habilitado en tu sistema con el siguiente comando:
```bash
csrutil status
```
Si necesita desactivar SIP, debe reiniciar su computadora en modo de recuperación (presionando Command+R durante el inicio), luego ejecute el siguiente comando:
```bash
csrutil disable
```
Si desea mantener SIP habilitado pero eliminar las protecciones de depuración, puede hacerlo con:
```bash
csrutil enable --without debug
```
### Otras Restricciones

SIP también impone varias otras restricciones. Por ejemplo, prohíbe la **carga de extensiones de kernel no firmadas** (kexts) y previene el **debugging** de procesos del sistema macOS. También inhibe herramientas como dtrace de inspeccionar procesos del sistema.

## Bypasses de SIP

Si un atacante logra eludir SIP, esto es lo que podrá hacer:

* Leer correos, mensajes, historial de Safari... de todos los usuarios
* Otorgar permisos para webcam, micrófono o cualquier cosa (escribiendo directamente sobre la base de datos TCC protegida por SIP)
* Persistencia: Podría guardar un malware en una ubicación protegida por SIP y ni siquiera root podrá eliminarlo. También podría manipular MRT.
* Facilidad para cargar extensiones de kernel (aunque aún hay otras protecciones avanzadas en su lugar para esto).

### Paquetes Instaladores

**Los paquetes instaladores firmados con el certificado de Apple** pueden eludir sus protecciones. Esto significa que incluso los paquetes firmados por desarrolladores estándar serán bloqueados si intentan modificar directorios protegidos por SIP.

### Archivo SIP Inexistente

Una posible laguna es que si un archivo está especificado en **`rootless.conf` pero actualmente no existe**, se puede crear. El malware podría explotar esto para **establecer persistencia** en el sistema. Por ejemplo, un programa malicioso podría crear un archivo .plist en `/System/Library/LaunchDaemons` si está listado en `rootless.conf` pero no está presente.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
El entitlement **`com.apple.rootless.install.heritable`** permite eludir SIP
{% endhint %}

[**Investigadores de esta publicación de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descubrieron una vulnerabilidad en el mecanismo de Protección de Integridad del Sistema (SIP) de macOS, denominada vulnerabilidad 'Shrootless'. Esta vulnerabilidad se centra en el daemon **`system_installd`**, que tiene un entitlement, **`com.apple.rootless.install.heritable`**, que permite que cualquiera de sus procesos hijos eluda las restricciones del sistema de archivos de SIP.

El daemon **`system_installd`** instalará paquetes que hayan sido firmados por **Apple**.

Los investigadores encontraron que durante la instalación de un paquete firmado por Apple (.pkg), **`system_installd`** **ejecuta** cualquier script **post-instalación** incluido en el paquete. Estos scripts son ejecutados por la shell predeterminada, **`zsh`**, que automáticamente **ejecuta** comandos del archivo **`/etc/zshenv`**, si existe, incluso en modo no interactivo. Este comportamiento podría ser explotado por atacantes: creando un archivo malicioso `/etc/zshenv` y esperando a que **`system_installd` invoque `zsh`**, podrían realizar operaciones arbitrarias en el dispositivo.

Además, se descubrió que **`/etc/zshenv` podría usarse como una técnica de ataque general**, no solo para eludir SIP. Cada perfil de usuario tiene un archivo `~/.zshenv`, que se comporta de la misma manera que `/etc/zshenv` pero no requiere permisos de root. Este archivo podría usarse como un mecanismo de persistencia, activándose cada vez que `zsh` se inicia, o como un mecanismo de elevación de privilegios. Si un usuario administrador se eleva a root usando `sudo -s` o `sudo <comando>`, se activaría el archivo `~/.zshenv`, elevando efectivamente a root.

En [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) se descubrió que el mismo proceso **`system_installd`** aún podía ser abusado porque colocaba el **script post-instalación dentro de una carpeta con nombre aleatorio protegida por SIP dentro de `/tmp`**. El asunto es que **`/tmp` en sí no está protegido por SIP**, por lo que era posible **montar** una **imagen virtual sobre él**, luego el **instalador** pondría allí el **script post-instalación**, **desmontaría** la imagen virtual, **recrearía** todas las **carpetas** y **añadiría** el **script post-instalación** con el **payload** para ejecutar.

### **com.apple.rootless.install**

{% hint style="danger" %}
El entitlement **`com.apple.rootless.install`** permite eludir SIP
{% endhint %}

Desde [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) El servicio XPC del sistema `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` tiene el entitlement **`com.apple.rootless.install`**, que otorga al proceso permiso para eludir las restricciones de SIP. También **expone un método para mover archivos sin ninguna verificación de seguridad.**

## Instantáneas del Sistema Sellado

Las Instantáneas del Sistema Sellado son una característica introducida por Apple en **macOS Big Sur (macOS 11)** como parte de su mecanismo de Protección de Integridad del Sistema (SIP) para proporcionar una capa adicional de seguridad y estabilidad del sistema. Son esencialmente versiones de solo lectura del volumen del sistema.

Aquí hay una mirada más detallada:

1. **Sistema Inmutable**: Las Instantáneas del Sistema Sellado hacen que el volumen del sistema de macOS sea "inmutable", lo que significa que no se puede modificar. Esto previene cualquier cambio no autorizado o accidental en el sistema que podría comprometer la seguridad o la estabilidad del sistema.
2. **Actualizaciones de Software del Sistema**: Cuando instalas actualizaciones o mejoras de macOS, macOS crea una nueva instantánea del sistema. El volumen de inicio de macOS luego usa **APFS (Apple File System)** para cambiar a esta nueva instantánea. Todo el proceso de aplicar actualizaciones se vuelve más seguro y confiable ya que el sistema siempre puede revertir a la instantánea anterior si algo sale mal durante la actualización.
3. **Separación de Datos**: En conjunto con el concepto de separación de volúmenes de Datos y Sistema introducido en macOS Catalina, la característica de Instantáneas del Sistema Sellado asegura que todos tus datos y configuraciones se almacenen en un volumen "**Datos**" separado. Esta separación hace que tus datos sean independientes del sistema, lo que simplifica el proceso de actualizaciones del sistema y mejora la seguridad del sistema.

Recuerda que estas instantáneas son gestionadas automáticamente por macOS y no ocupan espacio adicional en tu disco, gracias a las capacidades de compartición de espacio de APFS. También es importante notar que estas instantáneas son diferentes de las **instantáneas de Time Machine**, que son copias de seguridad del sistema accesibles por el usuario.

### Verificar Instantáneas

El comando **`diskutil apfs list`** lista los **detalles de los volúmenes APFS** y su disposición:

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
|   |   Instantánea:                FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disco de la Instantánea:    disk3s1s1
<strong>|   |   Punto de Montaje de la Instantánea: /
</strong><strong>|   |   Instantánea Sellada:           Sí
</strong>[...]
+-> Volumen disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Disco de Volumen APFS (Rol): disk3s5 (Datos)
|   Nombre:                      Macintosh HD - Datos (No distingue mayúsculas de minúsculas)
<strong>    |   Punto de Montaje:               /System/Volumes/Data
</strong><strong>    |   Capacidad Consumida:         412071784448 B (412.1 GB)
</strong>    |   Sellado:                      No
|   FileVault:                 Sí (Desbloqueado)
</code></pre>

En la salida anterior es posible ver que las **ubicaciones accesibles por el usuario** están montadas bajo `/System/Volumes/Data`.

Además, la **instantánea del volumen del sistema macOS** está montada en `/` y está **sellada** (firmada criptográficamente por el SO). Por lo tanto, si se elude SIP y se modifica, el **SO ya no arrancará**.

También es posible **verificar que el sellado está habilitado** ejecutando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Además, el disco de instantánea también se monta como **solo lectura**:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
