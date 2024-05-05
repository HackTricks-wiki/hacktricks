# macOS SIP

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares de robo**.

El objetivo principal de WhiteIntel es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

***

## **Información Básica**

**Protección de la Integridad del Sistema (SIP)** en macOS es un mecanismo diseñado para evitar que incluso los usuarios más privilegiados realicen cambios no autorizados en carpetas clave del sistema. Esta característica desempeña un papel crucial en mantener la integridad del sistema al restringir acciones como agregar, modificar o eliminar archivos en áreas protegidas. Las carpetas principales protegidas por SIP incluyen:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Las reglas que rigen el comportamiento de SIP están definidas en el archivo de configuración ubicado en **`/System/Library/Sandbox/rootless.conf`**. Dentro de este archivo, las rutas que tienen un asterisco (\*) como prefijo se consideran excepciones a las restricciones estrictas de SIP.

Considera el ejemplo a continuación:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Este fragmento implica que aunque SIP generalmente asegura el directorio **`/usr`**, existen subdirectorios específicos (`/usr/libexec/cups`, `/usr/local` y `/usr/share/man`) donde se permiten modificaciones, como se indica por el asterisco (\*) que precede a sus rutas.

Para verificar si un directorio o archivo está protegido por SIP, puedes usar el comando **`ls -lOd`** para comprobar la presencia de la bandera **`restricted`** o **`sunlnk`**. Por ejemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
En este caso, la bandera **`sunlnk`** significa que el directorio `/usr/libexec/cups` en sí mismo **no se puede eliminar**, aunque se pueden crear, modificar o eliminar archivos dentro de él.

Por otro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aquí, la bandera **`restricted`** indica que el directorio `/usr/libexec` está protegido por SIP. En un directorio protegido por SIP, no se pueden crear, modificar o eliminar archivos.

Además, si un archivo contiene el atributo extendido **`com.apple.rootless`**, ese archivo también estará **protegido por SIP**.

**SIP también limita otras acciones de root** como:

* Cargar extensiones de kernel no confiables
* Obtener puertos de tarea para procesos firmados por Apple
* Modificar variables de NVRAM
* Permitir la depuración del kernel

Las opciones se mantienen en la variable nvram como un bitflag (`csr-active-config` en Intel y `lp-sip0` se lee del Device Tree arrancado para ARM). Puedes encontrar las banderas en el código fuente de XNU en `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### Estado de SIP

Puedes verificar si SIP está habilitado en tu sistema con el siguiente comando:
```bash
csrutil status
```
Si necesitas deshabilitar SIP, debes reiniciar tu computadora en modo de recuperación (presionando Command+R durante el arranque), luego ejecuta el siguiente comando:
```bash
csrutil disable
```
Si deseas mantener SIP habilitado pero eliminar las protecciones de depuración, puedes hacerlo con:
```bash
csrutil enable --without debug
```
### Otras Restricciones

* **Prohíbe la carga de extensiones de kernel no firmadas** (kexts), asegurando que solo las extensiones verificadas interactúen con el kernel del sistema.
* **Evita la depuración** de los procesos del sistema macOS, protegiendo los componentes principales del sistema contra accesos y modificaciones no autorizados.
* **Inhibe herramientas** como dtrace de inspeccionar los procesos del sistema, protegiendo aún más la integridad de la operación del sistema.

[**Obtén más información sobre la información de SIP en esta charla**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## Saltos de SIP

Saltarse SIP permite a un atacante:

* **Acceder a Datos de Usuario**: Leer datos sensibles de usuario como correos, mensajes e historial de Safari de todas las cuentas de usuario.
* **Saltarse TCC**: Manipular directamente la base de datos de TCC (Transparencia, Consentimiento y Control) para otorgar acceso no autorizado a la cámara web, micrófono y otros recursos.
* **Establecer Persistencia**: Colocar malware en ubicaciones protegidas por SIP, haciéndolo resistente a la eliminación, incluso con privilegios de root. Esto también incluye la posibilidad de manipular la Herramienta de Eliminación de Malware (MRT).
* **Cargar Extensiones de Kernel**: Aunque existen salvaguardas adicionales, saltarse SIP simplifica el proceso de carga de extensiones de kernel no firmadas.

### Paquetes de Instalador

**Los paquetes de instalador firmados con el certificado de Apple** pueden saltarse sus protecciones. Esto significa que incluso los paquetes firmados por desarrolladores estándar serán bloqueados si intentan modificar directorios protegidos por SIP.

### Archivo SIP inexistente

Una posible laguna es que si un archivo está especificado en **`rootless.conf` pero actualmente no existe**, puede ser creado. El malware podría aprovechar esto para **establecer persistencia** en el sistema. Por ejemplo, un programa malicioso podría crear un archivo .plist en `/System/Library/LaunchDaemons` si está listado en `rootless.conf` pero no está presente.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
El permiso **`com.apple.rootless.install.heritable`** permite saltarse SIP
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Se descubrió que era posible **intercambiar el paquete de instalador después de que el sistema verificara su firma de código** y luego, el sistema instalaría el paquete malicioso en lugar del original. Dado que estas acciones eran realizadas por **`system_installd`**, permitiría saltarse SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Si se instalaba un paquete desde una imagen montada o una unidad externa, el **instalador** ejecutaría el binario desde **ese sistema de archivos** (en lugar de una ubicación protegida por SIP), haciendo que **`system_installd`** ejecutara un binario arbitrario.

#### CVE-2021-30892 - Shrootless

[**Investigadores de esta publicación de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descubrieron una vulnerabilidad en el mecanismo de Protección de Integridad del Sistema (SIP) de macOS, denominada vulnerabilidad 'Shrootless'. Esta vulnerabilidad se centra en el demonio **`system_installd`**, que tiene un permiso, **`com.apple.rootless.install.heritable`**, que permite que cualquiera de sus procesos secundarios se salte las restricciones del sistema de archivos de SIP.

El demonio **`system_installd`** instalará paquetes que hayan sido firmados por **Apple**.

Los investigadores descubrieron que durante la instalación de un paquete firmado por Apple (.pkg), **`system_installd`** **ejecuta** cualquier **script post-instalación** incluido en el paquete. Estos scripts son ejecutados por la shell predeterminada, **`zsh`**, que automáticamente **ejecuta** comandos del archivo **`/etc/zshenv`**, si existe, incluso en modo no interactivo. Este comportamiento podría ser explotado por atacantes: al crear un archivo malicioso `/etc/zshenv` y esperar a que **`system_installd` invoque `zsh`**, podrían realizar operaciones arbitrarias en el dispositivo.

Además, se descubrió que **`/etc/zshenv` podría ser utilizado como técnica de ataque general**, no solo para saltarse SIP. Cada perfil de usuario tiene un archivo `~/.zshenv`, que se comporta de la misma manera que `/etc/zshenv` pero no requiere permisos de root. Este archivo podría ser utilizado como mecanismo de persistencia, activándose cada vez que `zsh` se inicia, o como un mecanismo de elevación de privilegios. Si un usuario administrador se eleva a root usando `sudo -s` o `sudo <comando>`, el archivo `~/.zshenv` se activaría, elevándose efectivamente a root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

En [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) se descubrió que el mismo proceso **`system_installd`** aún podía ser abusado porque colocaba el **script post-instalación dentro de una carpeta con nombre aleatorio protegida por SIP dentro de `/tmp`**. La cuestión es que **`/tmp` en sí no está protegido por SIP**, por lo que era posible **montar** una **imagen virtual en él**, luego el **instalador** colocaría allí el **script post-instalación**, **desmontaría** la imagen virtual, **recrearía** todas las **carpetas** y **añadiría** el **script de post-instalación** con el **carga útil** a ejecutar.

#### [utilidad fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Se identificó una vulnerabilidad donde **`fsck_cs`** fue engañado para corromper un archivo crucial, debido a su capacidad de seguir **enlaces simbólicos**. Específicamente, los atacantes crearon un enlace desde _`/dev/diskX`_ al archivo `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Ejecutar **`fsck_cs`** en _`/dev/diskX`_ llevó a la corrupción de `Info.plist`. La integridad de este archivo es vital para la Protección de Integridad del Sistema (SIP) del sistema operativo, que controla la carga de extensiones de kernel. Una vez corrompido, la capacidad de SIP para gestionar exclusiones de kernel se ve comprometida.

Los comandos para explotar esta vulnerabilidad son:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
La explotación de esta vulnerabilidad tiene graves implicaciones. El archivo `Info.plist`, normalmente responsable de gestionar los permisos para las extensiones del kernel, se vuelve ineficaz. Esto incluye la imposibilidad de poner en lista negra ciertas extensiones, como `AppleHWAccess.kext`. En consecuencia, con el mecanismo de control de SIP desactivado, esta extensión puede cargarse, otorgando acceso no autorizado de lectura y escritura a la RAM del sistema.

#### [Montar sobre carpetas protegidas por SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Era posible montar un nuevo sistema de archivos sobre **carpetas protegidas por SIP para evadir la protección**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass de actualización (2016)](https://objective-see.org/blog/blog\_0x14.html)

El sistema está configurado para arrancar desde una imagen de disco del instalador incrustada dentro de `Install macOS Sierra.app` para actualizar el sistema operativo, utilizando la utilidad `bless`. El comando utilizado es el siguiente:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La seguridad de este proceso puede verse comprometida si un atacante altera la imagen de actualización (`InstallESD.dmg`) antes del arranque. La estrategia implica sustituir un cargador dinámico (dyld) con una versión maliciosa (`libBaseIA.dylib`). Esta sustitución resulta en la ejecución del código del atacante cuando se inicia el instalador.

El código del atacante obtiene control durante el proceso de actualización, explotando la confianza del sistema en el instalador. El ataque continúa alterando la imagen `InstallESD.dmg` a través de la técnica de swizzling, apuntando especialmente al método `extractBootBits`. Esto permite la inyección de código malicioso antes de que se emplee la imagen del disco.

Además, dentro de `InstallESD.dmg`, hay un `BaseSystem.dmg`, que sirve como sistema de archivos raíz del código de actualización. Inyectar una biblioteca dinámica en esto permite que el código malicioso opere dentro de un proceso capaz de alterar archivos a nivel de sistema operativo, aumentando significativamente el potencial de compromiso del sistema.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

En esta charla de [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), se muestra cómo **`systemmigrationd`** (que puede evadir SIP) ejecuta un script de **bash** y un script de **perl**, que pueden ser abusados a través de las variables de entorno **`BASH_ENV`** y **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Como se [**detalla en esta publicación de blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), un script `postinstall` de los paquetes `InstallAssistant.pkg` permitía la ejecución:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
y era posible crear un enlace simbólico en `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` que permitiría a un usuario **desrestringir cualquier archivo, evitando la protección de SIP**.

### **com.apple.rootless.install**

{% hint style="danger" %}
La concesión **`com.apple.rootless.install`** permite evitar SIP
{% endhint %}

La concesión `com.apple.rootless.install` es conocida por evitar la Protección de Integridad del Sistema (SIP) en macOS. Esto fue mencionado notablemente en relación con [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

En este caso específico, el servicio XPC del sistema ubicado en `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` posee esta concesión. Esto permite que el proceso relacionado evite las restricciones de SIP. Además, este servicio presenta notablemente un método que permite el movimiento de archivos sin aplicar medidas de seguridad.

## Instantáneas del Sistema Selladas

Las Instantáneas del Sistema Selladas son una característica introducida por Apple en **macOS Big Sur (macOS 11)** como parte de su mecanismo de **Protección de Integridad del Sistema (SIP)** para proporcionar una capa adicional de seguridad y estabilidad del sistema. Son esencialmente versiones de solo lectura del volumen del sistema.

Aquí tienes un vistazo más detallado:

1. **Sistema Inmutable**: Las Instantáneas del Sistema Selladas hacen que el volumen del sistema macOS sea "inmutable", lo que significa que no se puede modificar. Esto evita cualquier cambio no autorizado o accidental en el sistema que podría comprometer la seguridad o la estabilidad del sistema.
2. **Actualizaciones de Software del Sistema**: Cuando instalas actualizaciones o mejoras de macOS, macOS crea una nueva instantánea del sistema. El volumen de arranque de macOS luego utiliza **APFS (Sistema de Archivos Apple)** para cambiar a esta nueva instantánea. Todo el proceso de aplicar actualizaciones se vuelve más seguro y confiable, ya que el sistema siempre puede revertir a la instantánea anterior si algo sale mal durante la actualización.
3. **Separación de Datos**: En conjunto con el concepto de separación de volúmenes de Datos y Sistema introducido en macOS Catalina, la característica de Instantáneas del Sistema Selladas se asegura de que todos tus datos y configuraciones se almacenen en un volumen "**Datos**" separado. Esta separación hace que tus datos sean independientes del sistema, lo que simplifica el proceso de actualizaciones del sistema y mejora la seguridad del sistema.

Recuerda que estas instantáneas son gestionadas automáticamente por macOS y no ocupan espacio adicional en tu disco, gracias a las capacidades de uso compartido de espacio de APFS. También es importante tener en cuenta que estas instantáneas son diferentes de las **instantáneas de Time Machine**, que son copias de seguridad accesibles por el usuario de todo el sistema.

### Verificar Instantáneas

El comando **`diskutil apfs list`** muestra los **detalles de los volúmenes APFS** y su distribución:

<pre><code>+-- Contenedor disco3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Referencia de Contenedor APFS:     disco3
|   Tamaño (Capacidad Máxima):         494384795648 B (494.4 GB)
|   Capacidad Utilizada por Volúmenes: 219214536704 B (219.2 GB) (44.3% usado)
|   Capacidad No Asignada:             275170258944 B (275.2 GB) (55.7% libre)
|   |
|   +-&#x3C; Almacenamiento Físico disco0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Disco de Almacenamiento Físico APFS:   disco0s2
|   |   Tamaño:                               494384795648 B (494.4 GB)
|   |
|   +-> Volumen disco3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Disco de Volumen APFS (Rol):   disco3s1 (Sistema)
</strong>|   |   Nombre:                          Macintosh HD (No sensible a mayúsculas)
<strong>|   |   Punto de Montaje:                /System/Volumes/Update/mnt1
</strong>|   |   Capacidad Consumida:             12819210240 B (12.8 GB)
|   |   Sellado:                         Roto
|   |   FileVault:                      Sí (Desbloqueado)
|   |   Encriptado:                     No
|   |   |
|   |   Instantánea:                    FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disco de Instantánea:           disco3s1s1
<strong>|   |   Punto de Montaje de Instantánea: /
</strong><strong>|   |   Instantánea Sellada:            Sí
</strong>[...]
+-> Volumen disco3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Disco de Volumen APFS (Rol):   disco3s5 (Datos)
|   Nombre:                        Macintosh HD - Datos (No sensible a mayúsculas)
<strong>    |   Punto de Montaje:             /System/Volumes/Datos
</strong><strong>    |   Capacidad Consumida:         412071784448 B (412.1 GB)
</strong>    |   Sellado:                    No
|   FileVault:                 Sí (Desbloqueado)
</code></pre>

En la salida anterior es posible ver que las **ubicaciones accesibles por el usuario** están montadas bajo `/System/Volumes/Datos`.

Además, la **instantánea del volumen del sistema macOS** está montada en `/` y está **sellada** (firmada criptográficamente por el sistema operativo). Por lo tanto, si se evita SIP y se modifica, el **sistema no arrancará más**.

También es posible **verificar que el sellado está habilitado** ejecutando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Además, el disco de instantáneas también se monta como **solo lectura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares ladrones**.

El objetivo principal de WhiteIntel es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de búsqueda de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
