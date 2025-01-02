# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Información Básica**

**System Integrity Protection (SIP)** en macOS es un mecanismo diseñado para prevenir que incluso los usuarios más privilegiados realicen cambios no autorizados en carpetas clave del sistema. Esta función juega un papel crucial en el mantenimiento de la integridad del sistema al restringir acciones como agregar, modificar o eliminar archivos en áreas protegidas. Las carpetas principales protegidas por SIP incluyen:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Las reglas que rigen el comportamiento de SIP se definen en el archivo de configuración ubicado en **`/System/Library/Sandbox/rootless.conf`**. Dentro de este archivo, las rutas que están precedidas por un asterisco (\*) se denotan como excepciones a las estrictas restricciones de SIP. 

Considera el siguiente ejemplo:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Este fragmento implica que, aunque SIP generalmente asegura el **`/usr`** directorio, hay subdirectorios específicos (`/usr/libexec/cups`, `/usr/local`, y `/usr/share/man`) donde las modificaciones son permisibles, como lo indica el asterisco (\*) que precede sus rutas.

Para verificar si un directorio o archivo está protegido por SIP, puedes usar el **`ls -lOd`** comando para comprobar la presencia de la **`restricted`** o **`sunlnk`** bandera. Por ejemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
En este caso, la bandera **`sunlnk`** significa que el directorio `/usr/libexec/cups` **no puede ser eliminado**, aunque se pueden crear, modificar o eliminar archivos dentro de él.

Por otro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aquí, la **`restricted`** bandera indica que el directorio `/usr/libexec` está protegido por SIP. En un directorio protegido por SIP, no se pueden crear, modificar o eliminar archivos.

Además, si un archivo contiene el atributo **`com.apple.rootless`** atributo **extendido**, ese archivo también estará **protegido por SIP**.

> [!TIP]
> Tenga en cuenta que el gancho **Sandbox** **`hook_vnode_check_setextattr`** previene cualquier intento de modificar el atributo extendido **`com.apple.rootless`.**

**SIP también limita otras acciones de root** como:

- Cargar extensiones de kernel no confiables
- Obtener puertos de tarea para procesos firmados por Apple
- Modificar variables de NVRAM
- Permitir depuración del kernel

Las opciones se mantienen en la variable nvram como un bitflag (`csr-active-config` en Intel y `lp-sip0` se lee del Device Tree arrancado para ARM). Puede encontrar las banderas en el código fuente de XNU en `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

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
### Otras Restricciones

- **Prohíbe la carga de extensiones de kernel no firmadas** (kexts), asegurando que solo extensiones verificadas interactúen con el kernel del sistema.
- **Previene la depuración** de procesos del sistema macOS, protegiendo los componentes centrales del sistema de accesos y modificaciones no autorizadas.
- **Inhibe herramientas** como dtrace de inspeccionar procesos del sistema, protegiendo aún más la integridad de la operación del sistema.

[**Aprende más sobre la información de SIP en esta charla**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **Derechos relacionados con SIP**

- `com.apple.rootless.xpc.bootstrap`: Controlar launchd
- `com.apple.rootless.install[.heritable]`: Acceso al sistema de archivos
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Gestionar UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Capacidades de configuración de XPC
- `com.apple.rootless.xpc.effective-root`: Root a través de launchd XPC
- `com.apple.rootless.restricted-block-devices`: Acceso a dispositivos de bloque en bruto
- `com.apple.rootless.internal.installer-equivalent`: Acceso sin restricciones al sistema de archivos
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Acceso completo a NVRAM
- `com.apple.rootless.storage.label`: Modificar archivos restringidos por com.apple.rootless xattr con la etiqueta correspondiente
- `com.apple.rootless.volume.VM.label`: Mantener el intercambio de VM en el volumen

## Bypasses de SIP

Eludir SIP permite a un atacante:

- **Acceder a Datos de Usuario**: Leer datos sensibles de usuario como correo, mensajes e historial de Safari de todas las cuentas de usuario.
- **Bypass de TCC**: Manipular directamente la base de datos TCC (Transparencia, Consentimiento y Control) para otorgar acceso no autorizado a la cámara web, micrófono y otros recursos.
- **Establecer Persistencia**: Colocar malware en ubicaciones protegidas por SIP, haciéndolo resistente a la eliminación, incluso por privilegios de root. Esto también incluye la posibilidad de manipular la Herramienta de Eliminación de Malware (MRT).
- **Cargar Extensiones de Kernel**: Aunque hay salvaguardias adicionales, eludir SIP simplifica el proceso de carga de extensiones de kernel no firmadas.

### Paquetes de Instalador

**Los paquetes de instalador firmados con el certificado de Apple** pueden eludir sus protecciones. Esto significa que incluso los paquetes firmados por desarrolladores estándar serán bloqueados si intentan modificar directorios protegidos por SIP.

### Archivo SIP Inexistente

Una posible laguna es que si un archivo está especificado en **`rootless.conf` pero no existe actualmente**, puede ser creado. El malware podría explotar esto para **establecer persistencia** en el sistema. Por ejemplo, un programa malicioso podría crear un archivo .plist en `/System/Library/LaunchDaemons` si está listado en `rootless.conf` pero no presente.

### com.apple.rootless.install.heritable

> [!CAUTION]
> El derecho **`com.apple.rootless.install.heritable`** permite eludir SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Se descubrió que era posible **intercambiar el paquete de instalación después de que el sistema verificara su firma** de código y luego, el sistema instalaría el paquete malicioso en lugar del original. Como estas acciones fueron realizadas por **`system_installd`**, permitiría eludir SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Si un paquete se instalaba desde una imagen montada o unidad externa, el **instalador** **ejecutaría** el binario de **ese sistema de archivos** (en lugar de un lugar protegido por SIP), haciendo que **`system_installd`** ejecute un binario arbitrario.

#### CVE-2021-30892 - Shrootless

[**Investigadores de esta publicación de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descubrieron una vulnerabilidad en el mecanismo de Protección de Integridad del Sistema (SIP) de macOS, denominada vulnerabilidad 'Shrootless'. Esta vulnerabilidad se centra en el demonio **`system_installd`**, que tiene un derecho, **`com.apple.rootless.install.heritable`**, que permite a cualquiera de sus procesos secundarios eludir las restricciones del sistema de archivos de SIP.

El demonio **`system_installd`** instalará paquetes que han sido firmados por **Apple**.

Los investigadores encontraron que durante la instalación de un paquete firmado por Apple (.pkg), **`system_installd`** **ejecuta** cualquier **script post-instalación** incluido en el paquete. Estos scripts son ejecutados por el shell predeterminado, **`zsh`**, que automáticamente **ejecuta** comandos del archivo **`/etc/zshenv`**, si existe, incluso en modo no interactivo. Este comportamiento podría ser explotado por atacantes: creando un archivo malicioso `/etc/zshenv` y esperando a que **`system_installd` invoque `zsh`**, podrían realizar operaciones arbitrarias en el dispositivo.

Además, se descubrió que **`/etc/zshenv` podría ser utilizado como una técnica de ataque general**, no solo para eludir SIP. Cada perfil de usuario tiene un archivo `~/.zshenv`, que se comporta de la misma manera que `/etc/zshenv` pero no requiere permisos de root. Este archivo podría ser utilizado como un mecanismo de persistencia, activándose cada vez que se inicia `zsh`, o como un mecanismo de elevación de privilegios. Si un usuario administrador se eleva a root usando `sudo -s` o `sudo <comando>`, el archivo `~/.zshenv` se activaría, elevándose efectivamente a root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

En [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) se descubrió que el mismo proceso **`system_installd`** aún podría ser abusado porque estaba colocando el **script post-instalación dentro de una carpeta nombrada aleatoriamente protegida por SIP dentro de `/tmp`**. La cuestión es que **`/tmp` en sí no está protegido por SIP**, por lo que era posible **montar** una **imagen virtual en él**, luego el **instalador** colocaría allí el **script post-instalación**, **desmontaría** la imagen virtual, **recrearía** todas las **carpetas** y **agregaría** el **script de post instalación** con la **carga útil** a ejecutar.

#### [utilidad fsck_cs](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Se identificó una vulnerabilidad donde **`fsck_cs`** fue engañado para corromper un archivo crucial, debido a su capacidad para seguir **enlaces simbólicos**. Específicamente, los atacantes crearon un enlace de _`/dev/diskX`_ al archivo `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Ejecutar **`fsck_cs`** en _`/dev/diskX`_ llevó a la corrupción de `Info.plist`. La integridad de este archivo es vital para el SIP (Protección de Integridad del Sistema) del sistema operativo, que controla la carga de extensiones de kernel. Una vez corrompido, la capacidad de SIP para gestionar exclusiones de kernel se ve comprometida.

Los comandos para explotar esta vulnerabilidad son:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
La explotación de esta vulnerabilidad tiene graves implicaciones. El archivo `Info.plist`, normalmente responsable de gestionar los permisos para las extensiones del kernel, se vuelve ineficaz. Esto incluye la incapacidad de bloquear ciertas extensiones, como `AppleHWAccess.kext`. En consecuencia, con el mecanismo de control del SIP fuera de servicio, esta extensión puede ser cargada, otorgando acceso no autorizado de lectura y escritura a la RAM del sistema.

#### [Montar sobre carpetas protegidas por SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Fue posible montar un nuevo sistema de archivos sobre **carpetas protegidas por SIP para eludir la protección**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass de actualizador (2016)](https://objective-see.org/blog/blog_0x14.html)

El sistema está configurado para arrancar desde una imagen de disco de instalador embebida dentro de `Install macOS Sierra.app` para actualizar el sistema operativo, utilizando la utilidad `bless`. El comando utilizado es el siguiente:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La seguridad de este proceso puede verse comprometida si un atacante altera la imagen de actualización (`InstallESD.dmg`) antes de iniciar el arranque. La estrategia implica sustituir un cargador dinámico (dyld) por una versión maliciosa (`libBaseIA.dylib`). Este reemplazo resulta en la ejecución del código del atacante cuando se inicia el instalador.

El código del atacante obtiene control durante el proceso de actualización, explotando la confianza del sistema en el instalador. El ataque avanza alterando la imagen `InstallESD.dmg` a través de method swizzling, apuntando particularmente al método `extractBootBits`. Esto permite la inyección de código malicioso antes de que se utilice la imagen de disco.

Además, dentro de `InstallESD.dmg`, hay un `BaseSystem.dmg`, que sirve como el sistema de archivos raíz del código de actualización. Inyectar una biblioteca dinámica en esto permite que el código malicioso opere dentro de un proceso capaz de alterar archivos a nivel de OS, aumentando significativamente el potencial de compromiso del sistema.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

En esta charla de [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), se muestra cómo **`systemmigrationd`** (que puede eludir SIP) ejecuta un **bash** y un **perl** script, que pueden ser abusados a través de variables de entorno **`BASH_ENV`** y **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Como [**se detalla en esta publicación del blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), un script `postinstall` de `InstallAssistant.pkg` permitía ejecutar:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
y fue posible crear un symlink en `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` que permitiría a un usuario **desbloquear cualquier archivo, eludiendo la protección SIP**.

### **com.apple.rootless.install**

> [!CAUTION]
> La autorización **`com.apple.rootless.install`** permite eludir SIP

La autorización `com.apple.rootless.install` es conocida por eludir la Protección de Integridad del Sistema (SIP) en macOS. Esto se mencionó notablemente en relación con [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

En este caso específico, el servicio XPC del sistema ubicado en `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` posee esta autorización. Esto permite que el proceso relacionado eluda las restricciones de SIP. Además, este servicio presenta notablemente un método que permite el movimiento de archivos sin imponer ninguna medida de seguridad.

## Instantáneas del Sistema Selladas

Las Instantáneas del Sistema Selladas son una característica introducida por Apple en **macOS Big Sur (macOS 11)** como parte de su mecanismo de **Protección de Integridad del Sistema (SIP)** para proporcionar una capa adicional de seguridad y estabilidad del sistema. Son esencialmente versiones de solo lectura del volumen del sistema.

Aquí hay una mirada más detallada:

1. **Sistema Inmutable**: Las Instantáneas del Sistema Selladas hacen que el volumen del sistema macOS sea "inmutable", lo que significa que no puede ser modificado. Esto previene cualquier cambio no autorizado o accidental en el sistema que podría comprometer la seguridad o la estabilidad del sistema.
2. **Actualizaciones de Software del Sistema**: Cuando instalas actualizaciones o mejoras de macOS, macOS crea una nueva instantánea del sistema. El volumen de inicio de macOS luego utiliza **APFS (Apple File System)** para cambiar a esta nueva instantánea. Todo el proceso de aplicación de actualizaciones se vuelve más seguro y confiable, ya que el sistema siempre puede revertir a la instantánea anterior si algo sale mal durante la actualización.
3. **Separación de Datos**: En conjunto con el concepto de separación de volúmenes de Datos y Sistema introducido en macOS Catalina, la característica de Instantánea del Sistema Sellada asegura que todos tus datos y configuraciones se almacenen en un volumen separado de "**Datos**". Esta separación hace que tus datos sean independientes del sistema, lo que simplifica el proceso de actualizaciones del sistema y mejora la seguridad del sistema.

Recuerda que estas instantáneas son gestionadas automáticamente por macOS y no ocupan espacio adicional en tu disco, gracias a las capacidades de compartición de espacio de APFS. También es importante notar que estas instantáneas son diferentes de las **instantáneas de Time Machine**, que son copias de seguridad accesibles por el usuario de todo el sistema.

### Verificar Instantáneas

El comando **`diskutil apfs list`** lista los **detalles de los volúmenes APFS** y su disposición:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Referencia del Contenedor APFS:     disk3
|   Tamaño (Capacidad Máxima):          494384795648 B (494.4 GB)
|   Capacidad Usada por Volúmenes:      219214536704 B (219.2 GB) (44.3% usado)
|   Capacidad No Asignada:              275170258944 B (275.2 GB) (55.7% libre)
|   |
|   +-&#x3C; Almacenamiento Físico disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Disco de Almacenamiento Físico APFS:   disk0s2
|   |   Tamaño:                       494384795648 B (494.4 GB)
|   |
|   +-> Volumen disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Disco de Volumen APFS (Rol):   disk3s1 (Sistema)
</strong>|   |   Nombre:                      Macintosh HD (Sin distinción de mayúsculas)
<strong>|   |   Punto de Montaje:           /System/Volumes/Update/mnt1
</strong>|   |   Capacidad Consumida:         12819210240 B (12.8 GB)
|   |   Sellado:                    Roto
|   |   FileVault:                 Sí (Desbloqueado)
|   |   Encriptado:                 No
|   |   |
|   |   Instantánea:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disco de Instantánea:         disk3s1s1
<strong>|   |   Punto de Montaje de Instantánea:      /
</strong><strong>|   |   Instantánea Sellada:           Sí
</strong>[...]
+-> Volumen disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Disco de Volumen APFS (Rol):   disk3s5 (Datos)
|   Nombre:                      Macintosh HD - Datos (Sin distinción de mayúsculas)
<strong>    |   Punto de Montaje:               /System/Volumes/Data
</strong><strong>    |   Capacidad Consumida:         412071784448 B (412.1 GB)
</strong>    |   Sellado:                    No
|   FileVault:                 Sí (Desbloqueado)
</code></pre>

En la salida anterior es posible ver que **las ubicaciones accesibles por el usuario** están montadas bajo `/System/Volumes/Data`.

Además, la **instantánea del volumen del sistema de macOS** está montada en `/` y está **sellada** (firmada criptográficamente por el OS). Así que, si se elude SIP y se modifica, el **OS ya no arrancará**.

También es posible **verificar que el sellado está habilitado** ejecutando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Además, el disco de instantánea también se monta como **solo lectura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{{#include ../../../banners/hacktricks-training.md}}
