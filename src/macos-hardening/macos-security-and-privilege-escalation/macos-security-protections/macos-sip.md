# SIP de macOS

{{#include ../../../banners/hacktricks-training.md}}

## **Informacion basica**

**System Integrity Protection (SIP)** en macOS es un mecanismo disenado para impedir que incluso los usuarios con mas privilegios realicen cambios no autorizados en carpetas clave del sistema. Esta funcion desempena un papel crucial en el mantenimiento de la integridad del sistema al restringir acciones como anadir, modificar o eliminar archivos en areas protegidas. Las principales carpetas protegidas por SIP incluyen:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Las reglas que controlan el comportamiento de SIP se definen en el archivo de configuracion ubicado en **`/System/Library/Sandbox/rootless.conf`**. En este archivo, las rutas precedidas por un asterisco (\*) se indican como excepciones a las estrictas restricciones de SIP.

Considera el siguiente ejemplo:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Este fragmento implica que, aunque SIP generalmente protege el directorio **`/usr`**, existen subdirectorios específicos (`/usr/libexec/cups`, `/usr/local` y `/usr/share/man`) en los que se permiten modificaciones, como indica el asterisco (\*) que precede a sus rutas.

Para verificar si un directorio o archivo está protegido por SIP, puedes utilizar el comando **`ls -lOd`** para comprobar si aparecen los flags **`restricted`** o **`sunlnk`**. Por ejemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
En este caso, el flag **`sunlnk`** indica que el directorio `/usr/libexec/cups` en sí **no se puede eliminar**, aunque los archivos que contiene sí se pueden crear, modificar o eliminar.

Por otro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aquí, el flag **`restricted`** indica que el directorio `/usr/libexec` está protegido por SIP. En un directorio protegido por SIP, no se pueden crear, modificar ni eliminar archivos.

Además, si un archivo contiene el **atributo** extendido **`com.apple.rootless`**, ese archivo también estará **protegido por SIP**.

> [!TIP]
> Ten en cuenta que el hook de **Sandbox** **`hook_vnode_check_setextattr`** impide cualquier intento de modificar el atributo extendido **`com.apple.rootless`.**

**SIP también limita otras acciones de root**, como:

- Cargar kernel extensions no confiables
- Obtener task-ports para procesos firmados por Apple
- Modificar variables de NVRAM
- Permitir debugging del kernel

Las opciones se mantienen en una variable de NVRAM como un bitflag (`csr-active-config` en Intel y `lp-sip0` se lee del Device Tree arrancado en ARM). Puedes encontrar los flags en el código fuente de XNU, en `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Estado de SIP

Puedes comprobar si SIP está habilitado en tu sistema con el siguiente comando:
```bash
csrutil status
```
Si necesitas deshabilitar SIP, debes reiniciar el ordenador en modo de recuperación (pulsando Command+R durante el arranque) y, a continuación, ejecutar el siguiente comando:
```bash
csrutil disable
```
Si deseas mantener SIP habilitado, pero eliminar las protecciones de depuración, puedes hacerlo con:
```bash
csrutil enable --without debug
```
### Other Restrictions

- **Impide la carga de extensiones de kernel sin firmar** (kexts), garantizando que solo las extensiones verificadas interactúen con el kernel del sistema.
- **Impide la depuración** de los procesos del sistema de macOS, protegiendo los componentes principales del sistema frente al acceso y la modificación no autorizados.
- **Impide que herramientas** como dtrace inspeccionen los procesos del sistema, protegiendo aún más la integridad del funcionamiento del sistema.

[**Más información sobre SIP en esta charla**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **Entitlements relacionados con SIP**

- `com.apple.rootless.xpc.bootstrap`: Controlar launchd
- `com.apple.rootless.install[.heritable]`: Acceder al sistema de archivos
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Gestionar UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Capacidades de configuración de XPC
- `com.apple.rootless.xpc.effective-root`: Root mediante launchd XPC
- `com.apple.rootless.restricted-block-devices`: Acceso a dispositivos de bloques sin procesar
- `com.apple.rootless.internal.installer-equivalent`: Acceso sin restricciones al sistema de archivos
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Acceso completo a NVRAM
- `com.apple.rootless.storage.label`: Modificar archivos restringidos por el xattr com.apple.rootless con la etiqueta correspondiente
- `com.apple.rootless.volume.VM.label`: Mantener el intercambio de VM en el volumen

## Bypasses de SIP

El bypass de SIP permite a un atacante:

- **Acceder a los datos de los usuarios**: Leer datos confidenciales de los usuarios, como correos, mensajes y el historial de Safari de todas las cuentas de usuario.
- **Bypass de TCC**: Manipular directamente la base de datos de TCC (Transparency, Consent, and Control) para conceder acceso no autorizado a la webcam, el micrófono y otros recursos.
- **Establecer persistencia**: Colocar malware en ubicaciones protegidas por SIP, haciéndolo resistente a la eliminación, incluso mediante privilegios de root. Esto también incluye la posibilidad de manipular la Malware Removal Tool (MRT).
- **Cargar extensiones de kernel**: Aunque existen medidas de protección adicionales, omitir SIP simplifica el proceso de cargar extensiones de kernel sin firmar.

### Installer Packages

**Los installer packages firmados con el certificado de Apple** pueden omitir sus protecciones. Esto significa que incluso los paquetes firmados por desarrolladores estándar serán bloqueados si intentan modificar directorios protegidos por SIP.

### Archivo SIP inexistente

Una posible laguna es que, si se especifica un archivo en **`rootless.conf` pero actualmente no existe**, este puede crearse. El malware podría aprovecharlo para **establecer persistencia** en el sistema. Por ejemplo, un programa malicioso podría crear un archivo .plist en `/System/Library/LaunchDaemons` si aparece en `rootless.conf` pero no está presente.

### com.apple.rootless.install.heritable

> [!CAUTION]
> El entitlement **`com.apple.rootless.install.heritable`** permite omitir SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Se descubrió que era posible **intercambiar el installer package después de que el sistema verificara su firma** de código y, posteriormente, el sistema instalaría el paquete malicioso en lugar del original. Como estas acciones eran realizadas por **`system_installd`**, esto permitiría omitir SIP.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Si se instalaba un paquete desde una imagen montada o una unidad externa, el **installer** **ejecutaba** el binario desde **ese sistema de archivos** (en lugar de desde una ubicación protegida por SIP), haciendo que **`system_installd`** ejecutara un binario arbitrario.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Investigadores de esta entrada del blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descubrieron una vulnerabilidad en el mecanismo System Integrity Protection (SIP) de macOS, denominada vulnerabilidad «Shrootless». Esta vulnerabilidad se centra en el daemon **`system_installd`**, que dispone del entitlement **`com.apple.rootless.install.heritable`**, lo que permite que cualquiera de sus procesos secundarios omita las restricciones del sistema de archivos de SIP.<sup>[[4]](#references)</sup>

El daemon **`system_installd`** instalará paquetes firmados por **Apple**.

Los investigadores descubrieron que, durante la instalación de un paquete firmado por Apple (archivo .pkg), **`system_installd`** **ejecuta** cualquier script de **post-install** incluido en el paquete. Estos scripts son ejecutados por el shell predeterminado, **`zsh`**, que automáticamente **ejecuta** comandos del archivo **`/etc/zshenv`**, si existe, incluso en modo no interactivo. Los atacantes podrían aprovechar este comportamiento: al crear un archivo `/etc/zshenv` malicioso y esperar a que **`system_installd` invoque `zsh`**, podrían realizar operaciones arbitrarias en el dispositivo.<sup>[[4]](#references)</sup>

Además, se descubrió que **`/etc/zshenv` podía utilizarse como una técnica de ataque general**, no solo para omitir SIP. Cada perfil de usuario tiene un archivo `~/.zshenv`, que se comporta de la misma forma que `/etc/zshenv`, pero no requiere permisos de root. Este archivo podría utilizarse como mecanismo de persistencia, activándose cada vez que se inicia `zsh`, o como mecanismo de elevación de privilegios. Si un usuario administrador eleva sus privilegios a root mediante `sudo -s` o `sudo <command>`, se activaría el archivo `~/.zshenv`, elevando efectivamente los privilegios a root.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

En [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) se descubrió que el mismo proceso **`system_installd`** aún podía abusarse porque colocaba el **script de post-install dentro de una carpeta con un nombre aleatorio protegida por SIP en `/tmp`**. El problema es que **`/tmp` no está protegido por SIP**, por lo que era posible **montar** una **imagen virtual en él**; después, el **installer** colocaría allí el **script de post-install**, se **desmontaría** la imagen virtual, se **recrearían** todas las **carpetas** y se **añadiría** el script de **post-install** con el **payload** que se ejecutaría.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Se identificó una vulnerabilidad por la que se inducía a **`fsck_cs`** a corromper un archivo crucial, debido a su capacidad para seguir **enlaces simbólicos**. En concreto, los atacantes creaban un enlace desde _`/dev/diskX`_ al archivo `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Ejecutar **`fsck_cs`** sobre _`/dev/diskX`_ provocaba la corrupción de `Info.plist`. La integridad de este archivo es esencial para SIP (System Integrity Protection) del sistema operativo, que controla la carga de las extensiones de kernel. Una vez corrompido, la capacidad de SIP para gestionar las exclusiones del kernel queda comprometida.<sup>[[6]](#references)</sup>

Los comandos para explotar esta vulnerabilidad son:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
La explotación de esta vulnerabilidad tiene graves implicaciones. El archivo `Info.plist`, normalmente responsable de gestionar los permisos de las extensiones del kernel, deja de ser efectivo. Esto incluye la incapacidad de incluir ciertas extensiones en la blacklist, como `AppleHWAccess.kext`. En consecuencia, al quedar fuera de servicio el mecanismo de control de SIP, esta extensión puede cargarse, otorgando acceso no autorizado de lectura y escritura a la RAM del sistema.<sup>[[6]](#references)</sup>

#### [Montar sobre carpetas protegidas por SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Era posible montar un nuevo sistema de archivos sobre **carpetas protegidas por SIP para eludir la protección**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

El sistema está configurado para arrancar desde una imagen de disco del instalador integrada en `Install macOS Sierra.app` para actualizar el sistema operativo, utilizando la utilidad `bless`. El comando utilizado es el siguiente:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La seguridad de este proceso puede verse comprometida si un atacante altera la imagen de actualización (`InstallESD.dmg`) antes del arranque. La estrategia consiste en sustituir un dynamic loader (dyld) por una versión maliciosa (`libBaseIA.dylib`). Esta sustitución provoca la ejecución del código del atacante cuando se inicia el instalador.<sup>[[7]](#references)</sup>

El código del atacante obtiene el control durante el proceso de actualización, aprovechando la confianza del sistema en el instalador. El ataque procede alterando la imagen `InstallESD.dmg` mediante method swizzling, apuntando específicamente al método `extractBootBits`. Esto permite inyectar código malicioso antes de utilizar la imagen de disco.<sup>[[7]](#references)</sup>

Además, dentro de `InstallESD.dmg` hay un `BaseSystem.dmg`, que actúa como el root file system del código de actualización. Inyectar una dynamic library en él permite que el código malicioso opere dentro de un proceso capaz de modificar archivos a nivel del sistema operativo, aumentando considerablemente el potencial de comprometer el sistema.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

En esta charla de [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), se muestra cómo **`systemmigrationd`** (que puede bypass SIP) ejecuta un script de **bash** y otro de **perl**, que pueden abusarse mediante las variables de entorno **`BASH_ENV`** y **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Como se [**detalla en esta entrada de blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), un script `postinstall` de los paquetes `InstallAssistant.pkg` permitía ejecutar:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
y era posible crear un symlink en `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` que permitiría a un usuario **eliminar las restricciones de cualquier archivo, evitando la protección de SIP**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> El entitlement **`com.apple.rootless.install`** permite evadir SIP

Se sabe que el entitlement `com.apple.rootless.install` permite evadir System Integrity Protection (SIP) en macOS. Esto se mencionó específicamente en relación con [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

En este caso concreto, el servicio XPC del sistema ubicado en `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` posee este entitlement. Esto permite que el proceso relacionado eluda las restricciones de SIP. Además, este servicio presenta un método que permite mover archivos sin aplicar ninguna medida de seguridad.<sup>[[10]](#references)</sup>

## Snapshots sellados del sistema

Los Snapshots sellados del sistema son una función introducida por Apple en **macOS Big Sur (macOS 11)** como parte de su mecanismo **System Integrity Protection (SIP)**, para proporcionar una capa adicional de seguridad y estabilidad del sistema. Básicamente, son versiones de solo lectura del volumen del sistema.

A continuación se ofrece una explicación más detallada:

1. **Sistema inmutable**: los Snapshots sellados del sistema hacen que el volumen del sistema de macOS sea "inmutable", lo que significa que no puede modificarse. Esto evita cambios no autorizados o accidentales en el sistema que podrían comprometer la seguridad o la estabilidad del sistema.
2. **Actualizaciones del software del sistema**: cuando instalas actualizaciones o upgrades de macOS, macOS crea un nuevo snapshot del sistema. El volumen de arranque de macOS utiliza entonces **APFS (Apple File System)** para cambiar a este nuevo snapshot. Todo el proceso de aplicación de actualizaciones se vuelve más seguro y fiable, ya que el sistema siempre puede volver al snapshot anterior si algo sale mal durante la actualización.
3. **Separación de datos**: junto con el concepto de separación de los volúmenes Data y System introducido en macOS Catalina, la función de Snapshots sellados del sistema garantiza que todos tus datos y ajustes se almacenen en un volumen "**Data**" separado. Esta separación hace que tus datos sean independientes del sistema, lo que simplifica el proceso de actualización del sistema y mejora la seguridad del sistema.

Recuerda que macOS gestiona estos snapshots automáticamente y que no ocupan espacio adicional en el disco, gracias a las capacidades de uso compartido de espacio de APFS. También es importante señalar que estos snapshots son diferentes de los **snapshots de Time Machine**, que son backups del sistema completo accesibles para el usuario.

### Comprobar los snapshots

El comando **`diskutil apfs list`** muestra los **detalles de los volúmenes APFS** y su distribución:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
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
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

En el resultado anterior se puede ver que las **ubicaciones accesibles para el usuario** están montadas bajo `/System/Volumes/Data`.

Además, el **snapshot del volumen del sistema de macOS** está montado en `/` y está **sellado** (firmado criptográficamente por el sistema operativo). Por lo tanto, si se evade SIP y se modifica, el **sistema operativo ya no arrancará**.

También es posible **verificar que el sello está habilitado** ejecutando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Además, el disco snapshot también está montado como **de solo lectura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Referencias

- [1] [SyScan360 - Stefan Esser - OS X El Capitan hundiendo el S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Blog de Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (tres) errores lógicos ftw! - Blog de Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft descubre una nueva vulnerabilidad de macOS, Shrootless, que podría eludir System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Análisis técnico: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [La seguridad rootless de Apple, inútil, fue vulnerada con código que cabe en un tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Eludiendo System Integrity Protection de Apple - Blog de Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Provocando una migraña - Unique SIP Bypass en MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple mitiga las vulnerabilidades en los Installer Scripts - Blog de Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: El POC para SIP-Bypass también cabe en un tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
