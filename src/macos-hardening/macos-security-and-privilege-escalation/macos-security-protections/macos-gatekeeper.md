# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** es una función de seguridad desarrollada para sistemas operativos Mac, diseñada para garantizar que los usuarios **ejecuten solo software de confianza** en sus sistemas. Funciona **validando el software** que un usuario descarga e intenta abrir desde **fuentes fuera de la App Store**, como una aplicación, un complemento o un paquete de instalación.

El mecanismo clave de Gatekeeper radica en su proceso de **verificación**. Verifica si el software descargado está **firmado por un desarrollador reconocido**, asegurando la autenticidad del software. Además, determina si el software está **notarizado por Apple**, confirmando que está libre de contenido malicioso conocido y que no ha sido alterado después de la notarización.

Además, Gatekeeper refuerza el control y la seguridad del usuario al **solicitar a los usuarios que aprueben la apertura** del software descargado por primera vez. Esta salvaguarda ayuda a prevenir que los usuarios ejecuten inadvertidamente código ejecutable potencialmente dañino que pueden haber confundido con un archivo de datos inofensivo.

### Firmas de Aplicación

Las firmas de aplicación, también conocidas como firmas de código, son un componente crítico de la infraestructura de seguridad de Apple. Se utilizan para **verificar la identidad del autor del software** (el desarrollador) y para asegurar que el código no ha sido alterado desde que fue firmado por última vez.

Así es como funciona:

1. **Firmar la Aplicación:** Cuando un desarrollador está listo para distribuir su aplicación, **firma la aplicación utilizando una clave privada**. Esta clave privada está asociada con un **certificado que Apple emite al desarrollador** cuando se inscribe en el Programa de Desarrolladores de Apple. El proceso de firma implica crear un hash criptográfico de todas las partes de la aplicación y cifrar este hash con la clave privada del desarrollador.
2. **Distribuir la Aplicación:** La aplicación firmada se distribuye a los usuarios junto con el certificado del desarrollador, que contiene la clave pública correspondiente.
3. **Verificar la Aplicación:** Cuando un usuario descarga e intenta ejecutar la aplicación, su sistema operativo Mac utiliza la clave pública del certificado del desarrollador para descifrar el hash. Luego recalcula el hash basado en el estado actual de la aplicación y lo compara con el hash descifrado. Si coinciden, significa que **la aplicación no ha sido modificada** desde que el desarrollador la firmó, y el sistema permite que la aplicación se ejecute.

Las firmas de aplicación son una parte esencial de la tecnología Gatekeeper de Apple. Cuando un usuario intenta **abrir una aplicación descargada de internet**, Gatekeeper verifica la firma de la aplicación. Si está firmada con un certificado emitido por Apple a un desarrollador conocido y el código no ha sido alterado, Gatekeeper permite que la aplicación se ejecute. De lo contrario, bloquea la aplicación y alerta al usuario.

A partir de macOS Catalina, **Gatekeeper también verifica si la aplicación ha sido notarizada** por Apple, añadiendo una capa adicional de seguridad. El proceso de notarización verifica la aplicación en busca de problemas de seguridad conocidos y código malicioso, y si estas verificaciones son satisfactorias, Apple añade un ticket a la aplicación que Gatekeeper puede verificar.

#### Verificar Firmas

Al verificar alguna **muestra de malware**, siempre debes **verificar la firma** del binario, ya que el **desarrollador** que lo firmó puede estar ya **relacionado** con **malware.**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarización

El proceso de notarización de Apple sirve como una salvaguarda adicional para proteger a los usuarios de software potencialmente dañino. Implica que el **desarrollador envíe su aplicación para examen** por parte del **Servicio de Notaría de Apple**, que no debe confundirse con la Revisión de Aplicaciones. Este servicio es un **sistema automatizado** que examina el software enviado en busca de **contenido malicioso** y cualquier problema potencial con la firma de código.

Si el software **aprueba** esta inspección sin generar preocupaciones, el Servicio de Notaría genera un ticket de notarización. El desarrollador debe **adjuntar este ticket a su software**, un proceso conocido como 'stapling'. Además, el ticket de notarización también se publica en línea donde Gatekeeper, la tecnología de seguridad de Apple, puede acceder a él.

Al momento de la primera instalación o ejecución del software por parte del usuario, la existencia del ticket de notarización - ya sea adjunto al ejecutable o encontrado en línea - **informa a Gatekeeper que el software ha sido notariado por Apple**. Como resultado, Gatekeeper muestra un mensaje descriptivo en el diálogo de lanzamiento inicial, indicando que el software ha sido sometido a verificaciones de contenido malicioso por parte de Apple. Este proceso, por lo tanto, aumenta la confianza del usuario en la seguridad del software que instala o ejecuta en sus sistemas.

### spctl & syspolicyd

> [!CAUTION]
> Tenga en cuenta que a partir de la versión Sequoia, **`spctl`** ya no permite modificar la configuración de Gatekeeper.

**`spctl`** es la herramienta CLI para enumerar e interactuar con Gatekeeper (con el demonio `syspolicyd` a través de mensajes XPC). Por ejemplo, es posible ver el **estado** de GateKeeper con:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Tenga en cuenta que las verificaciones de firma de GateKeeper se realizan solo en **archivos con el atributo de Cuarentena**, no en todos los archivos.

GateKeeper verificará si, de acuerdo con las **preferencias y la firma**, un binario puede ser ejecutado:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** es el principal daemon responsable de hacer cumplir Gatekeeper. Mantiene una base de datos ubicada en `/var/db/SystemPolicy` y es posible encontrar el código para soportar la [base de datos aquí](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) y la [plantilla SQL aquí](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Tenga en cuenta que la base de datos no está restringida por SIP y es escribible por root, y la base de datos `/var/db/.SystemPolicy-default` se utiliza como una copia de seguridad original en caso de que la otra se corrompa.

Además, los paquetes **`/var/db/gke.bundle`** y **`/var/db/gkopaque.bundle`** contienen archivos con reglas que se insertan en la base de datos. Puede verificar esta base de datos como root con:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** también expone un servidor XPC con diferentes operaciones como `assess`, `update`, `record` y `cancel`, que también son accesibles utilizando las APIs **`SecAssessment*`** de **`Security.framework`** y **`xpctl`** en realidad se comunica con **`syspolicyd`** a través de XPC.

Nota cómo la primera regla terminó en "**App Store**" y la segunda en "**Developer ID**" y que en la imagen anterior estaba **habilitada para ejecutar aplicaciones de la App Store y desarrolladores identificados**.\
Si **modificas** esa configuración a App Store, las "**reglas de Developer ID Notarizado" desaparecerán**.

También hay miles de reglas de **tipo GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Estos son hashes que provienen de:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

O podrías listar la información anterior con:
```bash
sudo spctl --list
```
Las opciones **`--master-disable`** y **`--global-disable`** de **`spctl`** desactivarán completamente estas verificaciones de firma:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Cuando está completamente habilitado, aparecerá una nueva opción:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Es posible **verificar si una aplicación será permitida por GateKeeper** con:
```bash
spctl --assess -v /Applications/App.app
```
Es posible agregar nuevas reglas en GateKeeper para permitir la ejecución de ciertas aplicaciones con:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Respecto a las **extensiones del kernel**, la carpeta `/var/db/SystemPolicyConfiguration` contiene archivos con listas de kexts permitidos para ser cargados. Además, `spctl` tiene el derecho `com.apple.private.iokit.nvram-csr` porque es capaz de agregar nuevas extensiones del kernel preaprobadas que también deben guardarse en NVRAM en una clave `kext-allowed-teams`.

### Archivos de Cuarentena

Al **descargar** una aplicación o archivo, aplicaciones específicas de macOS como navegadores web o clientes de correo electrónico **adjuntan un atributo de archivo extendido**, comúnmente conocido como el "**flag de cuarentena**," al archivo descargado. Este atributo actúa como una medida de seguridad para **marcar el archivo** como proveniente de una fuente no confiable (internet), y potencialmente portadora de riesgos. Sin embargo, no todas las aplicaciones adjuntan este atributo; por ejemplo, el software común de clientes de BitTorrent generalmente omite este proceso.

**La presencia de un flag de cuarentena señala la característica de seguridad Gatekeeper de macOS cuando un usuario intenta ejecutar el archivo**.

En el caso en que el **flag de cuarentena no esté presente** (como con archivos descargados a través de algunos clientes de BitTorrent), **las verificaciones de Gatekeeper pueden no realizarse**. Por lo tanto, los usuarios deben tener precaución al abrir archivos descargados de fuentes menos seguras o desconocidas.

> [!NOTE] > **Verificar** la **validez** de las firmas de código es un proceso **intensivo en recursos** que incluye generar **hashes** criptográficos del código y todos sus recursos empaquetados. Además, verificar la validez del certificado implica hacer una **verificación en línea** a los servidores de Apple para ver si ha sido revocado después de haber sido emitido. Por estas razones, una verificación completa de la firma de código y la notarización es **impráctica de ejecutar cada vez que se lanza una aplicación**.
>
> Por lo tanto, estas verificaciones se **realizan solo al ejecutar aplicaciones con el atributo de cuarentena.**

> [!WARNING]
> Este atributo debe ser **establecido por la aplicación que crea/descarga** el archivo.
>
> Sin embargo, los archivos que están en sandbox tendrán este atributo establecido en cada archivo que creen. Y las aplicaciones no sandbox pueden establecerlo ellas mismas, o especificar la clave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) en el **Info.plist**, lo que hará que el sistema establezca el atributo extendido `com.apple.quarantine` en los archivos creados.

Además, todos los archivos creados por un proceso que llama a **`qtn_proc_apply_to_self`** están en cuarentena. O la API **`qtn_file_apply_to_path`** agrega el atributo de cuarentena a una ruta de archivo especificada.

Es posible **verificar su estado y habilitar/deshabilitar** (se requiere root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
También puedes **verificar si un archivo tiene el atributo extendido de cuarentena** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Verifica el **valor** de los **atributos** **extendidos** y encuentra la aplicación que escribió el atributo de cuarentena con:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
En realidad, un proceso "podría establecer banderas de cuarentena en los archivos que crea" (ya intenté aplicar la bandera USER_APPROVED en un archivo creado, pero no se aplica):

<details>

<summary>Código fuente para aplicar banderas de cuarentena</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Y **elimina** ese atributo con:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Y encuentra todos los archivos en cuarentena con:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
La información de cuarentena también se almacena en una base de datos central gestionada por LaunchServices en **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, lo que permite a la GUI obtener datos sobre los orígenes de los archivos. Además, esto puede ser sobrescrito por aplicaciones que podrían estar interesadas en ocultar sus orígenes. Además, esto se puede hacer desde las API de LaunchServices.

#### **libquarantine.dylb**

Esta biblioteca exporta varias funciones que permiten manipular los campos de atributos extendidos.

Las API `qtn_file_*` se ocupan de las políticas de cuarentena de archivos, las API `qtn_proc_*` se aplican a procesos (archivos creados por el proceso). Las funciones no exportadas `__qtn_syscall_quarantine*` son las que aplican las políticas que llaman a `mac_syscall` con "Quarantine" como primer argumento, lo que envía las solicitudes a `Quarantine.kext`.

#### **Quarantine.kext**

La extensión del kernel solo está disponible a través de la **caché del kernel en el sistema**; sin embargo, _puedes_ descargar el **Kernel Debug Kit de** [**https://developer.apple.com/**](https://developer.apple.com/), que contendrá una versión simbolizada de la extensión.

Este Kext enganchará a través de MACF varias llamadas para atrapar todos los eventos del ciclo de vida del archivo: Creación, apertura, renombrado, enlace duro... incluso `setxattr` para evitar que se establezca el atributo extendido `com.apple.quarantine`.

También utiliza un par de MIBs:

- `security.mac.qtn.sandbox_enforce`: Hacer cumplir la cuarentena junto con Sandbox
- `security.mac.qtn.user_approved_exec`: Los procesos en cuarentena solo pueden ejecutar archivos aprobados

### XProtect

XProtect es una función de **anti-malware** integrada en macOS. XProtect **verifica cualquier aplicación cuando se lanza o modifica por primera vez contra su base de datos** de malware conocido y tipos de archivos inseguros. Cuando descargas un archivo a través de ciertas aplicaciones, como Safari, Mail o Messages, XProtect escanea automáticamente el archivo. Si coincide con algún malware conocido en su base de datos, XProtect **impedirá que el archivo se ejecute** y te alertará sobre la amenaza.

La base de datos de XProtect se **actualiza regularmente** por Apple con nuevas definiciones de malware, y estas actualizaciones se descargan e instalan automáticamente en tu Mac. Esto asegura que XProtect esté siempre actualizado con las últimas amenazas conocidas.

Sin embargo, vale la pena señalar que **XProtect no es una solución antivirus completa**. Solo verifica una lista específica de amenazas conocidas y no realiza escaneos en acceso como la mayoría del software antivirus.

Puedes obtener información sobre la última actualización de XProtect ejecutando:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect se encuentra en una ubicación protegida por SIP en **/Library/Apple/System/Library/CoreServices/XProtect.bundle** y dentro del paquete puedes encontrar información que XProtect utiliza:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que el código con esos cdhashes use derechos heredados.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins y extensiones que no están permitidos cargar a través de BundleID y TeamID o que indican una versión mínima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reglas de Yara para detectar malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Base de datos SQLite3 con hashes de aplicaciones bloqueadas y TeamIDs.

Ten en cuenta que hay otra aplicación en **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionada con XProtect que no está involucrada en el proceso de Gatekeeper.

### No Gatekeeper

> [!CAUTION]
> Ten en cuenta que Gatekeeper **no se ejecuta cada vez** que ejecutas una aplicación, solo _**AppleMobileFileIntegrity**_ (AMFI) **verificará las firmas de código ejecutable** cuando ejecutes una aplicación que ya ha sido ejecutada y verificada por Gatekeeper.

Por lo tanto, anteriormente era posible ejecutar una aplicación para almacenarla en caché con Gatekeeper, luego **modificar archivos no ejecutables de la aplicación** (como archivos asar de Electron o NIB) y si no había otras protecciones en su lugar, la aplicación se **ejecutaba** con las adiciones **maliciosas**.

Sin embargo, ahora esto no es posible porque macOS **previene la modificación de archivos** dentro de los paquetes de aplicaciones. Así que, si intentas el ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), descubrirás que ya no es posible abusar de él porque después de ejecutar la aplicación para almacenarla en caché con Gatekeeper, no podrás modificar el paquete. Y si cambias, por ejemplo, el nombre del directorio Contents a NotCon (como se indica en el exploit), y luego ejecutas el binario principal de la aplicación para almacenarla en caché con Gatekeeper, se generará un error y no se ejecutará.

## Bypasses de Gatekeeper

Cualquier forma de eludir Gatekeeper (lograr que el usuario descargue algo y lo ejecute cuando Gatekeeper debería prohibirlo) se considera una vulnerabilidad en macOS. Estos son algunos CVEs asignados a técnicas que permitieron eludir Gatekeeper en el pasado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Se observó que si se utiliza la **Utilidad de Archivos** para la extracción, los archivos con **rutas que superan los 886 caracteres** no reciben el atributo extendido com.apple.quarantine. Esta situación permite inadvertidamente que esos archivos **eludan las** verificaciones de seguridad de Gatekeeper.

Consulta el [**informe original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para más información.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Cuando se crea una aplicación con **Automator**, la información sobre lo que necesita para ejecutarse está dentro de `application.app/Contents/document.wflow` y no en el ejecutable. El ejecutable es solo un binario genérico de Automator llamado **Automator Application Stub**.

Por lo tanto, podrías hacer que `application.app/Contents/MacOS/Automator\ Application\ Stub` **apunte con un enlace simbólico a otro Automator Application Stub dentro del sistema** y ejecutará lo que hay dentro de `document.wflow` (tu script) **sin activar Gatekeeper** porque el ejecutable real no tiene el xattr de cuarentena.

Ejemplo de ubicación esperada: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta el [**informe original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para más información.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

En este bypass se creó un archivo zip con una aplicación comenzando a comprimir desde `application.app/Contents` en lugar de `application.app`. Por lo tanto, el **atributo de cuarentena** se aplicó a todos los **archivos de `application.app/Contents`** pero **no a `application.app`**, que es lo que Gatekeeper estaba verificando, por lo que Gatekeeper fue eludido porque cuando se activó `application.app` **no tenía el atributo de cuarentena.**
```bash
zip -r test.app/Contents test.zip
```
Consulta el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para más información.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Incluso si los componentes son diferentes, la explotación de esta vulnerabilidad es muy similar a la anterior. En este caso, generaremos un Apple Archive desde **`application.app/Contents`** para que **`application.app` no obtenga el atributo de cuarentena** cuando sea descomprimido por **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulta el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para más información.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

El ACL **`writeextattr`** se puede utilizar para evitar que alguien escriba un atributo en un archivo:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Además, el formato de archivo **AppleDouble** copia un archivo incluyendo sus ACEs.

En el [**código fuente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) es posible ver que la representación de texto de la ACL almacenada dentro del xattr llamado **`com.apple.acl.text`** se establecerá como ACL en el archivo descomprimido. Así que, si comprimiste una aplicación en un archivo zip con el formato de archivo **AppleDouble** con una ACL que impide que otros xattrs sean escritos en él... el xattr de cuarentena no se estableció en la aplicación:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para más información.

Ten en cuenta que esto también podría ser explotado con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Se descubrió que **Google Chrome no estaba configurando el atributo de cuarentena** para los archivos descargados debido a algunos problemas internos de macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Los formatos de archivo AppleDouble almacenan los atributos de un archivo en un archivo separado que comienza con `._`, esto ayuda a copiar los atributos de los archivos **entre máquinas macOS**. Sin embargo, se notó que después de descomprimir un archivo AppleDouble, el archivo que comenzaba con `._` **no recibió el atributo de cuarentena**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Ser capaz de crear un archivo que no tenga el atributo de cuarentena, fue **posible eludir Gatekeeper.** El truco era **crear una aplicación de archivo DMG** utilizando la convención de nombres AppleDouble (comenzar con `._`) y crear un **archivo visible como un enlace simbólico a este archivo oculto** sin el atributo de cuarentena.\
Cuando se **ejecuta el archivo dmg**, como no tiene un atributo de cuarentena, **eludirá Gatekeeper.**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### uchg (de esta [charla](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crea un directorio que contenga una aplicación.
- Agrega uchg a la aplicación.
- Comprime la aplicación en un archivo tar.gz.
- Envía el archivo tar.gz a una víctima.
- La víctima abre el archivo tar.gz y ejecuta la aplicación.
- Gatekeeper no verifica la aplicación.

### Prevenir xattr de Cuarentena

En un paquete ".app" si el xattr de cuarentena no se agrega, al ejecutarlo **Gatekeeper no se activará**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
