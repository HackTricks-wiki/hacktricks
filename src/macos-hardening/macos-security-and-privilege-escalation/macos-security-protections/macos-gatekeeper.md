# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** es una función de seguridad desarrollada para los sistemas operativos Mac, diseñada para garantizar que los usuarios **ejecuten únicamente software de confianza** en sus sistemas. Funciona **validando el software** que un usuario descarga e intenta abrir desde **fuentes externas a la App Store**, como una aplicación, un plug-in o un paquete instalador.

El mecanismo clave de Gatekeeper reside en su proceso de **verificación**. Comprueba si el software está **firmado por un desarrollador reconocido**, garantizando la autenticidad del software. Además, comprueba si el software ha sido **notarizado por Apple**, confirmando que no contiene contenido malicioso conocido y que no ha sido manipulado después de la notarización.

Adicionalmente, Gatekeeper refuerza el control y la seguridad del usuario al **solicitar a los usuarios que aprueben la apertura** del software descargado por primera vez. Esta protección ayuda a evitar que los usuarios ejecuten inadvertidamente código ejecutable potencialmente dañino que podrían haber confundido con un archivo de datos inofensivo.

### Firmas de aplicaciones

Las firmas de aplicaciones, también conocidas como firmas de código, son un componente fundamental de la infraestructura de seguridad de Apple. Se utilizan para **verificar la identidad del autor del software** (el desarrollador) y garantizar que el código no haya sido manipulado desde la última vez que se firmó.

Así es como funciona:

1. **Firmar la aplicación:** Cuando un desarrollador está listo para distribuir su aplicación, la **firma mediante una clave privada**. Esta clave privada está asociada a un **certificado que Apple emite al desarrollador** cuando se inscribe en el Apple Developer Program. El proceso de firma implica crear un hash criptográfico de todas las partes de la aplicación y cifrar este hash con la clave privada del desarrollador.
2. **Distribuir la aplicación:** La aplicación firmada se distribuye a los usuarios junto con el certificado del desarrollador, que contiene la clave pública correspondiente.
3. **Verificar la aplicación:** Cuando un usuario descarga e intenta ejecutar la aplicación, el sistema operativo Mac utiliza la clave pública del certificado del desarrollador para descifrar el hash. Después, vuelve a calcular el hash basándose en el estado actual de la aplicación y lo compara con el hash descifrado. Si coinciden, significa que **la aplicación no ha sido modificada** desde que el desarrollador la firmó, y el sistema permite que se ejecute.

Las firmas de aplicaciones son una parte esencial de la tecnología Gatekeeper de Apple. Cuando un usuario intenta **abrir una aplicación descargada de Internet**, Gatekeeper verifica la firma de la aplicación. Si está firmada con un certificado emitido por Apple a un desarrollador conocido y el código no ha sido manipulado, Gatekeeper permite que la aplicación se ejecute. De lo contrario, bloquea la aplicación y alerta al usuario.

A partir de macOS Catalina, **Gatekeeper también comprueba si la aplicación ha sido notarizada** por Apple, añadiendo una capa adicional de seguridad. El proceso de notarización comprueba la aplicación en busca de problemas de seguridad conocidos y código malicioso y, si estas comprobaciones se superan, Apple añade un ticket a la aplicación que Gatekeeper puede verificar.

#### Comprobar firmas

Al analizar alguna **muestra de malware**, siempre debes **comprobar la firma** del binario, ya que el **desarrollador** que la firmó podría estar ya **relacionado** con **malware**.
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

El proceso de notarización de Apple actúa como una salvaguarda adicional para proteger a los usuarios frente a software potencialmente dañino. Consiste en que el **desarrollador envíe su aplicación para que sea examinada** por el **Notary Service de Apple**, que no debe confundirse con App Review. Este servicio es un **sistema automatizado** que analiza el software enviado para detectar la presencia de **contenido malicioso** y cualquier posible problema con la firma de código.

Si el software **supera** esta inspección sin generar ninguna preocupación, el Notary Service genera un ticket de notarización. A continuación, el desarrollador debe **adjuntar este ticket a su software**, un proceso conocido como «stapling». Además, el ticket de notarización también se publica online, donde Gatekeeper, la tecnología de seguridad de Apple, puede acceder a él.

Cuando el usuario instala o ejecuta el software por primera vez, la existencia del ticket de notarización, ya sea adjuntado al ejecutable o encontrado online, **informa a Gatekeeper de que el software ha sido notarizado por Apple**. Como resultado, Gatekeeper muestra un mensaje descriptivo en el diálogo de lanzamiento inicial, indicando que Apple ha realizado comprobaciones del software para detectar contenido malicioso. De este modo, el proceso aumenta la confianza del usuario en la seguridad del software que instala o ejecuta en sus sistemas.

### spctl & syspolicyd

> [!CAUTION]
> Ten en cuenta que, a partir de la versión Sequoia, **`spctl`** ya no permite modificar la configuración de Gatekeeper.

**`spctl`** es la herramienta CLI para enumerar e interactuar con Gatekeeper (con el daemon `syspolicyd` mediante mensajes XPC). Por ejemplo, es posible ver el **estado** de GateKeeper con:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Ten en cuenta que las comprobaciones de firma de GateKeeper se realizan únicamente en **archivos con el atributo Quarantine**, no en todos los archivos.

GateKeeper comprobará si, según las **preferencias y la firma**, se puede ejecutar un binario:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** es el daemon principal responsable de aplicar Gatekeeper. Mantiene una base de datos ubicada en `/var/db/SystemPolicy`, y es posible encontrar el código compatible con la [base de datos aquí](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) y la [plantilla SQL aquí](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Ten en cuenta que SIP no restringe la base de datos, que puede ser escrita por root, y que la base de datos `/var/db/.SystemPolicy-default` se utiliza como copia de seguridad original en caso de que la otra se corrompa.

Además, los bundles **`/var/db/gke.bundle`** y **`/var/db/gkopaque.bundle`** contienen archivos con reglas que se insertan en la base de datos. Puedes consultar esta base de datos como root con:
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
**`syspolicyd`** también expone un servidor XPC con diferentes operaciones como `assess`, `update`, `record` y `cancel`, a las que también se puede acceder mediante las APIs **`SecAssessment*`** de **`Security.framework`**, y **`spctl`** en realidad se comunica con **`syspolicyd`** mediante XPC.

Observa que la primera regla terminaba en "**App Store**" y la segunda en "**Developer ID**", y que en la imagen anterior estaba **habilitado ejecutar aplicaciones del App Store y de desarrolladores identificados**.\
Si **modificas** esa configuración a App Store, las reglas de "**Notarized Developer ID" desaparecerán**.

También hay miles de reglas de **tipo GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Estos son los hashes de:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

También puedes listar la información anterior con:
```bash
sudo spctl --list
```
Las opciones **`--master-disable`** y **`--global-disable`** de **`spctl`** **deshabilitarán por completo** estas comprobaciones de firma:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Una vez completamente habilitada, aparecerá una nueva opción:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Es posible **comprobar si GateKeeper permitirá una App** con:
```bash
spctl --assess -v /Applications/App.app
```
En macOS 14 y posteriores, **`syspolicy_check`** es una comprobación útil de alto nivel previa a la distribución de un application bundle. Produce diagnósticos de trusted execution más accionables que un resultado básico de `spctl`, aunque Apple sigue recomendando probar la ruta real de descarga/extracción/primer inicio, ya que también ejercita la propagación de quarantine.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
Es posible añadir nuevas reglas en GateKeeper para permitir la ejecución de determinadas aplicaciones con:
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
En cuanto a las **kernel extensions**, la carpeta `/var/db/SystemPolicyConfiguration` contiene archivos con listas de kexts permitidas para cargarse. Además, `spctl` tiene el entitlement `com.apple.private.iokit.nvram-csr`, ya que puede añadir nuevas kernel extensions preaprobadas, que también deben guardarse en la NVRAM en una clave `kext-allowed-teams`.

#### Gestión de Gatekeeper en macOS 15 (Sequoia) y versiones posteriores

- Se ha eliminado el antiguo bypass de Finder **Ctrl+Open / Clic derecho → Open**; los usuarios deben permitir explícitamente una app bloqueada desde **System Settings → Privacy & Security → Open Anyway** después del primer cuadro de diálogo de bloqueo.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` ya no se aceptan como cambios de política desatendidos. Las operaciones que modifican la base de datos de reglas o el estado global de evaluación están deprecated, por lo que debe usarse `spctl` para la evaluación y configurarse la aplicación de políticas mediante la interfaz o MDM.

A partir de macOS 15 Sequoia, los usuarios finales ya no pueden alternar la política de Gatekeeper desde `spctl`. La gestión se realiza mediante System Settings o implementando un perfil de configuración MDM con el payload `com.apple.systempolicy.control`. Ejemplo de fragmento de perfil para permitir App Store y desarrolladores identificados (pero no "Anywhere"):

<details>
<summary>Perfil MDM para permitir App Store y desarrolladores identificados</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Archivos en cuarentena

Al **descargar** una aplicación o archivo, ciertas **aplicaciones** de macOS, como los navegadores web o los clientes de correo electrónico, **adjuntan un atributo de archivo extendido**, conocido comúnmente como "**quarantine flag**", al archivo descargado. Este atributo actúa como una medida de seguridad para **marcar el archivo** como procedente de una fuente no confiable (Internet) y potencialmente peligrosa. Sin embargo, no todas las aplicaciones adjuntan este atributo; por ejemplo, el software cliente común de BitTorrent suele omitir este proceso.

**La presencia de un quarantine flag indica a la función de seguridad Gatekeeper de macOS que un usuario intenta ejecutar el archivo**.

Cuando el **quarantine flag no está presente** (como ocurre con los archivos descargados mediante algunos clientes de BitTorrent), es posible que no se realicen las **comprobaciones de Gatekeeper**. Por lo tanto, los usuarios deben tener precaución al abrir archivos descargados de fuentes menos seguras o desconocidas.

> [!NOTE] > **Comprobar** la **validez** de las firmas de código es un proceso que consume muchos **recursos**, ya que incluye la generación de **hashes criptográficos** del código y de todos sus recursos incluidos. Además, comprobar la validez del certificado implica realizar una **comprobación online** en los servidores de Apple para verificar si ha sido revocado después de su emisión. Por estas razones, realizar una comprobación completa de la firma del código y la notarización **cada vez que se inicia una aplicación no resulta práctico**.
>
> Por lo tanto, estas comprobaciones **solo se realizan al ejecutar aplicaciones con el atributo de cuarentena.**

> [!WARNING]
> Este atributo debe ser **establecido por la aplicación que crea o descarga** el archivo.
>
> Sin embargo, los archivos creados en sandbox tendrán este atributo establecido en todos los archivos que creen. Además, las aplicaciones que no están en sandbox pueden establecerlo por sí mismas o especificar la clave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) en el **Info.plist**, lo que hará que el sistema establezca el atributo extendido `com.apple.quarantine` en los archivos creados,

Además, todos los archivos creados por un proceso que llame a **`qtn_proc_apply_to_self`** se ponen en cuarentena. O la API **`qtn_file_apply_to_path`** añade el atributo de cuarentena a una ruta de archivo especificada.

Es posible **comprobar su estado y activarlo/desactivarlo** (se requiere root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
También puedes **comprobar si un archivo tiene el atributo extendido de cuarentena** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Comprueba el **valor** de los **atributos** **extendidos** y averigua la aplicación que escribió el atributo de cuarentena con:
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
En realidad, un proceso "podría establecer quarantine flags en los archivos que crea" (ya intenté aplicar el flag USER_APPROVED a un archivo creado, pero no se aplica):

<details>

<summary>Source Code para aplicar quarantine flags</summary>
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
La información de cuarentena también se almacena en una base de datos central gestionada por LaunchServices en **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, lo que permite a la GUI obtener datos sobre los orígenes del archivo. Además, las aplicaciones que puedan estar interesadas en ocultar sus orígenes pueden sobrescribirla. Esto también se puede hacer mediante las APIS de LaunchServices.

#### **libquarantine.dylib**

Esta library exporta varias funciones que permiten manipular los campos de extended attributes.

Las APIs `qtn_file_*` gestionan las políticas de cuarentena de los archivos, mientras que las APIs `qtn_proc_*` se aplican a los procesos (archivos creados por el proceso). Las funciones no exportadas `__qtn_syscall_quarantine*` son las que aplican las políticas y llaman a `mac_syscall` con `"Quarantine"` como primer argumento, lo que envía las solicitudes a `Quarantine.kext`.

#### **Quarantine.kext**

La kernel extension solo está disponible a través de la **kernel cache del sistema**; sin embargo, puedes _descargar el **Kernel Debug Kit desde** [**https://developer.apple.com/**](https://developer.apple.com/), que contendrá una versión symbolicated de la extension.

Este Kext utilizará hooks mediante MACF sobre varias llamadas para interceptar todos los eventos del ciclo de vida de los archivos: creación, apertura, renombrado, hard-linking... incluso `setxattr`, para evitar que establezca el extended attribute `com.apple.quarantine`.

También utiliza un par de MIBs:

- `security.mac.qtn.sandbox_enforce`: Aplica la cuarentena junto con Sandbox
- `security.mac.qtn.user_approved_exec`: Los procesos en cuarentena solo pueden ejecutar archivos aprobados

#### Provenance xattr (Ventura y posteriores)

macOS 13 Ventura introdujo un mecanismo de provenance independiente que se completa la primera vez que se permite la ejecución de una app en cuarentena.<sup>[[2]](#references)</sup> Se crean dos artefactos:

- El xattr `com.apple.provenance` en el directorio del bundle `.app` (un valor binario de tamaño fijo que contiene una primary key y flags).
- Una fila en la tabla `provenance_tracking` dentro de la base de datos ExecPolicy en `/var/db/SystemPolicyConfiguration/ExecPolicy/`, que almacena el cdhash y los metadatos de la app.

Uso práctico:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect es una función **antimalware** integrada en macOS. XProtect **comprueba cualquier aplicación cuando se ejecuta por primera vez o se modifica, comparándola con su base de datos** de malware conocido y tipos de archivos no seguros. Cuando descargas un archivo mediante determinadas aplicaciones, como Safari, Mail o Messages, XProtect analiza automáticamente el archivo. Si coincide con algún malware conocido en su base de datos, XProtect **impedirá que el archivo se ejecute** y te alertará sobre la amenaza.

Apple **actualiza periódicamente** la base de datos de XProtect con nuevas definiciones de malware, y estas actualizaciones se descargan e instalan automáticamente en tu Mac. Esto garantiza que XProtect esté siempre actualizado con las amenazas conocidas más recientes.

Sin embargo, cabe señalar que **XProtect no es una solución antivirus completa**. Solo comprueba una lista específica de amenazas conocidas y no realiza un escaneo en acceso como la mayoría del software antivirus.

Puedes obtener información sobre la última actualización de XProtect ejecutando:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect se encuentra en la ubicación protegida por SIP **/Library/Apple/System/Library/CoreServices/XProtect.bundle** y dentro del bundle puedes encontrar información que XProtect utiliza:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que el código con esos cdhashes utilice legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins y extensiones cuya carga no está permitida mediante BundleID y TeamID, o que indica una versión mínima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reglas de Yara para detectar malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Base de datos SQLite3 con hashes de aplicaciones bloqueadas y TeamIDs.

Ten en cuenta que existe otra App en **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionada con XProtect que no interviene en el proceso de Gatekeeper.

> XProtect Remediator: En las versiones modernas de macOS, Apple incluye scanners bajo demanda (XProtect Remediator) que se ejecutan periódicamente mediante launchd para detectar y remediar familias de malware. Puedes observar estos scans en los unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### No es Gatekeeper

> [!CAUTION]
> Ten en cuenta que Gatekeeper **no se ejecuta cada vez** que ejecutas una aplicación; solo _**AppleMobileFileIntegrity**_ **verificará las firmas del código ejecutable** cuando ejecutes una app que ya haya sido ejecutada y verificada por Gatekeeper.

Por lo tanto, anteriormente era posible ejecutar una app para almacenarla en la caché de Gatekeeper, después **modificar archivos no ejecutables de la aplicación** (como archivos asar de Electron o archivos NIB) y, si no había otras protecciones activas, la aplicación se **ejecutaba** con las adiciones **maliciosas**.

Sin embargo, ahora esto no es posible porque macOS **impide modificar archivos** dentro de los bundles de las aplicaciones. Por lo tanto, si intentas realizar el ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), comprobarás que ya no es posible abusar de él porque, después de ejecutar la app para almacenarla en la caché de Gatekeeper, no podrás modificar el bundle. Y si cambias, por ejemplo, el nombre del directorio Contents a NotCon (como se indica en el exploit) y después ejecutas el binario principal de la app para almacenarla en la caché de Gatekeeper, se generará un error y no se ejecutará.

## Bypasses de Gatekeeper

Cualquier forma de omitir Gatekeeper (conseguir que el usuario descargue algo y lo ejecute cuando Gatekeeper debería impedirlo) se considera una vulnerabilidad en macOS. Estos son algunos CVE asignados a técnicas que permitieron omitir Gatekeeper en el pasado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Se observó que, si se utiliza **Archive Utility** para extraer archivos, los archivos con **paths que superan los 886 caracteres** no reciben el atributo extendido com.apple.quarantine. Esta situación permite inadvertidamente que esos archivos **eludan las comprobaciones de seguridad de Gatekeeper**.<sup>[[5]](#references)</sup>

Consulta el [**informe original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para obtener más información.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Cuando se crea una aplicación con **Automator**, la información sobre lo que necesita para ejecutarse se encuentra dentro de `application.app/Contents/document.wflow`, no en el ejecutable. El ejecutable es simplemente un binario genérico de Automator llamado **Automator Application Stub**.

Por lo tanto, podías hacer que `application.app/Contents/MacOS/Automator\ Application\ Stub` **apuntara mediante un symbolic link a otro Automator Application Stub dentro del sistema** y ejecutaría lo que se encuentra dentro de `document.wflow` (tu script) **sin activar Gatekeeper**, porque el ejecutable real no tiene el xattr de quarantine.<sup>[[6]](#references)</sup>

Ejemplo de ubicación esperada: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta el [**informe original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para obtener más información.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

En este bypass se creó un archivo zip con una aplicación cuya compresión comenzaba desde `application.app/Contents` en lugar de `application.app`. Por lo tanto, el **quarantine attr** se aplicaba a todos los **archivos de `application.app/Contents`**, pero **no a `application.app`**, que era lo que Gatekeeper comprobaba. De este modo, Gatekeeper se omitía porque, cuando se activaba `application.app`, **no tenía el atributo de quarantine**.<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Consulta el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para obtener más información.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Aunque los componentes son diferentes, la explotación de esta vulnerabilidad es muy similar a la anterior. En este caso, generaremos un Apple Archive a partir de **`application.app/Contents`**, por lo que **`application.app` no obtendrá el atributo quarantine** al descomprimirse mediante **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulta el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para obtener más información.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

La ACL **`writeextattr`** se puede utilizar para impedir que cualquiera escriba un atributo en un archivo:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Además, el formato de archivo **AppleDouble** copia un archivo, incluidos sus ACE.<sup>[[9]](#references)</sup>

En el [**código fuente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) es posible ver que la representación de texto de la ACL almacenada dentro del xattr denominado **`com.apple.acl.text`** se establecerá como ACL en el archivo descomprimido. Por lo tanto, si comprimieras una aplicación en un archivo zip con el formato de archivo **AppleDouble**, con una ACL que impida escribir otros xattrs en ella... el xattr de quarantine no se establecía en la aplicación:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obtener más información.<sup>[[9]](#references)</sup>

Ten en cuenta que esto también podría explotarse con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Se descubrió que **Google Chrome no establecía el atributo quarantine** en los archivos descargados debido a algunos problemas internos de macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble almacena los atributos de un archivo en un archivo independiente cuyo nombre comienza con `._`; esto ayuda a copiar los atributos de los archivos **entre máquinas macOS**. Sin embargo, después de descomprimir un archivo AppleDouble, el archivo que comenzaba con `._` **no recibía el atributo quarantine**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Al poder crear un archivo que no tuviera establecido el atributo de cuarentena, era **posible evadir Gatekeeper**. El truco consistía en **crear una aplicación en un archivo DMG** utilizando la convención de nombres AppleDouble (comenzando con `._`) y crear un archivo **visible como un enlace simbólico a este** archivo oculto sin el atributo de cuarentena.\
Cuando se **ejecuta el archivo dmg**, al no tener un atributo de cuarentena, **evadirá Gatekeeper**.
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
### [CVE-2023-41067]

Apple corrigió un error lógico de LaunchServices en macOS Sonoma 14.0 mediante comprobaciones mejoradas. El aviso público solo indica que una app podía eludir Gatekeeper, por lo que no debe inferirse un formato de carrier o una cadena de explotación específicos basándose únicamente en la entrada del CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Un bypass de Gatekeeper en macOS 14.4 (publicado en marzo de 2024), derivado del manejo de ZIPs maliciosos por parte de `libarchive`, permitía a las apps evadir la evaluación. Actualiza a 14.4 o posterior, donde Apple corrigió el problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **workflow de Automator Quick Action** incluido en una app descargada podía activarse sin la evaluación de Gatekeeper, porque los workflows se trataban como datos y eran ejecutados por el helper de Automator fuera de la ruta normal del aviso de notarización. Por tanto, una `.app` modificada que incluyera una Quick Action que ejecutara un shell script (por ejemplo, dentro de `Contents/PlugIns/*.workflow/Contents/document.wflow`) podía ejecutarse inmediatamente al iniciarse. Apple añadió un diálogo de consentimiento adicional y corrigió la ruta de evaluación en Ventura **13.7**, Sonoma **14.7** y Sequoia **15**.<sup>[[3]](#references)</sup>

### Fallos de propagación de quarantine en los límites de extracción y copia

Un estudio de 2024 encontró brechas de propagación en las versiones probadas de iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) y 7z Utility (DMG/ZIP/7Z); también observó que el atributo se perdía durante las copias de host a guest de VMware Tools. Posteriormente, varios proveedores anunciaron correcciones, por lo que estos nombres deben considerarse pistas para realizar **nuevas pruebas específicas por versión**, no una lista permanente de software vulnerable. El mismo problema de trust boundary se aplica a los workflows nativos de Unix: `curl`/`scp` no añaden quarantine, y `tar`/`unzip` desde la línea de comandos no lo heredan automáticamente de un carrier archive.<sup>[[15]](#references)</sup>

Para las pruebas ofensivas, compara el carrier y la app final después de **cada** transición realizada por el navegador, el cliente de correo, el archivador, la imagen de disco, la sincronización cloud, la carpeta compartida y la copia de la VM. Un rechazo explícito de `spctl` no repara la ausencia de un xattr: sin quarantine, es posible que la ruta normal de Gatekeeper durante la primera apertura nunca solicite esa evaluación.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crea un directorio que contenga una app.
- Añade uchg a la app.
- Comprime la app en un archivo tar.gz.
- Envía el archivo tar.gz a una víctima.
- La víctima abre el archivo tar.gz y ejecuta la app.
- Gatekeeper no comprueba la app.<sup>[[12]](#references)</sup>

### Prevenir Quarantine xattr

En un bundle ".app", si no se le añade el quarantine xattr, **Gatekeeper no se activará** al ejecutarlo.

Consulta [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) para conocer primitives basadas en filesystem, flags, ACL y AppleDouble que pueden impedir o descartar extended attributes.



## References

- [1] [Apple Platform Security: Acerca del contenido de seguridad de macOS Sonoma 14.4 (incluye CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Cómo macOS realiza ahora el seguimiento de la procedencia de las apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Acerca del contenido de seguridad de macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia elimina el bypass de Gatekeeper mediante “Open” con Control‑click](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: El descubrimiento de CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifica una vulnerabilidad de Safari que permite realizar un bypass de Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifica una vulnerabilidad de macOS Archive Utility que permite realizar un bypass de Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [El talón de Aquiles de Gatekeeper: descubriendo una vulnerabilidad de macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Descubrimiento de un Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Encontrar y notificar un exploit de bypass de Gatekeeper con ayuda de Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Acerca del contenido de seguridad de macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Probar un producto notarised](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper Bypass — descubriendo debilidades en un mecanismo de seguridad de macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
