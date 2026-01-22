# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** es una funcionalidad de seguridad desarrollada para los sistemas operativos Mac, diseñada para garantizar que los usuarios **ejecuten sólo software de confianza** en sus sistemas. Funciona **validando el software** que un usuario descarga e intenta abrir desde **fuentes fuera del App Store**, como una app, un plug-in o un paquete instalador.

El mecanismo clave de Gatekeeper reside en su proceso de **verificación**. Comprueba si el software descargado está **firmado por un desarrollador reconocido**, asegurando la autenticidad del software. Además, determina si el software está **notarizado por Apple**, confirmando que está libre de contenido malicioso conocido y que no ha sido manipulado tras la notarización.

Adicionalmente, Gatekeeper refuerza el control del usuario y la seguridad al **solicitar al usuario la aprobación para abrir** el software descargado la primera vez. Esta salvaguarda ayuda a prevenir que los usuarios ejecuten inadvertidamente código ejecutable potencialmente dañino que podían haber confundido con un archivo de datos inofensivo.

### Application Signatures

Las firmas de aplicación, también conocidas como firmas de código, son un componente crítico de la infraestructura de seguridad de Apple. Se utilizan para **verificar la identidad del autor del software** (el desarrollador) y para asegurar que el código no ha sido manipulado desde la última vez que fue firmado.

Así es como funciona:

1. **Firmar la aplicación:** Cuando un desarrollador está listo para distribuir su aplicación, **firma la aplicación usando una clave privada**. Esta clave privada está asociada con un **certificado que Apple emite al desarrollador** cuando se inscribe en el Apple Developer Program. El proceso de firmado implica crear un hash criptográfico de todas las partes de la app y cifrar ese hash con la clave privada del desarrollador.
2. **Distribuir la aplicación:** La aplicación firmada se distribuye a los usuarios junto con el certificado del desarrollador, que contiene la clave pública correspondiente.
3. **Verificar la aplicación:** Cuando un usuario descarga e intenta ejecutar la aplicación, su sistema operativo utiliza la clave pública del certificado del desarrollador para descifrar el hash. Luego recalcula el hash basándose en el estado actual de la aplicación y lo compara con el hash descifrado. Si coinciden, significa que **la aplicación no ha sido modificada** desde que el desarrollador la firmó, y el sistema permite ejecutar la aplicación.

Las firmas de aplicación son una parte esencial de la tecnología Gatekeeper de Apple. Cuando un usuario intenta **abrir una aplicación descargada de internet**, Gatekeeper verifica la firma de la aplicación. Si está firmada con un certificado emitido por Apple a un desarrollador conocido y el código no ha sido manipulado, Gatekeeper permite ejecutar la aplicación. De lo contrario, bloquea la aplicación y alerta al usuario.

A partir de macOS Catalina, **Gatekeeper también comprueba si la aplicación ha sido notarizada** por Apple, añadiendo una capa adicional de seguridad. El proceso de notarización revisa la aplicación en busca de problemas de seguridad conocidos y código malicioso, y si estas comprobaciones pasan, Apple añade un ticket a la aplicación que Gatekeeper puede verificar.

#### Check Signatures

Al analizar alguna **muestra de malware** siempre debes **comprobar la firma** del binario, ya que el **desarrollador** que la firmó puede estar ya **relacionado** con malware.
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

El proceso de notarización de Apple sirve como una salvaguarda adicional para proteger a los usuarios de software potencialmente dañino. Implica que el **desarrollador envíe su aplicación para su examen** por parte del **Apple's Notary Service**, que no debe confundirse con App Review. Este servicio es un **sistema automatizado** que examina el software enviado en busca de **contenido malicioso** y de cualquier problema potencial con la firma de código.

Si el software **aprueba** esta inspección sin generar inquietudes, el Notary Service genera un ticket de notarización. El desarrollador debe entonces **adjuntar este ticket a su software**, un proceso conocido como 'stapling'. Además, el ticket de notarización también se publica en línea donde Gatekeeper, la tecnología de seguridad de Apple, puede acceder a él.

En la primera instalación o ejecución por parte del usuario, la existencia del ticket de notarización —ya sea stapled al ejecutable o disponible en línea— **informa a Gatekeeper que el software ha sido notarizado por Apple**. Como resultado, Gatekeeper muestra un mensaje descriptivo en el cuadro de diálogo de primer lanzamiento, indicando que Apple realizó comprobaciones en busca de contenido malicioso. Este proceso, por tanto, aumenta la confianza del usuario en la seguridad del software que instala o ejecuta en sus sistemas.

### spctl & syspolicyd

> [!CAUTION]
> Tenga en cuenta que a partir de la versión Sequoia, **`spctl`** ya no permite modificar la configuración de Gatekeeper.

**`spctl`** es la herramienta CLI para enumerar e interactuar con Gatekeeper (con el daemon `syspolicyd` vía mensajes XPC). Por ejemplo, es posible ver el **estado** de GateKeeper con:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Tenga en cuenta que las comprobaciones de firma de GateKeeper se realizan únicamente en **archivos con el atributo Quarantine**, no en todos los archivos.

GateKeeper comprobará si, según las **preferencias y la firma**, un binario puede ejecutarse:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** es el demonio principal encargado de hacer cumplir GateKeeper. Mantiene una base de datos ubicada en `/var/db/SystemPolicy` y es posible encontrar el código que la soporta en el [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) y la [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Ten en cuenta que la base de datos no está restringida por SIP y es escribible por root, y la base de datos `/var/db/.SystemPolicy-default` se utiliza como copia de seguridad original en caso de que la otra se corrompa.

Además, los bundles **`/var/db/gke.bundle`** y **`/var/db/gkopaque.bundle`** contienen archivos con reglas que se insertan en la base de datos. Puedes revisar esta base de datos como root con:
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
**`syspolicyd`** también expone un servidor XPC con diferentes operaciones como `assess`, `update`, `record` y `cancel`, que también son accesibles mediante las APIs **`Security.framework`'s `SecAssessment*`**, y **`spctl`** en realidad se comunica con **`syspolicyd`** vía XPC.

Fíjate cómo la primera regla terminaba en "**App Store**" y la segunda en "**Developer ID**" y que en la imagen anterior estaba **habilitado para ejecutar apps desde el App Store y desarrolladores identificados**.\  
Si **modificas** esa configuración a App Store, las "**Notarized Developer ID" reglas desaparecerán**.

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

O puedes listar la información anterior con:
```bash
sudo spctl --list
```
Las opciones **`--master-disable`** y **`--global-disable`** de **`spctl`** **deshabilitarán** por completo estas comprobaciones de firma:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Cuando esté completamente habilitado, aparecerá una nueva opción:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Es posible **comprobar si una App será permitida por GateKeeper** con:
```bash
spctl --assess -v /Applications/App.app
```
Es posible agregar nuevas reglas en GateKeeper para permitir la ejecución de ciertas apps con:
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
Con respecto a **kernel extensions**, la carpeta `/var/db/SystemPolicyConfiguration` contiene archivos con listas de kexts permitidos para cargarse. Además, `spctl` tiene la entitlement `com.apple.private.iokit.nvram-csr` porque es capaz de agregar nuevas kernel extensions preaprobadas que también deben guardarse en NVRAM en una clave `kext-allowed-teams`.

#### Gestión de Gatekeeper en macOS 15 (Sequoia) y posteriores

- El bypass de larga data del Finder **Ctrl+Open / Right‑click → Open** ha sido eliminado; los usuarios deben permitir explícitamente una app bloqueada desde **Ajustes del Sistema → Privacidad y Seguridad → Abrir de todos modos** después del primer diálogo de bloqueo.
- `spctl --master-disable/--global-disable` ya no son aceptados; `spctl` es efectivamente de solo lectura para evaluación y gestión de etiquetas mientras la aplicación de políticas se configura a través de la UI o MDM.

A partir de macOS 15 Sequoia, los usuarios finales ya no pueden alternar la política de Gatekeeper desde `spctl`. La gestión se realiza mediante System Settings o desplegando un perfil de configuración MDM con la payload `com.apple.systempolicy.control`. Fragmento de ejemplo de perfil para permitir App Store y desarrolladores identificados (pero no "Anywhere"):

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

Al **descargar** una aplicación o archivo, ciertas aplicaciones de macOS, como navegadores web o clientes de correo electrónico, **adjuntan un atributo extendido de archivo**, comúnmente conocido como la **bandera de cuarentena**, al archivo descargado. Este atributo actúa como una medida de seguridad para **marcar el archivo** como procedente de una fuente no confiable (Internet) y que potencialmente conlleva riesgos. Sin embargo, no todas las aplicaciones adjuntan este atributo; por ejemplo, el software cliente de BitTorrent suele omitir este proceso.

**La presencia de una bandera de cuarentena indica a la función de seguridad Gatekeeper de macOS cuando un usuario intenta ejecutar el archivo.**

En el caso de que la **bandera de cuarentena no esté presente** (como ocurre con archivos descargados mediante algunos clientes de BitTorrent), las **comprobaciones de Gatekeeper pueden no ejecutarse**. Por lo tanto, los usuarios deben tener precaución al abrir archivos descargados de fuentes menos seguras o desconocidas.

> [!NOTE] > **Comprobar** la **validez** de las firmas de código es un proceso que consume muchos recursos e incluye generar hashes criptográficos del código y de todos sus recursos incluidos. Además, comprobar la validez de un certificado implica realizar una verificación en línea contra los servidores de Apple para ver si ha sido revocado tras su emisión. Por estas razones, una comprobación completa de firma de código y notarización es poco práctica de ejecutar cada vez que se lanza una app.
>
> Por lo tanto, estas comprobaciones **solo se ejecutan** al ejecutar aplicaciones que tengan el atributo de cuarentena.

> [!WARNING]
> Este atributo debe ser **establecido por la aplicación que crea/descarga** el archivo.
>
> Sin embargo, los archivos creados por procesos sandboxed tendrán este atributo establecido en cada archivo que creen. Y las apps no sandboxed pueden establecerlo ellas mismas, o especificar la clave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) en el **Info.plist**, lo que hará que el sistema establezca el atributo extendido `com.apple.quarantine` en los archivos creados,

Además, todos los archivos creados por un proceso que llama a **`qtn_proc_apply_to_self`** quedan en cuarentena. O la API **`qtn_file_apply_to_path`** añade el atributo de cuarentena a una ruta de archivo especificada.

Es posible **comprobar su estado y habilitar/deshabilitarlo** (se requiere root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
También puedes **comprobar si un archivo tiene el atributo extendido quarantine** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Comprueba el **valor** de los **atributos** **extendidos** y averigua la aplicación que escribió el quarantine attr con:
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
En realidad, un proceso "podría establecer banderas de cuarentena en los archivos que crea" (ya intenté aplicar la bandera USER_APPROVED en un archivo creado pero no se aplica):

<details>

<summary>Código fuente: aplicar banderas de cuarentena</summary>
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
La información de Quarantine también se almacena en una base de datos central gestionada por LaunchServices en **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, lo que permite a la GUI obtener datos sobre el origen de los archivos. Además, esto puede ser sobrescrito por aplicaciones que quieran ocultar su origen. Además, esto se puede hacer desde las LaunchServices APIS.

#### **libquarantine.dylib**

Esta librería exporta varias funciones que permiten manipular los campos de atributos extendidos.

Las APIs `qtn_file_*` gestionan las políticas de quarantine de archivos, las APIs `qtn_proc_*` se aplican a procesos (archivos creados por el proceso). Las funciones no exportadas `__qtn_syscall_quarantine*` son las que aplican las políticas: llaman a `mac_syscall` con "Quarantine" como primer argumento, lo que envía las solicitudes a `Quarantine.kext`.

#### **Quarantine.kext**

La extensión del kernel solo está disponible a través de la **caché del kernel en el sistema**; sin embargo, _puedes_ descargar el **Kernel Debug Kit desde** [**https://developer.apple.com/**](https://developer.apple.com/), que contendrá una versión simbolicada de la extensión.

Este Kext engancha vía MACF varias llamadas para interceptar todos los eventos del ciclo de vida de archivos: creación, apertura, renombrado, hard-linkning... incluso `setxattr` para impedir que establezca el atributo extendido `com.apple.quarantine`.

También usa un par de MIBs:

- `security.mac.qtn.sandbox_enforce`: Aplicar la política de Quarantine junto con Sandbox
- `security.mac.qtn.user_approved_exec`: Los procesos en Quarantine solo pueden ejecutar archivos aprobados

#### Provenance xattr (Ventura y posteriores)

macOS 13 Ventura introdujo un mecanismo de provenance separado que se popula la primera vez que se permite ejecutar una app en cuarentena. Se crean dos artefactos:

- El xattr `com.apple.provenance` en el directorio del bundle `.app` (valor binario de tamaño fijo que contiene una clave primaria y flags).
- Una fila en la tabla `provenance_tracking` dentro de la base de datos ExecPolicy en `/var/db/SystemPolicyConfiguration/ExecPolicy/` que almacena el cdhash de la app y metadatos.

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

XProtect es una función integrada de **anti-malware** en macOS. XProtect **verifica cualquier aplicación cuando se lanza por primera vez o se modifica contra su base de datos** de malware conocido y tipos de archivo no seguros. Cuando descargas un archivo a través de ciertas apps, como Safari, Mail o Messages, XProtect escanea automáticamente el archivo. Si coincide con algún malware conocido en su base de datos, XProtect **impedirá que el archivo se ejecute** y te alertará sobre la amenaza.

La base de datos de XProtect es **actualizada regularmente** por Apple con nuevas definiciones de malware, y estas actualizaciones se descargan e instalan automáticamente en tu Mac. Esto asegura que XProtect esté siempre actualizado con las últimas amenazas conocidas.

Sin embargo, vale la pena señalar que **XProtect no es una solución antivirus completa**. Solo comprueba una lista específica de amenazas conocidas y no realiza escaneo en tiempo real como la mayoría de los antivirus.

Puedes obtener información sobre la última actualización de XProtect ejecutando:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect está ubicado en una ruta protegida por SIP en **/Library/Apple/System/Library/CoreServices/XProtect.bundle** y dentro del bundle puedes encontrar la información que usa XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que código con esos cdhashes use legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins y extensiones que no se permiten cargar vía BundleID y TeamID o que indican una versión mínima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reglas Yara para detectar malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Base de datos SQLite3 con hashes de aplicaciones bloqueadas y TeamIDs.

Ten en cuenta que hay otra App en **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionada con XProtect que no está involucrada en el proceso de Gatekeeper.

> XProtect Remediator: En macOS moderno, Apple incluye scanners on‑demand (XProtect Remediator) que se ejecutan periódicamente vía launchd para detectar y remediar familias de malware. Puedes observar estos escaneos en los unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Not Gatekeeper

> [!CAUTION]
> Note that Gatekeeper **isn't executed every time** you execute an application, just _**AppleMobileFileIntegrity**_ (AMFI) will only **verify executable code signatures** when you execute an app that has been already executed and verified by Gatekeeper.

Por lo tanto, antes era posible ejecutar una app para cachearla con Gatekeeper, luego **modificar archivos no ejecutables de la aplicación** (como Electron asar o archivos NIB) y si no existían otras protecciones, la aplicación se **ejecutaba** con las adiciones **maliciosas**.

Sin embargo, ahora esto no es posible porque macOS **impide modificar archivos** dentro de los bundles de las aplicaciones. Así que, si intentas el ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), verás que ya no es posible abusar de él porque después de ejecutar la app para cachearla con Gatekeeper, no podrás modificar el bundle. Y si cambias, por ejemplo, el nombre del directorio Contents a NotCon (como indica el exploit), y luego ejecutas el binario principal de la app para cachearlo con Gatekeeper, se producirá un error y no se ejecutará.

## Gatekeeper Bypasses

Cualquier forma de evitar Gatekeeper (lograr que el usuario descargue algo y lo ejecute cuando Gatekeeper debería impedirlo) se considera una vulnerabilidad en macOS. Estos son algunos CVEs asignados a técnicas que permitieron bypasses de Gatekeeper en el pasado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Se observó que si se usa **Archive Utility** para la extracción, los archivos con **rutas que exceden los 886 caracteres** no reciben el atributo extendido com.apple.quarantine. Esta situación permite inadvertidamente que esos archivos **circunvalen los** checks de seguridad de Gatekeeper.

Consulta el [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para más información.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Cuando una aplicación se crea con **Automator**, la información sobre lo que necesita para ejecutarse está dentro de `application.app/Contents/document.wflow` y no en el ejecutable. El ejecutable es simplemente un binario genérico de Automator llamado **Automator Application Stub**.

Por lo tanto, se podía hacer que `application.app/Contents/MacOS/Automator\ Application\ Stub` **apuntara con un enlace simbólico a otro Automator Application Stub dentro del sistema** y ejecutaría lo que está dentro de `document.wflow` (tu script) **sin activar Gatekeeper** porque el ejecutable real no tenía el xattr de quarantine.

Example os expected location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta el [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para más información.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

En este bypass se creó un zip con una aplicación empezando a comprimir desde `application.app/Contents` en lugar de `application.app`. Por lo tanto, el **atributo de quarantine** se aplicó a todos los **archivos de `application.app/Contents`** pero **no a `application.app`**, que era lo que Gatekeeper revisaba, de modo que Gatekeeper fue bypassed porque cuando se activaba `application.app` **no tenía el atributo de quarantine.**
```bash
zip -r test.app/Contents test.zip
```
Consulta el [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para más información.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Aunque los componentes son diferentes, la explotación de esta vulnerabilidad es muy similar a la anterior. En este caso se generará un Apple Archive a partir de **`application.app/Contents`**, por lo que **`application.app` no obtendrá el quarantine attr** cuando se descomprima con **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulta el [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para más información.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

La ACL **`writeextattr`** puede usarse para evitar que alguien escriba un atributo en un archivo:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Además, el formato de archivo **AppleDouble** copia un archivo incluyendo sus ACEs.

En el [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) es posible ver que la representación en texto de la ACL almacenada dentro del xattr llamado **`com.apple.acl.text`** se va a establecer como ACL en el archivo descomprimido. Así que, si comprimiste una aplicación en un archivo zip con el formato de archivo **AppleDouble** con una ACL que impide que otros xattrs se escriban en ella... el quarantine xattr no se estableció en la aplicación:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulta el [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para más información.

Ten en cuenta que esto también podría explotarse con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Se descubrió que **Google Chrome no establecía el atributo de cuarentena** en los archivos descargados debido a algunos problemas internos de macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Los formatos AppleDouble almacenan los atributos de un archivo en un archivo separado que comienza por `._`; esto ayuda a copiar atributos de archivo **entre máquinas macOS**. Sin embargo, se observó que después de descomprimir un archivo AppleDouble, el archivo que comienza con `._` **no recibía el atributo de cuarentena**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Al poder crear un archivo que no tuviera el atributo de cuarentena establecido, era **posible burlar Gatekeeper.** El truco consistía en **crear una aplicación DMG** usando la convención de nombres AppleDouble (iniciándola con `._`) y crear un **archivo visible como un sym link hacia este archivo oculto** sin el atributo de cuarentena.\
Cuando se ejecuta el **archivo DMG**, al no tener un atributo de cuarentena, **burlará Gatekeeper**.
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

Un Gatekeeper bypass corregido en macOS Sonoma 14.0 permitía que aplicaciones manipuladas se ejecutaran sin solicitar confirmación. Los detalles se divulgaron públicamente después del parche y el problema fue explotado activamente en el wild antes de la corrección. Asegúrese de que Sonoma 14.0 o posterior esté instalado.

### [CVE-2024-27853]

Un Gatekeeper bypass en macOS 14.4 (lanzado en marzo de 2024) derivado del manejo de ZIPs maliciosos por `libarchive` permitía que apps evadieran la evaluación. Actualice a 14.4 o posterior donde Apple abordó el problema.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **Automator Quick Action workflow** incrustado en una app descargada podía dispararse sin la evaluación de Gatekeeper, porque los workflows se trataban como datos y eran ejecutados por el helper de Automator fuera de la ruta normal del aviso de notarización. Una `.app` manipulada que incluyera un Quick Action que ejecute un script de shell (p. ej., dentro de `Contents/PlugIns/*.workflow/Contents/document.wflow`) podría, por tanto, ejecutarse inmediatamente al iniciarse. Apple añadió un diálogo de consentimiento adicional y corrigió la ruta de evaluación en Ventura **13.7**, Sonoma **14.7**, y Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Varias vulnerabilidades en herramientas de extracción populares (p. ej., The Unarchiver) provocaron que archivos extraídos de archivos comprimidos no conservaran el xattr `com.apple.quarantine`, habilitando oportunidades de bypass de Gatekeeper. Confíe siempre en macOS Archive Utility o en herramientas parcheadas al probar, y valide los xattrs después de la extracción.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Create a directory containing an app.
- Add uchg to the app.
- Compress the app to a tar.gz file.
- Send the tar.gz file to a victim.
- The victim opens the tar.gz file and runs the app.
- Gatekeeper does not check the app.

### Prevent Quarantine xattr

En un paquete ".app", si no se añade el xattr de cuarentena, al ejecutarlo **Gatekeeper no se activará**.


## Referencias

- Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
