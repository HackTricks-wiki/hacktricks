# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** es una función de seguridad desarrollada para los sistemas operativos Mac, diseñada para garantizar que los usuarios **ejecuten únicamente software de confianza** en sus sistemas. Funciona **validando el software** que un usuario descarga e intenta abrir desde **fuentes ajenas al App Store**, como una app, un plug-in o un paquete de instalación.

El mecanismo clave de Gatekeeper es su proceso de **verificación**. Comprueba si el software descargado está **firmado por un desarrollador reconocido**, para garantizar su autenticidad. Además, comprueba si el software está **notarizado por Apple**, lo que confirma que no contiene contenido malicioso conocido y que no se ha manipulado desde la notarización.

Además, Gatekeeper refuerza el control del usuario y la seguridad al **pedir a los usuarios que aprueben la apertura** del software descargado la primera vez. Esta protección ayuda a evitar que los usuarios ejecuten inadvertidamente código ejecutable potencialmente dañino que podrían haber confundido con un archivo de datos inofensivo.

### Firmas de aplicaciones

Las firmas de aplicaciones, también conocidas como firmas de código, son un componente fundamental de la infraestructura de seguridad de Apple. Se utilizan para **verificar la identidad del autor del software** (el desarrollador) y garantizar que el código no se haya manipulado desde la última vez que se firmó.

Así es como funciona:

1. **Firmar la aplicación:** Cuando un desarrollador está listo para distribuir su aplicación, la **firma con una clave privada**. Esta clave privada está asociada a un **certificado que Apple emite al desarrollador** cuando se inscribe en el Apple Developer Program. El proceso de firma consiste en crear un hash criptográfico de todas las partes de la app y cifrarlo con la clave privada del desarrollador.
2. **Distribuir la aplicación:** Después, la aplicación firmada se distribuye a los usuarios junto con el certificado del desarrollador, que contiene la clave pública correspondiente.
3. **Verificar la aplicación:** Cuando un usuario descarga la aplicación e intenta ejecutarla, el sistema operativo de su Mac utiliza la clave pública del certificado del desarrollador para descifrar el hash. Luego, vuelve a calcular el hash según el estado actual de la aplicación y lo compara con el hash descifrado. Si coinciden, significa que **la aplicación no se ha modificado** desde que el desarrollador la firmó, y el sistema permite que se ejecute.

Las firmas de aplicaciones son una parte esencial de la tecnología Gatekeeper de Apple. Cuando un usuario intenta **abrir una aplicación descargada de Internet**, Gatekeeper verifica su firma. Si está firmada con un certificado que Apple emitió a un desarrollador conocido y el código no se ha manipulado, Gatekeeper permite que la aplicación se ejecute. De lo contrario, la bloquea y alerta al usuario.

Desde macOS Catalina, **Gatekeeper también comprueba si Apple ha notarizado la aplicación**, lo que añade otra capa de seguridad. El proceso de notarización comprueba si la aplicación presenta problemas de seguridad conocidos y código malicioso. Si supera estas comprobaciones, Apple añade un ticket a la aplicación que Gatekeeper puede verificar.

#### Comprobar firmas

Al analizar una **muestra de malware**, siempre deberías **comprobar la firma** del binario, ya que el **desarrollador** que lo firmó podría estar ya **vinculado** con **malware**.

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

El proceso de notarización de Apple sirve como protección adicional para proteger a los usuarios del software potencialmente dañino. Consiste en que **el desarrollador envía su aplicación para que la examine** el **Apple Notary Service**, que no debe confundirse con App Review. Este servicio es un **sistema automatizado** que analiza el software enviado para detectar **contenido malicioso** y posibles problemas con la firma de código.

Si el software **supera** esta inspección sin generar inquietudes, el Notary Service genera un ticket de notarización. Luego, el desarrollador debe **adjuntar este ticket a su software**, en un proceso conocido como «stapling». Además, el ticket de notarización también se publica en línea, donde Gatekeeper, la tecnología de seguridad de Apple, puede acceder a él.

Cuando el usuario instala o ejecuta el software por primera vez, la existencia del ticket de notarización —ya sea adjunto al ejecutable o encontrado en línea— **indica a Gatekeeper que Apple ha notarizado el software**. Como resultado, Gatekeeper muestra un mensaje descriptivo en el cuadro de diálogo del primer inicio, que indica que Apple ha comprobado el software para detectar contenido malicioso. Este proceso aumenta la confianza de los usuarios en la seguridad del software que instalan o ejecutan en sus sistemas.

### spctl y syspolicyd

> [!CAUTION]
> Ten en cuenta que, a partir de Sequoia, **`spctl`** ya no permite modificar la configuración de Gatekeeper.

**`spctl`** es la herramienta CLI para enumerar e interactuar con Gatekeeper (con el daemon `syspolicyd` mediante mensajes XPC). Por ejemplo, es posible ver el **estado** de Gatekeeper con:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Ten en cuenta que las comprobaciones de firma de GateKeeper se realizan únicamente en **archivos con el atributo Quarantine**, no en todos los archivos.

GateKeeper comprobará si, según las **preferencias y la firma**, se puede ejecutar un binario:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** es el daemon principal responsable de aplicar Gatekeeper. Mantiene una base de datos ubicada en `/var/db/SystemPolicy`; puedes encontrar el código que da soporte a la [base de datos aquí](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) y la [plantilla SQL aquí](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Ten en cuenta que SIP no restringe la base de datos y que root puede escribir en ella. La base de datos `/var/db/.SystemPolicy-default` se utiliza como copia de seguridad original por si la otra se corrompe.

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

**`syspolicyd`** también expone un servidor XPC con distintas operaciones, como `assess`, `update`, `record` y `cancel`, a las que también se puede acceder mediante las API **`SecAssessment*`** de **`Security.framework`**. Además, **`spctl`** se comunica con **`syspolicyd`** mediante XPC.

Observa que la primera regla terminaba en "**App Store**" y la segunda en "**Developer ID**", y que en la imagen anterior estaba **habilitada la ejecución de apps de App Store y de desarrolladores identificados**.\
Si **modificas** esa configuración a App Store, **desaparecerán las reglas de "**Developer ID notarizado**"**.

También hay miles de reglas de **tipo GKE**:

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Estos son los hashes que provienen de:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

O puedes listar la información anterior con:

```bash
sudo spctl --list
```

Las opciones **`--master-disable`** y **`--global-disable`** de **`spctl`** **desactivarán** por completo estas comprobaciones de firma:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Cuando esté completamente habilitada, aparecerá una nueva opción:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Es posible **comprobar si GateKeeper permitirá una App** con:

```bash
spctl --assess -v /Applications/App.app
```

En macOS 14 y versiones posteriores, **`syspolicy_check`** es una herramienta de nivel superior útil para comprobar una aplicación empaquetada antes de distribuirla. Ofrece diagnósticos de ejecución confiable más prácticos que un resultado simple de `spctl`, aunque Apple sigue recomendando probar el flujo real de descarga, extracción y primer inicio, ya que también comprueba la propagación de la cuarentena.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

Es posible añadir nuevas reglas en GateKeeper para permitir la ejecución de ciertas aplicaciones con:

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

En cuanto a las **extensiones de kernel**, la carpeta `/var/db/SystemPolicyConfiguration` contiene archivos con listas de kexts que se pueden cargar. Además, `spctl` tiene el entitlement `com.apple.private.iokit.nvram-csr`, ya que puede añadir nuevas extensiones de kernel preaprobadas, que también deben guardarse en NVRAM en una clave `kext-allowed-teams`.

#### Administración de Gatekeeper en macOS 15 (Sequoia) y versiones posteriores

- Se ha eliminado el antiguo bypass de Finder **Ctrl+Abrir / Clic derecho → Abrir**; los usuarios deben permitir explícitamente una app bloqueada desde **Ajustes del Sistema → Privacidad y seguridad → Abrir de todos modos** después del primer diálogo de bloqueo.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` ya no se aceptan como cambios de política desatendidos. Las operaciones que modifican la base de datos de reglas o el estado global de evaluación están obsoletas, así que usa `spctl` para la evaluación y configura la aplicación de políticas mediante la interfaz o MDM.

A partir de macOS 15 Sequoia, los usuarios finales ya no pueden cambiar la política de Gatekeeper desde `spctl`. La administración se realiza mediante Ajustes del Sistema o implementando un perfil de configuración MDM con el payload `com.apple.systempolicy.control`. Ejemplo de fragmento de perfil para permitir App Store y desarrolladores identificados (pero no «Cualquier lugar»):

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

Al **descargar** una aplicación o un archivo, algunas **aplicaciones** de macOS, como los navegadores web o los clientes de correo electrónico, **añaden un atributo extendido al archivo**, conocido comúnmente como "**quarantine flag**", al archivo descargado. Este atributo sirve como medida de seguridad para **marcar el archivo** como procedente de una fuente no confiable (internet) y potencialmente riesgosa. Sin embargo, no todas las aplicaciones añaden este atributo; por ejemplo, los clientes de BitTorrent más comunes suelen omitir este proceso.

**La presencia de un quarantine flag activa la función de seguridad Gatekeeper de macOS cuando un usuario intenta ejecutar el archivo**.

Si el **quarantine flag no está presente** (como ocurre con los archivos descargados mediante algunos clientes de BitTorrent), es posible que no se realicen las **comprobaciones** de Gatekeeper. Por lo tanto, los usuarios deben tener cuidado al abrir archivos descargados de fuentes menos seguras o desconocidas.

> [!NOTE] > **Comprobar** la **validez** de las firmas de código es un proceso que consume muchos **recursos** e incluye generar **hashes** criptográficos del código y de todos los recursos incluidos en el paquete. Además, comprobar la validez del certificado implica realizar una **comprobación en línea** con los servidores de Apple para determinar si se revocó después de su emisión. Por estos motivos, no es **práctico realizar una comprobación completa de la firma de código y la notarización cada vez que se inicia una aplicación**.
>
> Por lo tanto, estas comprobaciones **solo se realizan al ejecutar aplicaciones con el atributo de cuarentena**.

> [!WARNING]
> Este atributo debe **establecerlo la aplicación que crea/descarga** el archivo.
>
> Sin embargo, los archivos en sandbox tendrán este atributo en todos los archivos que creen. Y las aplicaciones que no están en sandbox pueden establecerlo por sí mismas o especificar la clave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) en **Info.plist**, lo que hará que el sistema establezca el atributo extendido `com.apple.quarantine` en los archivos creados.

Además, todos los archivos creados por un proceso que llame a **`qtn_proc_apply_to_self`** quedan en cuarentena. También se puede usar la API **`qtn_file_apply_to_path`** para añadir el atributo de cuarentena a la ruta de un archivo especificado.

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

Comprueba el **valor** de los **atributos** **extendidos** y averigua qué aplicación escribió el atributo de cuarentena con:

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

En realidad, un proceso «podría establecer flags de quarantine en los archivos que crea» (ya intenté aplicar el flag USER_APPROVED a un archivo creado, pero no se aplica):

<details>

<summary>Código fuente: aplicar flags de quarantine</summary>

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

La información de cuarentena también se almacena en una base de datos central administrada por LaunchServices en **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, que permite a la interfaz gráfica obtener datos sobre el origen de los archivos. Además, las aplicaciones que podrían estar interesadas en ocultar su origen pueden sobrescribirla. Esto también se puede hacer mediante las API de LaunchServices.

#### **libquarantine.dylib**

Esta biblioteca exporta varias funciones que permiten manipular los campos de atributos extendidos.

Las API `qtn_file_*` se ocupan de las políticas de cuarentena de archivos; las API `qtn_proc_*` se aplican a los procesos (a los archivos creados por el proceso). Las funciones no exportadas `__qtn_syscall_quarantine*` son las que aplican las políticas: llaman a `mac_syscall` con "Quarantine" como primer argumento, lo que envía las solicitudes a `Quarantine.kext`.

#### **Quarantine.kext**

La extensión del kernel solo está disponible a través de la **caché del kernel del sistema**; sin embargo, puedes descargar el **Kernel Debug Kit desde** [**https://developer.apple.com/**](https://developer.apple.com/), que incluye una versión de la extensión con símbolos.

Esta Kext usa MACF para interceptar varias llamadas y capturar todos los eventos del ciclo de vida de los archivos: creación, apertura, cambio de nombre, creación de hard links... incluso `setxattr`, para impedir que establezca el atributo extendido `com.apple.quarantine`.

También usa un par de MIB:

- `security.mac.qtn.sandbox_enforce`: aplica la cuarentena junto con Sandbox
- `security.mac.qtn.user_approved_exec`: los procesos en cuarentena solo pueden ejecutar archivos aprobados

#### Atributo extendido de procedencia (Ventura y versiones posteriores)

macOS 13 Ventura introdujo un mecanismo de procedencia independiente que se completa la primera vez que se permite ejecutar una aplicación en cuarentena.<sup>[[2]](#references)</sup> Se crean dos artefactos:

- El atributo extendido `com.apple.provenance` en el directorio del bundle `.app` (un valor binario de tamaño fijo que contiene una clave primaria y flags).
- Una fila en la tabla `provenance_tracking`, dentro de la base de datos ExecPolicy en `/var/db/SystemPolicyConfiguration/ExecPolicy/`, que almacena el cdhash y los metadatos de la aplicación.

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

XProtect es una función **antimalware** integrada en macOS. XProtect **comprueba cada aplicación cuando se inicia por primera vez o se modifica, comparándola con su base de datos** de malware conocido y tipos de archivo no seguros. Cuando descargas un archivo mediante ciertas aplicaciones, como Safari, Mail o Messages, XProtect lo analiza automáticamente. Si coincide con algún malware conocido de su base de datos, XProtect **impedirá que el archivo se ejecute** y te avisará de la amenaza.

Apple **actualiza periódicamente** la base de datos de XProtect con nuevas definiciones de malware, y estas actualizaciones se descargan e instalan automáticamente en tu Mac. Esto garantiza que XProtect esté siempre al día con las amenazas conocidas más recientes.

Sin embargo, cabe señalar que **XProtect no es una solución antivirus completa**. Solo comprueba una lista específica de amenazas conocidas y no realiza análisis en tiempo real al acceder a los archivos, como la mayoría de los antivirus.

Puedes obtener información sobre la actualización más reciente de XProtect ejecutando:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect se encuentra en una ubicación protegida por SIP: **/Library/Apple/System/Library/CoreServices/XProtect.bundle**. Dentro del bundle puedes encontrar información que utiliza XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que el código con esos cdhashes use legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins y extensiones cuya carga está prohibida mediante BundleID y TeamID, o que indica una versión mínima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reglas de Yara para detectar malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Base de datos SQLite3 con hashes de aplicaciones bloqueadas y TeamIDs.

Ten en cuenta que hay otra App relacionada con XProtect en **`/Library/Apple/System/Library/CoreServices/XProtect.app`** que no interviene en el proceso de Gatekeeper.

> XProtect Remediator: En las versiones modernas de macOS, Apple incluye escáneres bajo demanda (XProtect Remediator) que se ejecutan periódicamente mediante launchd para detectar y remediar familias de malware. Puedes observar estos análisis en los logs unificados:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### No es Gatekeeper

> [!CAUTION]
> Ten en cuenta que Gatekeeper **no se ejecuta cada vez** que ejecutas una aplicación; solo _**AppleMobileFileIntegrity**_ (AMFI) **verifica las firmas del código ejecutable** cuando ejecutas una app que Gatekeeper ya había ejecutado y verificado.

Por lo tanto, antes era posible ejecutar una app para que Gatekeeper la almacenara en caché y luego **modificar archivos no ejecutables de la aplicación** (como archivos asar de Electron o NIB) y, si no había otras protecciones, la aplicación se **ejecutaba** con las adiciones **maliciosas**.

Sin embargo, ahora esto no es posible porque macOS **impide modificar archivos** dentro de los bundles de aplicaciones. Así que, si intentas el ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), verás que ya no es posible aprovecharlo porque, después de ejecutar la app para que Gatekeeper la almacene en caché, no podrás modificar el bundle. Y si, por ejemplo, cambias el nombre del directorio Contents a NotCon (como se indica en el exploit) y luego ejecutas el binario principal de la app para que Gatekeeper lo almacene en caché, se generará un error y no se ejecutará.

## Bypasses de Gatekeeper

Cualquier forma de bypass de Gatekeeper (lograr que el usuario descargue algo y lo ejecute cuando Gatekeeper debería impedirlo) se considera una vulnerabilidad en macOS. Estos son algunos CVE asignados a técnicas que permitieron hacer bypass de Gatekeeper en el pasado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Se observó que, si se utiliza **Archive Utility** para extraer archivos, los archivos con **rutas de más de 886 caracteres** no reciben el atributo extendido com.apple.quarantine. Esto permite inadvertidamente que esos archivos **evadan las** comprobaciones de seguridad de Gatekeeper.<sup>[[5]](#references)</sup>

Consulta el [**informe original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para obtener más información.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Cuando se crea una aplicación con **Automator**, la información sobre lo que debe ejecutar está dentro de `application.app/Contents/document.wflow`, no en el ejecutable. El ejecutable es solo un binario genérico de Automator llamado **Automator Application Stub**.

Por lo tanto, podrías hacer que `application.app/Contents/MacOS/Automator\ Application\ Stub` **apunte mediante un enlace simbólico a otro Automator Application Stub dentro del sistema**, y ejecutará lo que haya dentro de `document.wflow` (tu script) **sin activar Gatekeeper**, porque el ejecutable real no tiene el xattr quarantine.<sup>[[6]](#references)</sup>

Ejemplo de ubicación esperada: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta el [**informe original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para obtener más información.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

En este bypass, se creó un archivo zip con una aplicación, empezando la compresión desde `application.app/Contents` en lugar de `application.app`. Por lo tanto, el **atributo quarantine** se aplicó a todos los **archivos de `application.app/Contents`**, pero **no a `application.app`**, que era lo que Gatekeeper comprobaba. Así, se hizo bypass de Gatekeeper porque, al activarse `application.app`, **no tenía el atributo quarantine**.<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Consulta el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para obtener más información.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Aunque los componentes son diferentes, la explotación de esta vulnerabilidad es muy similar a la anterior. En este caso, generaremos un Apple Archive a partir de **`application.app/Contents`**, por lo que **`application.app` no tendrá el atributo quarantine** al descomprimirse con **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Consulta el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para obtener más información.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

La ACL **`writeextattr`** se puede usar para impedir que alguien escriba un atributo en un archivo:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Además, el formato de archivo **AppleDouble** copia un archivo, incluidos sus ACE.<sup>[[9]](#references)</sup>

En el [**código fuente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) se puede ver que la representación textual de la ACL almacenada dentro del xattr llamado **`com.apple.acl.text`** se establecerá como ACL en el archivo descomprimido. Por lo tanto, si comprimiste una aplicación en un archivo zip con el formato de archivo **AppleDouble** y una ACL que impide que se escriban otros xattrs en ella... el xattr de quarantine no se estableció en la aplicación:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obtener más información.<sup>[[9]](#references)</sup> Consulta la [reproducción de AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) para conocer los pasos de construcción y validación del sidecar.

Ten en cuenta que esto también podría explotarse con AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Se descubrió que **Google Chrome no establecía el atributo de cuarentena** en los archivos descargados debido a algunos problemas internos de macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble almacena los atributos de un archivo en un archivo separado cuyo nombre empieza por `._`; esto permite copiar atributos **entre máquinas macOS**. Sin embargo, después de descomprimir un archivo AppleDouble, el archivo que empieza por `._` **no recibía el atributo de cuarentena**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Al poder crear un archivo que no tuviera establecido el atributo de cuarentena, era **posible eludir Gatekeeper**. El truco consistía en **crear un archivo de aplicación DMG** siguiendo la convención de nombres AppleDouble (comenzando con `._`) y crear un **archivo visible como enlace simbólico a este archivo oculto** sin el atributo de cuarentena.\
Cuando se **ejecuta el archivo DMG**, como no tiene el atributo de cuarentena, **eludirá Gatekeeper**.

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

Apple corrigió un error lógico de LaunchServices en macOS Sonoma 14.0 mediante comprobaciones mejoradas. El aviso público solo indica que una app podía eludir Gatekeeper, así que no infieras un formato de archivo portador ni una cadena de explotación específica basándote únicamente en la entrada de CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Un bypass de Gatekeeper en macOS 14.4 (lanzado en marzo de 2024), causado por el manejo de ZIP maliciosos de `libarchive`, permitía a las apps eludir la evaluación. Actualiza a la versión 14.4 o posterior, donde Apple corrigió el problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **workflow de Automator Quick Action** integrado en una app descargada podía activarse sin la evaluación de Gatekeeper, porque los workflows se trataban como datos y los ejecutaba el helper de Automator fuera del flujo habitual del aviso de notarización. Por tanto, un `.app` manipulado que incluyera una Quick Action para ejecutar un script de shell (p. ej., dentro de `Contents/PlugIns/*.workflow/Contents/document.wflow`) podía ejecutarse inmediatamente al iniciarse. Apple añadió un cuadro de diálogo de consentimiento adicional y corrigió el flujo de evaluación en Ventura **13.7**, Sonoma **14.7** y Sequoia **15**.<sup>[[3]](#references)</sup>

### Fallos de propagación de cuarentena en los límites de extracción y copia

Un estudio de 2024 encontró brechas de propagación en las versiones probadas de iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) y 7z Utility (DMG/ZIP/7Z); también observó que el atributo se perdía al copiar desde el host a la máquina virtual con VMware Tools. Desde entonces, varios proveedores anunciaron correcciones, así que considera estos nombres como pistas para **volver a probar versiones específicas**, no como una lista permanente de software vulnerable. El mismo problema de límites de confianza se aplica a los workflows nativos de Unix: `curl`/`scp` no añaden cuarentena, y `tar`/`unzip` de línea de comandos no la heredan automáticamente de un archivo portador.<sup>[[15]](#references)</sup>

Para las pruebas ofensivas, compara el archivo portador y la app final después de **cada** transición entre navegador, cliente de correo, archivador, imagen de disco, sincronización en la nube, carpeta compartida y copia de máquina virtual. Un rechazo explícito de `spctl` no corrige la falta de un xattr: sin cuarentena, puede que el flujo habitual de Gatekeeper en la primera apertura ni siquiera solicite esa evaluación.<sup>[[15]](#references)</sup>

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

### uchg (de esta [charla](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crea un directorio que contenga una app.
- Añade uchg a la app.
- Comprime la app en un archivo tar.gz.
- Envía el archivo tar.gz a una víctima.
- La víctima abre el archivo tar.gz y ejecuta la app.
- Gatekeeper no comprueba la app.<sup>[[12]](#references)</sup>

### Evitar el xattr de cuarentena

Si no se añade el xattr de cuarentena a un bundle ".app", **Gatekeeper no se activará** al ejecutarlo.

Consulta [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) para ver primitivas basadas en filesystem, flags, ACL y AppleDouble que pueden impedir la adición o descartar atributos extendidos.





## References

- [1] [Seguridad de la plataforma Apple: Sobre el contenido de seguridad de macOS Sonoma 14.4 (incluye CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Cómo macOS rastrea ahora la procedencia de las apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Sobre el contenido de seguridad de macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia elimina el bypass de Gatekeeper mediante Control-clic en «Abrir»](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: El descubrimiento de CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, cómo eludir Gatekeeper de macOS](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifica una vulnerabilidad de Safari que permite eludir Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifica una vulnerabilidad de Archive Utility de macOS que permite eludir Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [El talón de Aquiles de Gatekeeper: descubriendo una vulnerabilidad de macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Descubrimiento de un bypass de Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Encontrar y notificar un exploit para eludir Gatekeeper con ayuda de Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Eludir los mecanismos de seguridad y privacidad de macOS: de Gatekeeper a System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Sobre el contenido de seguridad de macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Foros para desarrolladores de Apple: Probar un producto notarizado](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Eludir Gatekeeper: descubriendo debilidades en un mecanismo de seguridad de macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
