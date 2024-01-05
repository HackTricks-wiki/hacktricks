# macOS Sandbox

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

macOS Sandbox (inicialmente llamado Seatbelt) **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se está ejecutando la app. Esto ayuda a asegurar que **la aplicación solo accederá a los recursos esperados**.

Cualquier app con el **entitlement** **`com.apple.security.app-sandbox`** se ejecutará dentro del sandbox. Los **binarios de Apple** suelen ejecutarse dentro de un Sandbox y para publicar dentro de la **App Store**, **este entitlement es obligatorio**. Por lo tanto, la mayoría de las aplicaciones se ejecutarán dentro del sandbox.

Para controlar lo que un proceso puede o no hacer, el **Sandbox tiene hooks** en todos los **syscalls** a través del kernel. **Dependiendo** de los **entitlements** de la app, el Sandbox **permitirá** ciertas acciones.

Algunos componentes importantes del Sandbox son:

* La **extensión del kernel** `/System/Library/Extensions/Sandbox.kext`
* El **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **daemon** que se ejecuta en userland `/usr/libexec/sandboxd`
* Los **contenedores** `~/Library/Containers`

Dentro de la carpeta de contenedores puedes encontrar **una carpeta para cada app ejecutada en sandbox** con el nombre del bundle id:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Dentro de cada carpeta de id de paquete puedes encontrar el **plist** y el **Directorio de Datos** de la App:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Tenga en cuenta que incluso si los symlinks están ahí para "escapar" del Sandbox y acceder a otras carpetas, la App aún necesita **tener permisos** para acceder a ellos. Estos permisos están dentro del **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Todo lo creado/modificado por una aplicación en Sandbox recibirá el **atributo de cuarentena**. Esto evitará que un espacio de Sandbox active Gatekeeper si la aplicación en Sandbox intenta ejecutar algo con **`open`**.
{% endhint %}

### Perfiles de Sandbox

Los perfiles de Sandbox son archivos de configuración que indican lo que estará **permitido/prohibido** en ese **Sandbox**. Utiliza el **Lenguaje de Perfil de Sandbox (SBPL)**, que emplea el lenguaje de programación [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)). 

Aquí puedes encontrar un ejemplo:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Revisa esta [**investigación**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para verificar más acciones que podrían ser permitidas o denegadas.**
{% endhint %}

Servicios **sistémicos importantes** también se ejecutan dentro de su propio **sandbox** personalizado, como el servicio `mdnsresponder`. Puedes ver estos **perfiles de sandbox** personalizados dentro de:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Otros perfiles de sandbox se pueden verificar en [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Las aplicaciones de **App Store** usan el **perfil** **`/System/Library/Sandbox/Profiles/application.sb`**. Puedes revisar en este perfil cómo los derechos como **`com.apple.security.network.server`** permiten que un proceso utilice la red.

SIP es un perfil de Sandbox llamado platform_profile en /System/Library/Sandbox/rootless.conf

### Ejemplos de Perfiles de Sandbox

Para iniciar una aplicación con un **perfil de sandbox específico** puedes usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
Since there is no content provided between the `{% endcode %}` tags, there is nothing to translate. Please provide the relevant English text that you would like translated into Spanish, and I will be happy to assist you.
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
El contenido proporcionado ya está en formato de código y no contiene texto en inglés que requiera traducción. Por favor, proporciona el texto en inglés que necesitas traducir al español.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
```markdown
{% endcode %}

{% code title="touch3.sb" %}
```
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Tenga en cuenta que el **software autorizado por Apple** que se ejecuta en **Windows** **no tiene precauciones de seguridad adicionales**, como el aislamiento de aplicaciones.
{% endhint %}

Ejemplos de elusiones:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (pueden escribir archivos fuera del aislamiento cuyo nombre comienza con `~$`).

### Perfiles de Aislamiento de MacOS

macOS almacena perfiles de aislamiento del sistema en dos ubicaciones: **/usr/share/sandbox/** y **/System/Library/Sandbox/Profiles**.

Y si una aplicación de terceros lleva el derecho _**com.apple.security.app-sandbox**_, el sistema aplica el perfil **/System/Library/Sandbox/Profiles/application.sb** a ese proceso.

### **Perfil de Aislamiento de iOS**

El perfil predeterminado se llama **container** y no tenemos la representación de texto SBPL. En memoria, este aislamiento se representa como un árbol binario de Permitir/Denegar para cada permiso del aislamiento.

### Depurar y Eludir el Aislamiento

**Los procesos no nacen aislados en macOS: a diferencia de iOS**, donde el aislamiento es aplicado por el kernel antes de que se ejecute la primera instrucción de un programa, en macOS **un proceso debe optar por colocarse dentro del aislamiento.**

Los procesos se aíslan automáticamente desde el espacio de usuario cuando comienzan si tienen el derecho: `com.apple.security.app-sandbox`. Para una explicación detallada de este proceso, consulte:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Verificar Privilegios de PID**

[**Según esto**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), el **`sandbox_check`** (es un `__mac_syscall`), puede verificar **si una operación está permitida o no** por el aislamiento en un cierto PID.

La [**herramienta sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) puede verificar si un PID puede realizar una cierta acción:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### SBPL personalizado en aplicaciones de App Store

Podría ser posible que las empresas hagan que sus aplicaciones se ejecuten **con perfiles de Sandbox personalizados** (en lugar de con el predeterminado). Necesitan usar el derecho **`com.apple.security.temporary-exception.sbpl`** que debe ser autorizado por Apple.

Es posible verificar la definición de este derecho en **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Esto **evaluará la cadena después de este derecho** como un perfil de Sandbox.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
