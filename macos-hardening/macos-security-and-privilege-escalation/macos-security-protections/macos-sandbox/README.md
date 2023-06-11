# Sandbox de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

El Sandbox de macOS (inicialmente llamado Seatbelt) **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se está ejecutando la aplicación. Esto ayuda a garantizar que **la aplicación solo acceda a los recursos esperados**.

Cualquier aplicación con la **autorización** **`com.apple.security.app-sandbox`** se ejecutará dentro del sandbox. Los binarios de **Apple** suelen ejecutarse dentro de un Sandbox y para publicar en la **App Store**, **esta autorización es obligatoria**. Por lo tanto, la mayoría de las aplicaciones se ejecutarán dentro del sandbox.

Para controlar lo que un proceso puede o no hacer, el **Sandbox tiene hooks** en todas las **syscalls** en todo el kernel. **Dependiendo** de las **autorizaciones** de la aplicación, el Sandbox permitirá ciertas acciones.

Algunos componentes importantes del Sandbox son:

* La **extensión del kernel** `/System/Library/Extensions/Sandbox.kext`
* El **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **daemon** que se ejecuta en userland `/usr/libexec/sandboxd`
* Los **contenedores** `~/Library/Containers`

Dentro de la carpeta de contenedores se puede encontrar **una carpeta para cada aplicación ejecutada en el sandbox** con el nombre del identificador del paquete:
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
Dentro de cada carpeta de identificación de paquete se puede encontrar el archivo **plist** y el directorio **Data** de la aplicación:
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
Tenga en cuenta que aunque los enlaces simbólicos estén ahí para "escapar" del Sandbox y acceder a otras carpetas, la aplicación aún necesita **tener permisos** para acceder a ellas. Estos permisos están dentro del **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# In this file you can find the entitlements:
<key>Entitlements</key>
	<dict>
		<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
		<true/>
		<key>com.apple.accounts.appleaccount.fullaccess</key>
		<true/>
		<key>com.apple.appattest.spi</key>
		<true/>
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
[...]
```
### Perfiles de Sandbox

Los perfiles de Sandbox son archivos de configuración que indican lo que está **permitido/prohibido** en esa **Sandbox**. Utiliza el **Lenguaje de Perfil de Sandbox (SBPL)**, que utiliza el lenguaje de programación [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

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
Revisa esta [**investigación**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para ver más acciones que se pueden permitir o denegar.**
{% endhint %}

También se ejecutan **servicios del sistema importantes** dentro de su propio **sandbox personalizado**, como el servicio `mdnsresponder`. Puedes ver estos **perfiles de sandbox personalizados** en:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Otros perfiles de sandbox se pueden revisar en [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Las aplicaciones de **App Store** usan el **perfil** **`/System/Library/Sandbox/Profiles/application.sb`**. Puedes revisar en este perfil cómo los permisos, como **`com.apple.security.network.server`**, permiten que un proceso use la red.

SIP es un perfil de Sandbox llamado platform\_profile en /System/Library/Sandbox/rootless.conf

### Ejemplos de perfiles de Sandbox

Para iniciar una aplicación con un **perfil de sandbox específico**, puedes usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}
# Sandboxed touch utility

(version 1)

(deny default)

(import "system.sb")

;; Allow reading and writing to the file specified as an argument
(allow file-write-data file-read-data
    (literal "/path/to/file"))

;; Allow reading and writing to the user's Downloads directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Downloads")))

;; Allow reading and writing to the user's Desktop directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Desktop")))

;; Allow reading and writing to the user's Documents directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Documents")))

;; Allow reading and writing to the user's Music directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Music")))

;; Allow reading and writing to the user's Pictures directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Pictures")))

;; Allow reading and writing to the user's Movies directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Movies")))

;; Allow reading and writing to the user's Public directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Public")))

;; Allow reading and writing to the user's Sites directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Sites")))

;; Allow reading and writing to the user's Applications directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Applications")))

;; Allow reading and writing to the user's Library directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library")))

;; Allow reading and writing to the user's Movies directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Movies")))

;; Allow reading and writing to the user's Music directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Music")))

;; Allow reading and writing to the user's Pictures directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Pictures")))

;; Allow reading and writing to the user's Public directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Public")))

;; Allow reading and writing to the user's Sites directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Sites")))

;; Allow reading and writing to the user's Applications directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Applications")))

;; Allow reading and writing to the user's Library directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library")))

;; Allow reading and writing to the user's tmp directory
(allow file-write-data file-read-data
    (subpath (home-subpath "tmp")))

;; Allow reading and writing to the user's var directory
(allow file-write-data file-read-data
    (subpath (home-subpath "var")))

;; Allow reading and writing to the user's opt directory
(allow file-write-data file-read-data
    (subpath (home-subpath "opt")))

;; Allow reading and writing to the user's bin directory
(allow file-write-data file-read-data
    (subpath (home-subpath "bin")))

;; Allow reading and writing to the user's sbin directory
(allow file-write-data file-read-data
    (subpath (home-subpath "sbin")))

;; Allow reading and writing to the user's etc directory
(allow file-write-data file-read-data
    (subpath (home-subpath "etc")))

;; Allow reading and writing to the user's dev directory
(allow file-write-data file-read-data
    (subpath (home-subpath "dev")))

;; Allow reading and writing to the user's private directory
(allow file-write-data file-read-data
    (subpath (home-subpath "private")))

;; Allow reading and writing to the user's usr directory
(allow file-write-data file-read-data
    (subpath (home-subpath "usr")))

;; Allow reading and writing to the user's System directory
(allow file-write-data file-read-data
    (subpath (home-subpath "System")))

;; Allow reading and writing to the user's Volumes directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Volumes")))

;; Allow reading and writing to the user's Network directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Network")))

;; Allow reading and writing to the user's CoreServices directory
(allow file-write-data file-read-data
    (subpath (home-subpath "CoreServices")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Documents")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Documents")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Pictures")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Pictures")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Music")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Music")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Downloads")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Downloads")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Desktop")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Desktop")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Public")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Public")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Sites")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Sites")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Applications")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Applications")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Library")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Library")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/tmp")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/tmp")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/var")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/var")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/opt")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/opt")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/bin")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/bin")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/sbin")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/sbin")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/etc")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/etc")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/dev")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/dev")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/private")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/private")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/usr")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/usr")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/System")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/System")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Volumes")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Volumes")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/Network")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/Network")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/com~apple~CloudDocs/CoreServices")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library/Mobile Documents/iCloud~com~apple~CloudDocs/CoreServices")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Downloads")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Desktop")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Documents")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Music")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Pictures")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Movies")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Public")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Sites")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Applications")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Library")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "tmp")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "var")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "opt")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "bin")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "sbin")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "etc")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "dev")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "private")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "usr")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "System")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Volumes")))

;; Allow reading and writing to the user's iCloud Drive directory
(allow file-write-data file-read-data
    (subpath (home-subpath "Network")))

;; Allow reading and writing to the user
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
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
{% code title="touch2.sb" %}
```
(version 1)
(deny default)
(allow file-write*
    (regex #"^/Users/[^/]+/Desktop/[^/]+\.txt$")
    (regex #"^/Users/[^/]+/Documents/[^/]+\.txt$"))
```
{% endcode %}
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
{% code title="touch3.sb" %}
El archivo touch3.sb es un archivo de política de sandbox que restringe el acceso a ciertos recursos del sistema para la aplicación Touch. En particular, la política restringe el acceso a los archivos en el directorio /etc y /usr/local/bin, así como a los sockets de red. La política también restringe la capacidad de la aplicación para crear nuevos procesos y para leer y escribir en archivos fuera de su directorio de inicio. Al restringir el acceso a estos recursos, la política ayuda a prevenir que la aplicación Touch realice acciones maliciosas o no autorizadas en el sistema.
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
Ten en cuenta que el **software** de **Apple** que se ejecuta en **Windows** **no tiene precauciones de seguridad adicionales**, como el aislamiento de aplicaciones.
{% endhint %}

Ejemplos de bypass:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (pueden escribir archivos fuera del sandbox cuyo nombre comienza con `~$`).

### Depuración y bypass de Sandbox

**Los procesos no nacen aislados en macOS: a diferencia de iOS**, donde el aislamiento se aplica por el kernel antes de que se ejecute la primera instrucción de un programa, en macOS **un proceso debe elegir colocarse en el sandbox.**

Los procesos se aíslan automáticamente desde el espacio de usuario cuando se inician si tienen la concesión: `com.apple.security.app-sandbox`. Para obtener una explicación detallada de este proceso, consulte:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Comprobar los privilegios de PID**

[Según esto](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (es un `__mac_syscall`), puede comprobar **si una operación está permitida o no** por el sandbox en un PID determinado.

La [**herramienta sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) puede comprobar si un PID puede realizar una determinada acción:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### SBPL personalizado en aplicaciones de la App Store

Es posible que las empresas hagan que sus aplicaciones se ejecuten con **perfiles de Sandbox personalizados** (en lugar del predeterminado). Para ello, deben utilizar el permiso **`com.apple.security.temporary-exception.sbpl`**, el cual debe ser autorizado por Apple.

Es posible verificar la definición de este permiso en **`/System/Library/Sandbox/Profiles/application.sb:`**.
```scheme
(sandbox-array-entitlement
  "com.apple.security.temporary-exception.sbpl"
  (lambda (string)
    (let* ((port (open-input-string string)) (sbpl (read port)))
      (with-transparent-redirection (eval sbpl)))))
```
Esto **evaluará la cadena después de esta autorización** como un perfil de Sandbox.
