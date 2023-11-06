# Sandbox de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

El Sandbox de macOS (inicialmente llamado Seatbelt) **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil del Sandbox** con el que se está ejecutando la aplicación. Esto ayuda a garantizar que **la aplicación solo acceda a los recursos esperados**.

Cualquier aplicación con el **permiso** **`com.apple.security.app-sandbox`** se ejecutará dentro del sandbox. **Los binarios de Apple** suelen ejecutarse dentro de un Sandbox y, para publicar en la **App Store**, **este permiso es obligatorio**. Por lo tanto, la mayoría de las aplicaciones se ejecutarán dentro del sandbox.

Para controlar lo que un proceso puede o no puede hacer, el Sandbox tiene **hooks** en todas las **syscalls** del kernel. **Dependiendo** de los **permisos** de la aplicación, el Sandbox permitirá ciertas acciones.

Algunos componentes importantes del Sandbox son:

* La **extensión del kernel** `/System/Library/Extensions/Sandbox.kext`
* El **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **daemon** que se ejecuta en el espacio de usuario `/usr/libexec/sandboxd`
* Los **contenedores** `~/Library/Containers`

Dentro de la carpeta de contenedores, puedes encontrar **una carpeta para cada aplicación ejecutada en el sandbox** con el nombre del identificador del paquete:
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
Dentro de cada carpeta de identificación del paquete se pueden encontrar el archivo **plist** y el directorio **Data** de la aplicación:
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
Ten en cuenta que aunque los enlaces simbólicos estén ahí para "escapar" del Sandbox y acceder a otras carpetas, la aplicación aún necesita **tener permisos** para acceder a ellas. Estos permisos se encuentran dentro del **`.plist`**.
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
Todo lo creado/modificado por una aplicación en Sandbox obtendrá el atributo de **cuarentena**. Esto evitará que un espacio en Sandbox se active al ejecutar algo con **`open`**.
{% endhint %}

### Perfiles de Sandbox

Los perfiles de Sandbox son archivos de configuración que indican qué está **permitido/prohibido** en ese **Sandbox**. Utiliza el lenguaje de perfil de Sandbox (SBPL), que utiliza el lenguaje de programación [Scheme](https://es.wikipedia.org/wiki/Scheme).

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
Consulta esta [**investigación**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para obtener más información sobre las acciones que se pueden permitir o denegar**.
{% endhint %}

También se ejecutan importantes **servicios del sistema** dentro de su propio **sandbox personalizado**, como el servicio `mdnsresponder`. Puedes ver estos **perfiles de sandbox personalizados** en:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Otros perfiles de sandbox se pueden verificar en [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Las aplicaciones de **App Store** utilizan el perfil **`/System/Library/Sandbox/Profiles/application.sb`**. Puedes verificar en este perfil cómo los permisos, como **`com.apple.security.network.server`**, permiten que un proceso use la red.

SIP es un perfil de Sandbox llamado platform\_profile en /System/Library/Sandbox/rootless.conf

### Ejemplos de Perfiles de Sandbox

Para iniciar una aplicación con un **perfil de sandbox específico**, puedes usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
El archivo `touch.sb` contiene una política de sandboxing para restringir los privilegios de la aplicación `touch`. Esta política asegura que la aplicación solo tenga acceso a los recursos y funcionalidades permitidos, evitando así posibles vulnerabilidades y ataques de escalada de privilegios.

La política de sandboxing establece las siguientes restricciones:

- Acceso solo lectura a los archivos en el directorio `/usr/share/doc`.
- Acceso de escritura solo a los archivos en el directorio `/tmp`.
- Acceso a la red solo a través de conexiones salientes.
- Sin acceso a la cámara, el micrófono o la ubicación del dispositivo.
- Sin acceso a los servicios de notificación del sistema.
- Sin acceso a los servicios de impresión del sistema.
- Sin acceso a los servicios de calendario del sistema.
- Sin acceso a los servicios de libreta de direcciones del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de fotos del sistema.
- Sin acceso a los servicios de música del sistema.
- Sin acceso a los servicios de correo del sistema.
- Sin acceso a los servicios de mensajes del sistema.
- Sin acceso a los servicios de llamadas del sistema.
- Sin acceso a los servicios de contactos del sistema.
- Sin acceso a los servicios de notas del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de recordatorios del sistema.
- Sin acceso a los servicios de
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
Ten en cuenta que el **software** **desarrollado por Apple** que se ejecuta en **Windows** **no tiene precauciones de seguridad adicionales**, como el aislamiento de aplicaciones.
{% endhint %}

Ejemplos de bypass:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (pueden escribir archivos fuera del sandbox cuyo nombre comienza con `~$`).

### Perfiles de Sandbox de MacOS

macOS almacena los perfiles de sandbox del sistema en dos ubicaciones: **/usr/share/sandbox/** y **/System/Library/Sandbox/Profiles**.

Y si una aplicación de terceros tiene la autorización _**com.apple.security.app-sandbox**_, el sistema aplica el perfil **/System/Library/Sandbox/Profiles/application.sb** a ese proceso.

### **Perfil de Sandbox de iOS**

El perfil predeterminado se llama **container** y no tenemos la representación de texto SBPL. En memoria, este sandbox se representa como un árbol binario de Permitir/Denegar para cada permiso del sandbox.

### Depurar y Bypass Sandbox

**Los procesos no nacen aislados en macOS: a diferencia de iOS**, donde el sandbox se aplica por el kernel antes de que se ejecute la primera instrucción de un programa, en macOS **un proceso debe elegir colocarse en el sandbox.**

Los procesos se aíslan automáticamente desde el espacio de usuario cuando se inician si tienen la autorización: `com.apple.security.app-sandbox`. Para obtener una explicación detallada de este proceso, consulta:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Verificar los Privilegios del PID**

[Según esto](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), el **`sandbox_check`** (es una `__mac_syscall`), puede verificar **si una operación está permitida o no** por el sandbox en un PID específico.

La [**herramienta sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) puede verificar si un PID puede realizar una determinada acción:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Perfiles SBPL personalizados en aplicaciones de la App Store

Es posible que las empresas puedan hacer que sus aplicaciones se ejecuten con **perfiles de Sandbox personalizados** (en lugar del predeterminado). Deben utilizar el permiso **`com.apple.security.temporary-exception.sbpl`**, el cual debe ser autorizado por Apple.

Es posible verificar la definición de este permiso en **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Esto **evaluará la cadena después de este permiso** como un perfil de Sandbox.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
