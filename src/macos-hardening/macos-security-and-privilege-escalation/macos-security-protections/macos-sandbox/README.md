# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

MacOS Sandbox (inicialmente llamado Seatbelt) **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se está ejecutando la aplicación. Esto ayuda a garantizar que **la aplicación solo accederá a los recursos esperados**.

Cualquier aplicación con la **entitlement** **`com.apple.security.app-sandbox`** se ejecutará dentro del sandbox. **Los binarios de Apple** generalmente se ejecutan dentro de un Sandbox, y todas las aplicaciones de la **App Store tienen esa entitlement**. Por lo tanto, varias aplicaciones se ejecutarán dentro del sandbox.

Para controlar lo que un proceso puede o no hacer, el **Sandbox tiene hooks** en casi cualquier operación que un proceso podría intentar (incluyendo la mayoría de las syscalls) utilizando **MACF**. Sin embargo, **dependiendo** de las **entitlements** de la aplicación, el Sandbox podría ser más permisivo con el proceso.

Algunos componentes importantes del Sandbox son:

- La **extensión del kernel** `/System/Library/Extensions/Sandbox.kext`
- El **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Un **daemon** que se ejecuta en userland `/usr/libexec/sandboxd`
- Los **contenedores** `~/Library/Containers`

### Contenedores

Cada aplicación en sandbox tendrá su propio contenedor en `~/Library/Containers/{CFBundleIdentifier}` :
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
Dentro de cada carpeta de id de paquete, puedes encontrar el **plist** y el **Directorio de Datos** de la aplicación con una estructura que imita la carpeta de inicio:
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
> [!CAUTION]
> Tenga en cuenta que incluso si los symlinks están ahí para "escapar" del Sandbox y acceder a otras carpetas, la App aún necesita **tener permisos** para acceder a ellas. Estos permisos están dentro del **`.plist`** en los `RedirectablePaths`.

El **`SandboxProfileData`** es el perfil de sandbox compilado CFData escapado a B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
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
> [!WARNING]
> Todo lo creado/modificado por una aplicación en Sandbox recibirá el **atributo de cuarentena**. Esto evitará un espacio de sandbox al activar Gatekeeper si la aplicación en sandbox intenta ejecutar algo con **`open`**.

## Perfiles de Sandbox

Los perfiles de Sandbox son archivos de configuración que indican lo que se va a **permitir/prohibir** en ese **Sandbox**. Utiliza el **Lenguaje de Perfiles de Sandbox (SBPL)**, que utiliza el [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) lenguaje de programación.

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
> [!TIP]
> Consulta esta [**investigación**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para ver más acciones que podrían ser permitidas o denegadas.**
>
> Ten en cuenta que en la versión compilada de un perfil, el nombre de las operaciones es sustituido por sus entradas en un array conocido por el dylib y el kext, haciendo que la versión compilada sea más corta y más difícil de leer.

Los **servicios del sistema** importantes también se ejecutan dentro de su propio **sandbox** personalizado, como el servicio `mdnsresponder`. Puedes ver estos **perfiles de sandbox** personalizados en:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Otros perfiles de sandbox se pueden consultar en [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Las aplicaciones de la **App Store** utilizan el **perfil** **`/System/Library/Sandbox/Profiles/application.sb`**. Puedes verificar en este perfil cómo los derechos como **`com.apple.security.network.server`** permiten a un proceso utilizar la red.

Luego, algunos **servicios de demonios de Apple** utilizan diferentes perfiles ubicados en `/System/Library/Sandbox/Profiles/*.sb` o `/usr/share/sandbox/*.sb`. Estos sandboxes se aplican en la función principal que llama a la API `sandbox_init_XXX`.

**SIP** es un perfil de Sandbox llamado platform_profile en `/System/Library/Sandbox/rootless.conf`.

### Ejemplos de Perfiles de Sandbox

Para iniciar una aplicación con un **perfil de sandbox específico**, puedes usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

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

```scheme:touch2.sb
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

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> Tenga en cuenta que el **software** **autorizado por Apple** que se ejecuta en **Windows** **no tiene precauciones de seguridad adicionales**, como el sandboxing de aplicaciones.

Ejemplos de bypass:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (pueden escribir archivos fuera del sandbox cuyo nombre comienza con `~$`).

### Trazado de Sandbox

#### A través del perfil

Es posible rastrear todas las verificaciones que realiza el sandbox cada vez que se verifica una acción. Para ello, solo crea el siguiente perfil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Y luego simplemente ejecuta algo usando ese perfil:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
En `/tmp/trace.out` podrás ver cada verificación de sandbox realizada cada vez que se llamó (por lo que hay muchas duplicaciones).

También es posible rastrear el sandbox usando el **`-t`** parámetro: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### A través de API

La función `sandbox_set_trace_path` exportada por `libsystem_sandbox.dylib` permite especificar un nombre de archivo de rastreo donde se escribirán las verificaciones de sandbox.\
También es posible hacer algo similar llamando a `sandbox_vtrace_enable()` y luego obteniendo los registros de error del búfer llamando a `sandbox_vtrace_report()`.

### Inspección de Sandbox

`libsandbox.dylib` exporta una función llamada sandbox_inspect_pid que proporciona una lista del estado del sandbox de un proceso (incluidas las extensiones). Sin embargo, solo los binarios de la plataforma pueden usar esta función.

### Perfiles de Sandbox en MacOS e iOS

MacOS almacena los perfiles de sandbox del sistema en dos ubicaciones: **/usr/share/sandbox/** y **/System/Library/Sandbox/Profiles**.

Y si una aplicación de terceros tiene el _**com.apple.security.app-sandbox**_ derecho, el sistema aplica el perfil **/System/Library/Sandbox/Profiles/application.sb** a ese proceso.

En iOS, el perfil predeterminado se llama **container** y no tenemos la representación de texto SBPL. En memoria, este sandbox se representa como un árbol binario de Permitir/Denegar para cada permiso del sandbox.

### SBPL personalizado en aplicaciones de la App Store

Podría ser posible que las empresas hicieran que sus aplicaciones funcionaran **con perfiles de Sandbox personalizados** (en lugar de con el predeterminado). Necesitan usar el derecho **`com.apple.security.temporary-exception.sbpl`** que debe ser autorizado por Apple.

Es posible verificar la definición de este derecho en **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Esto **evalúa la cadena después de este derecho** como un perfil de Sandbox.

### Compilación y descompilación de un perfil de Sandbox

La herramienta **`sandbox-exec`** utiliza las funciones `sandbox_compile_*` de `libsandbox.dylib`. Las funciones principales exportadas son: `sandbox_compile_file` (espera una ruta de archivo, parámetro `-f`), `sandbox_compile_string` (espera una cadena, parámetro `-p`), `sandbox_compile_name` (espera un nombre de contenedor, parámetro `-n`), `sandbox_compile_entitlements` (espera un plist de derechos).

Esta versión revertida y [**de código abierto de la herramienta sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) permite que **`sandbox-exec`** escriba en un archivo el perfil de sandbox compilado.

Además, para confinar un proceso dentro de un contenedor, puede llamar a `sandbox_spawnattrs_set[container/profilename]` y pasar un contenedor o perfil preexistente.

## Depurar y eludir el Sandbox

En macOS, a diferencia de iOS donde los procesos están en sandbox desde el inicio por el kernel, **los procesos deben optar por el sandbox ellos mismos**. Esto significa que en macOS, un proceso no está restringido por el sandbox hasta que decide activamente entrar en él, aunque las aplicaciones de la App Store siempre están en sandbox.

Los procesos se en sandbox automáticamente desde el userland cuando comienzan si tienen el derecho: `com.apple.security.app-sandbox`. Para una explicación detallada de este proceso, consulta:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Extensiones de Sandbox**

Las extensiones permiten otorgar privilegios adicionales a un objeto y se otorgan llamando a una de las funciones:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Las extensiones se almacenan en la segunda ranura de etiqueta MACF accesible desde las credenciales del proceso. La siguiente **`sbtool`** puede acceder a esta información.

Ten en cuenta que las extensiones generalmente son otorgadas por procesos permitidos, por ejemplo, `tccd` otorgará el token de extensión de `com.apple.tcc.kTCCServicePhotos` cuando un proceso intente acceder a las fotos y se le permita en un mensaje XPC. Luego, el proceso necesitará consumir el token de extensión para que se le agregue.\
Ten en cuenta que los tokens de extensión son largos hexadecimales que codifican los permisos otorgados. Sin embargo, no tienen el PID permitido codificado, lo que significa que cualquier proceso con acceso al token podría ser **consumido por múltiples procesos**.

Ten en cuenta que las extensiones están muy relacionadas con los derechos también, por lo que tener ciertos derechos podría otorgar automáticamente ciertas extensiones.

### **Verificar privilegios de PID**

[**Según esto**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), las funciones **`sandbox_check`** (es un `__mac_syscall`), pueden verificar **si una operación está permitida o no** por el sandbox en un cierto PID, token de auditoría o ID único.

La [**herramienta sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (encuéntrala [compilada aquí](https://newosxbook.com/articles/hitsb.html)) puede verificar si un PID puede realizar ciertas acciones:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

También es posible suspender y reanudar el sandbox utilizando las funciones `sandbox_suspend` y `sandbox_unsuspend` de `libsystem_sandbox.dylib`.

Tenga en cuenta que para llamar a la función de suspensión se verifican algunos derechos para autorizar al llamador a invocarla, como:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Esta llamada al sistema (#381) espera un primer argumento de tipo cadena que indicará el módulo a ejecutar, y luego un código en el segundo argumento que indicará la función a ejecutar. Luego, el tercer argumento dependerá de la función ejecutada.

La llamada a la función `___sandbox_ms` envuelve `mac_syscall` indicando en el primer argumento `"Sandbox"`, así como `___sandbox_msp` es un envoltorio de `mac_set_proc` (#387). Luego, algunos de los códigos soportados por `___sandbox_ms` se pueden encontrar en esta tabla:

- **set_profile (#0)**: Aplica un perfil compilado o nombrado a un proceso.
- **platform_policy (#1)**: Impone verificaciones de políticas específicas de la plataforma (varía entre macOS y iOS).
- **check_sandbox (#2)**: Realiza una verificación manual de una operación específica del sandbox.
- **note (#3)**: Agrega una anotación a un Sandbox.
- **container (#4)**: Adjunta una anotación a un sandbox, típicamente para depuración o identificación.
- **extension_issue (#5)**: Genera una nueva extensión para un proceso.
- **extension_consume (#6)**: Consume una extensión dada.
- **extension_release (#7)**: Libera la memoria vinculada a una extensión consumida.
- **extension_update_file (#8)**: Modifica los parámetros de una extensión de archivo existente dentro del sandbox.
- **extension_twiddle (#9)**: Ajusta o modifica una extensión de archivo existente (por ejemplo, TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspende temporalmente todas las verificaciones del sandbox (requiere derechos apropiados).
- **unsuspend (#11)**: Reanuda todas las verificaciones del sandbox que fueron suspendidas previamente.
- **passthrough_access (#12)**: Permite el acceso directo a un recurso, eludiendo las verificaciones del sandbox.
- **set_container_path (#13)**: (solo iOS) Establece una ruta de contenedor para un grupo de aplicaciones o ID de firma.
- **container_map (#14)**: (solo iOS) Recupera una ruta de contenedor de `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Establece metadatos de modo usuario en el sandbox.
- **inspect (#16)**: Proporciona información de depuración sobre un proceso en sandbox.
- **dump (#18)**: (macOS 11) Volcar el perfil actual de un sandbox para análisis.
- **vtrace (#19)**: Rastrear operaciones del sandbox para monitoreo o depuración.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Desactiva perfiles nombrados (por ejemplo, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Realiza múltiples operaciones `sandbox_check` en una sola llamada.
- **reference_retain_by_audit_token (#28)**: Crea una referencia para un token de auditoría para su uso en verificaciones del sandbox.
- **reference_release (#29)**: Libera una referencia de token de auditoría previamente retenida.
- **rootless_allows_task_for_pid (#30)**: Verifica si `task_for_pid` está permitido (similar a las verificaciones `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Aplica un archivo de manifiesto de Protección de Integridad del Sistema (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Verifica el archivo de manifiesto SIP antes de la ejecución.
- **rootless_protected_volume (#33)**: (macOS) Aplica protecciones SIP a un disco o partición.
- **rootless_mkdir_protected (#34)**: Aplica protección SIP/DataVault a un proceso de creación de directorio.

## Sandbox.kext

Tenga en cuenta que en iOS la extensión del kernel contiene **todos los perfiles codificados** dentro del segmento `__TEXT.__const` para evitar que sean modificados. Las siguientes son algunas funciones interesantes de la extensión del kernel:

- **`hook_policy_init`**: Engancha `mpo_policy_init` y se llama después de `mac_policy_register`. Realiza la mayoría de las inicializaciones del Sandbox. También inicializa SIP.
- **`hook_policy_initbsd`**: Configura la interfaz sysctl registrando `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` y `security.mac.sandbox.debug_mode` (si se inicia con `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Se llama desde `mac_syscall` con "Sandbox" como primer argumento y un código que indica la operación en el segundo. Se utiliza un switch para encontrar el código a ejecutar según el código solicitado.

### MACF Hooks

**`Sandbox.kext`** utiliza más de un centenar de hooks a través de MACF. La mayoría de los hooks solo verificarán algunos casos triviales que permiten realizar la acción; si no, llamarán a **`cred_sb_evalutate`** con las **credenciales** de MACF y un número correspondiente a la **operación** a realizar y un **buffer** para la salida.

Un buen ejemplo de esto es la función **`_mpo_file_check_mmap`** que engancha **`mmap`** y que comenzará a verificar si la nueva memoria va a ser escribible (y si no, permitirá la ejecución), luego verificará si se utiliza para la caché compartida de dyld y, si es así, permitirá la ejecución, y finalmente llamará a **`sb_evaluate_internal`** (o uno de sus envoltorios) para realizar más verificaciones de autorización.

Además, de los cientos de hooks que utiliza Sandbox, hay 3 en particular que son muy interesantes:

- `mpo_proc_check_for`: Aplica el perfil si es necesario y si no se había aplicado previamente.
- `mpo_vnode_check_exec`: Se llama cuando un proceso carga el binario asociado, luego se realiza una verificación de perfil y también una verificación que prohíbe ejecuciones SUID/SGID.
- `mpo_cred_label_update_execve`: Se llama cuando se asigna la etiqueta. Este es el más largo, ya que se llama cuando el binario está completamente cargado pero aún no se ha ejecutado. Realizará acciones como crear el objeto sandbox, adjuntar la estructura del sandbox a las credenciales de kauth, eliminar el acceso a los puertos mach...

Tenga en cuenta que **`_cred_sb_evalutate`** es un envoltorio sobre **`sb_evaluate_internal`** y esta función obtiene las credenciales pasadas y luego realiza la evaluación utilizando la función **`eval`** que generalmente evalúa el **perfil de plataforma** que se aplica por defecto a todos los procesos y luego el **perfil de proceso específico**. Tenga en cuenta que el perfil de plataforma es uno de los componentes principales de **SIP** en macOS.

## Sandboxd

Sandbox también tiene un daemon de usuario en ejecución que expone el servicio XPC Mach `com.apple.sandboxd` y vincula el puerto especial 14 (`HOST_SEATBELT_PORT`) que la extensión del kernel utiliza para comunicarse con él. Expone algunas funciones utilizando MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
