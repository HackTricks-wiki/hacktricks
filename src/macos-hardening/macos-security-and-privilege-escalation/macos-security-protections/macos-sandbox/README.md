# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

MacOS Sandbox (inicialmente llamado Seatbelt) **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se ejecuta la aplicación. Esto ayuda a garantizar que **la aplicación solo accederá a los recursos esperados**.

Cualquier aplicación con el **entitlement** **`com.apple.security.app-sandbox`** se ejecutará dentro del sandbox. Los binarios de **Apple** normalmente se ejecutan dentro de un Sandbox, y todas las aplicaciones de la **App Store tienen ese entitlement**. Por lo tanto, varias aplicaciones se ejecutarán dentro del sandbox.<sup>[[4]](#references)</sup>

Para controlar lo que un proceso puede o no puede hacer, el **Sandbox tiene hooks** en casi cualquier operación que un proceso pueda intentar (incluida la mayoría de las syscalls) mediante **MACF**. Sin embargo, d**ependiendo** de los **entitlements** de la aplicación, el Sandbox puede ser más permisivo con el proceso.

Algunos componentes importantes del Sandbox son:

- La **extensión del kernel** `/System/Library/Extensions/Sandbox.kext`
- El **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Un **daemon** ejecutándose en userland `/usr/libexec/sandboxd`
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
Dentro de cada carpeta de bundle id puedes encontrar el **plist** y el **Data directory** de la App, con una estructura que imita la carpeta Home:
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
> Ten en cuenta que, aunque los symlinks estén ahí para "escapar" del Sandbox y acceder a otras carpetas, la App aún necesita **tener permisos** para acceder a ellas. Estos permisos están dentro del **`.plist`**, en `RedirectablePaths`.

El **`SandboxProfileData`** es el perfil de Sandbox compilado en formato CFData y convertido a B64.
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
> Todo lo creado/modificado por una aplicación en un Sandbox obtendrá el **atributo de cuarentena**. Esto impedirá un espacio de Sandbox al activar Gatekeeper si la aplicación en Sandbox intenta ejecutar algo con **`open`**.

## Perfiles de Sandbox

Los perfiles de Sandbox son archivos de configuración que indican qué estará **permitido/prohibido** en ese **Sandbox**. Utiliza el **Sandbox Profile Language (SBPL)**, que usa el lenguaje de programación [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

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
> Consulta esta [**investigación**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para comprobar más acciones que podrían permitirse o denegarse.**<sup>[[5]](#references)</sup>
>
> Ten en cuenta que, en la versión compilada de un perfil, los nombres de las operaciones se sustituyen por sus entradas en un array conocido por el dylib y el kext, lo que hace que la versión compilada sea más corta y difícil de leer.

Los **servicios del sistema** importantes también se ejecutan dentro de su propio **sandbox** personalizado, como el servicio `mdnsresponder`. Puedes consultar estos **sandbox profiles** personalizados en:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Puedes consultar otros sandbox profiles en [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- En iOS, el platform profile se encuentra dentro del sandbox `.kext`, en `_platform_profile_data`, dentro del binario.

Las aplicaciones de **App Store** utilizan el **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. En este profile puedes comprobar cómo entitlements como **`com.apple.security.network.server`** permiten que un proceso utilice la red.

Después, algunos **servicios daemon de Apple** utilizan distintos profiles ubicados en `/System/Library/Sandbox/Profiles/*.sb` o `/usr/share/sandbox/*.sb`. Estos sandboxes se aplican en la función principal que llama a la API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** es un Sandbox profile llamado platform_profile en `/System/Library/Sandbox/rootless.conf`.

### Ejemplos de Sandbox Profiles

Para iniciar una aplicación con un **sandbox profile específico**, puedes utilizar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> Ten en cuenta que el **software** creado por **Apple** que se ejecuta en **Windows** **no cuenta con precauciones de seguridad adicionales**, como el sandboxing de aplicaciones.

Ejemplos de bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (pueden escribir archivos fuera del sandbox cuyo nombre comienza por `~$`).<sup>[[7]](#references)</sup>

### Trazado de Sandbox

#### Mediante un perfil

Es posible rastrear todas las comprobaciones que realiza el sandbox cada vez que se verifica una acción. Para ello, solo hay que crear el siguiente perfil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Y luego simplemente ejecuta algo usando ese perfil:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
En `/tmp/trace.out` podrás ver cada comprobación de Sandbox realizada cada vez que se llamó (por lo tanto, habrá muchos duplicados).

También es posible hacer trace del Sandbox usando el parámetro **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Mediante la API

La función `sandbox_set_trace_path` exportada por `libsystem_sandbox.dylib` permite especificar un nombre de archivo de trace donde se escribirán las comprobaciones del Sandbox.\
También es posible hacer algo similar llamando a `sandbox_vtrace_enable()` y obteniendo después los logs de error del buffer mediante `sandbox_vtrace_report()`.

### Inspección del Sandbox

`libsandbox.dylib` exporta una función llamada sandbox_inspect_pid que proporciona una lista del estado del Sandbox de un proceso (incluidas las extensiones). Sin embargo, solo los binarios de la plataforma pueden usar esta función.

### Perfiles de Sandbox de MacOS e iOS

MacOS almacena los perfiles de Sandbox del sistema en dos ubicaciones: **/usr/share/sandbox/** y **/System/Library/Sandbox/Profiles**.

Además, si una aplicación de terceros incluye el entitlement _**com.apple.security.app-sandbox**_, el sistema aplica el perfil **/System/Library/Sandbox/Profiles/application.sb** a ese proceso.

En iOS, el perfil predeterminado se llama **container** y no disponemos de la representación de texto SBPL. En memoria, este Sandbox se representa como un árbol binario Allow/Deny para cada permiso del Sandbox.

### SBPL personalizado en aplicaciones de App Store

Podría ser posible que las empresas hagan que sus aplicaciones se ejecuten **con perfiles de Sandbox personalizados** (en lugar de usar el predeterminado). Necesitan usar el entitlement **`com.apple.security.temporary-exception.sbpl`**, que debe ser autorizado por Apple.

Es posible comprobar la definición de este entitlement en **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Esto **evaluará la cadena posterior a este entitlement** como un perfil de Sandbox.

### Compilación y descompilación de un perfil de Sandbox

La herramienta **`sandbox-exec`** utiliza las funciones `sandbox_compile_*` de `libsandbox.dylib`. Las funciones principales exportadas son: `sandbox_compile_file` (espera una ruta de archivo, parámetro `-f`), `sandbox_compile_string` (espera una cadena, parámetro `-p`), `sandbox_compile_name` (espera el nombre de un container, parámetro `-n`), `sandbox_compile_entitlements` (espera un plist de entitlements).

Esta versión revertida y [**open source de la herramienta sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) permite hacer que **`sandbox-exec`** escriba el perfil de Sandbox compilado en un archivo.

Además, para confinar un proceso dentro de un container, podría llamar a `sandbox_spawnattrs_set[container/profilename]` y pasar un container o un perfil preexistente.

## Depuración y bypass de Sandbox

En macOS, a diferencia de iOS, donde los procesos están sandboxed desde el inicio por el kernel, **los procesos deben activar el Sandbox por sí mismos**. Esto significa que, en macOS, un proceso no está restringido por el Sandbox hasta que decide entrar activamente en él, aunque las apps de la App Store siempre están sandboxed.

Los procesos se ejecutan automáticamente dentro de un Sandbox desde userland al iniciarse si tienen el entitlement: `com.apple.security.app-sandbox`. Para obtener una explicación detallada de este proceso, consulta:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Las extensiones permiten otorgar privilegios adicionales a un objeto y se conceden llamando a una de las siguientes funciones:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Las extensiones se almacenan en el segundo slot de etiqueta MACF, accesible desde las credenciales del proceso. El siguiente **`sbtool`** puede acceder a esta información.

Ten en cuenta que las extensiones normalmente son concedidas por procesos autorizados; por ejemplo, `tccd` concederá el token de extensión de `com.apple.tcc.kTCCServicePhotos` cuando un proceso intente acceder a las fotos y se le permita hacerlo en un mensaje XPC. Después, el proceso tendrá que consumir el token de extensión para que este se le añada.\
Ten en cuenta que los tokens de extensión son hexadecimales largos que codifican los permisos concedidos. Sin embargo, no tienen el PID autorizado codificado, lo que significa que cualquier proceso con acceso al token podría ser **consumido por varios procesos**.

Ten en cuenta que las extensiones también están muy relacionadas con los entitlements, por lo que tener ciertos entitlements podría conceder automáticamente determinadas extensiones.

### **Comprobar los privilegios de un PID**

[**Según esto**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), las funciones **`sandbox_check`** (es una `__mac_syscall`) pueden comprobar **si una operación está permitida o no** por el Sandbox en un PID, audit token o ID único determinado.<sup>[[8]](#references)</sup>

La [**herramienta sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (puedes encontrarla [compilada aquí](https://newosxbook.com/articles/hitsb.html)) puede comprobar si un PID puede realizar determinadas acciones:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

También es posible suspender y reanudar el sandbox usando las funciones `sandbox_suspend` y `sandbox_unsuspend` de `libsystem_sandbox.dylib`.

Ten en cuenta que, para llamar a la función de suspensión, se comprueban algunos entitlements para autorizar al caller a invocarla, como:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Esta llamada al sistema (#381) espera un argumento de tipo string en primer lugar, que indicará el módulo que se ejecutará, y después un código en el segundo argumento, que indicará la función que se ejecutará. El tercer argumento dependerá de la función ejecutada.<sup>[[2]](#references)</sup>

La función `___sandbox_ms` envuelve la llamada a `mac_syscall`, indicando `"Sandbox"` en el primer argumento, del mismo modo que `___sandbox_msp` es un wrapper de `mac_set_proc` (#387). A continuación se muestran algunos de los códigos compatibles con `___sandbox_ms`:

- **set_profile (#0)**: Aplica un profile compilado o con nombre a un proceso.
- **platform_policy (#1)**: Aplica comprobaciones de policy específicas de la plataforma (varían entre macOS e iOS).
- **check_sandbox (#2)**: Realiza una comprobación manual de una operación específica del sandbox.
- **note (#3)**: Añade una anotación a un Sandbox.
- **container (#4)**: Asocia una anotación a un sandbox, normalmente para debugging o identificación.
- **extension_issue (#5)**: Genera una nueva extension para un proceso.
- **extension_consume (#6)**: Consume una extension determinada.
- **extension_release (#7)**: Libera la memoria asociada a una extension consumida.
- **extension_update_file (#8)**: Modifica los parámetros de una extension de archivo existente dentro del sandbox.
- **extension_twiddle (#9)**: Ajusta o modifica una extension de archivo existente (por ejemplo, TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspende temporalmente todas las comprobaciones del sandbox (requiere los entitlements adecuados).
- **unsuspend (#11)**: Reanuda todas las comprobaciones del sandbox suspendidas anteriormente.
- **passthrough_access (#12)**: Permite el acceso passthrough directo a un recurso, omitiendo las comprobaciones del sandbox.
- **set_container_path (#13)**: (solo iOS) Establece una ruta de container para un app group o signing ID.
- **container_map (#14)**: (solo iOS) Recupera una ruta de container desde `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Establece metadatos en modo usuario dentro del sandbox.
- **inspect (#16)**: Proporciona información de debugging sobre un proceso en sandbox.
- **dump (#18)**: (macOS 11) Vuelca el profile actual de un sandbox para su análisis.
- **vtrace (#19)**: Traza las operaciones del sandbox para monitorización o debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Desactiva profiles con nombre (por ejemplo, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Realiza varias operaciones `sandbox_check` en una sola llamada.
- **reference_retain_by_audit_token (#28)**: Crea una referencia para un audit token que se utilizará en las comprobaciones del sandbox.
- **reference_release (#29)**: Libera una referencia de audit token retenida anteriormente.
- **rootless_allows_task_for_pid (#30)**: Verifica si `task_for_pid` está permitido (de forma similar a las comprobaciones de `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Aplica un archivo manifest de System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Comprueba el archivo manifest de SIP antes de la ejecución.
- **rootless_protected_volume (#33)**: (macOS) Aplica protecciones de SIP a un disco o partición.
- **rootless_mkdir_protected (#34)**: Aplica protección de SIP/DataVault a un proceso de creación de directorios.

## Sandbox.kext

Ten en cuenta que, en iOS, la extensión del kernel contiene **todos los profiles hardcodeados** dentro del segmento `__TEXT.__const` para evitar que se modifiquen. Las siguientes son algunas funciones interesantes de la extensión del kernel:

- **`hook_policy_init`**: Intercepta `mpo_policy_init` y se llama después de `mac_policy_register`. Realiza la mayoría de las inicializaciones del Sandbox. También inicializa SIP.
- **`hook_policy_initbsd`**: Configura la interfaz sysctl registrando `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` y `security.mac.sandbox.debug_mode` (si se ha iniciado con `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Es llamada por `mac_syscall` con `"Sandbox"` como primer argumento y un código que indica la operación como segundo argumento. Se utiliza un switch para encontrar el código que se ejecutará según el código solicitado.

### MACF Hooks

**`Sandbox.kext`** utiliza más de cien hooks mediante MACF. La mayoría de los hooks simplemente comprobarán algunos casos triviales que permiten realizar la acción; si no, llamarán a **`cred_sb_evalutate`** con las **credentials** de MACF, un número correspondiente a la **operación** que se realizará y un **buffer** para la salida.<sup>[[1]](#references)</sup>

Un buen ejemplo de esto es la función **`_mpo_file_check_mmap`**, que intercepta **`mmap`** y comienza comprobando si la nueva memoria será escribible (y, si no lo es, permite la ejecución); después comprueba si se utiliza para la dyld shared cache y, en ese caso, permite la ejecución; finalmente, llama a **`sb_evaluate_internal`** (o a uno de sus wrappers) para realizar comprobaciones adicionales de autorización.

Además, de entre los cientos de hooks que utiliza Sandbox, hay 3 especialmente interesantes:

- `mpo_proc_check_for`: Aplica el profile si es necesario y si no se había aplicado anteriormente.
- `mpo_vnode_check_exec`: Se llama cuando un proceso carga el binario asociado; después se realiza una comprobación del profile y también una comprobación que prohíbe las ejecuciones SUID/SGID.
- `mpo_cred_label_update_execve`: Se llama cuando se asigna el label. Es la más larga, ya que se llama cuando el binario se ha cargado por completo, pero aún no se ha ejecutado. Realiza acciones como crear el objeto sandbox, asociar la estructura sandbox a las credentials de kauth, eliminar el acceso a los mach ports...

Ten en cuenta que **`_cred_sb_evalutate`** es un wrapper sobre **`sb_evaluate_internal`** y que esta función recibe las credentials proporcionadas y realiza la evaluación mediante la función **`eval`**, que normalmente evalúa el **platform profile**, aplicado por defecto a todos los procesos, y después el **profile específico del proceso**. Ten en cuenta que el platform profile es uno de los componentes principales de **SIP** en macOS.

## Sandboxd

Sandbox también tiene un daemon de usuario en ejecución que expone el servicio XPC Mach `com.apple.sandboxd` y enlaza el puerto especial 14 (`HOST_SEATBELT_PORT`), que la extensión del kernel utiliza para comunicarse con él. Expone algunas funciones mediante MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
