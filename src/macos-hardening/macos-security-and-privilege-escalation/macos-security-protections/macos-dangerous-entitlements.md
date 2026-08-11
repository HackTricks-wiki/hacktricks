# Entitlements peligrosos de macOS y permisos de TCC

{{#include ../../../banners/hacktricks-training.md}}

Los entitlements declaran capacidades y excepciones de seguridad que el sistema operativo concede al código firmado. Las entradas siguientes se centran en aquellas que son especialmente útiles durante una revisión ofensiva.<sup>[[13]](#references)</sup>

> [!WARNING]
> Ten en cuenta que los entitlements que comienzan por **`com.apple`** no están disponibles para terceros; solo Apple puede concederlos... O, si utilizas un certificado empresarial, en realidad podrías crear tus propios entitlements que comiencen por **`com.apple`** y evadir las protecciones basadas en esto.

## Alto

### `com.apple.rootless.install.heritable`

El entitlement **`com.apple.rootless.install.heritable`** permite a un proceso **evadir SIP**. Consulta [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

El entitlement **`com.apple.rootless.install`** permite a un proceso **evadir SIP**. Consulta [this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Este entitlement permite a un proceso obtener el **task port de cualquier** proceso excepto del kernel. Consulta [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Este entitlement permite que otros procesos con el entitlement **`com.apple.security.cs.debugger`** obtengan el task port del proceso ejecutado por el binario con este entitlement e **inyecten código en él**. Consulta [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Las aplicaciones con el Debugging Tool Entitlement pueden llamar a `task_for_pid()` para recuperar un task port válido de aplicaciones sin firmar y de terceros que tengan el entitlement `Get Task Allow` establecido en `true`. Sin embargo, incluso con el debugging tool entitlement, un debugger **no puede obtener los task ports** de procesos que **no tienen el entitlement `Get Task Allow`** y que, por tanto, están protegidos por System Integrity Protection. Consulta [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Este entitlement permite a una aplicación **cargar frameworks, plug-ins o librerías sin exigir que estén firmados por Apple o que tengan el mismo Team ID** que el ejecutable principal, por lo que un atacante podría abusar de una carga arbitraria de librerías para inyectar código. Consulta [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Este entitlement es muy similar a **`com.apple.security.cs.disable-library-validation`**, pero **en lugar de deshabilitar directamente** la validación de librerías, permite que el proceso **llame a una system call `csops` para deshabilitarla** durante la ejecución.

El nombre del entitlement está hardcodeado en XNU junto a la operación de `csops` que lo consume:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
El handler del kernel para `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) muestra exactamente lo limitada que es la primitive:<sup>[[2]](#references)</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Por lo tanto, la operación:

- Es **solo para macOS** (`ENOTSUP` en cualquier otra plataforma).
- Solo funciona sobre **sí mismo** (`forself == 1`): no puedes eliminar la validación de bibliotecas de otro proceso con ella.
- Requiere que el proceso realmente **tenga el entitlement**, y se rechaza si el proceso está marcado como `CS_INSTALLER` o se ejecuta bajo una ruta raíz de subsistema.
- Elimina **`CS_REQUIRE_LV | CS_FORCED_LV`** de los flags de firma de código del proceso.

El comentario de XNU explica el caso de uso previsto y también por qué resulta interesante para un atacante:

> Esta opción se utiliza para eliminar la validación de bibliotecas de un proceso en ejecución. Se usa en arquitecturas de plugins cuando un programa necesita cargar bibliotecas no confiables. [...] Una vez que un proceso ha cargado la biblioteca no confiable, confiar en la validación de bibliotecas en el futuro no será efectivo.

En otras palabras, **cualquier binario que contenga este entitlement es un objetivo de dylib-injection**: consigue ejecutar código dentro de él (o convéncelo para que cargue tu plug-in) después de que haya eliminado `CS_REQUIRE_LV`, y heredarás todo lo que el proceso host tenga permitido hacer.

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **usar variables de entorno DYLD** que podrían utilizarse para inyectar bibliotecas y código. Consulta [**esto para obtener más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Según este blog**](https://objective-see.org/blog/blog_0x4C.html) **y** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), estos entitlements permiten a un proceso **modificar** la base de datos de **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### Derechos de autorización **`system.install.apple-software`** y **`system.install.apple-software.standard-user`**

Estos derechos de Authorization Services controlan la instalación de software proporcionado por Apple. Un proceso con entitlement para obtenerlos puede omitir el flujo de autorización habitual, lo que puede ser útil para la **escalada de privilegios**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement necesario para solicitar al **kernel que cargue una extensión del kernel**.

### **`com.apple.private.icloud-account-access`**

El entitlement **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`**, que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este entitlement.

Para obtener más **información** sobre el exploit para **obtener tokens de iCloud** mediante ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: No sé qué permite hacer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) menciona que este entitlement podría utilizarse para actualizar contenido protegido por SSV después de un reinicio. Si sabes cómo hacerlo, ¡envía un PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**El mismo informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) menciona que crear un snapshot sellado podría utilizarse para actualizar contenido protegido por SSV después de un reinicio. Si sabes cómo hacerlo, ¡envía un PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Este entitlement enumera los grupos de **keychain** a los que la aplicación tiene acceso:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Concede permisos de **Full Disk Access**, uno de los permisos más elevados de TCC que se pueden obtener.

### **`kTCCServiceAppleEvents`**

Permite que la aplicación envíe eventos a otras aplicaciones que se utilizan habitualmente para **automatizar tareas**. Al controlar otras aplicaciones, puede abusar de los permisos concedidos a estas.

Por ejemplo, hacer que soliciten al usuario su contraseña:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
O hacer que realicen **acciones arbitrarias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre otros permisos, **escribir la base de datos TCC del usuario**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario, lo que cambia la ruta de su carpeta de inicio y, por lo tanto, permite **bypassear TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar archivos dentro de los bundles de las apps (dentro de app.app), lo cual está **prohibido de forma predeterminada**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es posible comprobar quién tiene este acceso en _Ajustes del Sistema_ > _Privacidad y seguridad_ > _Gestión de apps._

### `kTCCServiceAccessibility`

El proceso podrá **abusar de las funciones de accesibilidad de macOS**, lo que significa, por ejemplo, que podrá pulsar teclas. Por lo tanto, podría solicitar acceso para controlar una app como Finder y aprobar el diálogo con este permiso.

## Entitlements relacionados con Trustcache/CDhash

Hay algunos entitlements que podrían utilizarse para bypass las protecciones de Trustcache/CDhash, que impiden la ejecución de versiones downgraded de binarios de Apple.

## Medio

### `com.apple.security.cs.allow-jit`

Este entitlement permite a un proceso **crear memoria que sea escribible y ejecutable** pasando el flag `MAP_JIT` a la función de sistema `mmap()`. Consulta [**esta página para obtener más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este entitlement permite **sobrescribir o parchear código C**, utilizar el **`NSCreateObjectFileImageFromMemory`** (obsoleto desde hace mucho tiempo y fundamentalmente inseguro) o utilizar el framework **DVDPlayback**. Consulta [**esta página para obtener más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Incluir este entitlement expone tu app a vulnerabilidades comunes en lenguajes de código no seguros para la memoria. Considera cuidadosamente si tu app necesita esta excepción.

### `com.apple.security.cs.disable-executable-page-protection`

Este entitlement permite **modificar secciones de sus propios archivos ejecutables** en el disco para forzar su salida. Consulta [**esta página para obtener más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> El Disable Executable Memory Protection Entitlement es un entitlement extremo que elimina una protección de seguridad fundamental de tu app, haciendo posible que un atacante reescriba el código ejecutable de tu app sin ser detectado. Prefiere entitlements más específicos si es posible.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Este entitlement permite montar un sistema de archivos nullfs (prohibido de forma predeterminada). Herramienta: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Según esta publicación de blog, este permiso TCC normalmente se encuentra en la forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permite que el proceso **solicite todos los permisos de TCC**.

### **`kTCCServicePostEvent`**

Permite **inyectar eventos sintéticos de teclado y ratón** en todo el sistema mediante `CGEventPost()`. Un proceso con este permiso puede simular pulsaciones de teclas, clics del ratón y eventos de desplazamiento en cualquier aplicación, proporcionando efectivamente **control remoto** del escritorio.

Esto es especialmente peligroso combinado con `kTCCServiceAccessibility` o `kTCCServiceListenEvent`, ya que permite tanto leer como inyectar entradas.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permite **interceptar todos los eventos de teclado y ratón** en todo el sistema (input monitoring / keylogging). Un proceso puede registrar un `CGEventTap` para capturar cada pulsación realizada en cualquier aplicación, incluidas contraseñas, números de tarjetas de crédito y mensajes privados.

Para consultar técnicas detalladas de explotación, véase:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permite **leer el búfer de pantalla** — tomar capturas de pantalla y grabar vídeo de cualquier aplicación, incluidos campos de texto seguros. Combinado con OCR, puede extraer automáticamente contraseñas y datos sensibles de la pantalla.

> [!WARNING]
> A partir de macOS Sonoma, la captura de pantalla muestra un indicador persistente en la barra de menús. En versiones anteriores, la grabación de pantalla puede ser completamente silenciosa.

### **`kTCCServiceCamera`**

Permite **capturar fotos y vídeo** desde la cámara integrada o cámaras USB conectadas. La inyección de código en un binario con permisos para la cámara permite realizar vigilancia visual silenciosa.

### **`kTCCServiceMicrophone`**

Permite **grabar audio** desde todos los dispositivos de entrada. Los daemons en segundo plano con acceso al micrófono permiten realizar vigilancia persistente del audio ambiental sin ninguna ventana de aplicación visible.

### **`kTCCServiceLocation`**

Permite consultar la **ubicación física** del dispositivo mediante triangulación Wi-Fi o balizas Bluetooth. La monitorización continua revela direcciones del domicilio y del trabajo, patrones de desplazamiento y rutinas diarias.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Acceso a **Contactos** (nombres, correos electrónicos y teléfonos — útil para spear-phishing), **Calendario** (horarios de reuniones y listas de asistentes) y **Fotos** (fotos personales y capturas de pantalla que pueden contener credenciales y metadatos de ubicación).

Para consultar técnicas completas de explotación para el robo de credenciales mediante permisos de TCC, véase:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements de Sandbox y firma de código

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Las **excepciones temporales del Sandbox** debilitan App Sandbox al permitir la comunicación con servicios Mach/XPC de todo el sistema que el Sandbox bloquea normalmente. Esta es la **principal primitiva de escape del Sandbox** — una aplicación comprometida dentro del Sandbox puede usar excepciones de mach-lookup para acceder a daemons privilegiados y explotar sus interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detailed exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, see:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** permiten que los binarios de controladores en espacio de usuario se comuniquen directamente con el kernel mediante interfaces de IOKit. Los binarios de DriverKit gestionan hardware: USB, Thunderbolt, PCIe, dispositivos HID, audio y redes.

Comprometer un binario de DriverKit permite:
- **Superficie de ataque del kernel** mediante llamadas `IOConnectCallMethod` malformadas
- **Suplantación de dispositivos USB** (emular un teclado para inyección HID)
- **Ataques DMA** mediante interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Para obtener información detallada sobre la explotación de IOKit/DriverKit, consulta:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (operaciones `CS_OPS_*` y `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement de herramienta de depuración (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement para deshabilitar la validación de bibliotecas](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement para permitir variables de entorno DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [La pesadilla de la actualización OTA de Apple: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement para permitir la ejecución de código compilado con JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement para permitir memoria ejecutable sin firma](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement para deshabilitar la protección de memoria ejecutable](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Guía de programación de Authorization Services](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
