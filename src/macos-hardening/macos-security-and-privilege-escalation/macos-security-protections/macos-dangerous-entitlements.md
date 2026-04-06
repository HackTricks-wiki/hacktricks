# macOS Entitlements peligrosos y permisos TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Tenga en cuenta que los entitlements que comienzan con **`com.apple`** no están disponibles para terceros; solo Apple puede otorgarlos... O si está usando un certificado empresarial podría crear sus propios entitlements que comiencen con **`com.apple`** y así bypassear protecciones basadas en esto.

## Alto

### `com.apple.rootless.install.heritable`

El entitlement **`com.apple.rootless.install.heritable`** permite **burlar SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

El entitlement **`com.apple.rootless.install`** permite **burlar SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Este entitlement permite obtener el **task port de cualquier** proceso, excepto el kernel. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Este entitlement permite a otros procesos con el **`com.apple.security.cs.debugger`** entitlement obtener el task port del proceso ejecutado por el binario con este entitlement e **inyectar código en él**. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Las apps con el Debugging Tool Entitlement pueden llamar a `task_for_pid()` para recuperar un task port válido de apps sin firmar y de terceros con el entitlement `Get Task Allow` establecido en `true`. Sin embargo, incluso con el debugging tool entitlement, un debugger **no puede obtener los task ports** de procesos que **no tienen el entitlement `Get Task Allow`**, y que por tanto están protegidos por System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Este entitlement permite **cargar frameworks, plug-ins, o librerías sin estar firmados por Apple ni con el mismo Team ID** que el ejecutable principal, por lo que un atacante podría abusar de una carga arbitraria de librería para inyectar código. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Este entitlement es muy similar a **`com.apple.security.cs.disable-library-validation`** pero **en lugar de** **desactivar directamente** la validación de librerías, permite al proceso **llamar al syscall `csops` para desactivarla**.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **usar variables de entorno DYLD** que podrían usarse para inyectar librerías y código. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), estos entitlements permiten **modificar** la base de datos de **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Estos entitlements permiten **instalar software sin pedir permisos** al usuario, lo cual puede ser útil para una **escalada de privilegios**.

### `com.apple.private.security.kext-management`

Entitlement necesario para pedir al **kernel que cargue una kernel extension**.

### **`com.apple.private.icloud-account-access`**

Con el entitlement **`com.apple.private.icloud-account-access`** es posible comunicarse con el servicio XPC **`com.apple.iCloudHelper`**, que **proporcionará iCloud tokens**.

**iMovie** y **Garageband** tenían este entitlement.

Para más **información** sobre el exploit para **obtener tokens de iCloud** desde ese entitlement mira la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: No sé qué permite hacer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: En [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. ¡Si sabes cómo, envía un PR por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: En [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. ¡Si sabes cómo, envía un PR por favor!

### `keychain-access-groups`

Este entitlement lista los grupos de **keychain** a los que la aplicación tiene acceso:
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

Concede permisos de **Full Disk Access**, uno de los permisos más altos de TCC que puedes tener.

### **`kTCCServiceAppleEvents`**

Permite que la app envíe eventos a otras aplicaciones que se usan comúnmente para **automatizar tareas**. Al controlar otras apps, puede abusar de los permisos concedidos a esas otras apps.

Por ejemplo, hacer que pidan al usuario su contraseña:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
O hacer que realicen **acciones arbitrarias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre otros permisos, **escribir la base de datos TCC del usuario**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario, lo que modifica la ruta de su carpeta home y por lo tanto permite **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar archivos dentro del bundle de las apps (dentro de app.app), lo cual **no está permitido por defecto**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es posible comprobar quién tiene este acceso en _Ajustes del Sistema_ > _Privacidad y Seguridad_ > _Gestión de aplicaciones_.

### `kTCCServiceAccessibility`

El proceso podrá **abusar de las funciones de accesibilidad de macOS**, lo que significa que, por ejemplo, podrá simular pulsaciones de teclas. Así, podría solicitar acceso para controlar una app como Finder y aprobar el diálogo con este permiso.

## Trustcache/CDhash related entitlements

Existen algunos entitlements que podrían usarse para bypass las protecciones Trustcache/CDhash, las cuales evitan la ejecución de versiones degradadas de binarios de Apple.

## Medium

### `com.apple.security.cs.allow-jit`

Este entitlement permite **crear memoria que sea escribible y ejecutable** pasando la bandera `MAP_JIT` a la función de sistema `mmap()`. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este entitlement permite **sobrescribir o parchear código C**, usar la ya obsoleta **`NSCreateObjectFileImageFromMemory`** (que es fundamentalmente insegura), o usar el framework **DVDPlayback**. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Incluir este entitlement expone tu app a vulnerabilidades comunes en lenguajes con manejo inseguro de memoria. Considera cuidadosamente si tu app necesita esta excepción.

### `com.apple.security.cs.disable-executable-page-protection`

Este entitlement permite **modificar secciones de sus propios archivos ejecutables** en disco para forzar su terminación. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> El Disable Executable Memory Protection Entitlement es un entitlement extremo que elimina una protección de seguridad fundamental de tu app, haciendo posible que un atacante reescriba el código ejecutable de tu app sin detección. Prefiere entitlements más restrictivos si es posible.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Este entitlement permite montar un sistema de archivos nullfs (prohibido por defecto). Herramienta: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Según esta entrada de blog, este permiso de TCC normalmente se encuentra en la forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permitir que el proceso **solicite todos los permisos TCC**.

### **`kTCCServicePostEvent`**

Permite **inyectar eventos sintéticos de teclado y ratón** en todo el sistema mediante `CGEventPost()`. Un proceso con este permiso puede simular pulsaciones de teclas, clics de ratón y eventos de desplazamiento en cualquier aplicación — proporcionando efectivamente **control remoto** del escritorio.

Esto es especialmente peligroso combinado con `kTCCServiceAccessibility` o `kTCCServiceListenEvent`, ya que permite tanto leer COMO inyectar entradas.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permite **interceptar todos los eventos de teclado y ratón** a nivel del sistema (monitoreo de entrada / keylogging). Un proceso puede registrar un `CGEventTap` para capturar cada pulsación de tecla en cualquier aplicación, incluidas contraseñas, números de tarjeta de crédito y mensajes privados.

Para técnicas de explotación detalladas, vea:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permite **leer el búfer de pantalla** — tomar capturas y grabar vídeo de la pantalla de cualquier aplicación, incluidos campos de texto seguros. Combinado con OCR, esto puede extraer automáticamente contraseñas y datos sensibles de la pantalla.

> [!WARNING]
> A partir de macOS Sonoma, la captura de pantalla muestra un indicador persistente en la barra de menús. En versiones anteriores, la grabación de pantalla puede ser completamente silenciosa.

### **`kTCCServiceCamera`**

Permite **capturar fotos y vídeo** desde la cámara integrada o cámaras USB conectadas. La inyección de código en un binario con permiso de cámara permite vigilancia visual silenciosa.

### **`kTCCServiceMicrophone`**

Permite **grabar audio** de todos los dispositivos de entrada. Demonios en segundo plano con acceso al micrófono proporcionan vigilancia de audio ambiental persistente sin ventana de aplicación visible.

### **`kTCCServiceLocation`**

Permite consultar la **ubicación física** del dispositivo mediante triangulación Wi‑Fi o balizas Bluetooth. El monitoreo continuo revela direcciones de casa/trabajo, patrones de viaje y rutinas diarias.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Acceso a **Contacts** (nombres, emails, teléfonos — útil para spear-phishing), **Calendar** (horarios de reuniones, listas de asistentes) y **Photos** (fotos personales, capturas de pantalla que pueden contener credenciales, metadatos de ubicación).

Para técnicas completas de explotación para robo de credenciales vía permisos TCC, vea:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox y entitlements de firma de código

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Las **excepciones temporales del Sandbox** debilitan el App Sandbox al permitir comunicación con servicios Mach/XPC a nivel del sistema que el sandbox normalmente bloquea. Esta es la **principal primitiva para escapar del sandbox** — una aplicación en sandbox comprometida puede usar excepciones mach-lookup para alcanzar daemons privilegiados y explotar sus interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Para la cadena de explotación detallada: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, ver:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** permiten que los user-space driver binaries se comuniquen directamente con el kernel a través de interfaces IOKit. Los DriverKit binaries gestionan hardware: USB, Thunderbolt, PCIe, HID devices, audio y networking.

Comprometer un DriverKit binary permite:
- **Kernel attack surface** a través de llamadas `IOConnectCallMethod` malformadas
- **USB device spoofing** (emular un teclado para HID injection)
- **DMA attacks** a través de interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Para una explotación detallada de IOKit/DriverKit, consulte:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
