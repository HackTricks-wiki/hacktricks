# macOS Dangerous Entitlements & TCC perms

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**artículos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** repositorios de [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>

{% hint style="warning" %}
Ten en cuenta que los entitlements que comienzan con **`com.apple`** no están disponibles para terceros, solo Apple puede otorgarlos.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

El entitlement **`com.apple.rootless.install.heritable`** permite **burlar SIP**. Consulta [esto para más información](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

El entitlement **`com.apple.rootless.install`** permite **burlar SIP**. Consulta [esto para más información](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente llamado `task_for_pid-allow`)**

Este entitlement permite obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. Consulta [**esto para más información**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Este entitlement permite a otros procesos con el entitlement **`com.apple.security.cs.debugger`** obtener el puerto de tarea del proceso ejecutado por el binario con este entitlement e **inyectar código en él**. Consulta [**esto para más información**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Las aplicaciones con el Entitlement de Herramienta de Depuración pueden llamar a `task_for_pid()` para recuperar un puerto de tarea válido para aplicaciones no firmadas y de terceros con el entitlement `Get Task Allow` establecido en `true`. Sin embargo, incluso con el entitlement de herramienta de depuración, un depurador **no puede obtener los puertos de tarea** de procesos que **no tienen el entitlement `Get Task Allow`**, y que por lo tanto están protegidos por la Protección de Integridad del Sistema. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Este entitlement permite **cargar frameworks, complementos o bibliotecas sin estar firmados por Apple o firmados con el mismo ID de equipo** que el ejecutable principal, por lo que un atacante podría abusar de alguna carga de biblioteca arbitraria para inyectar código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Este entitlement es muy similar a **`com.apple.security.cs.disable-library-validation`** pero **en lugar de deshabilitar directamente** la validación de la biblioteca, permite al proceso **llamar a una llamada al sistema `csops` para deshabilitarla**.\
Consulta [**esto para más información**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **utilizar variables de entorno DYLD** que podrían usarse para inyectar bibliotecas y código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Según este blog**](https://objective-see.org/blog/blog\_0x4C.html) **y** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), estos entitlements permiten **modificar** la **base de datos TCC**.

### **`system.install.apple-software`** y **`system.install.apple-software.standar-user`**

Estos entitlements permiten **instalar software sin solicitar permisos** al usuario, lo cual puede ser útil para una **escalada de privilegios**.

### `com.apple.private.security.kext-management`

Entitlement necesario para solicitar al **kernel cargar una extensión de kernel**.

### **`com.apple.private.icloud-account-access`**

Con el entitlement **`com.apple.private.icloud-account-access`** es posible comunicarse con el servicio XPC **`com.apple.iCloudHelper`** que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este entitlement.

Para obtener más **información** sobre la explotación para **obtener tokens de iCloud** de ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

POR HACER: No sé qué permite hacer esto

### `com.apple.private.apfs.revert-to-snapshot`

POR HACER: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. Si sabes cómo hacerlo, ¡envía un PR por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

POR HACER: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. Si sabes cómo hacerlo, ¡envía un PR por favor!

### `keychain-access-groups`

Esta lista de entitlements los grupos de **llaveros** a los que la aplicación tiene acceso:

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

Proporciona permisos de **Acceso completo al disco**, uno de los permisos más altos de TCC que se pueden tener.

### **`kTCCServiceAppleEvents`**

Permite que la aplicación envíe eventos a otras aplicaciones que se utilizan comúnmente para **automatizar tareas**. Al controlar otras aplicaciones, puede abusar de los permisos otorgados a estas otras aplicaciones.

Como hacer que le pidan la contraseña al usuario:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

O haciéndolos realizar **acciones arbitrarias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre otros permisos, **escribir en la base de datos TCC de los usuarios**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario que cambia la ruta de su carpeta de inicio y, por lo tanto, permite **burlar TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar archivos dentro de los paquetes de aplicaciones (dentro de app.app), lo cual está **desactivado por defecto**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Es posible verificar quién tiene este acceso en _Configuración del Sistema_ > _Privacidad y Seguridad_ > _Gestión de Aplicaciones._

### `kTCCServiceAccessibility`

El proceso podrá **abusar de las funciones de accesibilidad de macOS**, lo que significa que, por ejemplo, podrá presionar teclas. Por lo tanto, podría solicitar acceso para controlar una aplicación como Finder y aprobar el diálogo con este permiso.

## Medio

### `com.apple.security.cs.allow-jit`

Este permiso permite **crear memoria que es escribible y ejecutable** pasando la bandera `MAP_JIT` a la función del sistema `mmap()`. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este permiso permite **anular o parchear código C**, usar el **`NSCreateObjectFileImageFromMemory`** (que es fundamentalmente inseguro), o usar el framework **DVDPlayback**. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir este permiso expone tu aplicación a vulnerabilidades comunes en lenguajes de código no seguros en memoria. Considera cuidadosamente si tu aplicación necesita esta excepción.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Este permiso permite **modificar secciones de sus propios archivos ejecutables** en disco para salir de forma forzada. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
El Permiso de Deshabilitar Protección de Páginas Ejecutables es un permiso extremo que elimina una protección de seguridad fundamental de tu aplicación, lo que hace posible que un atacante reescriba el código ejecutable de tu aplicación sin ser detectado. Prefiere permisos más específicos si es posible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Este permiso permite montar un sistema de archivos nullfs (prohibido por defecto). Herramienta: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Según esta publicación de blog, este permiso de TCC generalmente se encuentra en la forma:

```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```

Permitir que el proceso **solicite todos los permisos de TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
