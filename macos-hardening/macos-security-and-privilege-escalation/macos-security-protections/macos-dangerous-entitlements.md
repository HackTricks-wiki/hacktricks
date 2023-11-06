# Entitlements Peligrosos de macOS y Permisos de TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

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

Este entitlement permite obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. Consulta [**esto para más información**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Este entitlement permite a otros procesos con el entitlement **`com.apple.security.cs.debugger`** obtener el puerto de tarea del proceso ejecutado por el binario con este entitlement e **inyectar código en él**. Consulta [**esto para más información**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Las aplicaciones con el Entitlement de Herramienta de Depuración pueden llamar a `task_for_pid()` para obtener un puerto de tarea válido para aplicaciones no firmadas y de terceros con el entitlement `Get Task Allow` establecido en `true`. Sin embargo, incluso con el entitlement de herramienta de depuración, un depurador **no puede obtener los puertos de tarea** de procesos que **no tienen el entitlement `Get Task Allow`**, y que por lo tanto están protegidos por System Integrity Protection. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Este entitlement permite **cargar frameworks, complementos o bibliotecas sin estar firmados por Apple o firmados con el mismo ID de equipo** que el ejecutable principal, por lo que un atacante podría abusar de alguna carga de biblioteca arbitraria para inyectar código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Este entitlement es muy similar a **`com.apple.security.cs.disable-library-validation`** pero en lugar de **desactivar directamente** la validación de la biblioteca, permite que el proceso **llame a una llamada de sistema `csops` para desactivarla**.\
Consulta [**esto para más información**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **usar variables de entorno DYLD** que podrían usarse para inyectar bibliotecas y código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` y `com.apple.rootless.storage`.`TCC`

[**Según este blog**](https://objective-see.org/blog/blog\_0x4C.html), estos entitlements permiten **modificar** la **base de datos TCC**.

### **`system.install.apple-software`** y **`system.install.apple-software.standar-user`**

Estos entitlements permiten **instalar software sin solicitar permisos** al usuario, lo cual puede ser útil para una **escalada de privilegios**.

### `com.apple.private.security.kext-management`

Entitlement necesario para solicitar al **kernel que cargue una extensión de kernel**.

### **`com.apple.private.icloud-account-access`**

El entitlement **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`** que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este entitlement.

Para obtener más **información** sobre la explotación para **obtener tokens de iCloud** a partir de ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)
### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: No sé qué permite hacer esto.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar el contenido protegido por SSV después de un reinicio. Si sabes cómo hacerlo, por favor envía un PR.

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar el contenido protegido por SSV después de un reinicio. Si sabes cómo hacerlo, por favor envía un PR.

### `keychain-access-groups`

Esta lista de permisos **keychain** agrupa los grupos a los que la aplicación tiene acceso:
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

Otorga permisos de **Acceso completo al disco**, uno de los permisos más altos de TCC que se pueden tener.

### **`kTCCServiceAppleEvents`**

Permite que la aplicación envíe eventos a otras aplicaciones que se utilizan comúnmente para **automatizar tareas**. Al controlar otras aplicaciones, puede abusar de los permisos otorgados a estas otras aplicaciones.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario que cambia su carpeta de inicio y, por lo tanto, permite **burlar TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar archivos dentro del paquete de aplicaciones (dentro de app.app), lo cual está **desactivado por defecto**.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

## Medio

### `com.apple.security.cs.allow-jit`

Este permiso permite **crear memoria que se puede escribir y ejecutar** pasando la bandera `MAP_JIT` a la función del sistema `mmap()`. Consulta [**esto para obtener más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este permiso permite **anular o parchear código C**, utilizar el marco de **`NSCreateObjectFileImageFromMemory`** (que es fundamentalmente inseguro) o utilizar el marco **DVDPlayback**. Consulta [**esto para obtener más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir este permiso expone tu aplicación a vulnerabilidades comunes en lenguajes de código no seguro en memoria. Considera cuidadosamente si tu aplicación necesita esta excepción.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Este permiso permite **modificar secciones de sus propios archivos ejecutables** en disco para salir forzosamente. Consulta [**esto para obtener más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
El permiso de Deshabilitar la Protección de Memoria Ejecutable es un permiso extremo que elimina una protección de seguridad fundamental de tu aplicación, lo que permite que un atacante reescriba el código ejecutable de tu aplicación sin ser detectado. Prefiere permisos más específicos si es posible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `kTCCServiceAll`

Según esta publicación de blog, este permiso de TCC generalmente se encuentra en la forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permitir que el proceso **solicite todos los permisos de TCC**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
