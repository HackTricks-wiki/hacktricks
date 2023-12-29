# macOS Permisos Peligrosos y Permisos TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres acceder a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
Ten en cuenta que los permisos que comienzan con **`com.apple`** no están disponibles para terceros, solo Apple puede otorgarlos.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

El permiso **`com.apple.rootless.install.heritable`** permite **evitar SIP**. Consulta [esto para más información](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

El permiso **`com.apple.rootless.install`** permite **evitar SIP**. Consulta [esto para más información](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente llamado `task_for_pid-allow`)**

Este permiso permite obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. Consulta [**esto para más información**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Este permiso permite que otros procesos con el permiso **`com.apple.security.cs.debugger`** obtengan el puerto de tarea del proceso ejecutado por el binario con este permiso e **inyecten código en él**. Consulta [**esto para más información**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Las aplicaciones con el permiso de Herramienta de Depuración pueden llamar a `task_for_pid()` para recuperar un puerto de tarea válido para aplicaciones no firmadas y de terceros con el permiso `Get Task Allow` establecido en `true`. Sin embargo, incluso con el permiso de herramienta de depuración, un depurador **no puede obtener los puertos de tarea** de procesos que **no tienen el permiso `Get Task Allow`**, y que por lo tanto están protegidos por la Protección de Integridad del Sistema. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Este permiso permite **cargar frameworks, plug-ins o bibliotecas sin estar firmados por Apple o con el mismo ID de Equipo** que el ejecutable principal, por lo que un atacante podría abusar de alguna carga de biblioteca arbitraria para inyectar código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Este permiso es muy similar a **`com.apple.security.cs.disable-library-validation`** pero **en lugar** de **deshabilitar directamente** la validación de bibliotecas, permite que el proceso **llame a una llamada al sistema `csops` para desactivarla**.\
Consulta [**esto para más información**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Este permiso permite **usar variables de entorno DYLD** que podrían usarse para inyectar bibliotecas y código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Según este blog**](https://objective-see.org/blog/blog\_0x4C.html) **y** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), estos permisos permiten **modificar** la base de datos **TCC**.

### **`system.install.apple-software`** y **`system.install.apple-software.standar-user`**

Estos permisos permiten **instalar software sin pedir permisos** al usuario, lo cual puede ser útil para una **escalada de privilegios**.

### `com.apple.private.security.kext-management`

Permiso necesario para pedir al **kernel que cargue una extensión de kernel**.

### **`com.apple.private.icloud-account-access`**

Con el permiso **`com.apple.private.icloud-account-access`** es posible comunicarse con el servicio XPC **`com.apple.iCloudHelper`** que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este permiso.

Para más **información** sobre el exploit para **obtener tokens de iCloud** de ese permiso consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: No sé qué permite hacer esto

### `com.apple.private.apfs.revert-to-snapshot`

TODO: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. Si sabes cómo hacerlo, ¡por favor envía un PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. Si sabes cómo hacerlo, ¡por favor envía un PR!

### `keychain-access-groups`

Este permiso lista los grupos de **keychain** a los que la aplicación tiene acceso:
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

Otorga permisos de **Acceso Completo al Disco**, uno de los permisos más altos de TCC que puedes tener.

### **`kTCCServiceAppleEvents`**

Permite que la aplicación envíe eventos a otras aplicaciones que comúnmente se utilizan para **automatizar tareas**. Controlando otras apps, puede abusar de los permisos otorgados a estas otras apps.

Como hacer que le pidan al usuario su contraseña:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

O haciendo que realicen **acciones arbitrarias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre otros permisos, **escribir en la base de datos TCC del usuario**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario que cambia la ruta de su carpeta de inicio y, por lo tanto, permite **evitar TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar archivos dentro del paquete de aplicaciones (dentro de app.app), lo cual está **prohibido por defecto**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Es posible verificar quién tiene este acceso en _Configuración del sistema_ > _Privacidad y seguridad_ > _Gestión de aplicaciones._

### `kTCCServiceAccessibility`

El proceso podrá **abusar de las funciones de accesibilidad de macOS**, lo que significa que, por ejemplo, podrá presionar teclas. Entonces podría solicitar acceso para controlar una aplicación como Finder y aprobar el diálogo con este permiso.

## Medio

### `com.apple.security.cs.allow-jit`

Este permiso permite **crear memoria que es escribible y ejecutable** pasando la bandera `MAP_JIT` a la función del sistema `mmap()`. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este permiso permite **sobrescribir o parchear código C**, usar el obsoleto **`NSCreateObjectFileImageFromMemory`** (que es fundamentalmente inseguro), o usar el marco de trabajo **DVDPlayback**. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir este permiso expone tu aplicación a vulnerabilidades comunes en lenguajes de código inseguros en memoria. Considera cuidadosamente si tu aplicación necesita esta excepción.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Este permiso permite **modificar secciones de sus propios archivos ejecutables** en disco para salir forzosamente. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

{% hint style="danger" %}
El permiso de Desactivación de Protección de Páginas Ejecutables es un permiso extremo que elimina una protección de seguridad fundamental de tu aplicación, lo que permite que un atacante reescriba el código ejecutable de tu aplicación sin detección. Prefiere permisos más específicos si es posible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Este permiso permite montar un sistema de archivos nullfs (prohibido por defecto). Herramienta: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Según este blogpost, este permiso TCC suele encontrarse en la forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permite al proceso **solicitar todos los permisos TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres acceder a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
