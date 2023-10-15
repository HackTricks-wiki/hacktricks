# macOS Entitlements Peligrosos y Permisos de TCC

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

### `com.apple.security.get-task-allow`

Este entitlement permite obtener el puerto de tarea del proceso ejecutado por el binario con este entitlement e **inyectar código en él**. Consulta [**esto para más información**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### **`com.apple.system-task-ports` (anteriormente llamado `task_for_pid-allow`)**

Este entitlement permite obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. Consulta [**esto para más información**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Las aplicaciones con el Entitlement de Herramienta de Depuración pueden llamar a `task_for_pid()` para obtener un puerto de tarea válido para aplicaciones no firmadas y de terceros con el entitlement `Get Task Allow` establecido en `true`. Sin embargo, incluso con el entitlement de herramienta de depuración, un depurador no puede obtener los puertos de tarea de los procesos que no tienen el entitlement `Get Task Allow` y que, por lo tanto, están protegidos por la Protección de Integridad del Sistema. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Este entitlement permite **cargar frameworks, complementos o bibliotecas sin estar firmados por Apple o firmados con el mismo ID de equipo** que el ejecutable principal, por lo que un atacante podría abusar de alguna carga de biblioteca arbitraria para inyectar código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **usar variables de entorno DYLD** que podrían usarse para inyectar bibliotecas y código. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### **`kTCCServiceSystemPolicyAllFiles`**

Otorga permisos de **Acceso Completo al Disco**, uno de los permisos más altos de TCC que se pueden tener.

### **`kTCCServiceAppleEvents`**

Permite que la aplicación envíe eventos a otras aplicaciones que se utilizan comúnmente para **automatizar tareas**. Al controlar otras aplicaciones, puede abusar de los permisos otorgados a estas otras aplicaciones.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario que cambia su carpeta de inicio y, por lo tanto, permite **burlar TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar aplicaciones dentro de sus carpetas (dentro de app.app), lo cual está deshabilitado de forma predeterminada.

## Medio

### `com.apple.security.cs.allow-jit`

Este entitlement permite **crear memoria que es escribible y ejecutable** pasando la bandera `MAP_JIT` a la función del sistema `mmap()`. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este entitlement permite **anular o parchear código C**, usar el obsoleto **`NSCreateObjectFileImageFromMemory`** (que es fundamentalmente inseguro) o usar el framework **DVDPlayback**. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir este entitlement expone tu aplicación a vulnerabilidades comunes en lenguajes de código no seguro en memoria. Considera cuidadosamente si tu aplicación necesita esta excepción.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Este entitlement permite **modificar secciones de sus propios archivos ejecutables** en disco para salir de forma forzada. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
El Entitlement de Desactivación de Protección de Memoria Ejecutable es un entitlement extremo que elimina una protección de seguridad fundamental de tu aplicación, lo que permite que un atacante reescriba el código ejecutable de tu aplicación sin detección. Prefiere entitlements más específicos si es posible.
{% endhint %}
### `com.apple.security.cs.allow-relative-library-loads`

TODO

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
