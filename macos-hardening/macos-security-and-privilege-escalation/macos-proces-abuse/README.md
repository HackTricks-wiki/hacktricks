# Abuso de Procesos en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abuso de Procesos en macOS

macOS, al igual que cualquier otro sistema operativo, proporciona una variedad de métodos y mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Si bien estas técnicas son esenciales para el funcionamiento eficiente del sistema, también pueden ser abusadas por actores malintencionados para **realizar actividades maliciosas**.

### Inyección de Bibliotecas

La inyección de bibliotecas es una técnica en la que un atacante **obliga a un proceso a cargar una biblioteca maliciosa**. Una vez inyectada, la biblioteca se ejecuta en el contexto del proceso objetivo, proporcionando al atacante los mismos permisos y acceso que el proceso.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Enganche de Funciones

El enganche de funciones implica **interceptar llamadas a funciones** o mensajes dentro de un código de software. Al enganchar funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos sensibles e incluso obtener control sobre el flujo de ejecución.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Comunicación entre Procesos

La Comunicación entre Procesos (IPC, por sus siglas en inglés) se refiere a diferentes métodos mediante los cuales los procesos separados **comparten e intercambian datos**. Si bien el IPC es fundamental para muchas aplicaciones legítimas, también puede ser utilizado de manera incorrecta para subvertir el aislamiento de procesos, filtrar información sensible o realizar acciones no autorizadas.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Inyección en Aplicaciones Electron

Las aplicaciones Electron ejecutadas con variables de entorno específicas pueden ser vulnerables a la inyección de procesos:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### NIB Sucio

Los archivos NIB **definen elementos de interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios** y **Gatekeeper no impide** que una aplicación ya ejecutada se vuelva a ejecutar si se modifica un archivo NIB. Por lo tanto, podrían utilizarse para hacer que programas arbitrarios ejecuten comandos arbitrarios:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Inyección en Aplicaciones .Net

Es posible inyectar código en aplicaciones .Net **abusando de la funcionalidad de depuración de .Net** (no protegida por las protecciones de macOS como el endurecimiento en tiempo de ejecución).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Inyección en Python

Si se establece la variable de entorno **`PYTHONINSPECT`**, el proceso de Python pasará a una interfaz de línea de comandos de Python una vez que haya terminado.

Otras variables de entorno como **`PYTHONPATH`** y **`PYTHONHOME`** también podrían ser útiles para hacer que un comando de Python ejecute código arbitrario.

Tenga en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizarán estas variables de entorno incluso si se ejecutan utilizando un Python incrustado.

## Detección

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) es una aplicación de código abierto que puede **detectar y bloquear acciones de inyección de procesos**:

* Usando **Variables de Entorno**: Monitorizará la presencia de cualquiera de las siguientes variables de entorno: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** y **`ELECTRON_RUN_AS_NODE`**
* Usando llamadas a **`task_for_pid`**: Para encontrar cuando un proceso quiere obtener el **puerto de tarea de otro**, lo que permite inyectar código en el proceso.
* **Parámetros de aplicaciones Electron**: Alguien puede usar los argumentos de línea de comandos **`--inspect`**, **`--inspect-brk`** y **`--remote-debugging-port`** para iniciar una aplicación Electron en modo de depuración y, por lo tanto, inyectar código en ella.
* Usando **enlaces simbólicos** o **enlaces duros**: Típicamente, el abuso más común es **colocar un enlace con nuestros privilegios de usuario** y **apuntarlo a una ubicación de mayor privilegio**. La detección es muy sencilla tanto para enlaces duros como para enlaces simbólicos. Si el proceso que crea el enlace tiene un **nivel de privilegio diferente** al del archivo de destino, creamos una **alerta**. Desafortunadamente, en el caso de los enlaces simbólicos, no es posible bloquearlos, ya que no tenemos información sobre el destino del enlace antes de su creación. Esta es una limitación del framework EndpointSecurity de Apple.
### Llamadas realizadas por otros procesos

En [**esta publicación de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo es posible utilizar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y luego obtener información sobre ese otro proceso.

Ten en cuenta que para llamar a esa función debes tener **el mismo uid** que el que ejecuta el proceso o ser **root** (y devuelve información sobre el proceso, no una forma de inyectar código).

## Referencias

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
