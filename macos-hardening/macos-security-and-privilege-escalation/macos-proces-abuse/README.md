# Abuso de Procesos en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abuso de Procesos en MacOS

MacOS, como cualquier otro sistema operativo, ofrece una variedad de métodos y mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Aunque estas técnicas son esenciales para el funcionamiento eficiente del sistema, también pueden ser abusadas por actores de amenazas para **realizar actividades maliciosas**.

### Inyección de Bibliotecas

La Inyección de Bibliotecas es una técnica en la que un atacante **fuerza a un proceso a cargar una biblioteca maliciosa**. Una vez inyectada, la biblioteca se ejecuta en el contexto del proceso objetivo, proporcionando al atacante los mismos permisos y acceso que el proceso.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Gancho de Funciones

El Gancho de Funciones implica **interceptar llamadas a funciones** o mensajes dentro de un código de software. Al enganchar funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos sensibles o incluso tomar control sobre el flujo de ejecución.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Comunicación Entre Procesos

La Comunicación Entre Procesos (IPC) se refiere a diferentes métodos por los cuales procesos separados **comparten e intercambian datos**. Aunque el IPC es fundamental para muchas aplicaciones legítimas, también puede ser mal utilizado para subvertir el aislamiento de procesos, filtrar información sensible o realizar acciones no autorizadas.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Inyección en Aplicaciones Electron

Las aplicaciones Electron ejecutadas con variables de entorno específicas podrían ser vulnerables a la inyección de procesos:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### NIB Sucio

Los archivos NIB **definen elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios** y **Gatekeeper no detiene** la ejecución de una aplicación ya ejecutada si un **archivo NIB es modificado**. Por lo tanto, podrían ser utilizados para hacer que programas arbitrarios ejecuten comandos arbitrarios:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Inyección en Aplicaciones Java

Es posible abusar de ciertas capacidades de Java (como la variable de entorno **`_JAVA_OPTS`**) para hacer que una aplicación Java ejecute **código/comandos arbitrarios**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Inyección en Aplicaciones .Net

Es posible inyectar código en aplicaciones .Net **abusando de la funcionalidad de depuración de .Net** (no protegida por las protecciones de macOS como el endurecimiento en tiempo de ejecución).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Inyección en Perl

Consulta diferentes opciones para hacer que un script de Perl ejecute código arbitrario en:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Inyección en Python

Si la variable de entorno **`PYTHONINSPECT`** está establecida, el proceso de python pasará a una CLI de python una vez que haya terminado. También es posible usar **`PYTHONSTARTUP`** para indicar un script de python que se ejecute al inicio de una sesión interactiva.\
Sin embargo, ten en cuenta que el script **`PYTHONSTARTUP`** no se ejecutará cuando **`PYTHONINSPECT`** cree la sesión interactiva.

Otras variables de entorno como **`PYTHONPATH`** y **`PYTHONHOME`** también podrían ser útiles para hacer que un comando de python ejecute código arbitrario.

Ten en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizarán estas variables de entorno incluso si se están ejecutando usando un python embebido.

{% hint style="danger" %}
En general, no encontré una manera de hacer que python ejecute código arbitrario abusando de las variables de entorno.\
Sin embargo, la mayoría de las personas instalan python usando **Homebrew**, que instalará python en una **ubicación escribible** para el usuario administrador predeterminado. Puedes secuestrarlo con algo como:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Incluso **root** ejecutará este código al correr python.
{% endhint %}

## Detección

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) es una aplicación de código abierto que puede **detectar y bloquear acciones de inyección de procesos**:

* Usando **Variables Ambientales**: Monitorea la presencia de cualquiera de las siguientes variables ambientales: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** y **`ELECTRON_RUN_AS_NODE`**
* Usando llamadas a **`task_for_pid`**: Para encontrar cuándo un proceso quiere obtener el **puerto de tarea de otro**, lo que permite inyectar código en el proceso.
* **Parámetros de aplicaciones Electron**: Alguien puede usar los argumentos de línea de comandos **`--inspect`**, **`--inspect-brk`** y **`--remote-debugging-port`** para iniciar una aplicación Electron en modo de depuración, y así inyectar código en ella.
* Usando **symlinks** o **hardlinks**: Típicamente, el abuso más común es **colocar un enlace con nuestros privilegios de usuario**, y **apuntarlo a una ubicación de mayor privilegio**. La detección es muy simple tanto para hardlinks como para symlinks. Si el proceso que crea el enlace tiene un **nivel de privilegio diferente** al del archivo objetivo, creamos una **alerta**. Desafortunadamente, en el caso de symlinks, el bloqueo no es posible, ya que no tenemos información sobre el destino del enlace antes de su creación. Esta es una limitación del marco de EndpointSecuriy de Apple.

### Llamadas realizadas por otros procesos

En [**este artículo del blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo es posible usar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y luego obtener información sobre ese otro proceso.

Nota que para llamar a esa función necesitas ser **el mismo uid** que el que ejecuta el proceso o **root** (y devuelve información sobre el proceso, no una forma de inyectar código).

## Referencias

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de Github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
