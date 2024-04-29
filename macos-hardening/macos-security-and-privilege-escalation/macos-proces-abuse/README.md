# Abuso de Procesos en macOS

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica de Procesos

Un proceso es una instancia de un ejecutable en ejecución, sin embargo, los procesos no ejecutan código, estos son hilos. Por lo tanto, **los procesos son simplemente contenedores para la ejecución de hilos** que proporcionan la memoria, descriptores, puertos, permisos...

Tradicionalmente, los procesos se iniciaban dentro de otros procesos (excepto el PID 1) llamando a **`fork`**, lo que crearía una copia exacta del proceso actual y luego el **proceso hijo** generalmente llamaría a **`execve`** para cargar el nuevo ejecutable y ejecutarlo. Luego, se introdujo **`vfork`** para hacer este proceso más rápido sin copiar memoria.\
Luego se introdujo **`posix_spawn`** combinando **`vfork`** y **`execve`** en una sola llamada y aceptando banderas:

* `POSIX_SPAWN_RESETIDS`: Restablecer los ids efectivos a los ids reales
* `POSIX_SPAWN_SETPGROUP`: Establecer la afiliación al grupo de procesos
* `POSUX_SPAWN_SETSIGDEF`: Establecer el comportamiento predeterminado de la señal
* `POSIX_SPAWN_SETSIGMASK`: Establecer la máscara de señal
* `POSIX_SPAWN_SETEXEC`: Ejecutar en el mismo proceso (como `execve` con más opciones)
* `POSIX_SPAWN_START_SUSPENDED`: Iniciar suspendido
* `_POSIX_SPAWN_DISABLE_ASLR`: Iniciar sin ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Usar el Nano allocator de libmalloc
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permitir `rwx` en segmentos de datos
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Cerrar todas las descripciones de archivos en exec(2) de forma predeterminada
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatorizar los bits altos del deslizamiento de ASLR

Además, `posix_spawn` permite especificar una matriz de **`posix_spawnattr`** que controla algunos aspectos del proceso generado, y **`posix_spawn_file_actions`** para modificar el estado de los descriptores.

Cuando un proceso muere, envía el **código de retorno al proceso padre** (si el padre murió, el nuevo padre es el PID 1) con la señal `SIGCHLD`. El padre necesita obtener este valor llamando a `wait4()` o `waitid()` y hasta que eso suceda, el hijo permanece en un estado zombie donde todavía está listado pero no consume recursos.

### PIDs

Los PIDs, identificadores de procesos, identifican un proceso único. En XNU, los **PIDs** son de **64 bits** que aumentan monótonamente y **nunca se reinician** (para evitar abusos).

### Grupos de Procesos, Sesiones y Coaliciones

**Los procesos** pueden ser insertados en **grupos** para facilitar su manejo. Por ejemplo, los comandos en un script de shell estarán en el mismo grupo de procesos, por lo que es posible **enviarles señales juntos** usando kill, por ejemplo.\
También es posible **agrupar procesos en sesiones**. Cuando un proceso inicia una sesión (`setsid(2)`), los procesos hijos se colocan dentro de la sesión, a menos que inicien su propia sesión.

La coalición es otra forma de agrupar procesos en Darwin. Un proceso que se une a una coalición le permite acceder a recursos compartidos, compartir un libro mayor o enfrentarse a Jetsam. Las coaliciones tienen diferentes roles: Líder, servicio XPC, Extensión.

### Credenciales y Personas

Cada proceso tiene **credenciales** que **identifican sus privilegios** en el sistema. Cada proceso tendrá un `uid` primario y un `gid` primario (aunque puede pertenecer a varios grupos).\
También es posible cambiar el id de usuario y de grupo si el binario tiene el bit `setuid/setgid`.\
Existen varias funciones para **establecer nuevos uids/gids**.

La llamada al sistema **`persona`** proporciona un **conjunto alternativo** de **credenciales**. Adoptar una persona asume su uid, gid y membresías de grupo **a la vez**. En el [**código fuente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) es posible encontrar la estructura:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Información Básica sobre Hilos

1. **Hilos POSIX (pthreads):** macOS soporta hilos POSIX (`pthreads`), que forman parte de una API estándar de hilos para C/C++. La implementación de pthreads en macOS se encuentra en `/usr/lib/system/libsystem_pthread.dylib`, que proviene del proyecto `libpthread` disponible públicamente. Esta biblioteca proporciona las funciones necesarias para crear y gestionar hilos.
2. **Creación de Hilos:** La función `pthread_create()` se utiliza para crear nuevos hilos. Internamente, esta función llama a `bsdthread_create()`, que es una llamada al sistema de nivel inferior específica del kernel XNU (el kernel en el que se basa macOS). Esta llamada al sistema toma varios indicadores derivados de `pthread_attr` (atributos) que especifican el comportamiento del hilo, incluidas las políticas de programación y el tamaño de la pila.
* **Tamaño de Pila Predeterminado:** El tamaño de pila predeterminado para los nuevos hilos es de 512 KB, que es suficiente para operaciones típicas pero puede ajustarse a través de atributos de hilo si se necesita más o menos espacio.
3. **Inicialización de Hilos:** La función `__pthread_init()` es crucial durante la configuración del hilo, utilizando el argumento `env[]` para analizar variables de entorno que pueden incluir detalles sobre la ubicación y el tamaño de la pila.

#### Terminación de Hilos en macOS

1. **Finalización de Hilos:** Los hilos suelen terminarse llamando a `pthread_exit()`. Esta función permite que un hilo salga limpiamente, realizando la limpieza necesaria y permitiendo que el hilo envíe un valor de retorno a los hilos que lo esperan.
2. **Limpieza de Hilos:** Al llamar a `pthread_exit()`, se invoca la función `pthread_terminate()`, que maneja la eliminación de todas las estructuras de hilo asociadas. Desasigna los puertos de hilo Mach (Mach es el subsistema de comunicación en el kernel XNU) y llama a `bsdthread_terminate`, una llamada al sistema que elimina las estructuras a nivel de kernel asociadas con el hilo.

#### Mecanismos de Sincronización

Para gestionar el acceso a recursos compartidos y evitar condiciones de carrera, macOS proporciona varios primitivos de sincronización. Estos son críticos en entornos de múltiples hilos para garantizar la integridad de los datos y la estabilidad del sistema:

1. **Mutex:**
* **Mutex Regular (Firma: 0x4D555458):** Mutex estándar con un tamaño de memoria de 60 bytes (56 bytes para el mutex y 4 bytes para la firma).
* **Mutex Rápido (Firma: 0x4d55545A):** Similar a un mutex regular pero optimizado para operaciones más rápidas, también de 60 bytes de tamaño.
2. **Variables de Condición:**
* Utilizadas para esperar a que ocurran ciertas condiciones, con un tamaño de 44 bytes (40 bytes más una firma de 4 bytes).
* **Atributos de Variables de Condición (Firma: 0x434e4441):** Atributos de configuración para variables de condición, de tamaño 12 bytes.
3. **Variable Once (Firma: 0x4f4e4345):**
* Asegura que un fragmento de código de inicialización se ejecute solo una vez. Su tamaño es de 12 bytes.
4. **Cerrojos de Lectura-Escritura:**
* Permite múltiples lectores o un escritor a la vez, facilitando el acceso eficiente a datos compartidos.
* **Cerrojo de Lectura-Escritura (Firma: 0x52574c4b):** Con un tamaño de 196 bytes.
* **Atributos de Cerrojo de Lectura-Escritura (Firma: 0x52574c41):** Atributos para cerrojos de lectura-escritura, de tamaño 20 bytes.

{% hint style="success" %}
Los últimos 4 bytes de esos objetos se utilizan para detectar desbordamientos.
{% endhint %}

### Variables Locales de Hilo (TLV)

Las **Variables Locales de Hilo (TLV)** en el contexto de archivos Mach-O (el formato para ejecutables en macOS) se utilizan para declarar variables específicas para **cada hilo** en una aplicación multi-hilo. Esto asegura que cada hilo tenga su propia instancia separada de una variable, proporcionando una forma de evitar conflictos y mantener la integridad de los datos sin necesidad de mecanismos explícitos de sincronización como mutexes.

En C y lenguajes relacionados, puedes declarar una variable local de hilo utilizando la palabra clave **`__thread`**. Así es como funciona en tu ejemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este fragmento define `tlv_var` como una variable local al hilo. Cada hilo que ejecute este código tendrá su propia `tlv_var`, y los cambios que un hilo realice en `tlv_var` no afectarán a `tlv_var` en otro hilo.

En el binario Mach-O, los datos relacionados con las variables locales al hilo se organizan en secciones específicas:

* **`__DATA.__thread_vars`**: Esta sección contiene metadatos sobre las variables locales al hilo, como sus tipos y estado de inicialización.
* **`__DATA.__thread_bss`**: Esta sección se utiliza para variables locales al hilo que no se inicializan explícitamente. Es una parte de la memoria reservada para datos inicializados en cero.

Mach-O también proporciona una API específica llamada **`tlv_atexit`** para gestionar las variables locales al hilo cuando un hilo finaliza. Esta API te permite **registrar destructores** —funciones especiales que limpian los datos locales al hilo cuando un hilo termina.

### Prioridades de Hilos

Entender las prioridades de los hilos implica observar cómo el sistema operativo decide qué hilos ejecutar y cuándo. Esta decisión está influenciada por el nivel de prioridad asignado a cada hilo. En macOS y sistemas tipo Unix, esto se maneja mediante conceptos como `nice`, `renice` y clases de Calidad de Servicio (QoS).

#### Nice y Renice

1. **Nice:**
* El valor `nice` de un proceso es un número que afecta su prioridad. Cada proceso tiene un valor nice que va desde -20 (la prioridad más alta) hasta 19 (la prioridad más baja). El valor nice predeterminado al crear un proceso suele ser 0.
* Un valor nice más bajo (más cercano a -20) hace que un proceso sea más "egoísta", dándole más tiempo de CPU en comparación con otros procesos con valores nice más altos.
2. **Renice:**
* `renice` es un comando utilizado para cambiar el valor nice de un proceso que ya está en ejecución. Esto se puede utilizar para ajustar dinámicamente la prioridad de los procesos, ya sea aumentando o disminuyendo su asignación de tiempo de CPU en función de los nuevos valores nice.
* Por ejemplo, si un proceso necesita más recursos de CPU temporalmente, podrías reducir su valor nice usando `renice`.

#### Clases de Calidad de Servicio (QoS)

Las clases de QoS son un enfoque más moderno para manejar las prioridades de los hilos, especialmente en sistemas como macOS que admiten **Grand Central Dispatch (GCD)**. Las clases de QoS permiten a los desarrolladores **categorizar** el trabajo en diferentes niveles según su importancia o urgencia. macOS gestiona la priorización de hilos automáticamente en función de estas clases de QoS:

1. **Interactivo con el Usuario:**
* Esta clase es para tareas que están interactuando actualmente con el usuario o que requieren resultados inmediatos para proporcionar una buena experiencia de usuario. Estas tareas tienen la prioridad más alta para mantener la interfaz receptiva (por ejemplo, animaciones o manejo de eventos).
2. **Iniciado por el Usuario:**
* Tareas que el usuario inicia y espera resultados inmediatos, como abrir un documento o hacer clic en un botón que requiere cálculos. Estas tienen alta prioridad pero por debajo de las interactivas con el usuario.
3. **Utilidad:**
* Estas tareas son de larga duración y suelen mostrar un indicador de progreso (por ejemplo, descargar archivos, importar datos). Tienen una prioridad más baja que las tareas iniciadas por el usuario y no necesitan finalizar inmediatamente.
4. **En Segundo Plano:**
* Esta clase es para tareas que operan en segundo plano y no son visibles para el usuario. Pueden ser tareas como indexación, sincronización o copias de seguridad. Tienen la prioridad más baja y un impacto mínimo en el rendimiento del sistema.

Al utilizar las clases de QoS, los desarrolladores no necesitan gestionar los números de prioridad exactos, sino centrarse en la naturaleza de la tarea, y el sistema optimiza los recursos de la CPU en consecuencia.

Además, existen diferentes **políticas de programación de hilos** que permiten especificar un conjunto de parámetros de programación que el programador tendrá en cuenta. Esto se puede hacer utilizando `thread_policy_[set/get]`. Esto podría ser útil en ataques de condiciones de carrera.

## Abuso de Procesos en MacOS

MacOS, al igual que cualquier otro sistema operativo, proporciona una variedad de métodos y mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Si bien estas técnicas son esenciales para el funcionamiento eficiente del sistema, también pueden ser abusadas por actores malintencionados para **realizar actividades maliciosas**.

### Inyección de Bibliotecas

La Inyección de Bibliotecas es una técnica en la que un atacante **obliga a un proceso a cargar una biblioteca maliciosa**. Una vez inyectada, la biblioteca se ejecuta en el contexto del proceso objetivo, proporcionando al atacante los mismos permisos y acceso que el proceso.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection/]
{% endcontent-ref %}

### Enganche de Funciones

El Enganche de Funciones implica **interceptar llamadas de funciones** o mensajes dentro de un código de software. Al enganchar funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos sensibles o incluso obtener control sobre el flujo de ejecución.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md]
{% endcontent-ref %}

### Comunicación entre Procesos

La Comunicación entre Procesos (IPC) se refiere a diferentes métodos mediante los cuales procesos separados **comparten y intercambian datos**. Si bien el IPC es fundamental para muchas aplicaciones legítimas, también se puede utilizar de manera incorrecta para subvertir el aislamiento de procesos, filtrar información sensible o realizar acciones no autorizadas.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication]
{% endcontent-ref %}

### Inyección de Aplicaciones Electron

Las aplicaciones Electron ejecutadas con variables de entorno específicas podrían ser vulnerables a la inyección de procesos:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md]
{% endcontent-ref %}

### Inyección en Chromium

Es posible utilizar las banderas `--load-extension` y `--use-fake-ui-for-media-stream` para realizar un **ataque de hombre en el navegador** que permita robar pulsaciones de teclas, tráfico, cookies, inyectar scripts en páginas...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md]
{% endcontent-ref %}

### NIB Sucio

Los archivos NIB **definen elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios** y **Gatekeeper no impide** que una aplicación ya ejecutada vuelva a ejecutarse si se modifica un **archivo NIB**. Por lo tanto, podrían usarse para hacer que programas arbitrarios ejecuten comandos arbitrarios:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md]
{% endcontent-ref %}

### Inyección en Aplicaciones Java

Es posible abusar de ciertas capacidades de Java (como la variable de entorno **`_JAVA_OPTS`**) para hacer que una aplicación Java ejecute **código/comandos arbitrarios**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md]
{% endcontent-ref %}

### Inyección en Aplicaciones .Net

Es posible inyectar código en aplicaciones .Net **abusando de la funcionalidad de depuración de .Net** (no protegida por protecciones de macOS como el endurecimiento en tiempo de ejecución).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md]
{% endcontent-ref %}

### Inyección en Perl

Revisa diferentes opciones para hacer que un script de Perl ejecute código arbitrario en:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md]
{% endcontent-ref %}

### Inyección en Ruby

También es posible abusar de las variables de entorno de Ruby para hacer que scripts arbitrarios ejecuten código arbitrario:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md]
{% endcontent-ref %}
### Inyección de Python

Si la variable de entorno **`PYTHONINSPECT`** está configurada, el proceso de Python ingresará a un cli de Python una vez que haya terminado. También es posible usar **`PYTHONSTARTUP`** para indicar un script de Python que se ejecutará al comienzo de una sesión interactiva.\
Sin embargo, tenga en cuenta que el script de **`PYTHONSTARTUP`** no se ejecutará cuando **`PYTHONINSPECT`** cree la sesión interactiva.

Otras variables de entorno como **`PYTHONPATH`** y **`PYTHONHOME`** también podrían ser útiles para hacer que un comando de Python ejecute código arbitrario.

Tenga en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizarán estas variables de entorno incluso si se ejecutan utilizando un Python integrado.

{% hint style="danger" %}
En general, no pude encontrar una forma de hacer que Python ejecute código arbitrario abusando de las variables de entorno.\
Sin embargo, la mayoría de las personas instalan Python usando **Hombrew**, lo que instalará Python en una **ubicación escribible** para el usuario administrador predeterminado. Puedes secuestrarlo con algo como:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Incluso **root** ejecutará este código al ejecutar python.
{% endhint %}

## Detección

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) es una aplicación de código abierto que puede **detectar y bloquear acciones de inyección de procesos**:

* Usando **Variables de Entorno**: Monitorizará la presencia de cualquiera de las siguientes variables de entorno: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** y **`ELECTRON_RUN_AS_NODE`**
* Usando llamadas a **`task_for_pid`**: Para encontrar cuando un proceso quiere obtener el **puerto de tarea de otro** lo que permite inyectar código en el proceso.
* Parámetros de aplicaciones **Electron**: Alguien puede usar los argumentos de línea de comandos **`--inspect`**, **`--inspect-brk`** y **`--remote-debugging-port`** para iniciar una aplicación Electron en modo de depuración, y así inyectar código en ella.
* Usando **enlaces simbólicos** o **enlaces duros**: Típicamente el abuso más común es **colocar un enlace con nuestros privilegios de usuario**, y **apuntarlo a una ubicación de mayor privilegio**. La detección es muy simple tanto para enlaces duros como para enlaces simbólicos. Si el proceso que crea el enlace tiene un **nivel de privilegio diferente** al archivo de destino, creamos una **alerta**. Desafortunadamente, en el caso de los enlaces simbólicos, no es posible bloquear, ya que no tenemos información sobre el destino del enlace antes de la creación. Esta es una limitación del framework de EndpointSecuriy de Apple.

### Llamadas realizadas por otros procesos

En [**esta publicación de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo es posible utilizar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y luego obtener información sobre ese otro proceso.

Ten en cuenta que para llamar a esa función necesitas tener el **mismo uid** que el que ejecuta el proceso o ser **root** (y devuelve información sobre el proceso, no una forma de inyectar código).

## Referencias

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>
