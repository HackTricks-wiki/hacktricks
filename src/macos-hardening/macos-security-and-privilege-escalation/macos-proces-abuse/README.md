# Abuso de procesos en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica sobre los procesos

Un proceso es una instancia de un ejecutable en ejecución; sin embargo, los procesos no ejecutan código, sino que lo hacen los threads. Por lo tanto, **los procesos son solo contenedores para ejecutar threads** que proporcionan la memoria, descriptores, puertos, permisos...

Tradicionalmente, los procesos se iniciaban dentro de otros procesos (excepto el PID 1) llamando a **`fork`**, que creaba una copia exacta del proceso actual; después, el **proceso hijo** generalmente llamaba a **`execve`** para cargar el nuevo ejecutable y ejecutarlo. Luego se introdujo **`vfork`** para hacer este proceso más rápido sin copiar la memoria.\
Después se introdujo **`posix_spawn`**, que combina **`vfork`** y **`execve`** en una sola llamada y acepta flags:

- `POSIX_SPAWN_RESETIDS`: Restablecer los ids efectivos a los ids reales
- `POSIX_SPAWN_SETPGROUP`: Establecer la afiliación al grupo de procesos
- `POSUX_SPAWN_SETSIGDEF`: Establecer el comportamiento predeterminado de las señales
- `POSIX_SPAWN_SETSIGMASK`: Establecer la máscara de señales
- `POSIX_SPAWN_SETEXEC`: Ejecutar en el mismo proceso (como `execve`, con más opciones)
- `POSIX_SPAWN_START_SUSPENDED`: Iniciar suspendido
- `_POSIX_SPAWN_DISABLE_ASLR`: Iniciar sin ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usar el allocator Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permitir `rwx` en los segmentos de datos
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Cerrar todas las descripciones de archivo en exec(2) de forma predeterminada
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatorizar los bits altos del desplazamiento de ASLR

Además, `posix_spawn` permite especificar un array de **`posix_spawnattr`** que controla algunos aspectos del proceso generado, y **`posix_spawn_file_actions`** para modificar el estado de los descriptores.

Cuando un proceso muere, envía el **código de retorno al proceso padre** (si el padre ha muerto, el nuevo padre es el PID 1) con la señal `SIGCHLD`. El padre debe obtener este valor llamando a `wait4()` o `waitid()` y, hasta que eso ocurra, el hijo permanece en un estado zombie en el que sigue listado, pero no consume recursos.

### PIDs

Los PIDs, identificadores de procesos, identifican un proceso único. En XNU, los **PIDs** tienen **64 bits**, aumentan monótonamente y **nunca hacen wrap** (para evitar abusos).

### Grupos de procesos, sesiones y coaliciones

Los **procesos** pueden insertarse en **grupos** para facilitar su gestión. Por ejemplo, los comandos de un shell script estarán en el mismo grupo de procesos, por lo que es posible **enviarles señales conjuntamente** usando kill, por ejemplo.\
También es posible **agrupar procesos en sesiones**. Cuando un proceso inicia una sesión (`setsid(2)`), los procesos hijos se establecen dentro de la sesión, a menos que inicien su propia sesión.

Coalition es otra forma de agrupar procesos en Darwin. Un proceso que se une a una coalation puede acceder a recursos del pool, compartir un ledger o enfrentarse a Jetsam. Las coalations tienen diferentes roles: Leader, XPC service, Extension.

### Credenciales y personae

Cada proceso contiene **credenciales** que **identifican sus privilegios** en el sistema. Cada proceso tendrá un `uid` primario y un `gid` primario (aunque puede pertenecer a varios grupos).\
También es posible cambiar el id de usuario y de grupo si el binario tiene el bit **`setuid/setgid`**.\
Existen varias funciones para **establecer nuevos uids/gids**.

El syscall **`persona`** proporciona un conjunto **alternativo** de **credenciales**. Adoptar una persona supone asumir su uid, gid y pertenencia a grupos **a la vez**. En el [**código fuente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) es posible encontrar la struct:
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
## Información básica sobre Threads

1. **POSIX Threads (pthreads):** macOS admite POSIX threads (`pthreads`), que forman parte de una API estándar de threading para C/C++. La implementación de pthreads en macOS se encuentra en `/usr/lib/system/libsystem_pthread.dylib`, que proviene del proyecto `libpthread`, disponible públicamente. Esta library proporciona las funciones necesarias para crear y gestionar threads.
2. **Creación de Threads:** La función `pthread_create()` se utiliza para crear nuevos threads. Internamente, esta función llama a `bsdthread_create()`, que es una system call de nivel inferior específica del kernel XNU (el kernel en el que se basa macOS). Esta system call recibe varios flags derivados de `pthread_attr` (atributos) que especifican el comportamiento del thread, incluidas las políticas de scheduling y el tamaño del stack.
- **Tamaño del Stack predeterminado:** El tamaño del stack predeterminado para los nuevos threads es de 512 KB, suficiente para las operaciones habituales, pero puede ajustarse mediante los atributos del thread si se necesita más o menos espacio.
3. **Inicialización del Thread:** La función `__pthread_init()` es fundamental durante la configuración del thread, ya que utiliza el argumento `env[]` para analizar variables de entorno que pueden incluir información sobre la ubicación y el tamaño del stack.

#### Terminación de Threads en macOS

1. **Salida de Threads:** Normalmente, los threads terminan llamando a `pthread_exit()`. Esta función permite que un thread salga limpiamente, realizando la limpieza necesaria y permitiendo que envíe un valor de retorno a cualquier thread que haga join.
2. **Limpieza del Thread:** Al llamar a `pthread_exit()`, se invoca la función `pthread_terminate()`, que gestiona la eliminación de todas las estructuras asociadas al thread. Esta función desasigna los puertos de threads de Mach (Mach es el subsistema de comunicación del kernel XNU) y llama a `bsdthread_terminate`, un syscall que elimina las estructuras a nivel del kernel asociadas al thread.

#### Mecanismos de Sincronización

Para gestionar el acceso a recursos compartidos y evitar race conditions, macOS proporciona varias primitivas de sincronización. Estas son esenciales en entornos multithreading para garantizar la integridad de los datos y la estabilidad del sistema:

1. **Mutexes:**
- **Mutex Regular (Signature: 0x4D555458):** Mutex estándar con un tamaño de 60 bytes (56 bytes para el mutex y 4 bytes para la signature).
- **Fast Mutex (Signature: 0x4d55545A):** Similar a un mutex regular, pero optimizado para operaciones más rápidas; también ocupa 60 bytes.
2. **Variables de Condición:**
- Se utilizan para esperar a que se cumplan ciertas condiciones y tienen un tamaño de 44 bytes (40 bytes más una signature de 4 bytes).
- **Atributos de las Variables de Condición (Signature: 0x434e4441):** Atributos de configuración para las variables de condición, con un tamaño de 12 bytes.
3. **Variable Once (Signature: 0x4f4e4345):**
- Garantiza que un fragmento de código de inicialización se ejecute una sola vez. Su tamaño es de 12 bytes.
4. **Read-Write Locks:**
- Permiten varios lectores o un único writer a la vez, facilitando un acceso eficiente a los datos compartidos.
- **Read Write Lock (Signature: 0x52574c4b):** Tiene un tamaño de 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Atributos para read-write locks, con un tamaño de 20 bytes.

> [!TIP]
> Los últimos 4 bytes de esos objetos se utilizan para detectar overflows.

### Variables Locales de Thread (TLV)

Las **Thread Local Variables (TLV)**, en el contexto de los archivos Mach-O (el formato de los ejecutables en macOS), se utilizan para declarar variables específicas de **cada thread** en una aplicación multithreading. Esto garantiza que cada thread tenga su propia instancia independiente de una variable, proporcionando una forma de evitar conflictos y mantener la integridad de los datos sin necesidad de mecanismos de sincronización explícitos, como los mutexes.

En C y lenguajes relacionados, puedes declarar una variable local de thread utilizando la palabra clave **`__thread`**. Así es como funciona en el ejemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este fragmento define `tlv_var` como una variable local al hilo. Cada hilo que ejecute este código tendrá su propia `tlv_var`, y los cambios que un hilo realice en `tlv_var` no afectarán a la `tlv_var` de otro hilo.

En el binario Mach-O, los datos relacionados con las variables locales al hilo se organizan en secciones específicas:

- **`__DATA.__thread_vars`**: Esta sección contiene los metadatos sobre las variables locales al hilo, como sus tipos y su estado de inicialización.
- **`__DATA.__thread_bss`**: Esta sección se utiliza para las variables locales al hilo que no se inicializan explícitamente. Es una parte de la memoria reservada para datos inicializados a cero.

Mach-O también proporciona una API específica llamada **`tlv_atexit`** para gestionar las variables locales al hilo cuando este termina. Esta API permite **registrar destructores**: funciones especiales que limpian los datos locales al hilo cuando un hilo finaliza.

### Threading Priorities

Comprender las prioridades de los hilos implica analizar cómo el sistema operativo decide qué hilos ejecutar y cuándo. Esta decisión está influida por el nivel de prioridad asignado a cada hilo. En macOS y en los sistemas similares a Unix, esto se gestiona mediante conceptos como `nice`, `renice` y las clases de Quality of Service (QoS).

#### Nice and Renice

1. **Nice:**
- El valor `nice` de un proceso es un número que afecta a su prioridad. Cada proceso tiene un valor nice comprendido entre -20 (la prioridad más alta) y 19 (la prioridad más baja). El valor nice predeterminado cuando se crea un proceso suele ser 0.
- Un valor nice más bajo (más cercano a -20) hace que un proceso sea más "egoísta", otorgándole más tiempo de CPU en comparación con otros procesos con valores nice más altos.
2. **Renice:**
- `renice` es un comando utilizado para cambiar el valor nice de un proceso que ya está en ejecución. Puede utilizarse para ajustar dinámicamente la prioridad de los procesos, aumentando o reduciendo la asignación de tiempo de CPU según los nuevos valores nice.
- Por ejemplo, si un proceso necesita temporalmente más recursos de CPU, se puede reducir su valor nice mediante `renice`.

#### Quality of Service (QoS) Classes

Las clases QoS son un enfoque más moderno para gestionar las prioridades de los hilos, especialmente en sistemas como macOS que admiten **Grand Central Dispatch (GCD)**. Las clases QoS permiten a los desarrolladores **categorizar** el trabajo en distintos niveles según su importancia o urgencia. macOS gestiona automáticamente la priorización de los hilos basándose en estas clases QoS:

1. **User Interactive:**
- Esta clase está destinada a tareas que interactúan actualmente con el usuario o que requieren resultados inmediatos para proporcionar una buena experiencia de usuario. Estas tareas reciben la máxima prioridad para mantener la interfaz receptiva (por ejemplo, animaciones o gestión de eventos).
2. **User Initiated:**
- Tareas iniciadas por el usuario para las que este espera resultados inmediatos, como abrir un documento o hacer clic en un botón que requiere realizar cálculos. Tienen una prioridad alta, pero inferior a User Interactive.
3. **Utility:**
- Estas tareas son de larga duración y normalmente muestran un indicador de progreso (por ejemplo, descargar archivos o importar datos). Tienen una prioridad inferior a las tareas iniciadas por el usuario y no necesitan finalizar inmediatamente.
4. **Background:**
- Esta clase está destinada a tareas que se ejecutan en segundo plano y no son visibles para el usuario. Pueden ser tareas como indexación, sincronización o backups. Tienen la prioridad más baja y un impacto mínimo en el rendimiento del sistema.

Mediante las clases QoS, los desarrolladores no necesitan gestionar números de prioridad exactos, sino centrarse en la naturaleza de la tarea, mientras el sistema optimiza los recursos de CPU en consecuencia.

Además, existen distintas **thread scheduling policies** que permiten especificar un conjunto de parámetros de planificación que el scheduler tendrá en cuenta. Esto puede hacerse mediante `thread_policy_[set/get]`. Esto podría resultar útil en ataques de race condition.

## MacOS Process Abuse

macOS, al igual que cualquier otro sistema operativo, proporciona diversos métodos y mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Aunque estas técnicas son esenciales para el funcionamiento eficiente del sistema, también pueden ser utilizadas de forma abusiva por threat actors para **realizar actividades maliciosas**.

### Library Injection

Library Injection es una técnica mediante la cual un atacante **fuerza a un proceso a cargar una library maliciosa**. Una vez inyectada, la library se ejecuta en el contexto del proceso objetivo, proporcionando al atacante los mismos permisos y acceso que tiene el proceso.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste en **interceptar llamadas a funciones** o mensajes dentro del código de un software. Mediante el hooking de funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos sensibles o incluso obtener control sobre el flujo de ejecución.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) hace referencia a los distintos métodos mediante los cuales procesos independientes **comparten e intercambian datos**. Aunque IPC es fundamental para muchas aplicaciones legítimas, también puede utilizarse de forma indebida para evadir el aislamiento de procesos, hacer leak de información sensible o realizar acciones no autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Las aplicaciones Electron ejecutadas con determinadas variables de entorno podrían ser vulnerables a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Es posible utilizar los flags `--load-extension` y `--use-fake-ui-for-media-stream` para realizar un **man in the browser attack**, lo que permite robar pulsaciones de teclas y tráfico, cookies, inyectar scripts en páginas...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Los archivos NIB **definen elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios** y **Gatekeeper no impide** que una aplicación ya ejecutada vuelva a ejecutarse si se **modifica un archivo NIB**. Por lo tanto, podrían utilizarse para hacer que programas arbitrarios ejecuten comandos arbitrarios:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es posible abusar de determinadas capacidades de Java (como la variable de entorno **`_JAVA_OPTS`**) para hacer que una aplicación Java ejecute **código/comandos arbitrarios**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Es posible inyectar código en aplicaciones .Net mediante el **abuso de la funcionalidad de debugging de .Net** (no protegida por mecanismos de protección de macOS, como runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Consulta distintas opciones para hacer que un script de Perl ejecute código arbitrario en:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

También es posible abusar de las variables de entorno de Ruby para hacer que scripts arbitrarios ejecuten código arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Si la variable de entorno **`PYTHONINSPECT`** está configurada, el proceso de Python accederá a una CLI de Python una vez que finalice. También es posible utilizar **`PYTHONSTARTUP`** para indicar un script de Python que se ejecute al principio de una sesión interactiva.\
Sin embargo, ten en cuenta que el script de **`PYTHONSTARTUP`** no se ejecutará cuando **`PYTHONINSPECT`** cree la sesión interactiva.

Otras variables de entorno, como **`PYTHONPATH`** y **`PYTHONHOME`**, también podrían resultar útiles para hacer que un comando de Python ejecute código arbitrario.

Ten en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizarán estas variables de entorno, aunque se ejecuten utilizando un Python embebido.

> [!CAUTION]
> En general, no pude encontrar una forma de hacer que Python ejecute código arbitrario abusando de variables de entorno.\
> Sin embargo, la mayoría de las personas instala pyhton mediante **Hombrew**, que instalará pyhton en una **ubicación escribible** para el usuario admin predeterminado. Puedes secuestrarlo con algo como:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Incluso **root** ejecutará este código al ejecutar Python.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) es una aplicación open source basada en **EndpointSecurity** que detecta y bloquea process injection. Es una buena referencia de las señales que son realmente observables desde ES, ya que genera alertas sobre:<sup>[[1]](#references)</sup>

- **Variables de entorno de injection** durante la ejecución de procesos: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` y `ELECTRON_RUN_AS_NODE`.
- Llamadas a **`task_for_pid`**: un proceso solicita el task port de otro, lo cual es un requisito previo para inyectarse en él.
- **Argumentos de debugging de Electron**: `--inspect`, `--inspect-brk` y `--remote-debugging-port`, que inician una aplicación Electron en modo debug y permiten que cualquiera se conecte a ella y ejecute código.
- **Creación de symlinks/hardlinks entre niveles de privilegio**: el mecanismo clásico de "crear un link como usuario normal y apuntarlo a una ubicación privilegiada". Ten en cuenta que se pueden generar alertas sobre los **symlinks**, pero no bloquearlos: EndpointSecurity no expone el destino del link antes de su creación.

### Calls made by other processes

En [**esta entrada de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo utilizar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y, posteriormente, obtener información sobre ese otro proceso.<sup>[[4]](#references)</sup>

Ten en cuenta que, para llamar a esa función, debes tener **el mismo uid** que el proceso en ejecución o ser **root** (y devuelve información sobre el proceso, no una forma de inyectar código).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
