# Abuse de procesos en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica sobre los procesos

Un proceso es una instancia de un ejecutable en ejecución; sin embargo, los procesos no ejecutan código, sino que lo hacen los threads. Por lo tanto, **los procesos son simplemente contenedores para ejecutar threads** que proporcionan la memoria, descriptores, puertos, permisos...

Tradicionalmente, los procesos se iniciaban dentro de otros procesos (excepto el PID 1) llamando a **`fork`**, que creaba una copia exacta del proceso actual; después, el **proceso hijo** generalmente llamaba a **`execve`** para cargar el nuevo ejecutable y ejecutarlo. Luego se introdujo **`vfork`** para hacer este proceso más rápido sin copiar memoria.\
Después se introdujo **`posix_spawn`**, que combina **`vfork`** y **`execve`** en una sola llamada y acepta flags:

- `POSIX_SPAWN_RESETIDS`: Restablecer los ids efectivos a los ids reales
- `POSIX_SPAWN_SETPGROUP`: Establecer la afiliación al grupo de procesos
- `POSUX_SPAWN_SETSIGDEF`: Establecer el comportamiento predeterminado de las señales
- `POSIX_SPAWN_SETSIGMASK`: Establecer la máscara de señales
- `POSIX_SPAWN_SETEXEC`: Ejecutar en el mismo proceso (como `execve` con más opciones)
- `POSIX_SPAWN_START_SUSPENDED`: Iniciar suspendido
- `_POSIX_SPAWN_DISABLE_ASLR`: Iniciar sin ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usar el allocator Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permitir `rwx` en los segmentos de datos
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Cerrar todas las descripciones de archivo en exec(2) de forma predeterminada
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatorizar los bits altos del desplazamiento de ASLR

Además, `posix_spawn` permite especificar un array de **`posix_spawnattr`** que controla algunos aspectos del proceso creado, y **`posix_spawn_file_actions`** para modificar el estado de los descriptores.

Cuando un proceso muere, envía el **código de retorno al proceso padre** (si el padre murió, el nuevo padre es el PID 1) con la señal `SIGCHLD`. El padre debe obtener este valor llamando a `wait4()` o `waitid()` y, hasta que eso ocurra, el hijo permanece en un estado zombie en el que sigue apareciendo en la lista, pero no consume recursos.

### PIDs

Los PIDs, identificadores de procesos, identifican un proceso único. En XNU, los **PIDs** tienen **64 bits**, aumentan monótonamente y **nunca se desbordan** (para evitar abusos).

### Grupos de procesos, sesiones y coaliciones

Los **procesos** pueden insertarse en **grupos** para facilitar su gestión. Por ejemplo, los comandos de un script de shell estarán en el mismo grupo de procesos, por lo que es posible **enviarles señales conjuntamente** usando kill, por ejemplo.\
También es posible **agrupar procesos en sesiones**. Cuando un proceso inicia una sesión (`setsid(2)`), los procesos hijos se establecen dentro de la sesión, a menos que inicien su propia sesión.

Coalition es otra forma de agrupar procesos en Darwin. Un proceso que se une a una coalition puede acceder a recursos del pool, compartir un ledger o enfrentarse a Jetsam. Las coalitions tienen diferentes roles: Leader, XPC service, Extension.

### Credenciales y personae

Cada proceso contiene **credenciales** que **identifican sus privilegios** en el sistema. Cada proceso tendrá un `uid` primario y un `gid` primario (aunque puede pertenecer a varios grupos).\
También es posible cambiar el id de usuario y de grupo si el binario tiene el bit `setuid/setgid`.\
Existen varias funciones para **establecer nuevos uids/gids**.

El syscall **`persona`** proporciona un conjunto **alternativo** de **credenciales**. Adoptar una persona asume su uid, gid y pertenencia a grupos **al mismo tiempo**. En el [**código fuente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) es posible encontrar la estructura:
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

1. **POSIX Threads (pthreads):** macOS admite POSIX threads (`pthreads`), que forman parte de una API estándar de threading para C/C++. La implementación de pthreads en macOS se encuentra en `/usr/lib/system/libsystem_pthread.dylib`, que proviene del proyecto `libpthread` disponible públicamente. Esta library proporciona las funciones necesarias para crear y gestionar threads.
2. **Creación de Threads:** La función `pthread_create()` se utiliza para crear nuevos threads. Internamente, esta función llama a `bsdthread_create()`, que es una system call de nivel inferior específica del kernel XNU (el kernel en el que se basa macOS). Esta system call acepta varios flags derivados de `pthread_attr` (atributos) que especifican el comportamiento del thread, incluidas las políticas de scheduling y el tamaño del stack.
- **Tamaño del Stack predeterminado:** El tamaño predeterminado del stack para los nuevos threads es de 512 KB, lo que es suficiente para las operaciones habituales, pero puede ajustarse mediante los atributos del thread si se necesita más o menos espacio.
3. **Inicialización del Thread:** La función `__pthread_init()` es crucial durante la configuración del thread, ya que utiliza el argumento `env[]` para analizar variables de entorno que pueden incluir información sobre la ubicación y el tamaño del stack.

#### Terminación de Threads en macOS

1. **Salida de Threads:** Normalmente, los threads terminan llamando a `pthread_exit()`. Esta función permite que un thread finalice correctamente, realice la limpieza necesaria y envíe un valor de retorno a cualquier thread que espere mediante join.
2. **Limpieza del Thread:** Al llamar a `pthread_exit()`, se invoca la función `pthread_terminate()`, que gestiona la eliminación de todas las estructuras asociadas al thread. Desasigna los Mach thread ports (Mach es el subsistema de comunicación del kernel XNU) y llama a `bsdthread_terminate`, una syscall que elimina las estructuras del kernel asociadas al thread.

#### Mecanismos de Synchronization

Para gestionar el acceso a recursos compartidos y evitar race conditions, macOS proporciona varias primitivas de synchronization. Estas son fundamentales en entornos multithreading para garantizar la integridad de los datos y la estabilidad del sistema:

1. **Mutexes:**
- **Mutex normal (Signature: 0x4D555458):** Mutex estándar con un tamaño de 60 bytes (56 bytes para el mutex y 4 bytes para la signature).
- **Fast Mutex (Signature: 0x4d55545A):** Similar a un mutex normal, pero optimizado para operaciones más rápidas; también tiene un tamaño de 60 bytes.
2. **Variables de condición:**
- Se utilizan para esperar a que se cumplan determinadas condiciones y tienen un tamaño de 44 bytes (40 bytes más una signature de 4 bytes).
- **Condition Variable Attributes (Signature: 0x434e4441):** Atributos de configuración para las variables de condición, con un tamaño de 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Garantiza que un fragmento de código de inicialización se ejecute una sola vez. Su tamaño es de 12 bytes.
4. **Read-Write Locks:**
- Permite varios lectores o un único writer a la vez, facilitando un acceso eficiente a los datos compartidos.
- **Read Write Lock (Signature: 0x52574c4b):** Tiene un tamaño de 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Atributos para read-write locks, con un tamaño de 20 bytes.

> [!TIP]
> Los últimos 4 bytes de esos objetos se utilizan para detectar overflows.

### Thread Local Variables (TLV)

Las **Thread Local Variables (TLV)**, en el contexto de los archivos Mach-O (el formato de los ejecutables en macOS), se utilizan para declarar variables específicas de **cada thread** en una aplicación multithreading. Esto garantiza que cada thread tenga su propia instancia independiente de una variable, proporcionando una forma de evitar conflictos y mantener la integridad de los datos sin necesitar mecanismos de synchronization explícitos, como los mutexes.

En C y lenguajes relacionados, puedes declarar una variable thread-local utilizando la palabra clave **`__thread`**. Así es como funciona en el ejemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este fragmento define `tlv_var` como una variable local al thread. Cada thread que ejecute este código tendrá su propio `tlv_var`, y los cambios que un thread realice en `tlv_var` no afectarán al `tlv_var` de otro thread.

En el binario Mach-O, los datos relacionados con las variables locales al thread se organizan en secciones específicas:

- **`__DATA.__thread_vars`**: Esta sección contiene los metadatos sobre las variables locales al thread, como sus tipos y su estado de inicialización.
- **`__DATA.__thread_bss`**: Esta sección se utiliza para las variables locales al thread que no se inicializan explícitamente. Es una parte de la memoria reservada para datos inicializados a cero.

Mach-O también proporciona una API específica llamada **`tlv_atexit`** para gestionar las variables locales al thread cuando este termina. Esta API permite **registrar destructors** —funciones especiales que limpian los datos locales al thread cuando un thread finaliza—.

### Prioridades de los threads

Comprender las prioridades de los threads implica analizar cómo el sistema operativo decide qué threads ejecutar y cuándo hacerlo. Esta decisión está influida por el nivel de prioridad asignado a cada thread. En macOS y en sistemas similares a Unix, esto se gestiona mediante conceptos como `nice`, `renice` y las clases Quality of Service (QoS).

#### Nice y Renice

1. **Nice:**
- El valor `nice` de un proceso es un número que afecta a su prioridad. Cada proceso tiene un valor `nice` entre -20 (la prioridad más alta) y 19 (la prioridad más baja). El valor `nice` predeterminado cuando se crea un proceso suele ser 0.
- Un valor `nice` más bajo (más cercano a -20) hace que un proceso sea más "egoísta", otorgándole más tiempo de CPU en comparación con otros procesos con valores `nice` más altos.
2. **Renice:**
- `renice` es un comando utilizado para cambiar el valor `nice` de un proceso que ya está en ejecución. Puede utilizarse para ajustar dinámicamente la prioridad de los procesos, aumentando o reduciendo la asignación de tiempo de CPU según los nuevos valores `nice`.
- Por ejemplo, si un proceso necesita temporalmente más recursos de CPU, se puede reducir su valor `nice` mediante `renice`.

#### Clases Quality of Service (QoS)

Las clases QoS son un enfoque más moderno para gestionar las prioridades de los threads, especialmente en sistemas como macOS que admiten **Grand Central Dispatch (GCD)**. Las clases QoS permiten a los desarrolladores **categorizar** el trabajo en distintos niveles según su importancia o urgencia. macOS gestiona automáticamente la priorización de los threads basándose en estas clases QoS:

1. **User Interactive:**
- Esta clase se utiliza para tareas que interactúan actualmente con el usuario o que requieren resultados inmediatos para ofrecer una buena experiencia de usuario. Estas tareas reciben la prioridad más alta para mantener la interfaz receptiva (por ejemplo, animaciones o gestión de eventos).
2. **User Initiated:**
- Tareas iniciadas por el usuario de las que se esperan resultados inmediatos, como abrir un documento o hacer clic en un botón que requiere realizar cálculos. Tienen una prioridad alta, pero inferior a User Interactive.
3. **Utility:**
- Estas tareas se ejecutan durante mucho tiempo y normalmente muestran un indicador de progreso (por ejemplo, descargar archivos o importar datos). Tienen una prioridad inferior a las tareas User Initiated y no necesitan finalizar inmediatamente.
4. **Background:**
- Esta clase se utiliza para tareas que funcionan en segundo plano y no son visibles para el usuario. Pueden ser tareas como indexación, sincronización o backups. Tienen la prioridad más baja y un impacto mínimo en el rendimiento del sistema.

Mediante las clases QoS, los desarrolladores no necesitan gestionar los valores exactos de prioridad, sino centrarse en la naturaleza de la tarea, mientras el sistema optimiza los recursos de CPU en consecuencia.

Además, existen distintas **thread scheduling policies** que permiten especificar un conjunto de parámetros de scheduling que el scheduler tendrá en cuenta. Esto puede hacerse mediante `thread_policy_[set/get]`. Puede resultar útil en ataques de race condition.

## MacOS Process Abuse

MacOS, al igual que cualquier otro sistema operativo, proporciona diversos métodos y mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Aunque estas técnicas son esenciales para el funcionamiento eficiente del sistema, los threat actors también pueden abusar de ellas para **realizar actividades maliciosas**.

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

Inter Process Communication (IPC) hace referencia a los distintos métodos mediante los cuales procesos separados **comparten e intercambian datos**. Aunque IPC es fundamental para muchas aplicaciones legítimas, también puede utilizarse de forma indebida para eludir el aislamiento de procesos, hacer leak de información sensible o realizar acciones no autorizadas.


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

Es posible abusar de ciertas capacidades de java (como la variable de entorno **`_JAVA_OPTS`**) para hacer que una aplicación java ejecute **código/comandos arbitrarios**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Es posible inyectar código en aplicaciones .Net mediante el **abuso de la funcionalidad de debugging de .Net** (que no está protegida por mecanismos de protección de macOS como runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Consulta distintas opciones para hacer que un script de Perl ejecute código arbitrario en:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

También es posible abusar de las variables de entorno de ruby para hacer que scripts arbitrarios ejecuten código arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Si la variable de entorno **`PYTHONINSPECT`** está definida, el proceso de python entrará en una cli de python cuando termine. También es posible utilizar **`PYTHONSTARTUP`** para indicar un script de python que se ejecute al inicio de una sesión interactiva.\
Sin embargo, ten en cuenta que el script **`PYTHONSTARTUP`** no se ejecutará cuando **`PYTHONINSPECT`** cree la sesión interactiva.

Otras variables de entorno, como **`PYTHONPATH`** y **`PYTHONHOME`**, también podrían ser útiles para hacer que un comando de python ejecute código arbitrario.

Ten en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizarán estas variables de entorno, aunque se ejecuten utilizando un python embebido.

> [!CAUTION]
> En general, no pude encontrar una forma de hacer que python ejecute código arbitrario abusando de las variables de entorno.\
> Sin embargo, la mayoría de las personas instala pyhton utilizando **Hombrew**, que instalará pyhton en una **ubicación con permisos de escritura** para el usuario admin predeterminado. Puedes hacer hijacking de este archivo con algo como:
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
> Incluso **root** ejecutará este código al ejecutar python.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) es una aplicación open source basada en **EndpointSecurity** que detecta y bloquea process injection. Es una buena referencia de las señales que realmente pueden observarse desde ES, ya que genera alertas sobre:<sup>[[1]](#references)[[2]](#references)</sup>

- **Variables de entorno de injection** durante la ejecución de un proceso: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` y `ELECTRON_RUN_AS_NODE`.
- Llamadas a **`task_for_pid`** —un proceso solicita el task port de otro, requisito previo para inyectarse en él—.
- **Argumentos de debugging de Electron** —`--inspect`, `--inspect-brk` y `--remote-debugging-port`—, que inician una aplicación Electron en modo debug y permiten que cualquiera se conecte y ejecute código en ella.<sup>[[3]](#references)</sup>
- **Creación de symlinks/hardlinks entre distintos niveles de privilegios** —la clásica primitiva de "crear un link como usuario normal y apuntarlo a una ubicación privilegiada". Ten en cuenta que los **symlinks pueden generar alertas, pero no bloquearse**: EndpointSecurity no expone el destino del link antes de su creación.

### Calls made by other processes

En [**esta publicación de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo utilizar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y, posteriormente, obtener información sobre ese otro proceso.<sup>[[4]](#references)</sup>

Ten en cuenta que para llamar a esa función necesitas tener **el mismo uid** que el usuario que ejecuta el proceso o ser **root** (y devuelve información sobre el proceso, no una forma de inyectar código).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
