# Abuso de procesos en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica de los procesos

Un proceso es una instancia de un ejecutable en ejecución; sin embargo, los procesos no ejecutan código, sino que lo hacen los threads. Por lo tanto, **los procesos son simplemente contenedores para ejecutar threads** que proporcionan la memoria, los descriptores, los puertos, los permisos...

Tradicionalmente, los procesos se iniciaban dentro de otros procesos (excepto el PID 1) llamando a **`fork`**, que creaba una copia exacta del proceso actual, y después el **proceso hijo** generalmente llamaba a **`execve`** para cargar el nuevo ejecutable y ejecutarlo. Después se introdujo **`vfork`** para hacer este proceso más rápido sin copiar memoria.\
Luego se introdujo **`posix_spawn`**, que combina **`vfork`** y **`execve`** en una sola llamada y acepta flags:

- `POSIX_SPAWN_RESETIDS`: Restablecer los ids efectivos a los ids reales
- `POSIX_SPAWN_SETPGROUP`: Establecer la afiliación al grupo de procesos
- `POSUX_SPAWN_SETSIGDEF`: Establecer el comportamiento predeterminado de las señales
- `POSIX_SPAWN_SETSIGMASK`: Establecer la máscara de señales
- `POSIX_SPAWN_SETEXEC`: Ejecutar en el mismo proceso (como `execve` con más opciones)
- `POSIX_SPAWN_START_SUSPENDED`: Iniciar suspendido
- `_POSIX_SPAWN_DISABLE_ASLR`: Iniciar sin ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usar el asignador Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permitir `rwx` en los segmentos de datos
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Cerrar todas las descripciones de archivos al ejecutar exec(2) de forma predeterminada
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatorizar los bits altos del desplazamiento de ASLR

Además, `posix_spawn` acepta configuraciones **`posix_spawnattr`** que controlan aspectos del proceso creado y entradas **`posix_spawn_file_actions`** que modifican los descriptores de archivos.

Cuando un proceso muere, envía el **código de retorno al proceso padre** (si el padre ha muerto, el nuevo padre es el PID 1) mediante la señal `SIGCHLD`. El padre necesita obtener este valor llamando a `wait4()` o `waitid()` y, hasta que eso ocurra, el hijo permanece en un estado zombie en el que sigue apareciendo en la lista, pero no consume recursos.

### PIDs

Los PIDs, identificadores de procesos, identifican un proceso único. En XNU, los **PIDs** tienen **64 bits**, aumentan monótonamente y **nunca hacen wrap** (para evitar abusos).

### Grupos de procesos, sesiones y coaliciones

Los **procesos** pueden insertarse en **grupos** para facilitar su gestión. Por ejemplo, los comandos de un script de shell estarán en el mismo grupo de procesos, por lo que es posible **enviarles señales conjuntamente** usando kill, por ejemplo.\
También es posible **agrupar procesos en sesiones**. Cuando un proceso inicia una sesión (`setsid(2)`), los procesos hijos se establecen dentro de la sesión, a menos que inicien su propia sesión.

Coalition es otra forma de agrupar procesos en Darwin. Un proceso que se une a una coalition puede acceder a recursos agrupados, compartir un ledger o enfrentarse a Jetsam. Las coalitions tienen diferentes roles: Leader, servicio XPC y Extension.

### Credenciales y personas

Cada proceso tiene **credenciales** que **identifican sus privilegios** en el sistema. Cada proceso tendrá un `uid` primario y un `gid` primario (aunque puede pertenecer a varios grupos).\
También es posible cambiar el id de usuario y de grupo si el binario tiene el bit `setuid/setgid`.\
Existen varias funciones para **establecer nuevos uids/gids**.

La syscall **`persona`** proporciona un conjunto **alternativo** de **credenciales**. Adoptar una persona asume su uid, gid y pertenencia a grupos **a la vez**. En el [**código fuente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) es posible encontrar la struct:
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
## Información básica sobre los threads

1. **POSIX Threads (pthreads):** macOS admite POSIX threads (`pthreads`), que forman parte de una API estándar de threading para C/C++. La implementación de pthreads en macOS se encuentra en `/usr/lib/system/libsystem_pthread.dylib`, que proviene del proyecto `libpthread` disponible públicamente. Esta library proporciona las funciones necesarias para crear y gestionar threads.
2. **Creación de threads:** La función `pthread_create()` se utiliza para crear nuevos threads. Internamente, esta función llama a `bsdthread_create()`, que es una llamada al sistema de nivel inferior específica del kernel XNU (el kernel en el que se basa macOS). Esta llamada al sistema recibe varios flags derivados de `pthread_attr` (atributos) que especifican el comportamiento del thread, incluidas las políticas de scheduling y el tamaño del stack.
- **Tamaño predeterminado del stack:** El tamaño predeterminado del stack para los nuevos threads es de 512 KB, lo que es suficiente para las operaciones habituales, pero puede ajustarse mediante los atributos del thread si se necesita más o menos espacio.
3. **Inicialización del thread:** La función `__pthread_init()` es crucial durante la configuración del thread, ya que utiliza el argumento `env[]` para analizar variables de entorno que pueden incluir información sobre la ubicación y el tamaño del stack.

#### Terminación de threads en macOS

1. **Salida de threads:** Normalmente, los threads se terminan llamando a `pthread_exit()`. Esta función permite que un thread salga correctamente, realizando la limpieza necesaria y permitiéndole enviar un valor de retorno a cualquier thread que realice un join.
2. **Limpieza del thread:** Al llamar a `pthread_exit()`, se invoca la función `pthread_terminate()`, que gestiona la eliminación de todas las estructuras asociadas al thread. Desasigna los ports de threads de Mach (Mach es el subsistema de comunicación del kernel XNU) y llama a `bsdthread_terminate`, una syscall que elimina las estructuras a nivel de kernel asociadas al thread.

#### Mecanismos de sincronización

Para gestionar el acceso a recursos compartidos y evitar condiciones de carrera, macOS proporciona varias primitivas de sincronización. Estas son fundamentales en entornos multithreading para garantizar la integridad de los datos y la estabilidad del sistema:

1. **Mutexes:**
- **Mutex regular (Signature: 0x4D555458):** Mutex estándar con un tamaño de 60 bytes (56 bytes para el mutex y 4 bytes para la signature).
- **Fast Mutex (Signature: 0x4d55545A):** Similar a un mutex regular, pero optimizado para operaciones más rápidas; también tiene un tamaño de 60 bytes.
2. **Variables de condición:**
- Se utilizan para esperar a que se produzcan determinadas condiciones, con un tamaño de 44 bytes (40 bytes más una signature de 4 bytes).
- **Atributos de las variables de condición (Signature: 0x434e4441):** Atributos de configuración para las variables de condición, con un tamaño de 12 bytes.
3. **Variable Once (Signature: 0x4f4e4345):**
- Garantiza que un fragmento de código de inicialización se ejecute una sola vez. Su tamaño es de 12 bytes.
4. **Read-Write Locks:**
- Permiten varios lectores o un único writer a la vez, facilitando un acceso eficiente a los datos compartidos.
- **Read Write Lock (Signature: 0x52574c4b):** Tiene un tamaño de 196 bytes.
- **Atributos de Read Write Lock (Signature: 0x52574c41):** Atributos para read-write locks, con un tamaño de 20 bytes.

> [!TIP]
> Los últimos 4 bytes de esos objetos se utilizan para detectar overflows.

### Thread Local Variables (TLV)

Las **Thread Local Variables (TLV)**, en el contexto de los archivos Mach-O (el formato de los ejecutables en macOS), se utilizan para declarar variables específicas de **cada thread** en una aplicación multithreading. Esto garantiza que cada thread tenga su propia instancia independiente de una variable, proporcionando una forma de evitar conflictos y mantener la integridad de los datos sin necesidad de mecanismos de sincronización explícitos, como los mutexes.

En C y lenguajes relacionados, puedes declarar una variable thread-local mediante la palabra clave **`__thread`**. Así es como funciona en el ejemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este fragmento define `tlv_var` como una variable local del thread. Cada thread que ejecute este código tendrá su propio `tlv_var`, y los cambios que un thread realice en `tlv_var` no afectarán al `tlv_var` de otro thread.

En el binario Mach-O, los datos relacionados con las variables locales del thread se organizan en secciones específicas:

- **`__DATA.__thread_vars`**: Esta sección contiene los metadatos sobre las variables locales del thread, como sus tipos y su estado de inicialización.
- **`__DATA.__thread_bss`**: Esta sección se utiliza para las variables locales del thread que no se inicializan explícitamente. Es una parte de la memoria reservada para datos inicializados a cero.

Mach-O también proporciona una API específica llamada **`tlv_atexit`** para gestionar las variables locales del thread cuando un thread termina. Esta API permite **registrar destructors** —funciones especiales que limpian los datos locales del thread cuando un thread termina—.

### Threading Priorities

Comprender las prioridades de los threads implica analizar cómo el sistema operativo decide qué threads ejecutar y cuándo. Esta decisión está influenciada por el nivel de prioridad asignado a cada thread. En macOS y los sistemas similares a Unix, esto se gestiona mediante conceptos como `nice`, `renice` y las clases Quality of Service (QoS).

#### Nice y Renice

1. **Nice:**
- El valor `nice` de un proceso es un número que afecta a su prioridad. Cada proceso tiene un valor nice que va de -20 (la prioridad más alta) a 19 (la prioridad más baja). El valor nice predeterminado cuando se crea un proceso suele ser 0.
- Un valor nice más bajo (más cercano a -20) hace que un proceso sea más "egoísta", dándole más tiempo de CPU en comparación con otros procesos con valores nice más altos.
2. **Renice:**
- `renice` es un comando utilizado para cambiar el valor nice de un proceso que ya está en ejecución. Puede utilizarse para ajustar dinámicamente la prioridad de los procesos, aumentando o reduciendo la asignación de tiempo de CPU según los nuevos valores nice.
- Por ejemplo, si un proceso necesita temporalmente más recursos de CPU, se puede reducir su valor nice mediante `renice`.

#### Quality of Service (QoS) Classes

Las clases QoS son un enfoque más moderno para gestionar las prioridades de los threads, especialmente en sistemas como macOS que admiten **Grand Central Dispatch (GCD)**. Las clases QoS permiten a los desarrolladores **categorizar** el trabajo en distintos niveles según su importancia o urgencia. macOS gestiona automáticamente la priorización de los threads según estas clases QoS:

1. **User Interactive:**
- Esta clase se utiliza para tareas que interactúan con el usuario en ese momento o que requieren resultados inmediatos para ofrecer una buena experiencia de usuario. Estas tareas reciben la prioridad más alta para mantener la interfaz receptiva (por ejemplo, animaciones o gestión de eventos).
2. **User Initiated:**
- Tareas iniciadas por el usuario para las que espera resultados inmediatos, como abrir un documento o hacer clic en un botón que requiere cálculos. Tienen una prioridad alta, pero inferior a User Interactive.
3. **Utility:**
- Estas tareas se ejecutan durante mucho tiempo y normalmente muestran un indicador de progreso (por ejemplo, descargar archivos o importar datos). Tienen una prioridad inferior a las tareas iniciadas por el usuario y no necesitan terminar inmediatamente.
4. **Background:**
- Esta clase se utiliza para tareas que funcionan en segundo plano y no son visibles para el usuario. Pueden ser tareas como indexación, sincronización o backups. Tienen la prioridad más baja y un impacto mínimo en el rendimiento del sistema.

Al utilizar clases QoS, los desarrolladores no necesitan gestionar los valores exactos de prioridad, sino centrarse en la naturaleza de la tarea, mientras el sistema optimiza los recursos de CPU en consecuencia.

Además, existen distintas **thread scheduling policies** que permiten especificar un conjunto de parámetros de scheduling que el scheduler tendrá en cuenta. Esto puede hacerse mediante `thread_policy_[set/get]`. Puede resultar útil en ataques de race condition.

## macOS Process Abuse

macOS proporciona muchos mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Aunque estos mecanismos son esenciales para el funcionamiento normal del sistema, los atacantes pueden abusar de ellos para realizar injection, code execution o acceder a datos.

### Library Injection

Library Injection es una técnica mediante la cual un atacante **obliga a un proceso a cargar una library maliciosa**. Una vez inyectada, la library se ejecuta en el contexto del proceso objetivo, proporcionando al atacante los mismos permisos y acceso que tiene el proceso.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste en **interceptar llamadas a funciones** o mensajes dentro del código de un software. Al hacer hooking de funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos sensibles o incluso obtener el control del flujo de ejecución.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) hace referencia a los distintos métodos mediante los cuales procesos separados **comparten e intercambian datos**. Aunque IPC es fundamental para muchas aplicaciones legítimas, también puede utilizarse indebidamente para evadir el aislamiento de procesos, hacer leak de información sensible o realizar acciones no autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Las aplicaciones Electron ejecutadas con determinadas variables de entorno podrían ser vulnerables a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Es posible utilizar los flags `--load-extension` y `--use-fake-ui-for-media-stream` para realizar un **man in the browser attack**, lo que permite robar pulsaciones de teclas, tráfico y cookies, e inyectar scripts en páginas...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Los archivos NIB **definen elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios** y **Gatekeeper no impide** que una aplicación ya ejecutada vuelva a ejecutarse si se **modifica un archivo NIB**. Por lo tanto, podrían utilizarse para hacer que programas arbitrarios ejecuten comandos arbitrarios:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es posible inyectar opciones de JVM mediante **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`**, y cargar un agente Java o nativo antes de que se inicie la aplicación.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** precarga JavaScript del atacante mediante `--require` (archivo) o `--import data:text/javascript,…` (sin archivo, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carga un módulo en un REPL interactivo, y **`ELECTRON_RUN_AS_NODE`** vuelve a habilitar todo esto en binarios Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Es posible inyectar código en aplicaciones .NET mediante **`DOTNET_STARTUP_HOOKS`** antes de `Main`, o abusando de la funcionalidad de debugging de .NET cuando sus requisitos previos están presentes.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash no interactivo lee **`BASH_ENV`**; los shells POSIX interactivos leen **`ENV`**; zsh lee **`$ZDOTDIR/.zshenv`**; y fish lee la configuración situada bajo **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Cada uno puede ejecutar un archivo de inicio controlado antes del comando previsto. Bash también ejecuta una command substitution colocada en **`PS4`** cada vez que xtrace está habilitado (por ejemplo, mediante **`SHELLOPTS=xtrace`** heredado):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** pueden cargar una configuración PHP controlada cuyo **`auto_prepend_file`** se ejecuta antes del script objetivo.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

El intérprete Lua independiente ejecuta código o un `@file` desde **`LUA_INIT`** (o su variante específica de versión) antes de procesar el script objetivo.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** y **`R_PROFILE`** redirigen los perfiles de inicio que contienen código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, junto con una ruta a una library de R, pueden cargar automáticamente un package instalado.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige el depot cuyo `config/startup.jl` se ejecuta automáticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** pueden inyectar una expresión de Erlang **`-eval`** sin requerir un archivo de payload; las cargas de trabajo de Elixir suelen iniciar la misma VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** y **`OCTAVE_VERSION_INITFILE`** redirigen los scripts de inicio de Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` es una aplicación .NET multiplataforma, por lo que varias variables de entorno permiten la ejecución antes del comando: **`XDG_CONFIG_HOME`** redirige los scripts de perfil que se ejecutan al inicio, **`PSModulePath`** secuestra la carga automática de módulos (un `.psm1` plantado se ejecuta durante la importación y puede ocultar cmdlets integrados), y las variables .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** y **`DOTNET_STARTUP_HOOKS`** cargan código del atacante en el proceso antes de `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Consulta distintas opciones para hacer que un script Perl ejecute código arbitrario en:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

También es posible abusar de las variables de entorno de ruby (**`RUBYOPT`**, **`RUBYLIB`**) para hacer que scripts arbitrarios ejecuten código arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

La cadena de la standard library basada en **`PYTHONWARNINGS`** y **`BROWSER`** puede ejecutar un comando durante el parsing de filtros de warnings. Una alternativa basada en archivos coloca `sitecustomize.py` en **`PYTHONPATH`**, de modo que la inicialización normal de `site` lo importe antes del script objetivo. **`PYTHONBREAKPOINT`** ejecuta un callable/module elegido cuando el código alcanza `breakpoint()`. Las variables exclusivas del modo interactivo, como **`PYTHONSTARTUP`**, tienen una aplicabilidad más limitada.

Ten en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizarán estas variables de entorno, aunque se ejecuten usando un Python embebido.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (y su fallback **`EXINIT`**) se ejecutan como comandos Ex durante un inicio normal, por lo que `:!cmd` / `:call system(...)` permiten code execution cuando una víctima abre Vim/Neovim con un entorno controlado:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Por separado, Homebrew suele instalar Python debajo de `/opt/homebrew`, donde los miembros del grupo local `admin` podrían poder reemplazar el launcher. Eso constituye un writable-binary hijack y no una injection mediante variables de entorno; verifica la propiedad y las ACL antes de considerarlo explotable.


## Detección

### Shield

[**Shield**](https://github.com/theevilbit/Shield) es una aplicación open source basada en **EndpointSecurity** que detecta y bloquea process injection. Es una buena referencia sobre qué señales son observables mediante Endpoint Security, ya que genera alertas sobre:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variables de entorno de injection** durante la ejecución del proceso: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` y `ELECTRON_RUN_AS_NODE`.
- Llamadas a **`task_for_pid`** —un proceso solicitando el task port de otro, requisito previo para inyectarse en él—.
- **Argumentos de debugging de Electron** —`--inspect`, `--inspect-brk` y `--remote-debugging-port`, que inician una aplicación Electron en modo debug y permiten que cualquiera se conecte y ejecute código en ella—.<sup>[[3]](#references)</sup>
- **Creación de symlinks/hardlinks entre niveles de privilegio** —la primitiva clásica de "plantar un link como usuario normal y apuntarlo a una ubicación privilegiada". Ten en cuenta que los **symlinks pueden generar alertas, pero no bloquearse**: EndpointSecurity no expone el destino del link antes de su creación.

### Calls made by other processes

En [**esta entrada de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo utilizar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y, posteriormente, obtener información sobre ese otro proceso.<sup>[[4]](#references)</sup>

Ten en cuenta que para llamar a esa función debes tener **el mismo uid** que el proceso en ejecución o ser **root** (y devuelve información sobre el proceso, no una forma de inyectar código).

## References

- [1] [Shield — detección open source de process injection en macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por qué las aplicaciones Electron no pueden almacenar tus secretos de forma confidencial: opción --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detección de modificaciones de tareas](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
