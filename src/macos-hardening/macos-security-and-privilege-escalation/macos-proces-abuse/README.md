# Abuso de procesos en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica sobre procesos

Un proceso es una instancia de un ejecutable en ejecución; sin embargo, los procesos no ejecutan código: lo hacen los threads. Por lo tanto, **los procesos son solo contenedores para los threads en ejecución** que proporcionan memoria, descriptores, puertos, permisos...

Tradicionalmente, los procesos se iniciaban dentro de otros procesos (excepto PID 1) llamando a **`fork`**, que creaba una copia exacta del proceso actual. Después, el **proceso hijo** normalmente llamaba a **`execve`** para cargar el nuevo ejecutable y ejecutarlo. Más tarde, se introdujo **`vfork`** para acelerar este proceso sin copiar la memoria.\
Luego se introdujo **`posix_spawn`**, que combina **`vfork`** y **`execve`** en una llamada y acepta flags:

- `POSIX_SPAWN_RESETIDS`: Restablece los ids efectivos a los ids reales
- `POSIX_SPAWN_SETPGROUP`: Establece la pertenencia al grupo de procesos
- `POSUX_SPAWN_SETSIGDEF`: Establece el comportamiento predeterminado de las señales
- `POSIX_SPAWN_SETSIGMASK`: Establece la máscara de señales
- `POSIX_SPAWN_SETEXEC`: Ejecuta en el mismo proceso (como `execve`, pero con más opciones)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia suspendido
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sin ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa el allocator Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` en segmentos de datos
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Cierra de forma predeterminada todos los descriptores de archivo al ejecutar exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatoriza los bits altos del desplazamiento de ASLR

Además, `posix_spawn` acepta ajustes **`posix_spawnattr`** que controlan aspectos del proceso creado y entradas **`posix_spawn_file_actions`** que modifican los descriptores de archivo.

Cuando un proceso termina, envía el **código de retorno al proceso padre** (si el padre terminó, el nuevo padre es PID 1) mediante la señal `SIGCHLD`. El padre debe obtener este valor llamando a `wait4()` o `waitid()`; hasta entonces, el hijo permanece en estado zombie: sigue apareciendo en la lista, pero no consume recursos.

### PIDs

Los PIDs (identificadores de proceso) identifican un proceso único. En XNU, los **PIDs** tienen **64 bits**, aumentan monótonamente y **nunca se reinician** (para evitar abusos).

### Grupos de procesos, sesiones y coaliciones

Los **procesos** pueden agruparse para facilitar su administración. Por ejemplo, los comandos de un script de shell estarán en el mismo grupo de procesos, por lo que es posible **enviarles señales conjuntamente**, por ejemplo, usando kill.\
También es posible **agrupar procesos en sesiones**. Cuando un proceso inicia una sesión (`setsid(2)`), los procesos hijo se incorporan a ella, a menos que inicien su propia sesión.

Coalition es otra forma de agrupar procesos en Darwin. Un proceso que se une a una coalition puede acceder a recursos del pool, compartir un ledger o estar sujeto a Jetsam. Las coalitions tienen distintos roles: Leader, servicio XPC y Extension.

### Credenciales y Personae

Cada proceso posee **credenciales** que **identifican sus privilegios** en el sistema. Cada proceso tiene un `uid` principal y un `gid` principal (aunque puede pertenecer a varios grupos).\
También es posible cambiar el id de usuario y de grupo si el binario tiene el bit `setuid/setgid`.\
Hay varias funciones para **establecer nuevos uids/gids**.

La syscall **`persona`** proporciona un conjunto **alternativo** de **credenciales**. Adoptar una persona implica asumir de una vez su uid, gid y pertenencia a grupos. En el [**código fuente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) se puede encontrar la estructura:

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

1. **POSIX Threads (pthreads):** macOS admite POSIX threads (`pthreads`), que forman parte de una API estándar de threading para C/C++. La implementación de pthreads en macOS se encuentra en `/usr/lib/system/libsystem_pthread.dylib`, que proviene del proyecto `libpthread`, disponible públicamente. Esta biblioteca proporciona las funciones necesarias para crear y gestionar threads.
2. **Creación de threads:** La función `pthread_create()` se utiliza para crear nuevos threads. Internamente, esta función llama a `bsdthread_create()`, una llamada al sistema de nivel inferior específica del kernel XNU (el kernel en el que se basa macOS). Esta llamada al sistema recibe varios flags derivados de `pthread_attr` (atributos) que especifican el comportamiento del thread, incluidas las políticas de scheduling y el tamaño de la pila.
   - **Tamaño de pila predeterminado:** El tamaño de pila predeterminado para los nuevos threads es de 512 KB, suficiente para las operaciones habituales, aunque se puede ajustar mediante los atributos del thread si se necesita más o menos espacio.
3. **Inicialización de threads:** La función `__pthread_init()` es fundamental durante la configuración del thread y utiliza el argumento `env[]` para analizar variables de entorno que pueden incluir detalles sobre la ubicación y el tamaño de la pila.

#### Terminación de threads en macOS

1. **Salida de threads:** Los threads suelen terminar llamando a `pthread_exit()`. Esta función permite que un thread finalice correctamente, realice las tareas de limpieza necesarias y envíe un valor de retorno a los threads que esperan unirse a él.
2. **Limpieza de threads:** Al llamar a `pthread_exit()`, se invoca la función `pthread_terminate()`, que elimina todas las estructuras asociadas al thread. Desasigna los puertos de threads de Mach (Mach es el subsistema de comunicación del kernel XNU) y llama a `bsdthread_terminate`, un syscall que elimina las estructuras del kernel asociadas al thread.

#### Mecanismos de sincronización

Para gestionar el acceso a recursos compartidos y evitar condiciones de carrera, macOS proporciona varias primitivas de sincronización. Son fundamentales en entornos multithreading para garantizar la integridad de los datos y la estabilidad del sistema:

1. **Mutexes:**
   - **Mutex normal (firma: 0x4D555458):** Mutex estándar con un tamaño de 60 bytes (56 bytes para el mutex y 4 bytes para la firma).
   - **Mutex rápido (firma: 0x4d55545A):** Similar a un mutex normal, pero optimizado para operaciones más rápidas; también ocupa 60 bytes.
2. **Variables de condición:**
   - Se utilizan para esperar a que se cumplan ciertas condiciones y ocupan 44 bytes (40 bytes más una firma de 4 bytes).
   - **Atributos de variables de condición (firma: 0x434e4441):** Atributos de configuración para las variables de condición, con un tamaño de 12 bytes.
3. **Variable Once (firma: 0x4f4e4345):**
   - Garantiza que un bloque de código de inicialización se ejecute una sola vez. Ocupa 12 bytes.
4. **Read-write locks:**
   - Permiten varios lectores o un escritor a la vez, facilitando el acceso eficiente a los datos compartidos.
   - **Read-write lock (firma: 0x52574c4b):** Ocupa 196 bytes.
   - **Atributos de read-write lock (firma: 0x52574c41):** Atributos para los read-write locks, con un tamaño de 20 bytes.

> [!TIP]
> Los últimos 4 bytes de esos objetos se usan para detectar desbordamientos.

### Variables locales de thread (TLV)

Las **variables locales de thread (TLV)** en el contexto de los archivos Mach-O (el formato de los ejecutables en macOS) se utilizan para declarar variables específicas de **cada thread** en una aplicación multithreading. Así, cada thread tiene su propia instancia independiente de una variable, lo que permite evitar conflictos y mantener la integridad de los datos sin necesitar mecanismos de sincronización explícitos, como los mutexes.

En C y lenguajes relacionados, se puede declarar una variable local de thread mediante la palabra clave **`__thread`**. Así funciona en el ejemplo:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Este fragmento define `tlv_var` como una variable local a cada hilo. Cada hilo que ejecute este código tendrá su propia `tlv_var`, y los cambios que realice un hilo en `tlv_var` no afectarán a la `tlv_var` de otro hilo.

En el binario Mach-O, los datos relacionados con las variables locales a cada hilo se organizan en secciones específicas:

- **`__DATA.__thread_vars`**: Esta sección contiene los metadatos de las variables locales a cada hilo, como sus tipos y su estado de inicialización.
- **`__DATA.__thread_bss`**: Esta sección se utiliza para las variables locales a cada hilo que no se inicializan explícitamente. Es una parte de la memoria reservada para datos inicializados a cero.

Mach-O también proporciona una API específica llamada **`tlv_atexit`** para gestionar las variables locales a cada hilo cuando un hilo termina. Esta API permite **registrar destructores**: funciones especiales que limpian los datos locales al hilo cuando este termina.

### Prioridades de los hilos

Para entender las prioridades de los hilos, hay que ver cómo decide el sistema operativo qué hilos ejecutar y cuándo. Esta decisión depende del nivel de prioridad asignado a cada hilo. En macOS y los sistemas tipo Unix, esto se gestiona mediante conceptos como `nice`, `renice` y las clases Quality of Service (QoS).

#### Nice y Renice

1. **Nice:**
   - El valor `nice` de un proceso es un número que afecta a su prioridad. Cada proceso tiene un valor `nice` que va de -20 (la prioridad más alta) a 19 (la más baja). El valor `nice` predeterminado al crear un proceso suele ser 0.
   - Un valor `nice` más bajo (más cercano a -20) hace que un proceso sea más «egoísta» y obtenga más tiempo de CPU que otros procesos con valores `nice` más altos.
2. **Renice:**
   - `renice` es un comando que se utiliza para cambiar el valor `nice` de un proceso en ejecución. Permite ajustar dinámicamente la prioridad de los procesos, aumentando o reduciendo el tiempo de CPU que reciben según los nuevos valores `nice`.
   - Por ejemplo, si un proceso necesita más recursos de CPU temporalmente, se puede reducir su valor `nice` mediante `renice`.

#### Clases Quality of Service (QoS)

Las clases QoS son un enfoque más moderno para gestionar las prioridades de los hilos, especialmente en sistemas como macOS que admiten **Grand Central Dispatch (GCD)**. Las clases QoS permiten a los desarrolladores **categorizar** el trabajo en distintos niveles según su importancia o urgencia. macOS gestiona automáticamente la priorización de los hilos según estas clases QoS:

1. **User Interactive:**
   - Esta clase se utiliza para tareas que interactúan con el usuario en ese momento o que requieren resultados inmediatos para ofrecer una buena experiencia. Estas tareas reciben la máxima prioridad para mantener la interfaz receptiva (por ejemplo, las animaciones o la gestión de eventos).
2. **User Initiated:**
   - Tareas iniciadas por el usuario para las que se esperan resultados inmediatos, como abrir un documento o hacer clic en un botón que requiere cálculos. Tienen prioridad alta, pero inferior a User Interactive.
3. **Utility:**
   - Estas tareas son de larga duración y suelen mostrar un indicador de progreso (por ejemplo, descargar archivos o importar datos). Tienen menor prioridad que las tareas iniciadas por el usuario y no necesitan finalizar de inmediato.
4. **Background:**
   - Esta clase se utiliza para tareas que se ejecutan en segundo plano y no son visibles para el usuario. Pueden ser tareas como indexar, sincronizar o realizar copias de seguridad. Tienen la prioridad más baja y un impacto mínimo en el rendimiento del sistema.

Con las clases QoS, los desarrolladores no necesitan gestionar los valores de prioridad exactos: pueden centrarse en la naturaleza de la tarea y el sistema optimiza los recursos de CPU en consecuencia.

Además, existen distintas **políticas de planificación de hilos** que permiten especificar un conjunto de parámetros de planificación que el planificador tendrá en cuenta. Esto se puede hacer mediante `thread_policy_[set/get]`. Puede resultar útil en ataques de race condition.

## Abuso de procesos en macOS

macOS proporciona numerosos mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Aunque estos mecanismos son esenciales para el funcionamiento normal del sistema, los atacantes pueden abusar de ellos para realizar injection, ejecutar código o acceder a datos.

### Library Injection

Library Injection es una técnica mediante la cual un atacante **obliga a un proceso a cargar una biblioteca maliciosa**. Una vez inyectada, la biblioteca se ejecuta en el contexto del proceso objetivo y proporciona al atacante los mismos permisos y accesos que tiene ese proceso.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste en **interceptar llamadas a funciones** o mensajes dentro del código de un programa. Al interceptar funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos confidenciales o incluso controlar el flujo de ejecución.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Esta página trata los metadatos de unwind de ARM64, las restricciones de PAC de arm64e y las cadenas de llamadas sintéticas.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Comunicación entre procesos

La comunicación entre procesos (IPC) se refiere a los distintos métodos que permiten a procesos separados **compartir e intercambiar datos**. Aunque IPC es fundamental para muchas aplicaciones legítimas, también se puede utilizar indebidamente para subvertir el aislamiento entre procesos, hacer leak de información confidencial o realizar acciones no autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Las aplicaciones Electron ejecutadas con variables de entorno específicas pueden ser vulnerables a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Es posible utilizar las flags `--load-extension` y `--use-fake-ui-for-media-stream` para realizar un **man in the browser attack** que permita robar pulsaciones de teclas, tráfico y cookies, e inyectar scripts en páginas...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Los archivos NIB **definen elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios**, y **Gatekeeper no impide** que una aplicación ya ejecutada vuelva a ejecutarse si se **modifica un archivo NIB**. Por lo tanto, se podrían utilizar para hacer que programas arbitrarios ejecuten comandos arbitrarios:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es posible inyectar opciones de JVM mediante **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`** y cargar un agente Java o nativo antes de que se inicie la aplicación.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** precarga JavaScript controlado por el atacante mediante `--require` (archivo) o `--import data:text/javascript,…` (sin archivo, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carga un módulo en un REPL interactivo, y **`ELECTRON_RUN_AS_NODE`** vuelve a habilitar todo esto en binarios de Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Es posible inyectar código en aplicaciones .NET mediante **`DOTNET_STARTUP_HOOKS`** antes de `Main`, o abusando de la funcionalidad de depuración de .NET cuando se cumplen sus requisitos previos.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash no interactivo lee **`BASH_ENV`**; los shells POSIX interactivos leen **`ENV`**; zsh lee **`$ZDOTDIR/.zshenv`**; y fish lee archivos de configuración en **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Cada uno puede ejecutar un archivo de inicio controlado antes del comando previsto. Bash también ejecuta una sustitución de comandos colocada en **`PS4`** cada vez que se habilita xtrace (por ejemplo, mediante **`SHELLOPTS=xtrace`** heredado):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Al iniciar `/bin/zsh -s`, el shell lee un programa desde la entrada estándar. Por lo tanto, un descargador que copie un documento estructurado no confiable en la entrada estándar del proceso hijo sin analizarlo primero convierte todo el documento en código fuente del shell. Se observó un loader que enviaba línea por línea un archivo iCalendar público mediante una pipe anónima. Los metadatos del calendario fallaban como comandos, pero zsh continuaba hasta llegar a líneas ejecutables colocadas después de `DESCRIPTION:`. Esas líneas descargaban e iniciaban el siguiente bundle de aplicación. El tipo de contenido esperado del archivo y el hecho de que estuviera alojado en un sitio de confianza no lo hacían seguro; el límite peligroso era pasar sus bytes a un intérprete.<sup>[[5]](#references)</sup>

Las etapas relacionadas se tratan en [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) y [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** pueden cargar una configuración PHP controlada cuyo **`auto_prepend_file`** se ejecuta antes del script objetivo.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

El intérprete independiente de Lua ejecuta código o un `@file` de **`LUA_INIT`** (o su variante específica de versión) antes de procesar el script objetivo.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** y **`R_PROFILE`** redirigen a perfiles de inicio que contienen código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, junto con una ruta de biblioteca de R, pueden cargar automáticamente un paquete instalado.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige al depot cuyo archivo `config/startup.jl` se ejecuta automáticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** pueden inyectar una expresión **`-eval`** en la VM de Erlang sin necesidad de un archivo de payload; las cargas de trabajo de Elixir suelen iniciar la misma VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** y **`OCTAVE_VERSION_INITFILE`** redirigen a scripts de inicio de Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` es una aplicación .NET multiplataforma, por lo que varias variables de entorno permiten la ejecución previa al comando: **`XDG_CONFIG_HOME`** redirige a los scripts de perfil que se ejecutan al inicio, **`PSModulePath`** permite secuestrar la carga automática de módulos (un archivo `.psm1` colocado allí se ejecuta al importarse y puede suplantar cmdlets integrados), y las variables de .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** y **`DOTNET_STARTUP_HOOKS`** cargan código del atacante en el proceso antes de `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Comprueba distintas opciones para hacer que un script Perl ejecute código arbitrario en:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

También es posible abusar de las variables de entorno de ruby (**`RUBYOPT`**, **`RUBYLIB`**) para hacer que scripts arbitrarios ejecuten código arbitrario:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

La cadena de la biblioteca estándar **`PYTHONWARNINGS`** y **`BROWSER`** puede ejecutar un comando durante el análisis de filtros de advertencias. Una alternativa basada en archivos coloca `sitecustomize.py` en **`PYTHONPATH`** para que la inicialización normal de `site` lo importe antes del script objetivo. **`PYTHONBREAKPOINT`** ejecuta un callable/módulo elegido cuando el código llega a `breakpoint()`. Las variables exclusivas del modo interactivo, como **`PYTHONSTARTUP`**, tienen una aplicabilidad más limitada.

Ten en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizan estas variables de entorno, aunque se ejecuten con un Python integrado.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (y su alternativa `EXINIT`) se ejecutan como comandos Ex durante el inicio normal, por lo que `:!cmd` / `:call system(...)` permiten la ejecución de código cuando una víctima abre Vim/Neovim con un entorno controlado:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Por otro lado, Homebrew suele instalar Python en `/opt/homebrew`, donde los miembros del grupo `admin` local pueden tener la posibilidad de reemplazar el launcher. Esto es un secuestro de binario con permisos de escritura, no una inyección mediante variables de entorno; comprueba la propiedad y las ACL antes de considerarlo explotable.


## Detección

### Shield

[**Shield**](https://github.com/theevilbit/Shield) es una aplicación de código abierto basada en **EndpointSecurity** que detecta y bloquea process injection. Es una buena referencia para saber qué señales se pueden observar mediante Endpoint Security, ya que genera alertas sobre:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variables de entorno de Injection** al ejecutar procesos: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` y `ELECTRON_RUN_AS_NODE`.
- Llamadas a **`task_for_pid`**: un proceso solicita el puerto de tarea de otro, requisito previo para inyectarse en él.
- **Argumentos de depuración de Electron**: `--inspect`, `--inspect-brk` y `--remote-debugging-port`, que inician una aplicación Electron en modo de depuración y permiten que cualquiera se conecte y ejecute código en ella.<sup>[[3]](#references)</sup>
- **Creación de symlinks/hardlinks entre niveles de privilegio**: la técnica clásica de «crear un enlace como usuario normal y apuntarlo a una ubicación privilegiada». Ten en cuenta que **se pueden generar alertas sobre los symlinks, pero no bloquearlos**: EndpointSecurity no expone el destino del enlace antes de su creación.

### Llamadas realizadas por otros procesos

En [**esta publicación de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo utilizar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y, después, obtener información sobre ese otro proceso.<sup>[[4]](#references)</sup>

Ten en cuenta que para llamar a esa función debes tener **el mismo uid** que el proceso en ejecución o ser **root** (y devuelve información sobre el proceso, no una forma de inyectar código).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — detección de process injection en macOS de código abierto (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por qué las aplicaciones Electron no pueden almacenar tus secretos de forma confidencial: la opción --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detección de modificaciones de tareas](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Una nueva versión del stealer para macOS MacSync apunta a entusiastas de las criptomonedas y desarrolladores](https://securelist.com/macsync-new-version/121383/)
