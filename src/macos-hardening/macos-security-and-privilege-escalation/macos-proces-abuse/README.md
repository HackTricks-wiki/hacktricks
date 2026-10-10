# Abuso de procesos en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica sobre los procesos

Un proceso es una instancia de un ejecutable en ejecución; sin embargo, los procesos no ejecutan código: lo hacen los threads. Por lo tanto, **los procesos son solo contenedores para ejecutar threads** que proporcionan memoria, descriptores, puertos, permisos...

Tradicionalmente, los procesos se iniciaban dentro de otros procesos (excepto PID 1) mediante una llamada a **`fork`**, que creaba una copia exacta del proceso actual. Luego, el **proceso hijo** generalmente llamaba a **`execve`** para cargar el nuevo ejecutable y ejecutarlo. Después se introdujo **`vfork`** para acelerar este proceso sin copiar memoria.\
Luego se introdujo **`posix_spawn`**, que combina **`vfork`** y **`execve`** en una sola llamada y acepta flags:

- `POSIX_SPAWN_RESETIDS`: Restablece los ids efectivos a los ids reales
- `POSIX_SPAWN_SETPGROUP`: Establece la pertenencia al grupo de procesos
- `POSUX_SPAWN_SETSIGDEF`: Establece el comportamiento predeterminado de las señales
- `POSIX_SPAWN_SETSIGMASK`: Establece la máscara de señales
- `POSIX_SPAWN_SETEXEC`: Ejecuta en el mismo proceso (como `execve`, con más opciones)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia suspendido
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sin ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa el asignador Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` en los segmentos de datos
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Cierra todos los descriptores de archivo de forma predeterminada al ejecutar exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatoriza los bits altos del desplazamiento de ASLR

Además, `posix_spawn` acepta opciones **`posix_spawnattr`** que controlan aspectos del proceso creado y entradas **`posix_spawn_file_actions`** que modifican los descriptores de archivo.

Cuando un proceso muere, envía el **código de retorno al proceso padre** mediante la señal `SIGCHLD` (si el padre murió, el nuevo padre es PID 1). El padre debe obtener este valor llamando a `wait4()` o `waitid()`; hasta que esto ocurra, el hijo permanece en estado zombi: sigue apareciendo en la lista, pero no consume recursos.

### PIDs

Los PIDs (identificadores de proceso) identifican un proceso único. En XNU, los **PIDs** tienen **64 bits**, aumentan de forma monótona y **nunca se reinician** (para evitar abusos).

### Grupos de procesos, sesiones y coaliciones

Los **procesos** pueden agruparse para que sea más fácil administrarlos. Por ejemplo, los comandos de un script de shell estarán en el mismo grupo de procesos, lo que permite **enviarles señales conjuntamente**, por ejemplo, mediante `kill`.\
También es posible **agrupar procesos en sesiones**. Cuando un proceso inicia una sesión (`setsid(2)`), los procesos hijos se incorporan a ella, salvo que inicien su propia sesión.

Una coalición es otra forma de agrupar procesos en Darwin. Al unirse a una coalición, un proceso puede acceder a recursos de pool, compartir un ledger o verse afectado por Jetsam. Las coaliciones tienen distintos roles: líder, servicio XPC y extensión.

### Credenciales y Personae

Cada proceso contiene **credenciales** que **identifican sus privilegios** en el sistema. Cada proceso tiene un `uid` principal y un `gid` principal (aunque puede pertenecer a varios grupos).\
También es posible cambiar el ID de usuario y de grupo si el binario tiene el bit `setuid/setgid`.\
Hay varias funciones para **establecer nuevos uids/gids**.

La syscall **`persona`** proporciona un conjunto **alternativo** de **credenciales**. Adoptar una persona implica asumir al mismo tiempo su uid, gid y pertenencia a grupos. En el [**código fuente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) se puede encontrar la estructura:

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

## Información básica sobre los hilos

1. **POSIX Threads (pthreads):** macOS admite los hilos POSIX (`pthreads`), que forman parte de una API estándar de hilos para C/C++. La implementación de pthreads en macOS se encuentra en `/usr/lib/system/libsystem_pthread.dylib`, que proviene del proyecto `libpthread`, disponible públicamente. Esta biblioteca proporciona las funciones necesarias para crear y administrar hilos.
2. **Creación de hilos:** La función `pthread_create()` se usa para crear hilos nuevos. Internamente, esta función llama a `bsdthread_create()`, una llamada al sistema de nivel inferior específica del kernel XNU (el kernel en el que se basa macOS). Esta llamada al sistema recibe varias flags derivadas de `pthread_attr` (atributos), que especifican el comportamiento del hilo, incluidas las políticas de planificación y el tamaño de la pila.
   - **Tamaño de pila predeterminado:** El tamaño de pila predeterminado para los hilos nuevos es de 512 KB, suficiente para las operaciones habituales, aunque puede ajustarse mediante los atributos del hilo si se necesita más o menos espacio.
3. **Inicialización de hilos:** La función `__pthread_init()` es fundamental durante la configuración del hilo y utiliza el argumento `env[]` para analizar variables de entorno que pueden incluir detalles sobre la ubicación y el tamaño de la pila.

#### Terminación de hilos en macOS

1. **Finalización de hilos:** Normalmente, los hilos se terminan llamando a `pthread_exit()`. Esta función permite que un hilo finalice correctamente, realice las tareas de limpieza necesarias y devuelva un valor a los hilos que lo esperen mediante join.
2. **Limpieza de hilos:** Al llamar a `pthread_exit()`, se invoca la función `pthread_terminate()`, que se encarga de eliminar todas las estructuras asociadas al hilo. Esta función desasigna los puertos de hilo de Mach (Mach es el subsistema de comunicación del kernel XNU) y llama a `bsdthread_terminate`, una syscall que elimina las estructuras del kernel asociadas al hilo.

#### Mecanismos de sincronización

Para administrar el acceso a los recursos compartidos y evitar condiciones de carrera, macOS proporciona varias primitivas de sincronización. Son fundamentales en entornos multihilo para garantizar la integridad de los datos y la estabilidad del sistema:

1. **Mutexes:**
   - **Mutex normal (firma: 0x4D555458):** Mutex estándar con una huella de memoria de 60 bytes (56 bytes para el mutex y 4 bytes para la firma).
   - **Mutex rápido (firma: 0x4d55545A):** Similar a un mutex normal, pero optimizado para operaciones más rápidas; también ocupa 60 bytes.
2. **Variables de condición:**
   - Se usan para esperar a que se cumplan ciertas condiciones y ocupan 44 bytes (40 bytes más una firma de 4 bytes).
   - **Atributos de variables de condición (firma: 0x434e4441):** Atributos de configuración para las variables de condición, con un tamaño de 12 bytes.
3. **Variable once (firma: 0x4f4e4345):**
   - Garantiza que un fragmento de código de inicialización se ejecute una sola vez. Ocupa 12 bytes.
4. **Bloqueos de lectura y escritura:**
   - Permiten que haya varios lectores o un escritor a la vez, lo que facilita el acceso eficiente a los datos compartidos.
   - **Bloqueo de lectura y escritura (firma: 0x52574c4b):** Ocupa 196 bytes.
   - **Atributos de bloqueo de lectura y escritura (firma: 0x52574c41):** Atributos para los bloqueos de lectura y escritura; ocupan 20 bytes.

> [!TIP]
> Los últimos 4 bytes de esos objetos se usan para detectar desbordamientos.

### Variables locales de hilo (TLV)

Las **variables locales de hilo (TLV)** en el contexto de los archivos Mach-O (el formato de los ejecutables en macOS) se usan para declarar variables específicas de **cada hilo** en una aplicación multihilo. Esto garantiza que cada hilo tenga su propia instancia independiente de una variable, lo que permite evitar conflictos y mantener la integridad de los datos sin necesitar mecanismos de sincronización explícitos, como los mutexes.

En C y lenguajes relacionados, puedes declarar una variable local de hilo usando la palabra clave **`__thread`**. Así funciona en el ejemplo:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Este fragmento define `tlv_var` como una variable local al hilo. Cada hilo que ejecute este código tendrá su propio `tlv_var`, y los cambios que haga un hilo en `tlv_var` no afectarán al `tlv_var` de otro hilo.

En el binario Mach-O, los datos relacionados con las variables locales al hilo se organizan en secciones específicas:

- **`__DATA.__thread_vars`**: Esta sección contiene los metadatos de las variables locales al hilo, como sus tipos y su estado de inicialización.
- **`__DATA.__thread_bss`**: Esta sección se utiliza para las variables locales al hilo que no se inicializan explícitamente. Es una parte de la memoria reservada para datos inicializados en cero.

Mach-O también proporciona una API específica llamada **`tlv_atexit`** para gestionar las variables locales al hilo cuando este termina. Esta API permite **registrar destructores**: funciones especiales que limpian los datos locales al hilo cuando este finaliza.

### Prioridades de los hilos

Para entender las prioridades de los hilos, hay que ver cómo decide el sistema operativo qué hilos ejecutar y cuándo. Esta decisión depende del nivel de prioridad asignado a cada hilo. En macOS y en los sistemas tipo Unix, esto se gestiona mediante conceptos como `nice`, `renice` y las clases de Quality of Service (QoS).

#### Nice y Renice

1. **Nice:**
   - El valor `nice` de un proceso es un número que afecta a su prioridad. Cada proceso tiene un valor `nice` que va de -20 (la prioridad más alta) a 19 (la más baja). El valor `nice` predeterminado al crear un proceso suele ser 0.
   - Un valor `nice` más bajo (más cercano a -20) hace que un proceso sea más «egoísta», al darle más tiempo de CPU que a otros procesos con valores `nice` más altos.
2. **Renice:**
   - `renice` es un comando que se utiliza para cambiar el valor `nice` de un proceso que ya está en ejecución. Permite ajustar dinámicamente la prioridad de los procesos, aumentando o reduciendo el tiempo de CPU que reciben según los nuevos valores `nice`.
   - Por ejemplo, si un proceso necesita más recursos de CPU temporalmente, se puede reducir su valor `nice` con `renice`.

#### Clases de Quality of Service (QoS)

Las clases QoS son un enfoque más moderno para gestionar las prioridades de los hilos, especialmente en sistemas como macOS que admiten **Grand Central Dispatch (GCD)**. Las clases QoS permiten a los desarrolladores **categorizar** el trabajo en distintos niveles según su importancia o urgencia. macOS gestiona automáticamente la prioridad de los hilos según estas clases QoS:

1. **User Interactive:**
   - Esta clase es para las tareas que interactúan con el usuario en ese momento o que necesitan resultados inmediatos para ofrecer una buena experiencia. Estas tareas reciben la prioridad más alta para mantener la interfaz receptiva (por ejemplo, las animaciones o la gestión de eventos).
2. **User Initiated:**
   - Tareas que inicia el usuario y para las que espera resultados inmediatos, como abrir un documento o hacer clic en un botón que requiere cálculos. Tienen prioridad alta, pero inferior a la de User Interactive.
3. **Utility:**
   - Estas tareas suelen ser de larga duración y normalmente muestran un indicador de progreso (por ejemplo, descargar archivos o importar datos). Tienen menos prioridad que las tareas iniciadas por el usuario y no necesitan terminar de inmediato.
4. **Background:**
   - Esta clase es para tareas que se ejecutan en segundo plano y no son visibles para el usuario. Pueden ser tareas como la indexación, la sincronización o las copias de seguridad. Tienen la prioridad más baja y un impacto mínimo en el rendimiento del sistema.

Con las clases QoS, los desarrolladores no necesitan gestionar los valores exactos de prioridad, sino centrarse en la naturaleza de la tarea; el sistema optimiza los recursos de CPU en consecuencia.

Además, existen distintas **políticas de planificación de hilos** que especifican un conjunto de parámetros de planificación que el planificador tendrá en cuenta. Esto puede hacerse mediante `thread_policy_[set/get]`. Esto puede ser útil en ataques de race condition.

## Abuso de procesos en macOS

macOS proporciona muchos mecanismos para que **los procesos interactúen, se comuniquen y compartan datos**. Aunque estos mecanismos son esenciales para el funcionamiento normal del sistema, los atacantes pueden abusar de ellos para realizar injection, ejecutar código o acceder a datos.

### Library Injection

Library Injection es una técnica mediante la cual un atacante **fuerza a un proceso a cargar una library maliciosa**. Una vez inyectada, la library se ejecuta en el contexto del proceso objetivo, lo que proporciona al atacante los mismos permisos y accesos que tiene el proceso.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste en **interceptar llamadas a funciones** o mensajes dentro del código de un software. Al interceptar funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos sensibles o incluso controlar el flujo de ejecución.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Comunicación entre procesos

La comunicación entre procesos (IPC) hace referencia a los distintos métodos mediante los cuales procesos separados **comparten e intercambian datos**. Aunque la IPC es fundamental para muchas aplicaciones legítimas, también puede utilizarse indebidamente para eludir el aislamiento entre procesos, filtrar información sensible o realizar acciones no autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection en aplicaciones Electron

Las aplicaciones Electron ejecutadas con variables de entorno específicas podrían ser vulnerables a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection en Chromium

Es posible utilizar las flags `--load-extension` y `--use-fake-ui-for-media-stream` para realizar un **man in the browser attack** que permite robar pulsaciones de teclas, tráfico y cookies, e inyectar scripts en páginas...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Los archivos NIB **definen elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios** y **Gatekeeper no impide** que se vuelva a ejecutar una aplicación ya ejecutada si se **modifica un archivo NIB**. Por tanto, podrían utilizarse para hacer que programas arbitrarios ejecuten comandos arbitrarios:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection en aplicaciones Java

Es posible inyectar opciones JVM mediante **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`** y cargar un agente Java o nativo antes de que se inicie la aplicación.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection en Node.js

**`NODE_OPTIONS`** precarga JavaScript del atacante mediante `--require` (archivo) o `--import data:text/javascript,…` (sin archivo, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carga un módulo en un REPL interactivo, y **`ELECTRON_RUN_AS_NODE`** vuelve a habilitar todo esto en los binarios Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection en aplicaciones .Net

Es posible inyectar código en aplicaciones .NET mediante **`DOTNET_STARTUP_HOOKS`** antes de `Main`, o abusando de la funcionalidad de depuración de .NET cuando se cumplen sus requisitos previos.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash no interactivo lee **`BASH_ENV`**; los shells POSIX interactivos leen **`ENV`**; zsh lee **`$ZDOTDIR/.zshenv`**; y fish lee la configuración ubicada bajo **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Cada uno puede ejecutar un archivo de inicio controlado antes del comando previsto. Bash también ejecuta una sustitución de comandos incluida en **`PS4`** cada vez que xtrace está habilitado (por ejemplo, mediante **`SHELLOPTS=xtrace`** heredado):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** pueden cargar una configuración PHP controlada cuyo **`auto_prepend_file`** se ejecuta antes del script objetivo.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

El intérprete Lua independiente ejecuta código o un `@file` de **`LUA_INIT`** (o de su variante específica de versión) antes de procesar el script objetivo.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** y **`R_PROFILE`** redirigen a perfiles de inicio que contienen código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, junto con una ruta a una library de R, pueden cargar automáticamente un paquete instalado.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige al depot cuyo `config/startup.jl` se ejecuta automáticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang y Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** pueden inyectar una expresión Erlang VM **`-eval`** sin requerir un archivo de payload; las cargas de trabajo de Elixir suelen iniciar la misma VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** y **`OCTAVE_VERSION_INITFILE`** redirigen los scripts de inicio de Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` es una aplicación .NET multiplataforma, por lo que varias variables de entorno permiten ejecutar código antes del comando: **`XDG_CONFIG_HOME`** redirige los scripts de perfil que se ejecutan al inicio, **`PSModulePath`** permite secuestrar la carga automática de módulos (un `.psm1` colocado allí se ejecuta al importarse y puede ocultar cmdlets integrados), y las variables de .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** y **`DOTNET_STARTUP_HOOKS`** cargan código del atacante en el proceso antes de `Main`.

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

La cadena de la biblioteca estándar **`PYTHONWARNINGS`** y **`BROWSER`** puede ejecutar un comando durante el análisis del filtro de advertencias. Una alternativa basada en archivos consiste en colocar `sitecustomize.py` en **`PYTHONPATH`** para que la inicialización normal de `site` lo importe antes del script objetivo. **`PYTHONBREAKPOINT`** ejecuta una función o un módulo elegido cuando el código llega a `breakpoint()`. Las variables exclusivas del modo interactivo, como **`PYTHONSTARTUP`**, tienen un ámbito de aplicación más limitado.

Ten en cuenta que los ejecutables compilados con **`pyinstaller`** no utilizan estas variables de entorno, aunque se ejecuten con un Python integrado.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (y su alternativa `EXINIT`) se ejecutan como comandos Ex durante un inicio normal, por lo que `:!cmd` / `:call system(...)` permiten ejecutar código cuando una víctima abre Vim/Neovim con un entorno controlado:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Por otra parte, Homebrew suele instalar Python en `/opt/homebrew`, donde los miembros del grupo local `admin` pueden tener permiso para reemplazar el launcher. Esto es un secuestro de binario escribible, no una injection mediante variables de entorno; comprueba la propiedad y las ACL antes de considerarlo explotable.


## Detección

### Shield

[**Shield**](https://github.com/theevilbit/Shield) es una aplicación de código abierto basada en **EndpointSecurity** que detecta y bloquea process injection. Es una buena referencia para saber qué señales se pueden observar mediante Endpoint Security, ya que genera alertas sobre:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variables de entorno de injection** al ejecutar un proceso: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` y `ELECTRON_RUN_AS_NODE`.
- Llamadas a **`task_for_pid`**: un proceso solicita el task port de otro, requisito previo para inyectarse en él.
- **Argumentos de depuración de Electron**: `--inspect`, `--inspect-brk` y `--remote-debugging-port`, que inician una aplicación Electron en modo de depuración y permiten que cualquiera se conecte y ejecute código en ella.<sup>[[3]](#references)</sup>
- **Creación de symlinks/hardlinks entre niveles de privilegio**: la técnica clásica de «crear un enlace como usuario normal y apuntarlo a una ubicación privilegiada». Ten en cuenta que **se pueden generar alertas sobre los symlinks, pero no bloquearlos**: EndpointSecurity no expone el destino del enlace antes de su creación.

### Llamadas realizadas por otros procesos

En [**esta publicación de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes ver cómo se puede utilizar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y, después, obtener información sobre ese otro proceso.<sup>[[4]](#references)</sup>

Ten en cuenta que para llamar a esa función debes tener **el mismo uid** que el proceso o ser **root** (y devuelve información sobre el proceso; no permite inyectar código).

## References

- [1] [Shield — detección de process injection en macOS de código abierto (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por qué las aplicaciones Electron no pueden almacenar tus secretos de forma confidencial: la opción --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detección de modificaciones de tareas](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
