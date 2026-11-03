# Abuso de procesos en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica sobre los procesos

Un proceso es una instancia de un ejecutable en ejecución; sin embargo, los procesos no ejecutan código: lo hacen los threads. Por lo tanto, **los procesos son simplemente contenedores para ejecutar threads** que proporcionan memoria, descriptores, puertos, permisos...

Tradicionalmente, los procesos se iniciaban dentro de otros procesos (excepto el PID 1) llamando a **`fork`**, que creaba una copia exacta del proceso actual. Luego, el **proceso hijo** generalmente llamaba a **`execve`** para cargar el nuevo ejecutable y ejecutarlo. Después se introdujo **`vfork`** para acelerar este proceso sin copiar la memoria.\
Luego se introdujo **`posix_spawn`**, que combina **`vfork`** y **`execve`** en una sola llamada y acepta flags:

- `POSIX_SPAWN_RESETIDS`: Restablece los IDs efectivos a los IDs reales
- `POSIX_SPAWN_SETPGROUP`: Establece la pertenencia al grupo de procesos
- `POSUX_SPAWN_SETSIGDEF`: Establece el comportamiento predeterminado de las señales
- `POSIX_SPAWN_SETSIGMASK`: Establece la máscara de señales
- `POSIX_SPAWN_SETEXEC`: Ejecuta en el mismo proceso (como `execve`, pero con más opciones)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia el proceso suspendido
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sin ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa el asignador Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` en los segmentos de datos
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Cierra por defecto todos los descriptores de archivo en exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatoriza los bits altos del desplazamiento de ASLR

Además, `posix_spawn` acepta ajustes de **`posix_spawnattr`** que controlan aspectos del proceso creado y entradas de **`posix_spawn_file_actions`** que modifican los descriptores de archivo.

Cuando un proceso termina, envía el **código de retorno al proceso padre** (si el padre terminó, el nuevo padre es el PID 1) mediante la señal `SIGCHLD`. El padre debe obtener este valor llamando a `wait4()` o `waitid()` y, hasta que eso ocurra, el hijo permanece en estado zombi: sigue apareciendo en la lista, pero no consume recursos.

### PIDs

Los PIDs, o identificadores de proceso, identifican un proceso único. En XNU, los **PIDs** tienen **64 bits**, aumentan de forma monótona y **nunca vuelven a empezar desde cero** (para evitar abusos).

### Grupos de procesos, sesiones y coaliciones

Los **procesos** pueden agruparse para facilitar su gestión. Por ejemplo, los comandos de un script de shell pertenecerán al mismo grupo de procesos, por lo que es posible **enviarles señales juntos** usando `kill`, por ejemplo.\
También es posible **agrupar procesos en sesiones**. Cuando un proceso inicia una sesión (`setsid(2)`), sus procesos hijos se incluyen en ella, salvo que inicien su propia sesión.

La coalición es otra forma de agrupar procesos en Darwin. Un proceso que se une a una coalición puede acceder a recursos del pool, compartir un ledger o verse afectado por Jetsam. Las coaliciones tienen distintos roles: Leader, servicio XPC y Extension.

### Credenciales y personas

Cada proceso tiene **credenciales** que **identifican sus privilegios** en el sistema. Cada proceso tendrá un `uid` principal y un `gid` principal (aunque puede pertenecer a varios grupos).\
También es posible cambiar el ID de usuario y de grupo si el binario tiene el bit `setuid/setgid`.\
Hay varias funciones para **establecer nuevos uids/gids**.

La syscall **`persona`** proporciona un conjunto **alternativo** de **credenciales**. Adoptar una persona asume de una vez su uid, gid y pertenencias a grupos. En el [**código fuente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) se puede encontrar la estructura:

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

1. **POSIX Threads (pthreads):** macOS admite POSIX threads (`pthreads`), que forman parte de una API estándar de hilos para C/C++. La implementación de pthreads en macOS se encuentra en `/usr/lib/system/libsystem_pthread.dylib`, que proviene del proyecto `libpthread`, disponible públicamente. Esta biblioteca proporciona las funciones necesarias para crear y administrar hilos.
2. **Creación de hilos:** La función `pthread_create()` se usa para crear hilos nuevos. Internamente, esta función llama a `bsdthread_create()`, una llamada al sistema de nivel inferior específica del kernel XNU (el kernel en el que se basa macOS). Esta llamada al sistema recibe varios flags derivados de `pthread_attr` (atributos) que especifican el comportamiento del hilo, incluidas las políticas de planificación y el tamaño de la pila.
   - **Tamaño de pila predeterminado:** El tamaño de pila predeterminado para los hilos nuevos es de 512 KB, suficiente para las operaciones habituales, pero se puede ajustar mediante los atributos del hilo si se necesita más o menos espacio.
3. **Inicialización de hilos:** La función `__pthread_init()` es fundamental durante la configuración del hilo y utiliza el argumento `env[]` para analizar variables de entorno que pueden incluir detalles sobre la ubicación y el tamaño de la pila.

#### Terminación de hilos en macOS

1. **Salida de hilos:** Los hilos suelen terminarse llamando a `pthread_exit()`. Esta función permite que un hilo termine correctamente, realice las tareas de limpieza necesarias y envíe un valor de retorno a cualquier hilo que espere su finalización con `join`.
2. **Limpieza de hilos:** Al llamar a `pthread_exit()`, se invoca la función `pthread_terminate()`, que elimina todas las estructuras asociadas al hilo. Desasigna los puertos de hilo de Mach (Mach es el subsistema de comunicación del kernel XNU) y llama a `bsdthread_terminate`, una llamada al sistema que elimina las estructuras del kernel asociadas al hilo.

#### Mecanismos de sincronización

Para administrar el acceso a recursos compartidos y evitar condiciones de carrera, macOS proporciona varias primitivas de sincronización. Son esenciales en entornos multihilo para garantizar la integridad de los datos y la estabilidad del sistema:

1. **Mutexes:**
   - **Mutex normal (Signature: 0x4D555458):** Mutex estándar con una huella de memoria de 60 bytes (56 bytes para el mutex y 4 bytes para la firma).
   - **Fast Mutex (Signature: 0x4d55545A):** Similar a un mutex normal, pero optimizado para operaciones más rápidas; también ocupa 60 bytes.
2. **Variables de condición:**
   - Se usan para esperar a que se cumplan determinadas condiciones y tienen un tamaño de 44 bytes (40 bytes más una firma de 4 bytes).
   - **Atributos de variables de condición (Signature: 0x434e4441):** Atributos de configuración para variables de condición, con un tamaño de 12 bytes.
3. **Variable Once (Signature: 0x4f4e4345):**
   - Garantiza que un fragmento de código de inicialización se ejecute una sola vez. Tiene un tamaño de 12 bytes.
4. **Bloqueos de lectura-escritura:**
   - Permiten varios lectores o un escritor a la vez, lo que facilita el acceso eficiente a los datos compartidos.
   - **Bloqueo de lectura-escritura (Signature: 0x52574c4b):** Tiene un tamaño de 196 bytes.
   - **Atributos de bloqueo de lectura-escritura (Signature: 0x52574c41):** Atributos para los bloqueos de lectura-escritura, con un tamaño de 20 bytes.

> [!TIP]
> Los últimos 4 bytes de esos objetos se usan para detectar desbordamientos.

### Variables locales de hilo (TLV)

Las **variables locales de hilo (TLV)** en el contexto de los archivos Mach-O (el formato de los ejecutables en macOS) se usan para declarar variables específicas de **cada hilo** en una aplicación multihilo. Esto garantiza que cada hilo tenga su propia instancia independiente de una variable, lo que permite evitar conflictos y mantener la integridad de los datos sin necesitar mecanismos de sincronización explícitos, como mutexes.

En C y lenguajes relacionados, puedes declarar una variable local de hilo con la palabra clave **`__thread`**. Así funciona en el ejemplo:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Este fragmento define `tlv_var` como una variable local al hilo. Cada hilo que ejecute este código tendrá su propio `tlv_var`, y los cambios que haga un hilo en `tlv_var` no afectarán al `tlv_var` de otro hilo.

En el binario Mach-O, los datos relacionados con las variables locales al hilo se organizan en secciones específicas:

- **`__DATA.__thread_vars`**: esta sección contiene los metadatos de las variables locales al hilo, como sus tipos y su estado de inicialización.
- **`__DATA.__thread_bss`**: esta sección se usa para las variables locales al hilo que no se inicializan explícitamente. Es una parte de la memoria reservada para datos inicializados a cero.

Mach-O también proporciona una API específica llamada **`tlv_atexit`** para gestionar las variables locales al hilo cuando este termina. Esta API permite **registrar destructores**: funciones especiales que limpian los datos locales al hilo cuando este finaliza.

### Prioridades de los hilos

Para entender las prioridades de los hilos, hay que ver cómo decide el sistema operativo qué hilos ejecutar y cuándo. Esta decisión está influida por el nivel de prioridad asignado a cada hilo. En macOS y en los sistemas tipo Unix, esto se gestiona mediante conceptos como `nice`, `renice` y las clases de Quality of Service (QoS).

#### Nice y Renice

1. **Nice:**
   - El valor `nice` de un proceso es un número que afecta a su prioridad. Cada proceso tiene un valor `nice` de -20 (la prioridad más alta) a 19 (la más baja). El valor `nice` predeterminado al crear un proceso suele ser 0.
   - Un valor `nice` más bajo (más cercano a -20) hace que un proceso sea más «egoísta» y le da más tiempo de CPU en comparación con otros procesos que tienen valores `nice` más altos.
2. **Renice:**
   - `renice` es un comando que se usa para cambiar el valor `nice` de un proceso que ya está en ejecución. Permite ajustar dinámicamente la prioridad de los procesos, aumentando o reduciendo el tiempo de CPU que reciben según los nuevos valores `nice`.
   - Por ejemplo, si un proceso necesita más recursos de CPU temporalmente, se puede reducir su valor `nice` con `renice`.

#### Clases de Quality of Service (QoS)

Las clases de QoS son un método más moderno para gestionar las prioridades de los hilos, especialmente en sistemas como macOS, compatibles con **Grand Central Dispatch (GCD)**. Las clases de QoS permiten a los desarrolladores **clasificar** el trabajo en distintos niveles según su importancia o urgencia. macOS gestiona automáticamente la prioridad de los hilos según estas clases de QoS:

1. **User Interactive:**
   - Esta clase es para tareas que interactúan con el usuario en ese momento o que requieren resultados inmediatos para ofrecer una buena experiencia. Estas tareas reciben la máxima prioridad para mantener la interfaz receptiva (p. ej., las animaciones o la gestión de eventos).
2. **User Initiated:**
   - Tareas iniciadas por el usuario de las que se esperan resultados inmediatos, como abrir un documento o hacer clic en un botón que requiere cálculos. Tienen una prioridad alta, pero inferior a la de User Interactive.
3. **Utility:**
   - Estas tareas son de larga duración y normalmente muestran un indicador de progreso (p. ej., descargar archivos o importar datos). Tienen menos prioridad que las tareas iniciadas por el usuario y no necesitan finalizar de inmediato.
4. **Background:**
   - Esta clase es para tareas que se ejecutan en segundo plano y no son visibles para el usuario. Pueden ser tareas como indexar, sincronizar o crear copias de seguridad. Tienen la prioridad más baja y un impacto mínimo en el rendimiento del sistema.

Con las clases de QoS, los desarrolladores no necesitan gestionar los valores exactos de prioridad; pueden centrarse en la naturaleza de la tarea, y el sistema optimiza los recursos de CPU según corresponda.

Además, existen distintas **políticas de planificación de hilos** que permiten especificar un conjunto de parámetros de planificación que el planificador tendrá en cuenta. Esto se puede hacer con `thread_policy_[set/get]`. Puede resultar útil en ataques de race condition.

## Abuso de procesos en macOS

macOS ofrece muchos mecanismos para que los **procesos interactúen, se comuniquen y compartan datos**. Aunque estos mecanismos son esenciales para el funcionamiento normal del sistema, los atacantes pueden abusar de ellos para realizar inyección, ejecutar código o acceder a datos.

### Library Injection

Library Injection es una técnica en la que un atacante **obliga a un proceso a cargar una biblioteca maliciosa**. Una vez inyectada, la biblioteca se ejecuta en el contexto del proceso objetivo y proporciona al atacante los mismos permisos y acceso que tiene ese proceso.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking consiste en **interceptar llamadas a funciones** o mensajes dentro del código de un programa. Al enganchar funciones, un atacante puede **modificar el comportamiento** de un proceso, observar datos confidenciales e incluso controlar el flujo de ejecución.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Esta página trata los metadatos de unwind de ARM64, las restricciones de PAC de arm64e y las cadenas de llamadas sintéticas.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) se refiere a los distintos métodos que permiten a procesos separados **compartir e intercambiar datos**. Aunque IPC es fundamental para muchas aplicaciones legítimas, también se puede usar indebidamente para subvertir el aislamiento entre procesos, filtrar información confidencial o realizar acciones no autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Las aplicaciones Electron ejecutadas con ciertas variables de entorno podrían ser vulnerables a la inyección de procesos:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Es posible usar las flags `--load-extension` y `--use-fake-ui-for-media-stream` para realizar un **ataque man-in-the-browser** que permita robar pulsaciones de teclas, tráfico y cookies, e inyectar scripts en páginas, entre otras cosas:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Los archivos NIB **definen elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Sin embargo, pueden **ejecutar comandos arbitrarios**, y **Gatekeeper no impide** que una aplicación ya ejecutada vuelva a ejecutarse si se modifica un **archivo NIB**. Por tanto, se podrían usar para hacer que programas arbitrarios ejecuten comandos arbitrarios:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Es posible inyectar opciones de JVM mediante **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** o **`JDK_JAVA_OPTIONS`** y cargar un agente Java o nativo antes de que se inicie la aplicación.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** precarga JavaScript del atacante mediante `--require` (archivo) o `--import data:text/javascript,…` (sin archivo, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carga un módulo en un REPL interactivo, y **`ELECTRON_RUN_AS_NODE`** vuelve a habilitar todo esto en los binarios de Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Es posible inyectar código en aplicaciones .NET mediante **`DOTNET_STARTUP_HOOKS`**, antes de `Main`, o abusando de la funcionalidad de depuración de .NET cuando se cumplen sus requisitos previos.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash no interactivo lee **`BASH_ENV`**; los shells POSIX interactivos leen **`ENV`**; zsh lee **`$ZDOTDIR/.zshenv`**; y fish lee la configuración ubicada bajo **`XDG_CONFIG_HOME`** o **`XDG_DATA_DIRS`**. Cada uno puede ejecutar un archivo de inicio controlado antes del comando previsto. Bash también ejecuta una sustitución de comandos incluida en **`PS4`** cada vez que se habilita xtrace (p. ej., mediante **`SHELLOPTS=xtrace`** heredado):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Al iniciar `/bin/zsh -s`, el shell lee un programa desde la entrada estándar. Por tanto, si un downloader copia un documento estructurado no confiable en la entrada estándar del proceso hijo sin analizarlo primero, convierte todo el documento en código fuente de shell. Un loader observado transmitió línea por línea un archivo iCalendar público a través de una tubería anónima. Los metadatos del calendario fallaban como comandos, pero zsh continuaba hasta llegar a líneas ejecutables colocadas después de `DESCRIPTION:`. Esas líneas descargaban e iniciaban el siguiente application bundle. El tipo de contenido esperado del archivo y el alojamiento de confianza no lo hacían seguro; el límite peligroso consistía en pasar sus bytes a un intérprete.<sup>[[5]](#references)</sup>

Las etapas relacionadas se tratan en [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) y [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** o **`PHP_INI_SCAN_DIR`** pueden cargar una configuración PHP controlada cuyo **`auto_prepend_file`** se ejecuta antes del script objetivo.

[Inyección de inicio mediante la configuración de PHP y `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

El intérprete independiente de Lua ejecuta código o un `@file` indicado en **`LUA_INIT`** (o en su variante específica de versión) antes de procesar el script objetivo.

[Inyección de inicio de Lua mediante `LUA_INIT` (archivo y código en línea)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** y **`R_PROFILE`** redirigen a perfiles de inicio que contienen código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, junto con una ruta de bibliotecas de R, permiten en cambio cargar automáticamente un paquete instalado.

[Perfiles de inicio de R y carga de paquetes](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige al depot cuyo `config/startup.jl` se ejecuta automáticamente.

[Inyección mediante `JULIA_DEPOT_PATH` y `startup.jl` de Julia](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** o **`ERL_ZFLAGS`** pueden inyectar una expresión Erlang VM **`-eval`** sin necesitar un archivo de payload; las cargas de trabajo de Elixir suelen iniciar la misma VM.

[Inyección mediante flags de Erlang/Elixir VM](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** y **`OCTAVE_VERSION_INITFILE`** redirigen a los scripts de inicio de Octave.

[Inyección mediante archivos de inicio de GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` es una aplicación .NET multiplataforma, por lo que varias variables de entorno permiten ejecutar código antes del comando: **`XDG_CONFIG_HOME`** redirige a los scripts de perfil que se ejecutan al inicio, **`PSModulePath`** permite secuestrar la carga automática de módulos (un archivo `.psm1` colocado allí se ejecuta al importarse y puede suplantar cmdlets integrados), y las variables de .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** y **`DOTNET_STARTUP_HOOKS`** cargan código del atacante en el proceso antes de `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Revisa las distintas opciones para hacer que un script Perl ejecute código arbitrario en:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

También es posible abusar de las variables de entorno de Ruby (**`RUBYOPT`**, **`RUBYLIB`**) para hacer que scripts arbitrarios ejecuten código arbitrario:


[Opciones de carga `RUBYOPT`/`RUBYLIB` de Ruby](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

La cadena de la biblioteca estándar **`PYTHONWARNINGS`** y **`BROWSER`** puede ejecutar un comando durante el análisis de filtros de advertencia. Una alternativa basada en archivos consiste en colocar `sitecustomize.py` en **`PYTHONPATH`**, de modo que la inicialización normal de `site` lo importe antes del script objetivo. **`PYTHONBREAKPOINT`** ejecuta una función o un módulo elegidos cuando el código llega a `breakpoint()`. Las variables de uso exclusivo en modo interactivo, como **`PYTHONSTARTUP`**, tienen un ámbito de aplicación más limitado.

Ten en cuenta que los ejecutables compilados con **`pyinstaller`** no usarán estas variables de entorno, aunque se ejecuten con un Python integrado.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (y su alternativa `EXINIT`) se ejecutan como comandos Ex durante un inicio normal, por lo que `:!cmd` / `:call system(...)` permiten ejecutar código cuando una víctima abre Vim/Neovim con un entorno controlado:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Por otra parte, Homebrew suele instalar Python bajo `/opt/homebrew`, donde los miembros del grupo `admin` local podrían reemplazar el lanzador. Esto es un secuestro de binario escribible, no una inyección mediante variables de entorno; comprueba la propiedad y las ACL antes de considerarlo explotable.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) es una aplicación de código abierto basada en **EndpointSecurity** que detecta y bloquea la inyección de procesos. Es una buena referencia para saber qué señales se pueden observar mediante Endpoint Security, ya que genera alertas sobre:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variables de entorno de inyección** al ejecutar un proceso: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` y `ELECTRON_RUN_AS_NODE`.
- Llamadas a **`task_for_pid`**: un proceso solicita el task port de otro proceso, requisito previo para inyectar código en él.
- **Argumentos de depuración de Electron**: `--inspect`, `--inspect-brk` y `--remote-debugging-port`, que inician una aplicación Electron en modo de depuración y permiten que cualquiera se conecte y ejecute código en ella.<sup>[[3]](#references)</sup>
- **Creación de symlinks/hardlinks entre niveles de privilegio**: la técnica clásica de «crear un enlace como usuario normal y apuntarlo a una ubicación privilegiada». Ten en cuenta que **se pueden generar alertas por los symlinks, pero no bloquearlos**: EndpointSecurity no expone el destino del enlace antes de su creación.

### Llamadas realizadas por otros procesos

En [**esta entrada de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puedes encontrar cómo usar la función **`task_name_for_pid`** para obtener información sobre otros **procesos que inyectan código en un proceso** y, después, obtener información sobre ese otro proceso.<sup>[[4]](#references)</sup>

Ten en cuenta que para llamar a esa función debes tener **el mismo uid** que el proceso en ejecución o ser **root** (y la función devuelve información sobre el proceso, no una forma de inyectar código).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — detección de inyección de procesos en macOS de código abierto (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por qué las aplicaciones Electron no pueden almacenar tus secretos de forma confidencial: opción --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detección de modificaciones de tareas](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Una nueva versión del malware ladrón de macOS MacSync apunta a entusiastas de las criptomonedas y desarrolladores](https://securelist.com/macsync-new-version/121383/)
